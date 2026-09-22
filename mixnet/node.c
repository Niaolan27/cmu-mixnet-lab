/**
 * Copyright (C) 2023 Carnegie Mellon University
 *
 * This file is part of the Mixnet course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the Mixnet project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */
#include "node.h"

#include "connection.h"
#include "packet.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * Debug logging. Compiles to nothing unless MIXNET_DEBUG is defined, since
 * the autograder parses console output.
 */
#ifdef MIXNET_DEBUG
#include <stdio.h>
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...) ((void) 0)
#endif

// Total size of an STP packet: 12B header + 6B payload
#define STP_PACKET_SIZE (sizeof(mixnet_packet) + sizeof(mixnet_packet_stp))

// Total size of an LSA packet advertising n links: 12B header + (4 + 4n)B
#define LSA_PACKET_SIZE(n) (sizeof(mixnet_packet) +                     \
                            sizeof(mixnet_packet_lsa) +                 \
                            (sizeof(mixnet_lsa_link_params) * (size_t) (n)))

/**
 * One vertex of the network topology: a mixnet node, together with the links
 * that node advertised. A vertex's index in graph.v is its id; ids are
 * stable because CP2 never removes a node.
 *
 * A vertex id and a port number are different namespaces and must never be
 * compared: a port indexes *our own* links, a vertex id indexes every node
 * we have heard of. mixnet_address is the only identifier common to both.
 */
struct vertex {
    mixnet_address addr;            // The node this vertex stands for
    bool advertised;                // Have we received this node's LSA?
    uint16_t num_links;             // Links it advertised
    mixnet_lsa_link_params *links;  // [num_links]; NULL until its LSA arrives
};

/** Adjacency list: one row per node, holding that node's own links. */
struct graph {
    struct vertex *v;               // [count], the index is the vertex id
    uint16_t count;
    uint16_t capacity;
};

/**
 * The path to one destination: Dijkstra's output for it, kept between runs
 * so that routing a packet is a lookup. The route is in exactly the form the
 * routing header wants, the intermediate hops only, since the header carries
 * source and destination itself.
 *
 * `reachable` is needed because a direct neighbor and an unreachable node
 * both have no intermediate hops, so `route == NULL` cannot tell them apart.
 */
struct fib_entry {
    bool reachable;                 // False: no path on the current topology
    uint16_t route_len;             // Hops strictly between us and the destination
    mixnet_address *route;          // [route_len], in forwarding order; NULL if none
};

/**
 * One packet held back by mixing, waiting for its batch to fill. The egress
 * port is resolved before the packet is enqueued, so that a packet with no
 * route is dropped instead of occupying a slot the batch would then wait on
 * forever.
 */
struct mix_slot {
    uint8_t port;                   // Egress port, resolved at enqueue time
    mixnet_packet *packet;          // Ours until the batch is flushed
};

/**
 * This node's protocol state.
 *
 * Spanning-tree invariant:
 *     root == config.node_addr  <=>  path_len == 0
 *                               <=>  next_hop == INVALID_MIXADDR
 *
 * The FIB is derived state: it is rebuilt from the topology whenever the
 * topology changes, and nothing else ever writes to it.
 */
struct node_state {
    // Spanning tree (CP1)
    mixnet_address root;        // Believed root of the spanning tree
    uint16_t path_len;          // Hop count from this node to the root
    mixnet_address next_hop;    // Parent: neighbor on the path to the root

    mixnet_address *neighbor_addr;  // [num_neighbors] port -> neighbor address
    bool *blocked;                  // [num_neighbors] port -> FLOOD blocked?

    uint64_t hello_start_ms;        // Last hello broadcast (root only)
    uint64_t reelection_start_ms;   // Last hello heard from the parent

    // Link state (CP2)
    struct graph topology;          // Global view, assembled from LSAs
    uint64_t lsa_start_ms;          // Last time we advertised our own links

    // Shortest paths (CP2)
    struct fib_entry *fib;          // [fib_count], parallel to topology.v
    uint16_t fib_count;             // topology.count as of the last rebuild

    // Mixing (CP2)
    struct mix_slot *mix;           // [mixing_factor], oldest first; NULL if unused
    uint16_t mix_count;             // Held packets; always < mixing_factor here
};

/** Monotonic milliseconds; the STP intervals are in ms. */
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (((uint64_t) ts.tv_sec) * 1000u) +
           (((uint64_t) ts.tv_nsec) / 1000000u);
}

/** Reverse lookup: neighbor address -> port, or -1 if not a known neighbor. */
static int port_of(const struct mixnet_node_config *c,
                   const struct node_state *s,
                   const mixnet_address addr) {

    if (addr == INVALID_MIXADDR) { return -1; }
    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if (s->neighbor_addr[p] == addr) { return (int) p; }
    }
    return -1;
}

/** The vertex id for an address, or -1 if we have never heard of it. */
static int id_find(const struct graph *g, const mixnet_address addr) {
    for (uint16_t i = 0; i < g->count; i++) {
        if (g->v[i].addr == addr) { return (int) i; }
    }
    return -1;
}

/**
 * Find-or-insert: the vertex id for an address, appending a link-less vertex
 * if this is the first time we have seen it. Returns -1 only if we are out
 * of memory.
 *
 * This inserts rather than merely searching because a node can be named in
 * someone else's neighbor list before its own LSA arrives; without that, a
 * relaxation loop would hit an address with no id.
 */
static int id_lookup(struct graph *g, const mixnet_address addr) {
    const int found = id_find(g, addr);
    if (found >= 0) { return found; }

    if (g->count == g->capacity) {
        const uint32_t cap = (g->capacity == 0) ?
            8u : ((uint32_t) g->capacity * 2u);
        if (cap > UINT16_MAX) { return -1; }

        struct vertex *grown = realloc(g->v, sizeof(*grown) * cap);
        if (grown == NULL) { return -1; }
        g->v = grown;
        g->capacity = (uint16_t) cap;
    }
    g->v[g->count].addr = addr;
    g->v[g->count].advertised = false;
    g->v[g->count].num_links = 0;
    g->v[g->count].links = NULL;

    return (int) g->count++;
}

/**
 * Install an LSA's neighbor list as the advertising node's row, and return
 * whether that changed anything.
 *
 * An advertisement is a complete replacement, never a delta: the originator
 * is the sole authority on its own links, so merging into the existing row
 * would retain edges the originator no longer advertises.
 */
static bool graph_update(struct graph *g, const mixnet_address origin,
                         const uint16_t num_links,
                         const mixnet_lsa_link_params *const links) {

    // Intern every mentioned address *before* taking a row pointer: these
    // inserts can realloc g->v, which would dangle a pointer taken earlier.
    for (uint16_t i = 0; i < num_links; i++) {
        if (id_lookup(g, links[i].neighbor_mixaddr) < 0) { return false; }
    }
    const int id = id_lookup(g, origin);
    if (id < 0) { return false; }

    struct vertex *row = &g->v[id];  // Safe: no further inserts past here
    const size_t bytes = sizeof(*links) * (size_t) num_links;

    // Byte-identical to the row we already hold, so nothing downstream of
    // the topology needs recomputing. The advertised test is what separates
    // "merely named in someone else's neighbor list" from "advertised zero
    // links": both leave links == NULL, so without it a link-less node's
    // first LSA would be mistaken for a no-op.
    if (row->advertised && (row->num_links == num_links) &&
        ((num_links == 0) || (memcmp(row->links, links, bytes) == 0))) {
        return false;
    }

    mixnet_lsa_link_params *copy = NULL;
    if (num_links > 0) {
        if ((copy = malloc(bytes)) == NULL) { return false; }
        memcpy(copy, links, bytes);
    }
    free(row->links);  // NULL on a row that was only ever interned
    row->links = copy;
    row->num_links = num_links;
    row->advertised = true;

    return true;
}

/** The links array of an LSA payload, which trails it in the packet. */
static const mixnet_lsa_link_params *lsa_links(
        const mixnet_packet_lsa *const lsa) {
    return (const mixnet_lsa_link_params *)
        (((const char *) lsa) + sizeof(*lsa));
}

/**
 * Hand a packet to the framework. On success the callee takes ownership and
 * frees it; a negative return means we built a malformed packet, in which
 * case ownership stays with us and we must free it ourselves.
 */
static void send_packet(void *const handle, const uint8_t port,
                        mixnet_packet *const packet) {
    int rc;
    while ((rc = mixnet_send(handle, port, packet)) == 0) {
        // Not sent: the docstring requires us to re-attempt until it is
    }
    if (rc < 0) {
        DBG("[node] malformed packet on port %u (type %u)\n",
            (unsigned) port, (unsigned) packet->type);
        free(packet);
    }
}

/** Allocate an STP packet carrying this node's current bid. */
static mixnet_packet *make_stp_packet(const struct mixnet_node_config *c,
                                      const struct node_state *s) {
    mixnet_packet *packet = malloc(STP_PACKET_SIZE);
    if (packet == NULL) { return NULL; }

    packet->total_size = (uint16_t) STP_PACKET_SIZE;
    packet->type = PACKET_TYPE_STP;

    mixnet_packet_stp *payload = (mixnet_packet_stp *) packet->payload;
    payload->root_address = s->root;
    payload->path_length = s->path_len;
    payload->node_address = c->node_addr;

    return packet;
}

/**
 * Allocate an LSA advertising this node's own links. This is the one place
 * the two namespaces meet: we walk our *ports* and write out the *addresses*
 * they lead to, since that is all a remote node can make sense of.
 */
static mixnet_packet *make_lsa_packet(const struct mixnet_node_config *c,
                                      const struct node_state *s) {

    const size_t size = LSA_PACKET_SIZE(c->num_neighbors);
    mixnet_packet *packet = malloc(size);
    if (packet == NULL) { return NULL; }

    packet->total_size = (uint16_t) size;
    packet->type = PACKET_TYPE_LSA;

    mixnet_packet_lsa *lsa = (mixnet_packet_lsa *) packet->payload;
    lsa->node_address = c->node_addr;
    lsa->neighbor_count = c->num_neighbors;

    mixnet_lsa_link_params *links =
        (mixnet_lsa_link_params *) (packet->payload + sizeof(*lsa));

    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        links[p].neighbor_mixaddr = s->neighbor_addr[p];  // port -> address
        links[p].cost = c->link_costs[p];                 // costs are by port
    }
    return packet;
}

/** Byte-for-byte copy; mixnet_send() consumes a packet, so each port needs one. */
static mixnet_packet *clone_packet(const mixnet_packet *const packet) {
    mixnet_packet *copy = malloc(packet->total_size);
    if (copy != NULL) { memcpy(copy, packet, packet->total_size); }
    return copy;
}

/**
 * Send this node's STP bid to every neighbor, optionally skipping one port.
 * Pass except_port = -1 to send on all of them. STP is never gated by the
 * blocked state: blocking applies to FLOOD only, which is what lets a
 * wrongly-blocked port recover.
 */
static void broadcast_stp(void *const handle,
                          const struct mixnet_node_config *c,
                          const struct node_state *s,
                          const int except_port) {

    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if ((int) p == except_port) { continue; }

        mixnet_packet *packet = make_stp_packet(c, s);
        if (packet == NULL) { continue; }
        send_packet(handle, (uint8_t) p, packet);
    }
}

/**
 * Send a copy of a packet out over every spanning-tree link except one. Pass
 * except_port = -1 to use every tree link. The caller keeps ownership of
 * `packet`; only the copies are handed to the framework.
 *
 * Shared by FLOOD and LSA, whose forwarding rules are identical: tree links
 * only, never back out the link it arrived on.
 */
static void broadcast_on_tree(void *const handle,
                              const struct mixnet_node_config *c,
                              const struct node_state *s,
                              const int except_port,
                              const mixnet_packet *const packet) {

    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if (((int) p == except_port) || s->blocked[p]) { continue; }

        mixnet_packet *copy = clone_packet(packet);
        if (copy == NULL) { continue; }
        send_packet(handle, (uint8_t) p, copy);
    }
}

/*
 * Shortest paths. Dijkstra runs from this node over s->topology whenever the
 * topology changes, and writes one FIB entry per vertex. Between runs the
 * data path only reads the FIB; it never computes.
 *
 * Linear scans throughout: the network is at most a few hundred nodes, and
 * this runs a handful of times during the initial LSA burst and then stops,
 * since a re-advertisement that changes nothing never gets here.
 */

// Cost of a destination no path has reached yet
#define INFINITE_COST UINT32_MAX

/**
 * Dijkstra's working state for one vertex; indexed by vertex id.
 *
 * `path` is the whole route from us to this vertex: the hops after us, the
 * vertex itself last. The equal-cost tie-break needs all of it rather than
 * just the first hop, since two paths can leave through the same neighbor
 * and only diverge further along. The rows live in the same allocation as
 * the array, so freeing the array frees them too.
 */
struct sp_vertex {
    uint32_t cost;              // Cheapest known path from us; INFINITE_COST if none
    mixnet_address *path;       // [path_len]; empty for us, unreached, or both
    uint16_t path_len;
    bool settled;               // Cost is final
};

/**
 * Whether path a beats path b: cheaper, or equal cost and holding the
 * smaller address at the first hop where the two differ, compared from our
 * end. That is the handout's equal-cost rule. A path that is a prefix of the
 * other is the smaller one; between two paths to the *same* vertex that
 * cannot happen, since both end at that vertex, but the settling order below
 * compares paths to different vertices, where it can.
 *
 * It is also the order vertices are settled in, and that matters when a link
 * costs zero: a vertex must not be settled while an equal-cost, smaller path
 * could still reach it over a zero-cost link from a vertex that is not
 * settled yet. Settling by (cost, path) rules that out, because any such path
 * runs through an unsettled vertex that is itself smaller on both halves of
 * the key -- its cost cannot be larger, and its path is a prefix.
 */
static bool path_is_better(const uint32_t cost_a,
                           const mixnet_address *const path_a,
                           const uint16_t len_a,
                           const uint32_t cost_b,
                           const mixnet_address *const path_b,
                           const uint16_t len_b) {

    if (cost_a != cost_b) { return cost_a < cost_b; }

    const uint16_t common = (len_a < len_b) ? len_a : len_b;
    for (uint16_t i = 0; i < common; i++) {
        if (path_a[i] != path_b[i]) { return path_a[i] < path_b[i]; }
    }
    return len_a < len_b;
}

/**
 * Dijkstra from `self` over the topology. Each vertex's advertised links are
 * its outgoing edges, so asymmetric costs need no special handling. Returns
 * the per-vertex result, owned by the caller, or NULL if out of memory.
 *
 * A single allocation holds the vertex array, one path row per vertex, and
 * one scratch row for the candidate being relaxed. A row of g->count
 * addresses is always enough: every path here is simple, since it is built
 * from settled vertices only and never re-enters one.
 */
static struct sp_vertex *run_dijkstra(const struct graph *g, const int self) {
    const size_t count = g->count;
    if (count == 0) { return NULL; }

    const size_t head = sizeof(struct sp_vertex) * count;
    const size_t body = sizeof(mixnet_address) * count * (count + 1);

    struct sp_vertex *sp = malloc(head + body);
    if (sp == NULL) { return NULL; }

    // Rows follow the array; the last one is scratch, not owned by a vertex
    mixnet_address *const rows = (mixnet_address *) ((char *) sp + head);
    mixnet_address *const candidate = rows + (count * count);

    for (uint16_t i = 0; i < g->count; i++) {
        sp[i] = (struct sp_vertex) { .cost = INFINITE_COST,
                                     .path = rows + ((size_t) i * count),
                                     .path_len = 0, .settled = false };
    }
    sp[self].cost = 0;  // Reached by the empty path, which beats every other

    for (;;) {
        // Settle the best vertex that some path has reached
        int u = -1;
        for (uint16_t i = 0; i < g->count; i++) {
            if (sp[i].settled || (sp[i].cost == INFINITE_COST)) { continue; }
            if ((u < 0) ||
                path_is_better(sp[i].cost, sp[i].path, sp[i].path_len,
                               sp[u].cost, sp[u].path, sp[u].path_len)) {
                u = (int) i;
            }
        }
        if (u < 0) { break; }
        sp[u].settled = true;

        // Relax its outgoing links. Every link's far end has an id, because
        // graph_update interns every address an LSA names; a settled far end
        // cannot be improved, by the settling order above.
        const struct vertex *from = &g->v[u];
        for (uint16_t k = 0; k < from->num_links; k++) {
            const mixnet_lsa_link_params *link = &from->links[k];
            const int w = id_find(g, link->neighbor_mixaddr);
            if ((w < 0) || sp[w].settled) { continue; }

            // The candidate is u's path with w appended, so relaxing from us
            // yields the one-hop path {w} without a special case
            const uint32_t cost = sp[u].cost + link->cost;
            const uint16_t len = (uint16_t) (sp[u].path_len + 1);
            memcpy(candidate, sp[u].path, sizeof(*candidate) * sp[u].path_len);
            candidate[len - 1] = link->neighbor_mixaddr;

            if (path_is_better(cost, candidate, len,
                               sp[w].cost, sp[w].path, sp[w].path_len)) {
                sp[w].cost = cost;
                sp[w].path_len = len;
                memcpy(sp[w].path, candidate, sizeof(*candidate) * len);
            }
        }
    }
    return sp;
}

/** Discard every FIB entry and size the table for `count` vertices. */
static bool fib_reset(struct node_state *s, const uint16_t count) {
    for (uint16_t i = 0; i < s->fib_count; i++) { free(s->fib[i].route); }
    free(s->fib);
    s->fib = NULL;
    s->fib_count = 0;

    if (count == 0) { return true; }
    if ((s->fib = calloc(count, sizeof(*s->fib))) == NULL) { return false; }
    s->fib_count = count;  // Zeroed, so every entry starts unreachable
    return true;
}

/**
 * Turn Dijkstra's result for one destination into its FIB entry: the
 * destination's path without the destination itself, which the routing
 * header carries separately.
 */
static bool install_route(struct fib_entry *entry,
                          const struct sp_vertex *sp, const int dst) {

    const uint16_t hops = (uint16_t) (sp[dst].path_len - 1);  // Reachable: >= 1
    if (hops > MAX_MIXNET_ROUTE_LENGTH) { return false; }  // Header cannot carry it

    mixnet_address *route = NULL;
    if (hops > 0) {
        if ((route = malloc(sizeof(*route) * hops)) == NULL) { return false; }
        memcpy(route, sp[dst].path, sizeof(*route) * hops);
    }
    entry->reachable = true;
    entry->route_len = hops;
    entry->route = route;
    return true;
}

/**
 * Rebuild the FIB from the topology. Our own row must be present, since it
 * is the only source of our outgoing edges; until then nothing is reachable.
 */
static void update_shortest_path(const struct mixnet_node_config *c,
                                 struct node_state *s) {

    const struct graph *g = &s->topology;
    if (!fib_reset(s, g->count)) { return; }

    const int self = id_find(g, c->node_addr);
    if (self < 0) { return; }

    struct sp_vertex *sp = run_dijkstra(g, self);
    if (sp == NULL) { return; }

    for (uint16_t id = 0; id < g->count; id++) {
        if (((int) id == self) || (sp[id].cost == INFINITE_COST)) { continue; }
        if (!install_route(&s->fib[id], sp, (int) id)) {
            DBG("[%u] no FIB entry for %u\n",
                (unsigned) c->node_addr, (unsigned) g->v[id].addr);
        }
    }
    free(sp);
}

/** The path to a destination, or NULL if the topology has none. */
static const struct fib_entry *fib_lookup(const struct node_state *s,
                                          const mixnet_address dst) {
    const int id = id_find(&s->topology, dst);
    if ((id < 0) || (id >= (int) s->fib_count) || !s->fib[id].reachable) {
        return NULL;
    }
    return &s->fib[id];
}

/**
 * Advertise our own links, and install them in our own row. We never receive
 * our own LSA, so this is the only thing that ever populates that row.
 *
 * Called repeatedly rather than once. Our first advertisement can go out
 * while the tree is still settling, and a flood across a tree that is still
 * changing may not reach every node; re-advertising repairs that, and is
 * idempotent at every receiver.
 */
static void originate_lsa(void *const handle,
                          const struct mixnet_node_config *c,
                          struct node_state *s) {

    // A neighbor's address is learned from the STP packets it sends, so we
    // cannot describe our own links until we have heard from all of them.
    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        if (s->neighbor_addr[p] == INVALID_MIXADDR) { return; }
    }

    mixnet_packet *packet = make_lsa_packet(c, s);
    if (packet == NULL) { return; }

    const mixnet_packet_lsa *lsa = (const mixnet_packet_lsa *) packet->payload;
    if (graph_update(&s->topology, c->node_addr,
                     lsa->neighbor_count, lsa_links(lsa))) {
        update_shortest_path(c, s);
    }
    broadcast_on_tree(handle, c, s, -1, packet);
    free(packet);
}

/** Reopen every port. Blocks computed against a stale root are meaningless. */
static void unblock_all(const struct mixnet_node_config *c,
                        struct node_state *s) {
    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        s->blocked[p] = false;
    }
}

/** Become the root of a depth-0 tree. Used at startup and on re-election. */
static void become_root(const struct mixnet_node_config *c,
                        struct node_state *s) {
    s->root = c->node_addr;
    s->path_len = 0;
    s->next_hop = INVALID_MIXADDR;
}

static bool state_init(const struct mixnet_node_config *c,
                       struct node_state *s) {

    s->neighbor_addr = malloc(sizeof(mixnet_address) * c->num_neighbors);
    s->blocked = malloc(sizeof(bool) * c->num_neighbors);

    // A node with no neighbors gets NULL from malloc(0); that is fine, but
    // a genuine allocation failure is not.
    if ((c->num_neighbors > 0) &&
        ((s->neighbor_addr == NULL) || (s->blocked == NULL))) {
        free(s->neighbor_addr);
        free(s->blocked);
        return false;
    }
    become_root(c, s);

    for (uint16_t p = 0; p < c->num_neighbors; p++) {
        s->neighbor_addr[p] = INVALID_MIXADDR;  // Learned from the first STP packet
        s->blocked[p] = false;                  // See the note in the CP1 plan
    }
    s->hello_start_ms = now_ms();
    s->reelection_start_ms = now_ms();

    // The topology starts empty: even our own row waits on STP to supply our
    // neighbors' addresses. See originate_lsa().
    s->topology.v = NULL;
    s->topology.count = 0;
    s->topology.capacity = 0;
    s->lsa_start_ms = now_ms();

    // The FIB follows the topology; see update_shortest_path()
    s->fib = NULL;
    s->fib_count = 0;

    // Each node is a separate process, so rand() would otherwise start from
    // the same state everywhere and every node would pick the same waypoints.
    // Mixing the address in keeps nodes that start in the same millisecond
    // apart. This is the only rand() user in our process.
    srand((unsigned) (now_ms() ^ ((uint64_t) c->node_addr * 2654435761u)));

    // Only a factor above 1 ever holds a packet back; 1 (the default) and 0
    // both mean "send immediately", so they need no buffer. A flush always
    // drains to empty, so the buffer never has to hold more than one batch.
    s->mix = NULL;
    s->mix_count = 0;
    if (c->mixing_factor > 1) {
        s->mix = malloc(sizeof(struct mix_slot) * c->mixing_factor);
        if (s->mix == NULL) {
            free(s->neighbor_addr);
            free(s->blocked);
            return false;
        }
    }
    return true;
}

static void state_free(struct node_state *s) {
    free(s->neighbor_addr);
    free(s->blocked);
    s->neighbor_addr = NULL;
    s->blocked = NULL;

    // A node that ends the run mid-batch still owns those packets
    for (uint16_t i = 0; i < s->mix_count; i++) { free(s->mix[i].packet); }
    free(s->mix);
    s->mix = NULL;
    s->mix_count = 0;

    fib_reset(s, 0);

    for (uint16_t i = 0; i < s->topology.count; i++) {
        free(s->topology.v[i].links);
    }
    free(s->topology.v);
    s->topology.v = NULL;
    s->topology.count = 0;
    s->topology.capacity = 0;
}

/**
 * STP receive path. The branch chain decides how *our* state changes; the two
 * rules after it react to what the *sender* claims, and so are evaluated on
 * post-update state. The cases are mutually exclusive: a parent leaves
 * path_len one greater than the packet's, a sibling leaves them equal, so
 * neither can also satisfy the child test.
 */
static void handle_stp(void *const handle,
                       const struct mixnet_node_config *c,
                       struct node_state *s, const uint8_t port,
                       mixnet_packet *const packet) {

    const mixnet_packet_stp *stp =
        (const mixnet_packet_stp *) packet->payload;

    const mixnet_address pkt_root = stp->root_address;
    const uint16_t pkt_path_len = stp->path_length;
    const mixnet_address pkt_addr = stp->node_address;

    // Neighbor discovery: every STP packet identifies its sender
    s->neighbor_addr[port] = pkt_addr;

    // A better (numerically smaller) root supersedes everything
    if (s->root > pkt_root) {
        s->root = pkt_root;
        s->path_len = (uint16_t) (pkt_path_len + 1);
        s->next_hop = pkt_addr;
        unblock_all(c, s);
        broadcast_stp(handle, c, s, -1);
    }
    // Hello from our parent: adopt its distance, whether it shrank or grew,
    // then relay the wave on all *other* links
    else if ((pkt_root == s->root) && (pkt_addr == s->next_hop)) {
        s->path_len = (uint16_t) (pkt_path_len + 1);
        broadcast_stp(handle, c, s, (int) port);
    }
    // A better path to the same root through this neighbor. The second
    // disjunct is the equal-cost case, broken by smallest neighbor address.
    else if ((pkt_root == s->root) &&
             ((s->path_len > (pkt_path_len + 1)) ||
              ((s->path_len > pkt_path_len) && (s->next_hop > pkt_addr)))) {

        const int old_parent_port = port_of(c, s, s->next_hop);
        if (old_parent_port >= 0) {
            // No longer a tree edge from our side. Recoverable: if that
            // neighbor later re-parents onto us, the child rule below
            // reopens the port.
            s->blocked[old_parent_port] = true;
        }
        s->path_len = (uint16_t) (pkt_path_len + 1);
        s->blocked[port] = false;
        s->next_hop = pkt_addr;
        broadcast_stp(handle, c, s, -1);
    }
    // Same root, and the sender is at least as close to it as we are, yet
    // it is neither our parent nor worth switching to: a sibling at equal
    // depth, or a node one hop closer that lost the parent tie-break to a
    // smaller address. Either way this link is not a tree edge from our
    // side. The second case only arises when a node has two neighbors one
    // hop closer than itself (any even-length ring); leaving that port open
    // keeps the ring cyclic and FLOOD/LSA traffic storms.
    else if ((pkt_root == s->root) && (pkt_path_len <= s->path_len)) {
        s->blocked[port] = true;
    }

    // The sender is claiming to be our child; that link is a tree edge
    if ((pkt_root == s->root) && (pkt_path_len == (s->path_len + 1))) {
        s->blocked[port] = false;
    }
    // Evidence that our path to our root is alive. The root test matters: a
    // parent that has regressed to a worse root is evidence the path is
    // gone, and must not hold the timer open.
    if ((pkt_addr == s->next_hop) && (pkt_root == s->root)) {
        s->reelection_start_ms = now_ms();
    }
    free(packet);
}

/**
 * FLOOD forwarding. Handout 2.3.1: flood packets travel only on links
 * belonging to the spanning tree, and a node that receives one on a non-user
 * port also forwards it up to its user port.
 */
static void handle_flood(void *const handle,
                         const struct mixnet_node_config *c,
                         struct node_state *s, const uint8_t port,
                         mixnet_packet *const packet) {

    const uint8_t user_port = (uint8_t) c->num_neighbors;
    const bool from_user = (port == user_port);

    // Arrived over a link that is not part of the tree. Dropping it here is
    // what prevents broadcast storms on cyclic topologies, and it must not
    // reach the user either, or that node counts the flood twice.
    if (!from_user && s->blocked[port]) {
        DBG("[%u] FLOOD dropped: ingress port %u is blocked\n",
            (unsigned) c->node_addr, (unsigned) port);
        free(packet);
        return;
    }

    // Out over every other tree link. A flood injected by our own user
    // arrives on the user port, which is never a valid except_port, so it
    // correctly goes out over all of them.
    broadcast_on_tree(handle, c, s, (int) port, packet);

    // A flood from a neighbor is also delivered to this node's user; one
    // injected by our own user is not sent back to it.
    if (from_user) {
        free(packet);
    }
    else {
        DBG("[%u] FLOOD delivered to user\n", (unsigned) c->node_addr);
        send_packet(handle, user_port, packet);
    }
}

/**
 * LSA receive path. An advertisement is both consumed and re-flooded: the
 * consume half adds one row to our adjacency list, the re-flood half is what
 * carries every node's purely local knowledge to every other node. Neither
 * alone produces a global view.
 */
static void handle_lsa(void *const handle,
                       const struct mixnet_node_config *c,
                       struct node_state *s, const uint8_t port,
                       mixnet_packet *const packet) {

    // LSAs are control traffic: the user neither sends nor receives one
    if (port == (uint8_t) c->num_neighbors) {
        free(packet);
        return;
    }

    // Bounds-check before trusting neighbor_count, since the links array is
    // variable-size and a short packet would send us reading past it
    if ((packet->total_size < LSA_PACKET_SIZE(0)) ||
        (packet->total_size <
            LSA_PACKET_SIZE(((const mixnet_packet_lsa *)
                             packet->payload)->neighbor_count))) {

        DBG("[%u] LSA dropped: bad total_size %u\n",
            (unsigned) c->node_addr, (unsigned) packet->total_size);
        free(packet);
        return;
    }
    const mixnet_packet_lsa *lsa = (const mixnet_packet_lsa *) packet->payload;

    // Our own advertisement, come back to us. Impossible on a settled tree,
    // but the blocked sets can disagree briefly while STP converges. Our row
    // is authoritative from our own config, so neither install this nor put
    // it back on the wire.
    if (lsa->node_address == c->node_addr) {
        free(packet);
        return;
    }

    // Arrived over a non-tree link: the same rule that keeps FLOOD from
    // storming. The tree spans every node, so a copy still reaches us.
    if (s->blocked[port]) {
        DBG("[%u] LSA dropped: ingress port %u is blocked\n",
            (unsigned) c->node_addr, (unsigned) port);
        free(packet);
        return;
    }

    if (graph_update(&s->topology, lsa->node_address,
                     lsa->neighbor_count, lsa_links(lsa))) {

        DBG("[%u] LSA from %u: %u links, topology now %u nodes\n",
            (unsigned) c->node_addr, (unsigned) lsa->node_address,
            (unsigned) lsa->neighbor_count, (unsigned) s->topology.count);

        update_shortest_path(c, s);
    }

    // Re-flooded even when the row did not change, unlike the plan's first
    // sketch. Suppressing that would strand nodes further along the tree: a
    // neighbor that already holds this row would stop an advertisement whose
    // only remaining job is to reach the nodes behind it. Termination does
    // not depend on the suppression anyway -- the tree is acyclic, and we
    // never send back out the ingress port, so a flood dies at the leaves.
    broadcast_on_tree(handle, c, s, (int) port, packet);
    free(packet);
}

/** The routing header of a DATA or PING packet, which leads the payload. */
static mixnet_packet_routing_header *routing_header(
        mixnet_packet *const packet) {
    return (mixnet_packet_routing_header *) packet->payload;
}

/** The PING fields, which trail the routing header and its route. */
static mixnet_packet_ping *ping_fields(mixnet_packet *const packet) {
    const mixnet_packet_routing_header *rh = routing_header(packet);
    return (mixnet_packet_ping *) (rh->route + rh->route_length);
}

/**
 * Whether a DATA or PING packet's declared size covers everything we read
 * from it: the routing header, the route it declares, and the PING fields.
 * A PING fresh from the user has no PING fields yet, hence the flag.
 */
static bool routed_packet_is_well_formed(mixnet_packet *const packet,
                                         const bool has_ping_fields) {

    size_t needed = sizeof(mixnet_packet) + sizeof(mixnet_packet_routing_header);
    if (packet->total_size < needed) { return false; }

    needed += sizeof(mixnet_address) * routing_header(packet)->route_length;
    if ((packet->type == PACKET_TYPE_PING) && has_ping_fields) {
        needed += sizeof(mixnet_packet_ping);
    }
    return packet->total_size >= needed;
}

/**
 * Send a routed packet to its next hop: the route entry the hop index points
 * at, or the destination itself once the route is used up. Takes ownership
 * of the packet.
 *
 * This is the only path from a routed packet to the wire, for all three of
 * the roles in handle_routed(), which is why mixing lives here and nowhere
 * else. STP and LSA leave through send_packet() and broadcast_on_tree()
 * instead, so control traffic bypasses mixing and keeps flowing while a
 * batch fills; a packet addressed to us goes up the user port, which is not
 * "the network", so it is not held back either.
 *
 * The batch release is the mixing: we collect exactly `mixing_factor`
 * packets and then send all of them. Releasing one per arrival would instead
 * leave a permanent backlog of k-1 and preserve input order exactly.
 */
static void send_to_next_hop(void *const handle,
                             const struct mixnet_node_config *c,
                             struct node_state *s,
                             mixnet_packet *const packet) {

    const mixnet_packet_routing_header *rh = routing_header(packet);
    const mixnet_address next_hop = (rh->hop_index < rh->route_length) ?
        rh->route[rh->hop_index] : rh->dst_address;

    const int port = port_of(c, s, next_hop);
    if (port < 0) {
        DBG("[%u] dropped: next hop %u is not a neighbor\n",
            (unsigned) c->node_addr, (unsigned) next_hop);
        free(packet);
        return;
    }
    if (s->mix == NULL) {       // mixing_factor <= 1: today's behavior
        send_packet(handle, (uint8_t) port, packet);
        return;
    }

    s->mix[s->mix_count].port = (uint8_t) port;
    s->mix[s->mix_count].packet = packet;
    s->mix_count++;

    // The batch is complete the moment the k'th packet arrives, so it goes
    // out here rather than on the next check_timers() tick. Order within a
    // batch is FIFO: the handout asks for batching, not a shuffle, and
    // staying deterministic keeps routes checkable in pcap.
    if (s->mix_count >= c->mixing_factor) {
        DBG("[%u] mixing: releasing a batch of %u\n",
            (unsigned) c->node_addr, (unsigned) s->mix_count);

        for (uint16_t i = 0; i < s->mix_count; i++) {
            send_packet(handle, s->mix[i].port, s->mix[i].packet);
        }
        s->mix_count = 0;
    }
}

/**
 * The hops strictly between two vertices on the shortest path out of `from`,
 * written into `out`. Returns how many were written, or -1 if there is no
 * path or it does not fit in `capacity`.
 *
 * install_route() does this for the FIB, but only ever rooted at us. Random
 * routing needs a leg rooted at the waypoint, which is why this runs its own
 * Dijkstra rather than reading s->fib.
 */
static int path_between(const struct graph *g, const int from, const int to,
                        mixnet_address *const out, const uint16_t capacity) {

    if (from == to) { return 0; }

    struct sp_vertex *sp = run_dijkstra(g, from);
    if (sp == NULL) { return -1; }

    int written = -1;
    if (sp[to].cost != INFINITE_COST) {
        const uint16_t hops = (uint16_t) (sp[to].path_len - 1);  // Minus `to`

        if (hops <= capacity) {
            if (hops > 0) { memcpy(out, sp[to].path, sizeof(*out) * hops); }
            written = (int) hops;
        }
    }
    free(sp);
    return written;
}

/**
 * A random detour to `dst`: the shortest path to a randomly chosen waypoint
 * W, then W itself, then the shortest path from W onward. See the plan, §4.
 *
 * Returns the hops, owned by the caller, or NULL to mean "no detour, use the
 * shortest path". Every failure takes that exit rather than dropping the
 * packet: a source that cannot build a detour should still deliver.
 *
 * W is spliced in between the two legs because neither contains it. A
 * fib_entry route is the hops strictly between us and its destination, and
 * path_between() is the same, so concatenating the legs alone would join
 * them at a node in neither and leave two non-adjacent hops in the middle.
 * The packet would then be dropped by send_to_next_hop(), silently.
 */
static mixnet_address *random_route(const struct mixnet_node_config *c,
                                    const struct node_state *s,
                                    const mixnet_address dst,
                                    uint16_t *const len_out) {

    const struct graph *g = &s->topology;

    // Eligible waypoints are the vertices that are neither endpoint. Both
    // endpoints reduce to the shortest path, so allowing them would just be
    // a slower way of not randomizing. Counted and then scanned to, so there
    // is no candidate array to allocate per packet.
    uint16_t eligible = 0;
    for (uint16_t i = 0; i < g->count; i++) {
        if ((g->v[i].addr != c->node_addr) && (g->v[i].addr != dst)) { eligible++; }
    }
    if (eligible == 0) { return NULL; }   // Two-node topology, or barely converged

    uint16_t k = (uint16_t) (rand() % eligible);
    int wid = -1;
    for (uint16_t i = 0; i < g->count; i++) {
        if ((g->v[i].addr == c->node_addr) || (g->v[i].addr == dst)) { continue; }
        if (k == 0) { wid = (int) i; break; }
        k--;
    }
    if (wid < 0) { return NULL; }         // Cannot happen: the scan mirrors the count

    const mixnet_address w = g->v[wid].addr;
    const int did = id_find(g, dst);
    if (did < 0) { return NULL; }

    // First leg: the FIB is rooted here, so it already knows src -> W
    const struct fib_entry *src_to_w = fib_lookup(s, w);
    if (src_to_w == NULL) { return NULL; }              // W not reachable yet

    // install_route() allows a route of exactly MAX_MIXNET_ROUTE_LENGTH, so
    // this rejects only what genuinely cannot be carried, W included.
    const uint16_t head = src_to_w->route_len;
    if ((head + 1) > MAX_MIXNET_ROUTE_LENGTH) { return NULL; }

    mixnet_address *route = malloc(sizeof(*route) * MAX_MIXNET_ROUTE_LENGTH);
    if (route == NULL) { return NULL; }

    if (head > 0) { memcpy(route, src_to_w->route, sizeof(*route) * head); }
    route[head] = w;                                    // The splice

    // Second leg, rooted at W, which the FIB cannot answer
    const int tail = path_between(g, wid, did, route + head + 1,
                                  (uint16_t) (MAX_MIXNET_ROUTE_LENGTH - head - 1));
    if (tail < 0) {                                     // Unreachable, or too long
        free(route);
        return NULL;
    }
    *len_out = (uint16_t) (head + 1 + tail);
    DBG("[%u] random route to %u via %u: %u hops\n", (unsigned) c->node_addr,
        (unsigned) dst, (unsigned) w, (unsigned) *len_out);

    return route;
}

/**
 * Source role. The user handed us a packet with source and destination set
 * and no route. Look the destination up in the FIB, write the route into the
 * header, and send toward the first hop.
 *
 * A DATA payload sits right after the header, where the route needs to go,
 * so it moves down first; memmove, since the regions overlap. The framework
 * allocates user packets at MAX_MIXNET_PACKET_SIZE, so there is room as long
 * as the result is a legal packet. A PING from the user has no PING fields
 * yet; those are appended here.
 */
static void source_route(void *const handle,
                         const struct mixnet_node_config *c,
                         struct node_state *s,
                         mixnet_packet *const packet) {

    mixnet_packet_routing_header *rh = routing_header(packet);
    const struct fib_entry *path = fib_lookup(s, rh->dst_address);
    if (path == NULL) {
        DBG("[%u] dropped: no route to %u\n",
            (unsigned) c->node_addr, (unsigned) rh->dst_address);
        free(packet);
        return;
    }

    // The shortest path, unless this node randomizes and a detour could be
    // built. random_route() returns NULL to mean "use the FIB" (§4).
    const mixnet_address *route = path->route;
    uint16_t route_len = path->route_len;
    mixnet_address *detour = NULL;

    if (c->do_random_routing) {
        uint16_t detour_len = 0;
        detour = random_route(c, s, rh->dst_address, &detour_len);
        if (detour != NULL) {
            route = detour;
            route_len = detour_len;
        }
    }

    char *const old_tail = (char *) (rh->route + rh->route_length);
    char *const new_tail = (char *) (rh->route + route_len);
    const size_t tail_size = (packet->type == PACKET_TYPE_DATA) ?
        (size_t) (((char *) packet + packet->total_size) - old_tail) :  // User's data
        sizeof(mixnet_packet_ping);                                     // Added below

    const size_t total_size = (size_t) (new_tail - (char *) packet) + tail_size;
    if (total_size > MAX_MIXNET_PACKET_SIZE) {
        DBG("[%u] dropped: %zu-byte packet to %u does not fit\n",
            (unsigned) c->node_addr, total_size, (unsigned) rh->dst_address);
        free(detour);
        free(packet);
        return;
    }

    if (packet->type == PACKET_TYPE_DATA) { memmove(new_tail, old_tail, tail_size); }
    if (route_len > 0) {
        memcpy(rh->route, route, sizeof(mixnet_address) * route_len);
    }
    free(detour);           // Copied into the header; `route` dangles past here

    rh->route_length = route_len;
    rh->hop_index = 0;
    packet->total_size = (uint16_t) total_size;

    if (packet->type == PACKET_TYPE_PING) {
        mixnet_packet_ping *ping = ping_fields(packet);
        ping->is_request = true;
        ping->_pad[0] = 0;
        ping->send_time = now_ms();
    }
    send_to_next_hop(handle, c, s, packet);
}

/**
 * A PING reply is the request sent back the way it came: source and
 * destination swapped, route reversed, hop index restarted, and the request
 * flag cleared so the reply is not itself answered.
 */
static mixnet_packet *make_ping_reply(const mixnet_packet *const request) {
    mixnet_packet *reply = clone_packet(request);
    if (reply == NULL) { return NULL; }

    mixnet_packet_routing_header *rh = routing_header(reply);
    const mixnet_address src = rh->src_address;
    rh->src_address = rh->dst_address;
    rh->dst_address = src;

    for (uint16_t i = 0; i < (rh->route_length / 2); i++) {
        const uint16_t j = (uint16_t) (rh->route_length - 1 - i);
        const mixnet_address hop = rh->route[i];
        rh->route[i] = rh->route[j];
        rh->route[j] = hop;
    }
    rh->hop_index = 0;
    ping_fields(reply)->is_request = false;
    return reply;
}

/**
 * DATA and PING receive path. The node plays one of three roles, decided by
 * where the packet came from and whom it is for:
 *
 *   source:       from our user, so we choose the route;
 *   destination:  addressed to us, so it goes up to our user, and a PING
 *                 request also earns a reply;
 *   forwarder:    anything else, so we advance the hop index and pass it on.
 *
 * Unlike FLOOD and LSA these may arrive over any link, blocked or not: the
 * spanning tree constrains flooding only.
 */
static void handle_routed(void *const handle,
                          const struct mixnet_node_config *c,
                          struct node_state *s, const uint8_t port,
                          mixnet_packet *const packet) {

    const uint8_t user_port = (uint8_t) c->num_neighbors;
    const bool from_user = (port == user_port);

    if (!routed_packet_is_well_formed(packet, !from_user)) {
        DBG("[%u] %s dropped: bad total_size %u\n", (unsigned) c->node_addr,
            (packet->type == PACKET_TYPE_PING) ? "PING" : "DATA",
            (unsigned) packet->total_size);
        free(packet);
        return;
    }
    if (from_user) {
        source_route(handle, c, s, packet);
        return;
    }

    mixnet_packet_routing_header *rh = routing_header(packet);
    if (rh->dst_address == c->node_addr) {
        if ((packet->type == PACKET_TYPE_PING) && ping_fields(packet)->is_request) {
            mixnet_packet *reply = make_ping_reply(packet);
            if (reply != NULL) { send_to_next_hop(handle, c, s, reply); }
        }
        send_packet(handle, user_port, packet);
        return;
    }

    // A forwarder is the hop the index points at; anything else is a packet
    // that should never have reached us
    if ((rh->hop_index >= rh->route_length) ||
        (rh->route[rh->hop_index] != c->node_addr)) {
        DBG("[%u] dropped: not hop %u of the route to %u\n",
            (unsigned) c->node_addr, (unsigned) rh->hop_index,
            (unsigned) rh->dst_address);
        free(packet);
        return;
    }
    rh->hop_index++;
    send_to_next_hop(handle, c, s, packet);
}

/**
 * Runs on every iteration of the main loop, not only when a packet arrives:
 * a node whose neighbors have gone silent still has to send hellos and still
 * has to time out.
 */
static void check_timers(void *const handle,
                         const struct mixnet_node_config *c,
                         struct node_state *s) {

    const uint64_t now = now_ms();

    // The root drives the tree with a periodic hello. It has no parent, so
    // it never refreshes reelection_start_ms and must not test it.
    if (s->root == c->node_addr) {
        if ((now - s->hello_start_ms) >= c->root_hello_interval_ms) {
            broadcast_stp(handle, c, s, -1);
            s->hello_start_ms = now;
        }
    }
    // No hello from our parent for too long: the path to the root is gone.
    // Discard the old root outright, otherwise we keep believing it and
    // reject the very packets that would repair the tree.
    else if ((now - s->reelection_start_ms) >= c->reelection_interval_ms) {
        DBG("[node] reelection: dropping root %u\n", (unsigned) s->root);

        become_root(c, s);
        unblock_all(c, s);
        broadcast_stp(handle, c, s, -1);

        s->hello_start_ms = now;
        s->reelection_start_ms = now;
    }

    // Re-advertise our own links, independently of our role in the tree.
    // See originate_lsa() for why this repeats rather than firing once.
    if ((now - s->lsa_start_ms) >= c->root_hello_interval_ms) {
        originate_lsa(handle, c, s);
        s->lsa_start_ms = now;
    }
}

void run_node(void *const handle,
              volatile bool *const keep_running,
              const struct mixnet_node_config c) {

    struct node_state s;
    if (!state_init(&c, &s)) { return; }

    DBG("[%u] start, %u neighbors\n",
        (unsigned) c.node_addr, (unsigned) c.num_neighbors);

    // Every node begins by claiming to be the root of a tree of depth 0
    broadcast_stp(handle, &c, &s, -1);

    while (*keep_running) {
        uint8_t port = 0;
        mixnet_packet *packet = NULL;

        // Non-blocking: returns 0 when nothing is waiting, which is what
        // lets one iteration of this loop double as the timer tick.
        if (mixnet_recv(handle, &port, &packet) > 0) {
            switch (packet->type) {
            case PACKET_TYPE_STP:
                handle_stp(handle, &c, &s, port, packet);
                break;

            case PACKET_TYPE_FLOOD:
                handle_flood(handle, &c, &s, port, packet);
                break;

            case PACKET_TYPE_LSA:
                handle_lsa(handle, &c, &s, port, packet);
                break;

            case PACKET_TYPE_DATA:
            case PACKET_TYPE_PING:
                handle_routed(handle, &c, &s, port, packet);
                break;

            default:
                // Unknown type; the framework never delivers one
                free(packet);
                break;
            }
        }
        check_timers(handle, &c, &s);
    }
    DBG("[%u] exit: root=%u len=%u parent=%u topology=%u nodes\n",
        (unsigned) c.node_addr, (unsigned) s.root, (unsigned) s.path_len,
        (unsigned) s.next_hop, (unsigned) s.topology.count);

    state_free(&s);
}
