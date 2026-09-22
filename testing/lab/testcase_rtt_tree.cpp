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
#include "common/testing.h"

/**
 * RTT driver for the 8-node (near-complete) BINARY TREE topology, wired the
 * same way as testcase_stp_convergence_tree:
 *
 *                        0
 *                      /   \
 *                     1     2
 *                    / \   / \
 *                   3   4 5   6
 *                  /
 *                 7
 *
 * The deepest leaf is 7, and the paths that climb over the root are the long
 * ones: 7 - 3 - 1 - 0 - 2 - 6 is 5 hops, the diameter of this tree (7 - 5 is
 * the same length). So this test-case pings from node 7 to node 6.
 *
 * As in testcase_rtt_line, the round-trip time is printed by the *source node*
 * (node 7) when the response returns to it; this test-case only injects the
 * ping and confirms the round trip completed.
 */
class testcase_rtt_tree final : public testcase {
public:
    explicit testcase_rtt_tree() : testcase("testcase_rtt_tree") {}

    virtual void pcap(const uint16_t /* fragment_id */,
                      const mixnet_packet *const packet) override {
        // We only expect the ping request (delivered at node 6) and the ping
        // response (delivered back at node 7).
        if (packet->type == PACKET_TYPE_PING) { pcap_count_++; }
        else { pass_pcap_ = false; }
    }

    virtual void setup() override {
        init_graph(8);
        graph_->add_edge(0, 1);
        graph_->add_edge(0, 2);
        graph_->add_edge(1, 3);
        graph_->add_edge(1, 4);
        graph_->add_edge(2, 5);
        graph_->add_edge(2, 6);
        graph_->add_edge(3, 7);
    }

    virtual error_code run(orchestrator& o) override {
        await_convergence();                 // let STP + routing settle
        // Watch every node's user-delivered packets via the pcap plane.
        for (uint16_t i = 0; i < graph_->num_nodes; i++) {
            DIE_ON_ERROR(o.pcap_change_subscription(i, true));
        }
        // Ping between the two furthest nodes; source = node 7.
        DIE_ON_ERROR(o.send_packet(7, 6, PACKET_TYPE_PING));
        await_packet_propagation();
        return error_code::NONE;
    }

    virtual void teardown() override {
        // Request delivered at node 6 + response delivered back at node 7.
        pass_teardown_ = (pcap_count_ == 2);
    }
};

int main(int argc, char **argv) {
    testcase_rtt_tree tc;
    return testcase::run_testcase(tc, argc, argv);
}
