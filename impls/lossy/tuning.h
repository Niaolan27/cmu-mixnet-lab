/**
 * STP emission tuning: Scenario 2, the hybrid topology over lossy links.
 *
 * node.c is identical in every scenario folder; this file is the only thing
 * that differs between them. Times are in microseconds.
 */
#ifndef LAB_TUNING_H_
#define LAB_TUNING_H_

/**
 * Root election. A node with address a stays silent for
 * min(a, ELECTION_CAP) * ELECTION_STEP_US, unless it hears of a better root
 * first. The lowest address therefore speaks first, and its advertisement
 * reaches everyone else before their own timers expire, so no other node
 * ever claims the root. One step must comfortably exceed the time the
 * root's wave takes to cross the network, hold-downs and the retransmits
 * that loss makes necessary included.
 */
#define ELECTION_STEP_US    30000ull
#define ELECTION_CAP        7u

/** Wait between a (root, distance) change and advertising it. */
#define HOLD_DOWN_US        2000ull

/**
 * Repeat interval on a port whose neighbor still needs our state, and the
 * number of unanswered repeats after which the interval starts doubling.
 * With half of all packets lost, these repeats are what carry the tree, so
 * they are fast: a neighbor that has heard us answers within a hold-down,
 * so anything slower than that only delays convergence.
 */
#define FAST_RETRANSMIT_US  4000ull
#define BACKOFF_AFTER       6u

/**
 * A port whose first reply took at least LONG_LINK_US to arrive is treated
 * as a long-distance link and gets keepalives every KEEPALIVE_LONG_US
 * instead of every hello interval. No such links exist in this scenario.
 */
#define LONG_LINK_US        20000ull
#define KEEPALIVE_LONG_US   50000ull

#endif // LAB_TUNING_H_
