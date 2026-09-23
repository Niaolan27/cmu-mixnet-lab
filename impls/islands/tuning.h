/**
 * STP emission tuning: the EC scenario, island meshes joined by long links.
 *
 * node.c is identical in every scenario folder; this file is the only thing
 * that differs between them. Times are in microseconds.
 */
#ifndef LAB_TUNING_H_
#define LAB_TUNING_H_

/**
 * Root election. A node with address a stays silent for
 * min(a, ELECTION_CAP) * ELECTION_STEP_US, unless it hears of a better root
 * first. The root's wave has to cross two 50 ms links to reach the far
 * island, so one step is sized so that even the far island's lowest
 * address is still waiting when the wave arrives.
 */
#define ELECTION_STEP_US    40000ull
#define ELECTION_CAP        7u

/** Wait between a (root, distance) change and advertising it. */
#define HOLD_DOWN_US        2000ull

/**
 * Repeat interval on a port whose neighbor still needs our state, and the
 * number of unanswered repeats after which the interval starts doubling.
 * Links do not lose packets here, but a reply over a long link takes a
 * full round trip to come back; a repeat any sooner than that would cross
 * the long link for nothing. So repeats are slow insurance only.
 */
#define FAST_RETRANSMIT_US  200000ull
#define BACKOFF_AFTER       6u

/**
 * A port whose first reply took at least LONG_LINK_US to arrive is treated
 * as a long-distance link and gets keepalives every KEEPALIVE_LONG_US
 * instead of every hello interval. Intra-island replies take a hold-down,
 * inter-island ones a round trip of 100 ms and more, so the threshold sits
 * well clear of both.
 */
#define LONG_LINK_US        20000ull
#define KEEPALIVE_LONG_US   50000ull

#endif // LAB_TUNING_H_
