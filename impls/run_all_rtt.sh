#!/usr/bin/env bash
#
# run_all_rtt.sh — sweep the four lab topologies' RTT test-cases in one shot and
#                  record the worst-case RTT each one prints, so you don't have
#                  to run run_ec2.sh four times and dig the number out of the
#                  per-host node logs by hand.
#
# This is the RTT counterpart of run_all_topologies.sh. For each topology it
# invokes ./impls/run_ec2.sh with NODE_LOGS=1 (the RTT is printed by the *source
# node*, not the orchestrator, so the node logs have to be dumped), keeps the
# full transcript in results/rtt_<topology>.log, and appends the run's "RTT to
# <dst>: <n> us" line to results/rtt.txt.
#
# The source/destination pair is baked into each test-case: it's the topology's
# two furthest nodes (line 0->7, tree 7->6, ring 0->4, full_mesh 0->7 — every
# pair is one hop in a full mesh).
#
# Sync behavior, failure handling, and env vars all match run_all_topologies.sh:
# by DEFAULT the first topology syncs + builds every host (SYNC=1) and the rest
# reuse that build (SYNC=0); a topology that fails does NOT abort the sweep, and
# the exit status is non-zero if any topology failed.
#
# NOTE: measuring RTT needs the microsecond ping timestamp in mixnet/node.c —
# the source node prints "RTT to <dst>: <n> us" when the response returns. If a
# run records NO RTT, check that the hosts were synced with that node.c (SYNC=1)
# rather than reusing an older build.
#
# Usage:
#   SSH_KEY=<path to key> ./impls/run_all_rtt.sh [hosts-file]
#
#   [hosts-file]   defaults to hosts.txt at the repo root
#
# Env:
#   SSH_KEY     path to your EC2 private key — passed through to run_ec2.sh
#   TOPOS       space-separated topology list
#               (default: "line tree ring full_mesh")
#   REPS        runs per topology (default: 1). With REPS>1 every run's RTT is
#               recorded, so you can average out network jitter.
#   RESULTS     file the RTT lines are appended to (default: results/rtt.txt)
#   LOG_DIR     directory for the per-topology transcripts (default: results)
#   SYNC        see "Sync behavior" above
#   Any other run_ec2.sh env var (IMPL, REMOTE_DIR, ORCH_IP, SSH) is inherited.
#
# Examples:
#   SSH_KEY=~/.ssh/id_ed25519 ./impls/run_all_rtt.sh
#   SSH_KEY=~/.ssh/id_ed25519 REPS=5 ./impls/run_all_rtt.sh       # average jitter out
#   SSH_KEY=~/.ssh/id_ed25519 SYNC=0 ./impls/run_all_rtt.sh       # hosts already built
#   SSH_KEY=~/.ssh/id_ed25519 TOPOS="ring full_mesh" ./impls/run_all_rtt.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

HOSTS_FILE="${1:-$ROOT/hosts.txt}"
[ -f "$HOSTS_FILE" ] || { echo "error: hosts file '$HOSTS_FILE' not found" >&2; exit 1; }

TOPOS="${TOPOS:-line tree ring full_mesh}"
REPS="${REPS:-1}"
LOG_DIR="${LOG_DIR:-$ROOT/results}"
RESULTS="${RESULTS:-$LOG_DIR/rtt.txt}"
mkdir -p "$LOG_DIR" "$(dirname "$RESULTS")"

# Did the caller pin SYNC? If so, honor it for every run; otherwise sync on the
# very first run only and reuse that build for the rest.
SYNC_PINNED=0
[ -n "${SYNC+x}" ] && SYNC_PINNED=1

FAILED=()
FIRST=1

for topo in $TOPOS; do
    tc="testcase_rtt_$topo"

    for rep in $(seq 1 "$REPS"); do
        if [ "$REPS" = "1" ]; then
            log="$LOG_DIR/rtt_$topo.log"; tag="$topo"
        else
            log="$LOG_DIR/rtt_${topo}_$rep.log"; tag="$topo run $rep/$REPS"
        fi

        if [ "$SYNC_PINNED" = "1" ]; then
            sync_val="$SYNC"
        elif [ "$FIRST" = "1" ]; then
            sync_val=1
        else
            sync_val=0
        fi
        FIRST=0

        echo "============================================================="
        echo ">> $tc   ($tag, SYNC=$sync_val)  -> $log"
        echo "============================================================="

        # `if` context suppresses set -e, so a failing run is handled here
        # rather than killing the sweep. The transcript is kept either way.
        if SYNC="$sync_val" NODE_LOGS=1 \
            "$HERE/run_ec2.sh" "$tc" "$HOSTS_FILE" 2>&1 | tee "$log"; then
            :
        fi

        # The RTT is printed once, by the source node, into that host's node
        # log block; NODE_LOGS=1 put it in the transcript.
        line="$(grep -oE 'RTT to [0-9]+: [0-9]+ us' "$log" | tail -1 || true)"
        if [ -n "$line" ] && grep -q "PASS $tc" "$log"; then
            echo "[RTT] $tc $line" >> "$RESULTS"
            echo ">> recorded: [RTT] $tc $line"
        else
            echo "[FAILED] $tc (see ${log#$ROOT/})" >> "$RESULTS"
            FAILED+=("$tag")
            echo ">> !! $tc produced no RTT — see $log"
        fi
    done
done

echo "============================================================="
echo ">> results appended to ${RESULTS#$ROOT/}; transcripts in ${LOG_DIR#$ROOT/}/"
if [ "${#FAILED[@]}" -gt 0 ]; then
    echo ">> FAILED: ${FAILED[*]}"
    exit 1
fi
echo ">> all topologies reported an RTT"
