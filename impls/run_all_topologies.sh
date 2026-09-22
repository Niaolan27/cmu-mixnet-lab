#!/usr/bin/env bash
#
# run_all_topologies.sh — sweep the four lab topologies in one shot and record
#                         each [STP] result line, so you don't have to run
#                         run_ec2.sh four times and copy the numbers by hand.
#
# For each topology it invokes ./impls/run_ec2.sh, keeps the full transcript in
# results/<topology>.log, and appends the run's single [STP] line to
# results/runs.txt — the same raw format you're already collecting.
#
# Sync behavior: by DEFAULT the FIRST topology syncs + builds every host
# (SYNC=1) and the remaining three reuse that build (SYNC=0), since the sources
# don't change between topologies. Export SYNC yourself to force one value for
# the whole sweep (SYNC=0 to skip the build entirely when hosts are already
# warm, SYNC=1 to re-sync before every topology).
#
# A topology that fails or doesn't converge does NOT abort the sweep: it's
# recorded as FAILED in results/runs.txt and the sweep moves on, so one bad run
# doesn't cost you the other three. The exit status is non-zero if any topology
# failed.
#
# Usage:
#   SSH_KEY=<path to key> ./impls/run_all_topologies.sh [hosts-file]
#
#   [hosts-file]   defaults to hosts.txt at the repo root
#
# Env:
#   SSH_KEY     path to your EC2 private key — passed through to run_ec2.sh
#   TOPOS       space-separated topology list
#               (default: "line tree ring full_mesh")
#   RESULTS     file the [STP] lines are appended to (default: results/runs.txt)
#   LOG_DIR     directory for the per-topology transcripts (default: results)
#   SYNC        see "Sync behavior" above
#   Any other run_ec2.sh env var (NODE_LOGS, IMPL, REMOTE_DIR, ORCH_IP, SSH)
#   is inherited as-is.
#
# Examples:
#   SSH_KEY=~/.ssh/id_ed25519 ./impls/run_all_topologies.sh
#   SSH_KEY=~/.ssh/id_ed25519 ./impls/run_all_topologies.sh hosts.txt
#   SSH_KEY=~/.ssh/id_ed25519 SYNC=0 ./impls/run_all_topologies.sh      # hosts already built
#   SSH_KEY=~/.ssh/id_ed25519 TOPOS="ring full_mesh" ./impls/run_all_topologies.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

HOSTS_FILE="${1:-$ROOT/hosts.txt}"
[ -f "$HOSTS_FILE" ] || { echo "error: hosts file '$HOSTS_FILE' not found" >&2; exit 1; }

TOPOS="${TOPOS:-line tree ring full_mesh}"
LOG_DIR="${LOG_DIR:-$ROOT/results}"
RESULTS="${RESULTS:-$LOG_DIR/runs.txt}"
mkdir -p "$LOG_DIR" "$(dirname "$RESULTS")"

# Did the caller pin SYNC? If so, honor it for every topology; otherwise sync on
# the first topology only and reuse that build for the rest.
SYNC_PINNED=0
[ -n "${SYNC+x}" ] && SYNC_PINNED=1

FAILED=()
FIRST=1

for topo in $TOPOS; do
    tc="testcase_stp_convergence_$topo"
    log="$LOG_DIR/$topo.log"

    if [ "$SYNC_PINNED" = "1" ]; then
        sync_val="$SYNC"
    elif [ "$FIRST" = "1" ]; then
        sync_val=1
    else
        sync_val=0
    fi
    FIRST=0

    echo "============================================================="
    echo ">> $tc   (SYNC=$sync_val)  -> $log"
    echo "============================================================="

    # `if` context suppresses set -e, so a failing run is handled here rather
    # than killing the sweep. The transcript is kept either way.
    if SYNC="$sync_val" "$HERE/run_ec2.sh" "$tc" "$HOSTS_FILE" 2>&1 | tee "$log"; then
        :
    fi

    # run_ec2.sh emits the [STP] line twice (once live from the orchestrator
    # stream, once from its own grep after the separator) — tail -1 keeps a
    # single entry per run.
    line="$(grep -E '^\[STP\]' "$log" | tail -1 || true)"
    if [ -n "$line" ] && echo "$line" | grep -q 'converged=true'; then
        echo "$line" >> "$RESULTS"
        echo ">> recorded: $line"
    else
        echo "[FAILED] $tc (see ${log#$ROOT/})" >> "$RESULTS"
        FAILED+=("$topo")
        echo ">> !! $tc did not converge — see $log"
    fi
done

echo "============================================================="
echo ">> results appended to ${RESULTS#$ROOT/}; transcripts in ${LOG_DIR#$ROOT/}/"
if [ "${#FAILED[@]}" -gt 0 ]; then
    echo ">> FAILED: ${FAILED[*]}"
    exit 1
fi
echo ">> all topologies converged"
