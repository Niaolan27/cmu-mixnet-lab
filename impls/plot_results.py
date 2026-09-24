#!/usr/bin/env python3
"""
plot_results.py — render the lab's two figures from the raw result files.

Reads the lines that run_all_topologies.sh / run_all_rtt.sh append to
results/runs.txt and results/rtt.txt, and writes:

  results/stp_convergence.png   STP control packets exchanged, per topology
  results/rtt.png               ping round-trip time, per topology

Driving both off the raw files means the figures in the writeup always match
the numbers actually measured — re-run a sweep, re-run this.

Two notes on what the axes claim:

  * STP convergence is measured in CONTROL PACKETS (the harness field is
    stp_packets_until_convergence), not wall-clock time. Packet count is the
    hardware-independent measure; wall-clock across EC2 hosts would mostly
    report scheduler noise.

  * The four RTT test-cases ping DIFFERENT node pairs, so they sit at
    different hop counts (see PING_PAIRS). The hop count is annotated under
    each column, because comparing the bare times without it invites the
    wrong conclusion.

Usage:
  ./impls/plot_results.py [-o results-dir]
  ./impls/plot_results.py --runs results/runs.txt --rtt results/rtt.txt
"""

import argparse
import pathlib
import re
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.path import Path
from matplotlib.patches import PathPatch

REPO = pathlib.Path(__file__).resolve().parent.parent

# Chart tokens: one-hue sequential ramp (blue), light->dark with magnitude,
# plus the chrome/ink greys. Ramp steps 250/400/500/700 validate as an ordinal
# ramp on the #fcfcfb surface (monotone L, all adjacent dL >= 0.06, light end
# 2.06:1). Text never wears the data colour — labels stay in ink tokens.
RAMP = ["#86b6ef", "#3987e5", "#256abf", "#0d366b"]
SURFACE = "#fcfcfb"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
BASELINE = "#c3c2b7"

# Pretty names for the topology slugs in the testcase names.
LABELS = {
    "tree": "Binary tree",
    "ring": "Ring",
    "line": "Line",
    "full_mesh": "Full mesh",
}

# Which pair each RTT test-case pings, and how many hops separate them on the
# converged tree. Taken from testing/lab/testcase_rtt_*.cpp — keep in sync if
# a test-case changes its endpoints.
#
#   full_mesh  0 -> 7   diameter 1, every pair is adjacent
#   ring       0 -> 4   0-1-2-3-4, the far side of an 8-node ring
#   tree       7 -> 6   7-3-1-0-2-6, across the root
#   line       0 -> 7   the whole line end to end
PING_PAIRS = {
    "full_mesh": (0, 7, 1),
    "ring":      (0, 4, 4),
    "tree":      (7, 6, 5),
    "line":      (0, 7, 7),
}

STP_RE = re.compile(
    r"^\[STP\]\s+testcase_stp_convergence_(?P<topo>\w+)\s+"
    r"converged=(?P<converged>\w+)\s+"
    r"stp_packets_until_convergence=(?P<packets>\d+)"
)

RTT_RE = re.compile(
    r"^\[RTT\]\s+testcase_rtt_(?P<topo>\w+)\s+RTT to \d+:\s+(?P<us>\d+)\s*us"
)


def parse(path, regex, field, require_converged=False):
    """Last matching line wins per topology, so a re-run supersedes an old one."""
    if not path.exists():
        return {}
    results = {}
    for line in path.read_text().splitlines():
        m = regex.match(line.strip())
        if not m:
            continue
        if require_converged and m.group("converged") != "true":
            print(f"skipping non-converged run: {line.strip()}", file=sys.stderr)
            continue
        results[m.group("topo")] = int(m.group(field))
    return results


def rounded_column(ax, x, height, width, radius_px, color):
    """
    A column with a rounded cap and a square baseline end.

    The corner radius is given in pixels and converted per-axis, so the arc
    renders circular no matter how the data/band scales differ.
    """
    x0, x1, y0 = x - width / 2, x + width / 2, 0.0
    px_per_x = ax.transData.transform((1, 0))[0] - ax.transData.transform((0, 0))[0]
    px_per_y = ax.transData.transform((0, 1))[1] - ax.transData.transform((0, 0))[1]
    rx = min(radius_px / abs(px_per_x), width / 2)
    ry = min(radius_px / abs(px_per_y), height / 2)

    verts = [
        (x0, y0),                             # square baseline corner
        (x0, height - ry),
        (x0, height), (x0 + rx, height),      # rounded cap, left
        (x1 - rx, height),
        (x1, height), (x1, height - ry),      # rounded cap, right
        (x1, y0),
        (x0, y0),
    ]
    codes = [
        Path.MOVETO,
        Path.LINETO,
        Path.CURVE3, Path.CURVE3,
        Path.LINETO,
        Path.CURVE3, Path.CURVE3,
        Path.LINETO,
        Path.CLOSEPOLY,
    ]
    ax.add_patch(PathPatch(Path(verts, codes), facecolor=color,
                           edgecolor="none", zorder=3))


def column_chart(results, title, subtitle, ylabel, out, fmt=str, sublabels=None):
    """
    One column per topology, sorted low -> high so the ramp and the
    left-to-right ordering carry the same signal.
    """
    order = sorted(results.items(), key=lambda kv: kv[1])
    names = [LABELS.get(t, t) for t, _ in order]
    values = [v for _, v in order]
    colors = RAMP[-len(values):] if len(values) < len(RAMP) else RAMP

    fig, ax = plt.subplots(figsize=(6.8, 4.2), dpi=200)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    xs = range(len(values))
    ax.set_xlim(-0.65, len(values) - 0.35)
    ax.set_ylim(0, max(values) * 1.14)

    # Recessive grid on the value axis, behind the columns.
    ax.yaxis.grid(True, color=GRIDLINE, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    ax.xaxis.grid(False)

    fig.canvas.draw()  # transforms must be live before the px->data conversion
    for x, v, c in zip(xs, values, colors):
        # 4 CSS px, scaled to the figure DPI so it reads the same on export.
        rounded_column(ax, x, v, 0.40, 4.0 * fig.dpi / 100.0, c)
        # Value on the cap, in ink — never in the column's own colour.
        ax.text(x, v + max(values) * 0.025, fmt(v), va="bottom", ha="center",
                fontsize=11, color=INK_SECONDARY)

    ax.set_xticks(list(xs))
    ax.set_xticklabels(names, fontsize=10.5, color=INK_PRIMARY)
    ax.tick_params(axis="x", length=0, pad=8)
    ax.tick_params(axis="y", colors=INK_MUTED, labelsize=9.5, length=0)

    # Secondary line under each tick (e.g. hop count), one step down the ink
    # hierarchy so it reads as context rather than as the category name.
    if sublabels:
        for x, (topo, _) in zip(xs, order):
            if topo in sublabels:
                ax.text(x, -0.105, sublabels[topo], transform=ax.get_xaxis_transform(),
                        ha="center", va="top", fontsize=9, color=INK_MUTED)

    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(BASELINE)
    ax.spines["bottom"].set_linewidth(1.0)

    ax.set_ylabel(ylabel, fontsize=9.5, color=INK_MUTED, labelpad=10)
    ax.set_title(title, fontsize=13, color=INK_PRIMARY, loc="left", pad=24,
                 fontweight="semibold")
    ax.text(0, 1.045, subtitle, transform=ax.transAxes, fontsize=9.5,
            color=INK_SECONDARY)

    fig.tight_layout()
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, facecolor=SURFACE, bbox_inches="tight", pad_inches=0.3)
    plt.close(fig)
    print(f"wrote {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=pathlib.Path,
                    default=REPO / "results" / "runs.txt")
    ap.add_argument("--rtt", type=pathlib.Path,
                    default=REPO / "results" / "rtt.txt")
    ap.add_argument("-o", "--out-dir", type=pathlib.Path,
                    default=REPO / "results")
    args = ap.parse_args()

    wrote = False

    stp = parse(args.runs, STP_RE, "packets", require_converged=True)
    if stp:
        column_chart(
            stp,
            "STP convergence cost by topology",
            "Control packets exchanged before the spanning tree converges · 8 nodes",
            "STP packets until convergence",
            args.out_dir / "stp_convergence.png",
        )
        wrote = True
    else:
        print(f"no converged [STP] lines in {args.runs}", file=sys.stderr)

    rtt = parse(args.rtt, RTT_RE, "us")
    if rtt:
        hops = {}
        for topo in rtt:
            if topo in PING_PAIRS:
                src, dst, n = PING_PAIRS[topo]
                hops[topo] = f"{src}→{dst} · {n} hop" + ("s" if n != 1 else "")
        column_chart(
            rtt,
            "Ping round-trip time by topology",
            "One PING and its response, timed at the source · 8 nodes",
            "Round-trip time (µs)",
            args.out_dir / "rtt.png",
            fmt=lambda v: f"{v:,}",
            sublabels=hops,
        )
        wrote = True
    else:
        print(f"no [RTT] lines in {args.rtt}", file=sys.stderr)

    if not wrote:
        sys.exit("nothing to plot")


if __name__ == "__main__":
    main()
