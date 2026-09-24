#!/usr/bin/env python3
"""
plot_stp_convergence.py — column chart of STP convergence cost per topology.

Reads the [STP] lines that run_all_topologies.sh appends to results/runs.txt
and renders results/stp_convergence.png, so the figure in the writeup always
matches the numbers actually measured (re-run the sweep, re-run this).

Note on the metric: the harness counts CONTROL PACKETS exchanged before the
spanning tree converges (stp_packets_until_convergence), not wall-clock time.
Packet count is the hardware-independent measure — wall-clock would mostly
report EC2 scheduling noise — so that is what the axis says.

Usage:
  ./impls/plot_stp_convergence.py [runs-file] [-o out.png]

  [runs-file]   defaults to results/runs.txt at the repo root
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

STP_RE = re.compile(
    r"^\[STP\]\s+testcase_stp_convergence_(?P<topo>\w+)\s+"
    r"converged=(?P<converged>\w+)\s+"
    r"stp_packets_until_convergence=(?P<packets>\d+)"
)


def parse_runs(path):
    """Last [STP] line wins per topology, so a re-run supersedes an old one."""
    results = {}
    for line in path.read_text().splitlines():
        m = STP_RE.match(line.strip())
        if not m:
            continue
        if m.group("converged") != "true":
            print(f"skipping non-converged run: {line.strip()}", file=sys.stderr)
            continue
        results[m.group("topo")] = int(m.group("packets"))
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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("runs", nargs="?", default=REPO / "results" / "runs.txt",
                    type=pathlib.Path)
    ap.add_argument("-o", "--out", default=REPO / "results" / "stp_convergence.png",
                    type=pathlib.Path)
    args = ap.parse_args()

    results = parse_runs(args.runs)
    if not results:
        sys.exit(f"no converged [STP] lines found in {args.runs}")

    # Sorted low -> high: the chart's job is comparing magnitude, so the ramp
    # and the left-to-right ordering carry the same signal.
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
        ax.text(x, v + max(values) * 0.025, f"{v}", va="bottom", ha="center",
                fontsize=11, color=INK_SECONDARY)

    ax.set_xticks(list(xs))
    ax.set_xticklabels(names, fontsize=10.5, color=INK_PRIMARY)
    ax.tick_params(axis="x", length=0, pad=8)
    ax.tick_params(axis="y", colors=INK_MUTED, labelsize=9.5, length=0)

    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(BASELINE)
    ax.spines["bottom"].set_linewidth(1.0)

    ax.set_ylabel("STP packets until convergence", fontsize=9.5,
                  color=INK_MUTED, labelpad=10)
    ax.set_title("STP convergence cost by topology", fontsize=13,
                 color=INK_PRIMARY, loc="left", pad=24, fontweight="semibold")
    ax.text(0, 1.045, "Control packets exchanged before the spanning tree "
                      "converges · 8 nodes",
            transform=ax.transAxes, fontsize=9.5, color=INK_SECONDARY)

    fig.tight_layout()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.out, facecolor=SURFACE, bbox_inches="tight", pad_inches=0.3)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
