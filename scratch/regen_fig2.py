"""
Regenerate fig_static_vs_tag.png with a clean, non-overlapping vertical layout.
Top section: Static graph (single red arrow spanning all windows)
Middle: Timeline of 20 windows with active W8-W13 highlighted
Bottom: F-TAG corridors (green arrows) clearly below the timeline
False alert callout on the left side.
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

DPI = 400
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif', 'Georgia'],
    'font.size': 13,
    'figure.dpi': DPI,
    'savefig.dpi': DPI,
    'figure.facecolor': 'white',
    'axes.facecolor': 'white',
    'savefig.facecolor': 'white',
})

C_RED = '#C62828'
C_GREEN = '#2E7D32'
C_GREEN_LIGHT = '#A5D6A7'
C_GREY = '#F5F5F5'
C_GREY_BORDER = '#BDBDBD'

fig, ax = plt.subplots(figsize=(14, 7))

TAU = 20
ACTIVE_START, ACTIVE_END = 8, 13
BOX_W, BOX_H = 0.85, 0.7

# ── Y-level assignments (well-separated) ──
Y_STATIC_ARROW = 8.0
Y_STATIC_LABEL = 8.6
Y_BOXES = 5.5
Y_FTAG_LABEL = 4.2
Y_CORRIDORS_TOP = 3.2
Y_FALSE_ALERT_TEXT = 3.0

# ════════════════════════════════════════════════════
# TOP: Static graph — single red arrow across all windows
# ════════════════════════════════════════════════════
ax.annotate("", xy=(TAU - 0.1, Y_STATIC_ARROW), xytext=(0, Y_STATIC_ARROW),
            arrowprops=dict(arrowstyle="-|>", color=C_RED, lw=3.5))
ax.text(TAU / 2, Y_STATIC_LABEL,
        "Static Graph: 1 timeless path (no temporal constraints)",
        color=C_RED, ha="center", fontsize=14, fontweight="bold")

# ════════════════════════════════════════════════════
# MIDDLE: Timeline of 20 windows
# ════════════════════════════════════════════════════
for w in range(TAU):
    active = ACTIVE_START <= w <= ACTIVE_END
    fc = C_GREEN_LIGHT if active else C_GREY
    ec = C_GREEN if active else C_GREY_BORDER
    lw = 2.0 if active else 0.8
    ax.add_patch(mpatches.FancyBboxPatch(
        (w + 0.075, Y_BOXES - BOX_H/2), BOX_W, BOX_H,
        boxstyle="round,pad=0.05",
        facecolor=fc, edgecolor=ec, linewidth=lw))
    ax.text(w + 0.5, Y_BOXES,
            f"W{w}", ha="center", va="center",
            fontsize=8 if not active else 9,
            fontweight='bold' if active else 'normal',
            color='#1B5E20' if active else '#757575')

# Active window bracket / label
bracket_y = Y_BOXES + BOX_H/2 + 0.15
ax.annotate("", xy=(ACTIVE_START + 0.075, bracket_y),
            xytext=(ACTIVE_END + 0.925, bracket_y),
            arrowprops=dict(arrowstyle="|-|", color=C_GREEN, lw=1.5,
                           mutation_scale=8))
ax.text((ACTIVE_START + ACTIVE_END + 1) / 2, bracket_y + 0.3,
        "Active Window (W8\u2013W13)", ha="center", fontsize=11,
        color=C_GREEN, fontweight="bold")

# ════════════════════════════════════════════════════
# BOTTOM: F-TAG corridors (green arrows below the timeline)
# ════════════════════════════════════════════════════
ax.text((ACTIVE_START + ACTIVE_END + 1) / 2, Y_FTAG_LABEL,
        "F-TAG: 252 distinct chronological corridors",
        color=C_GREEN, ha="center", fontsize=14, fontweight="bold")

rng = np.random.default_rng(42)
n_drawn = 16
spacing = 0.16
for i in range(n_drawn):
    start = rng.integers(ACTIVE_START, ACTIVE_END)
    end = rng.integers(start, ACTIVE_END + 1)
    y = Y_CORRIDORS_TOP - i * spacing
    # Offset start/end to align with box centers
    x_start = start + 0.2
    x_end = end + 0.8
    ax.annotate("", xy=(x_end, y), xytext=(x_start, y),
                arrowprops=dict(arrowstyle="-|>", color=C_GREEN,
                               lw=1.6, alpha=0.5))

# Ellipsis to indicate more corridors
ax.text((ACTIVE_START + ACTIVE_END + 1) / 2,
        Y_CORRIDORS_TOP - (n_drawn) * spacing - 0.1,
        "...  (252 total valid temporal instantiations)  ...",
        ha="center", fontsize=10, color='#616161', style='italic')

# ════════════════════════════════════════════════════
# LEFT: False alert callout at W0
# ════════════════════════════════════════════════════
# Red X marker on W0
ax.plot(0.5, Y_BOXES, marker='x', markersize=18, markeredgewidth=3,
        color=C_RED, zorder=5)

ax.annotate("False alert at W0\n(topology inactive\nuntil W8)",
            xy=(0.5, Y_BOXES - BOX_H/2 - 0.1),
            xytext=(2.5, Y_FALSE_ALERT_TEXT),
            fontsize=11, color=C_RED, fontweight='bold',
            ha="center",
            arrowprops=dict(arrowstyle="-|>", color=C_RED, lw=1.8,
                           connectionstyle="arc3,rad=-0.2"),
            bbox=dict(boxstyle='round,pad=0.4', facecolor='#FFCDD2',
                      edgecolor=C_RED, alpha=0.85))

# ════════════════════════════════════════════════════
# Axis cleanup
# ════════════════════════════════════════════════════
ax.set_xlim(-1, TAU + 1)
ax.set_ylim(0, 9.5)
ax.axis("off")
ax.set_title("Static Graph vs. F-TAG: Temporal Corridor Expansion",
             fontsize=16, fontweight="bold", pad=15)

plt.tight_layout()
plt.savefig("Figures/fig_static_vs_tag.png", dpi=DPI, bbox_inches="tight")
plt.close()
print("[OK] fig_static_vs_tag.png — redesigned with vertical layout")
