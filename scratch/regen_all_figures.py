"""
Regenerate ALL paper figures at publication quality.
- 400 DPI for crisp text at any print size
- Serif font (matching LaTeX body text)
- Larger font sizes (readable when scaled to column width)
- Thicker lines and larger markers
- Consistent color palette across all figures
- White backgrounds
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd
import scipy.stats as st
import os

# ─── Global publication style ───────────────────────────────────────
DPI = 400
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif', 'Georgia'],
    'font.size': 14,
    'axes.titlesize': 15,
    'axes.labelsize': 14,
    'xtick.labelsize': 12,
    'ytick.labelsize': 12,
    'legend.fontsize': 12,
    'figure.dpi': DPI,
    'savefig.dpi': DPI,
    'axes.linewidth': 1.2,
    'lines.linewidth': 2.5,
    'lines.markersize': 9,
    'figure.facecolor': 'white',
    'axes.facecolor': 'white',
    'savefig.facecolor': 'white',
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1,
})

# Consistent color palette
C_FTAG = '#2E7D32'       # deep green
C_ZHANG = '#C62828'       # deep red
C_FTAG_LIGHT = '#66BB6A'  # light green bars
C_ZHANG_LIGHT = '#EF5350' # light red bars
C_NAVY = '#1d3557'
C_CORAL = '#e63946'
C_TEAL = '#457b9d'
C_AMBER = '#f4a261'

def mean_ci95(data):
    if len(data) == 0:
        return 0, 0, 0
    m = np.mean(data)
    if len(data) < 2:
        return m, m, m
    se = st.sem(data)
    if se == 0:
        return m, m, m
    h = se * st.t.ppf((1 + 0.95) / 2., len(data)-1)
    return m, m - h, m + h


# ════════════════════════════════════════════════════════════════════
# FIGURE 2: Static vs. F-TAG Temporal Corridor Expansion
# ════════════════════════════════════════════════════════════════════
def regen_fig2():
    fig, ax = plt.subplots(figsize=(12, 4.5))

    TAU = 20
    ACTIVE_START, ACTIVE_END = 8, 13

    # Draw the 20 window boxes
    for w in range(TAU):
        active = ACTIVE_START <= w <= ACTIVE_END
        color = "#A5D6A7" if active else "#F5F5F5"
        ec = "#2E7D32" if active else "#BDBDBD"
        lw = 1.5 if active else 0.8
        ax.add_patch(mpatches.Rectangle((w, 3.2), 0.9, 0.8,
                     facecolor=color, edgecolor=ec, linewidth=lw))
        ax.text(w + 0.45, 3.6, f"W{w}", ha="center", va="center",
                fontsize=8, fontweight='bold' if active else 'normal',
                color='#1B5E20' if active else '#757575')

    # Static graph: single timeless corridor
    ax.annotate("", xy=(TAU - 0.1, 5.4), xytext=(0, 5.4),
                arrowprops=dict(arrowstyle="-|>", color=C_ZHANG, lw=3))
    ax.text(TAU / 2, 5.7, "Static Graph: 1 timeless path (no temporal constraints)",
            color=C_ZHANG, ha="center", fontsize=12, fontweight="bold")

    # F-TAG: sample of 252 corridors
    rng = np.random.default_rng(0)
    n_drawn = 14
    y0 = 2.6
    for i in range(n_drawn):
        start = rng.integers(ACTIVE_START, ACTIVE_END)
        end = rng.integers(start, ACTIVE_END + 1)
        y = y0 - i * 0.11
        ax.annotate("", xy=(end + 0.9, y), xytext=(start, y),
                    arrowprops=dict(arrowstyle="-|>", color=C_FTAG,
                                   lw=1.8, alpha=0.55))
    ax.text(ACTIVE_START + (ACTIVE_END - ACTIVE_START) / 2, y0 + 0.4,
            "F-TAG: 252 distinct chronological corridors\n(confined to active window W8\u2013W13)",
            color=C_FTAG, ha="center", fontsize=12, fontweight="bold")

    # False alert marker
    ax.annotate("False alert at W0\n(topology inactive until W8)",
                xy=(0.45, 3.2), xytext=(0.45, 1.2),
                arrowprops=dict(arrowstyle="-|>", color=C_ZHANG, lw=1.5),
                ha="center", fontsize=11, color=C_ZHANG, fontweight='bold')

    ax.set_xlim(-0.5, TAU + 0.5)
    ax.set_ylim(0.7, 6.2)
    ax.axis("off")
    ax.set_title("Static Graph vs. F-TAG: Temporal Corridor Expansion",
                 fontsize=14, fontweight="bold", pad=10)

    plt.tight_layout()
    plt.savefig("Figures/fig_static_vs_tag.png", dpi=DPI, bbox_inches="tight")
    plt.close()
    print("[OK] fig_static_vs_tag.png")


# ════════════════════════════════════════════════════════════════════
# FIGURE 3: FWoC Tightness + Chokepoint Rank vs Evidence Completeness
# ════════════════════════════════════════════════════════════════════
def regen_fig3():
    df_fwoc = pd.read_csv("experiment/results/track_a_exp1_fwoc.csv")
    df_choke = pd.read_csv("experiment/results/track_a_exp3_chokepoint.csv")
    dataset_name = "LLDOS 1.0"

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.5))
    fig.suptitle(f"Evidence-Conditioned Metric Quality \u2014 {dataset_name}",
                 fontsize=15, fontweight="bold", y=1.02)

    df_f = df_fwoc[df_fwoc["dataset"] == dataset_name]
    df_c = df_choke[df_choke["dataset"] == dataset_name]

    comp_levels = sorted(df_f["completeness"].unique())
    means_t, ci_lo_t, ci_hi_t = [], [], []
    for c in comp_levels:
        vals = df_f[df_f["completeness"] == c]["tightness_pct"].values
        m, lo, hi = mean_ci95(list(vals))
        means_t.append(m)
        ci_lo_t.append(m - lo)
        ci_hi_t.append(hi - m)

    x_pct = [c * 100 for c in comp_levels]
    ax1.errorbar(x_pct, means_t, yerr=[ci_lo_t, ci_hi_t],
                 fmt='o-', capsize=6, capthick=2, color=C_NAVY, linewidth=2.5,
                 markersize=10, markerfacecolor=C_TEAL, markeredgecolor=C_NAVY,
                 markeredgewidth=1.5, elinewidth=2)
    ax1.set_xlabel("Evidence Completeness (%)")
    ax1.set_ylabel("|FWoC| / |Capture Duration| (%)")
    ax1.set_title("(a) FWoC Tightness", fontweight="bold")
    ax1.set_xticks(x_pct)
    ax1.set_xticklabels([f"{int(p)}%" for p in x_pct])
    ax1.set_xlim(min(x_pct) - 5, max(x_pct) + 5)
    ax1.set_ylim(0, 115)
    ax1.grid(True, alpha=0.25, linestyle='--')
    ax1.axhline(y=100, color=C_CORAL, linestyle='--', alpha=0.6, lw=1.5,
                label="No narrowing (100%)")
    ax1.legend(framealpha=0.9)
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)

    means_r, ci_lo_r, ci_hi_r = [], [], []
    for c in comp_levels:
        vals = df_c[df_c["completeness"] == c]["pivot_rank"].values
        m, lo, hi = mean_ci95(list(vals))
        means_r.append(m)
        ci_lo_r.append(m - lo)
        ci_hi_r.append(hi - m)

    ax2.errorbar(x_pct, means_r, yerr=[ci_lo_r, ci_hi_r],
                 fmt='s-', capsize=6, capthick=2, color=C_CORAL, linewidth=2.5,
                 markersize=10, markerfacecolor=C_AMBER, markeredgecolor=C_CORAL,
                 markeredgewidth=1.5, elinewidth=2)
    ax2.set_xlabel("Evidence Completeness (%)")
    ax2.set_ylabel("True Pivot Host Rank Position")
    ax2.set_title("(b) Chokepoint Rank Accuracy", fontweight="bold")
    ax2.set_xticks(x_pct)
    ax2.set_xticklabels([f"{int(p)}%" for p in x_pct])
    ax2.set_xlim(min(x_pct) - 5, max(x_pct) + 5)
    ax2.set_ylim(0.5, max(5, max(means_r) + 1))
    ax2.invert_yaxis()
    ax2.grid(True, alpha=0.25, linestyle='--')
    ax2.axhline(y=1, color=C_FTAG, linestyle='--', alpha=0.6, lw=1.5,
                label="Rank #1 (best)")
    ax2.legend(framealpha=0.9)
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig("Figures/fig_chokepoint_tmin.png", dpi=DPI, bbox_inches="tight")
    plt.close()
    print("[OK] fig_chokepoint_tmin.png")


# ════════════════════════════════════════════════════════════════════
# FIGURE 4: Falsification Detection F1 (Full Infrastructure Wipe)
# ════════════════════════════════════════════════════════════════════
def regen_fig4():
    scenarios = ['Precedence\nSwap', 'State\nRevocation', 'Window\nClosure']

    # From Table 3 - Full Infrastructure Wipe
    # Zhang: P=1.0,R=1.0 / P=1.0,R=0.0 / P=1.0,R=0.0
    # F-TAG: P=0.88,R=1.0 / P=0.86,R=0.90 / P=0.88,R=1.0
    zhang_f1 = [1.0, 0.0, 0.0]
    ftag_f1 = [round(2*0.88*1.0/(0.88+1.0), 2),
               round(2*0.86*0.90/(0.86+0.90), 2),
               round(2*0.88*1.0/(0.88+1.0), 2)]

    x = np.arange(len(scenarios))
    width = 0.32

    fig, ax = plt.subplots(figsize=(9, 5.5))

    bars1 = ax.bar(x - width/2, zhang_f1, width, label='Zhang (Static)',
                   color=C_ZHANG_LIGHT, edgecolor=C_ZHANG, linewidth=1.5,
                   zorder=3)
    bars2 = ax.bar(x + width/2, ftag_f1, width, label='F-TAG (Ours)',
                   color=C_FTAG_LIGHT, edgecolor=C_FTAG, linewidth=1.5,
                   zorder=3)

    # Value labels on top of bars
    for bar in bars2:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                f'{height:.2f}', ha='center', va='bottom',
                fontsize=12, fontweight='bold', color=C_FTAG)
    for bar in bars1:
        height = bar.get_height()
        if height > 0:
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                    f'{height:.2f}', ha='center', va='bottom',
                    fontsize=12, fontweight='bold', color=C_ZHANG)

    # MISS labels
    for i, val in enumerate(zhang_f1):
        if val == 0.0:
            ax.text(x[i] - width/2, 0.03, 'MISS', ha='center', va='bottom',
                    fontsize=13, fontweight='bold', color=C_ZHANG,
                    bbox=dict(boxstyle='round,pad=0.2', facecolor='#FFCDD2',
                              edgecolor=C_ZHANG, alpha=0.8))

    ax.set_ylabel('F1 Score')
    ax.set_xlabel('Falsification Scenario')
    ax.set_xticks(x)
    ax.set_xticklabels(scenarios)
    ax.set_ylim(0, 1.18)
    ax.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.legend(loc='upper right', framealpha=0.9)
    ax.grid(axis='y', alpha=0.25, linestyle='--', zorder=0)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_title("Falsification Detection: Full Infrastructure Wipe (LLDOS 1.0)",
                 fontweight="bold", pad=10)

    plt.tight_layout()
    plt.savefig('Figures/fig_falsification_detection.png', dpi=DPI, bbox_inches='tight')
    plt.close()
    print("[OK] fig_falsification_detection.png")


# ════════════════════════════════════════════════════════════════════
# FIGURE 6: FWoC + AF_conf ROC (stitched)
# ════════════════════════════════════════════════════════════════════
def regen_fig6_stitch():
    """Re-stitch the FWoC panel with the ROC panel at matched resolution."""
    from PIL import Image

    fwoc_path = "Figures/fig_fwoc.png"
    roc_path = "experiment/results/afconf_roc.png"

    if not os.path.exists(fwoc_path):
        print("[WARN] fig_fwoc.png not found — extracting from existing composite")
        composite = Image.open("Figures/fig_fwoc_afconf.png")
        # Left 65% is FWoC panel
        cut_x = int(composite.width * 0.65)
        left = composite.crop((0, 0, cut_x, composite.height))
        left.save(fwoc_path)

    fwoc = Image.open(fwoc_path)
    roc = Image.open(roc_path)

    # Match heights
    target_height = fwoc.height
    scale = target_height / roc.height
    new_width = int(roc.width * scale)
    roc_resized = roc.resize((new_width, target_height), Image.Resampling.LANCZOS)

    # Add a small gap between panels
    gap = 20
    combined = Image.new('RGB',
                         (fwoc.width + gap + roc_resized.width, target_height),
                         (255, 255, 255))
    combined.paste(fwoc, (0, 0))
    combined.paste(roc_resized, (fwoc.width + gap, 0))
    combined.save("Figures/fig_fwoc_afconf.png", quality=95)
    print("[OK] fig_fwoc_afconf.png (stitched)")


# ════════════════════════════════════════════════════════════════════
# Run everything
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("Regenerating all paper figures at publication quality...")
    print(f"  DPI: {DPI}, Font: serif")
    print()
    regen_fig2()
    regen_fig3()
    regen_fig4()
    regen_fig6_stitch()
    print()
    print("All figures regenerated. Verify in Figures/ directory.")
