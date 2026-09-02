"""
Regenerate fig_fwoc.png (the left panel of fig_fwoc_afconf) at publication quality.
Uses the same CSV data as the original run_track_a_experiments.py.
Shows FWoC tightness (which saturates at 100% for LLDOS due to structural properties).
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import scipy.stats as st

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
    'lines.markersize': 10,
    'figure.facecolor': 'white',
    'axes.facecolor': 'white',
    'savefig.facecolor': 'white',
})

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

df = pd.read_csv("experiment/results/track_a_exp1_fwoc.csv")

fig, ax = plt.subplots(figsize=(6, 5))

colors = {'LLDOS 1.0': '#1d3557', 'LLDOS 2.0.2': '#e63946'}
markers = {'LLDOS 1.0': 'o', 'LLDOS 2.0.2': 's'}
fills = {'LLDOS 1.0': '#457b9d', 'LLDOS 2.0.2': '#f4a261'}

for dataset in ['LLDOS 1.0', 'LLDOS 2.0.2']:
    df_d = df[df["dataset"] == dataset]
    comp_levels = sorted(df_d["completeness"].unique())
    means, ci_lo, ci_hi = [], [], []
    for c in comp_levels:
        vals = df_d[df_d["completeness"] == c]["tightness_pct"].values
        m, lo, hi = mean_ci95(list(vals))
        means.append(m)
        ci_lo.append(m - lo)
        ci_hi.append(hi - m)
    x_pct = [c * 100 for c in comp_levels]
    ax.errorbar(x_pct, means, yerr=[ci_lo, ci_hi],
                fmt=f'{markers[dataset]}-', capsize=6, capthick=2,
                color=colors[dataset], linewidth=2.5,
                markersize=10, markerfacecolor=fills[dataset],
                markeredgecolor=colors[dataset], markeredgewidth=1.5,
                elinewidth=2, label=dataset)

ax.set_xlabel("Evidence Completeness (%)")
ax.set_ylabel("|FWoC| / |Capture Duration| (%)")
ax.set_title("(a) FWoC Tightness vs. Evidence Loss", fontweight="bold", pad=10)
ax.set_xticks([25, 50, 75, 100])
ax.set_ylim(0, 115)
ax.grid(True, alpha=0.25, linestyle='--')
ax.axhline(y=100, color='#C62828', linestyle='--', alpha=0.5, lw=1.5,
            label="Structural saturation (100%)")
ax.legend(framealpha=0.9)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

plt.tight_layout()
plt.savefig("Figures/fig_fwoc.png", dpi=DPI, bbox_inches="tight")
plt.close()
print("[OK] fig_fwoc.png")
