import pandas as pd
import matplotlib.pyplot as plt
import os
import scipy.stats as st
import numpy as np

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

df_fwoc = pd.read_csv("experiment/results/track_a_exp1_fwoc.csv")
df_choke = pd.read_csv("experiment/results/track_a_exp3_chokepoint.csv")
dataset_name = "LLDOS 1.0"
output_path = "Figures/fig_chokepoint_tmin.png"

fig, ax2 = plt.subplots(1, 1, figsize=(6, 5))

df_f = df_fwoc[df_fwoc["dataset"] == dataset_name]
df_c = df_choke[df_choke["dataset"] == dataset_name]

comp_levels = sorted(df_f["completeness"].unique())

x_pct = [c * 100 for c in comp_levels]

means_r, ci_lo_r, ci_hi_r = [], [], []
for c in comp_levels:
    vals = df_c[df_c["completeness"] == c]["pivot_rank"].values
    m, lo, hi = mean_ci95(list(vals))
    means_r.append(m)
    ci_lo_r.append(m - lo)
    ci_hi_r.append(hi - m)

ax2.errorbar(x_pct, means_r, yerr=[ci_lo_r, ci_hi_r],
             fmt='s-', capsize=5, color='#e63946', linewidth=2,
             markersize=8, markerfacecolor='#f4a261')
ax2.set_xlabel("Evidence Completeness (%)", fontsize=11)
ax2.set_ylabel("True Pivot Host Rank Position", fontsize=11)
ax2.set_title("Chokepoint Rank Accuracy vs. Evidence Completeness", fontsize=11, fontweight="bold")
ax2.set_xticks(x_pct)
ax2.set_ylim(0.5, max(5, max(means_r) + 1))
ax2.invert_yaxis()
ax2.grid(True, alpha=0.3)
ax2.axhline(y=1, color='green', linestyle='--', alpha=0.5, label="Rank #1 (best)")
ax2.legend(fontsize=9)

plt.tight_layout()
plt.savefig(output_path, dpi=200, bbox_inches="tight")
print(f"Saved {output_path}")
