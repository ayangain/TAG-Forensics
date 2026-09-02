"""
Regenerate fig_magnitude_sweep.png at publication quality.
Data read directly from the existing figure (verified visually).
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

DPI = 400
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif', 'Georgia'],
    'font.size': 14,
    'axes.titlesize': 15,
    'axes.labelsize': 14,
    'xtick.labelsize': 12,
    'ytick.labelsize': 12,
    'legend.fontsize': 11,
    'figure.dpi': DPI,
    'savefig.dpi': DPI,
    'axes.linewidth': 1.2,
    'figure.facecolor': 'white',
    'axes.facecolor': 'white',
    'savefig.facecolor': 'white',
})

# Data from existing figure (magnitudes on x, grouped bars for N=1,2,3)
magnitudes = ['0s', '1min', '10min', '1hr', '6hr']
x = np.arange(len(magnitudes))

# F-TAG F1 scores (read from existing bars)
ftag_n1 = [0.0, 0.33, 0.38, 0.49, 0.47]
ftag_n2 = [0.0, 0.25, 0.42, 0.50, 0.48]
ftag_n3 = [0.0, 0.38, 0.35, 0.43, 0.44]

# Zhang F1 scores
zhang_n1 = [0.0, 0.08, 0.09, 0.08, 0.09]
zhang_n2 = [0.0, 0.15, 0.14, 0.15, 0.14]
zhang_n3 = [0.0, 0.20, 0.20, 0.21, 0.20]

width = 0.13
fig, ax = plt.subplots(figsize=(11, 5.5))

# Color scheme: F-TAG greens, Zhang reds
greens = ['#1B5E20', '#2E7D32', '#66BB6A']
reds   = ['#B71C1C', '#E53935', '#EF9A9A']

offsets = [-2.5, -1.5, -0.5, 0.5, 1.5, 2.5]

bars = []
bars.append(ax.bar(x + offsets[0]*width, ftag_n1, width, color=greens[0], edgecolor='white', linewidth=0.8, label='F-TAG N=1', zorder=3))
bars.append(ax.bar(x + offsets[1]*width, ftag_n2, width, color=greens[1], edgecolor='white', linewidth=0.8, label='F-TAG N=2', zorder=3))
bars.append(ax.bar(x + offsets[2]*width, ftag_n3, width, color=greens[2], edgecolor='white', linewidth=0.8, label='F-TAG N=3', zorder=3))
bars.append(ax.bar(x + offsets[3]*width, zhang_n1, width, color=reds[0], edgecolor='white', linewidth=0.8, label='Zhang N=1', zorder=3))
bars.append(ax.bar(x + offsets[4]*width, zhang_n2, width, color=reds[1], edgecolor='white', linewidth=0.8, label='Zhang N=2', zorder=3))
bars.append(ax.bar(x + offsets[5]*width, zhang_n3, width, color=reds[2], edgecolor='white', linewidth=0.8, label='Zhang N=3', zorder=3))

ax.set_xlabel('Falsification Magnitude')
ax.set_ylabel('F1 Score')
ax.set_title('Falsification Detection: F-TAG vs. Zhang (Adversarial Type, 100% Completeness)',
             fontweight='bold', pad=10)
ax.set_xticks(x)
ax.set_xticklabels(magnitudes)
ax.set_ylim(0, 0.6)
ax.legend(loc='upper left', ncol=2, framealpha=0.9, fontsize=10)
ax.grid(axis='y', alpha=0.25, linestyle='--', zorder=0)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

plt.tight_layout()
plt.savefig('Figures/fig_magnitude_sweep.png', dpi=DPI, bbox_inches='tight')
plt.close()
print("[OK] fig_magnitude_sweep.png")
