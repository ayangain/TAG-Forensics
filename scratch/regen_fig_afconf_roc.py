"""
Regenerate Figures/fig_afconf_roc.png with correct LaTeX math rendering.
Fixes bash-expansion bug that mangled $AF_{conf}$, $P(H_1)$, and $F_1$.
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

DPI = 400
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif', 'Georgia'],
    'font.size': 13,
    'axes.titlesize': 14,
    'axes.labelsize': 13,
    'xtick.labelsize': 12,
    'ytick.labelsize': 12,
    'legend.fontsize': 11,
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

fig, ax = plt.subplots(figsize=(6.5, 5.2))

fpr = np.array([0.0, 0.250, 1.0])
tpr = np.array([0.0, 0.852, 1.0])

# ROC curve
ax.plot(fpr, tpr, color='#E65100', lw=3, marker='o', markersize=8,
        markerfacecolor='#FF8F00', markeredgecolor='#E65100', markeredgewidth=1.5,
        label=r'Wipe vs. Random (AUC = 0.801)', zorder=3)

# Diagonal chance line
ax.plot([0, 1], [0, 1], color='#1A237E', lw=2, linestyle='--',
        alpha=0.6, label='Random Chance (AUC = 0.500)')

# Shaded area under curve
ax.fill_between(fpr, tpr, alpha=0.10, color='#FF8F00', zorder=2)

# Operating point 1: theta >= 0.50
ax.plot(0.250, 0.852, marker='*', markersize=16, color='#D84315', zorder=5)
ax.annotate(r'$\theta \geq 0.50$ (All Root Flagged)' '\n' r'TPR=0.85, FPR=0.25, $F_1=0.81$',
            xy=(0.250, 0.852), xytext=(0.38, 0.68),
            fontsize=10.5, fontweight='bold', color='#BF360C',
            arrowprops=dict(arrowstyle='-|>', color='#BF360C', lw=1.8),
            bbox=dict(boxstyle='round,pad=0.25', facecolor='#FBE9E7', edgecolor='#FF8A65', alpha=0.95))

# Operating point 2: theta >= 0.70, 0.85, 0.90 (at origin)
ax.plot(0.0, 0.0, marker='X', markersize=12, color='#B71C1C', zorder=5)
ax.annotate(r'$\theta \geq 0.70, 0.85$ (Zero Flagged)' '\n' r'TPR=0.00, FPR=0.00 (Silent)',
            xy=(0.0, 0.0), xytext=(0.10, 0.18),
            fontsize=10.5, fontweight='bold', color='#B71C1C',
            arrowprops=dict(arrowstyle='-|>', color='#B71C1C', lw=1.8),
            bbox=dict(boxstyle='round,pad=0.25', facecolor='#FFEBEE', edgecolor='#EF9A9A', alpha=0.95))

ax.set_xlim([-0.02, 1.02])
ax.set_ylim([-0.02, 1.05])
ax.set_xlabel('False Positive Rate (FAR on Benign Loss)', fontweight='bold')
ax.set_ylabel('True Positive Rate (Recall on Wiped Logs)', fontweight='bold')
ax.set_title(r'$AF_{conf}$ ROC & Operating Points ($P(H_1) = 0.15$)', fontweight='bold', pad=10)
ax.legend(loc='lower right', framealpha=0.95, edgecolor='#BDBDBD')
ax.grid(True, alpha=0.25, linestyle='--')
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

plt.tight_layout()
plt.savefig('Figures/fig_afconf_roc.png', dpi=DPI, bbox_inches='tight')
plt.close()
print('[OK] Regenerated Figures/fig_afconf_roc.png successfully.')
