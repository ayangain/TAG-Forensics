"""
Regenerate the AF_conf ROC curve for the MulVAL topology at publication quality.

The ROC curve is reconstructed from the verified root-privilege target rates:
  - Wipe: 85.4% of gap nodes land on root-privilege nodes
  - Random: 25.2% of gap nodes land on root-privilege nodes

With Prior=0.30, the Bayesian posterior AF_conf = P(H1|root) vs P(H1|non-root)
creates a binary classifier with known TPR/FPR characteristics that produce AUC=0.801.

This reconstruction matches the verified trace output exactly.
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
    'legend.fontsize': 13,
    'figure.dpi': DPI,
    'savefig.dpi': DPI,
    'axes.linewidth': 1.2,
    'lines.linewidth': 2.5,
    'figure.facecolor': 'white',
    'axes.facecolor': 'white',
    'savefig.facecolor': 'white',
})

# The AF_conf posterior with Prior=0.30 produces two score levels:
#   - Root nodes: score_high (above threshold)
#   - Non-root nodes: score_low (below threshold)
# Wipe targets: 85.4% root, 14.6% non-root  (positive class)
# Random targets: 25.2% root, 74.8% non-root  (negative class)
#
# The ROC curve has exactly one operating point (the threshold between scores):
#   TPR = 0.854  (fraction of wipe nodes scoring above threshold)
#   FPR = 0.252  (fraction of random nodes scoring above threshold)
# Plus the (0,0) and (1,1) corners.
# AUC = area under this 3-point curve.

fpr = np.array([0.0, 0.252, 1.0])
tpr = np.array([0.0, 0.854, 1.0])
# Verify AUC
roc_auc = np.trapezoid(tpr, fpr)
print(f"Reconstructed AUC: {roc_auc:.3f}")
assert abs(roc_auc - 0.801) < 0.005, f"AUC mismatch: {roc_auc:.4f} vs expected 0.801"

fig, ax = plt.subplots(figsize=(5.5, 5))

# ROC curve
ax.plot(fpr, tpr, color='#E65100', lw=3, marker='o', markersize=8,
        markerfacecolor='#FF8F00', markeredgecolor='#E65100', markeredgewidth=1.5,
        label=f'Wipe vs. Random (AUC = {roc_auc:.3f})', zorder=3)

# Diagonal reference
ax.plot([0, 1], [0, 1], color='#1A237E', lw=2, linestyle='--',
        alpha=0.7, label='Random Chance (AUC = 0.500)')

# Shade area under curve
ax.fill_between(fpr, tpr, alpha=0.12, color='#FF8F00', zorder=2)

# Operating point annotation
ax.annotate(f'Operating Point\nTPR={tpr[1]:.2f}, FPR={fpr[1]:.2f}',
            xy=(fpr[1], tpr[1]),
            xytext=(fpr[1] + 0.15, tpr[1] - 0.15),
            fontsize=10,
            arrowprops=dict(arrowstyle='-|>', color='#424242', lw=1.5),
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#FFF3E0',
                      edgecolor='#E65100', alpha=0.9))

ax.set_xlim([-0.02, 1.02])
ax.set_ylim([-0.02, 1.05])
ax.set_xlabel('False Positive Rate')
ax.set_ylabel('True Positive Rate')
ax.set_title('$AF_{conf}$ ROC (MulVAL, Prior=0.30)', fontweight='bold', pad=10)
ax.legend(loc='lower right', framealpha=0.9)
ax.grid(True, alpha=0.2, linestyle='--')
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.set_aspect('equal')

plt.tight_layout()
plt.savefig('experiment/results/afconf_roc.png', dpi=DPI, bbox_inches='tight')
plt.close()
print("[OK] afconf_roc.png (MulVAL, AUC=0.801)")
