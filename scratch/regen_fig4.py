"""
scratch/regen_fig4.py
=====================
Regenerate Figure 4 (Figures/fig_falsification_detection.png) under operational tolerance delta=1:
- Scenarios: 'Precedence Swap', 'Vulnerability Patching', 'Connectivity Expiration'
- 30-seed F1 values under Full Infrastructure Wipe at delta=1:
    Zhang (Static): [1.00, 0.00, 0.00]  (catches precedence swaps, misses structural cuts)
    F-TAG (delta=1):[0.00, 0.90, 1.00]  (absorbs 1-window swap jitter, catches structural cuts)
- Publication quality (400 DPI, Serif font, clean annotations and MISS callouts)
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
    'legend.fontsize': 12,
    'figure.dpi': DPI,
    'savefig.dpi': DPI,
    'axes.linewidth': 1.2,
    'figure.facecolor': 'white',
    'axes.facecolor': 'white',
    'savefig.facecolor': 'white',
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1,
})

C_FTAG = '#1B5E20'
C_FTAG_LIGHT = '#81C784'
C_ZHANG = '#B71C1C'
C_ZHANG_LIGHT = '#E57373'

scenarios = ['Precedence\nSwap', 'Vulnerability\nPatching', 'Connectivity\nExpiration']
zhang_f1 = [1.00, 0.00, 0.00]
ftag_f1 = [0.00, 0.90, 1.00]

x = np.arange(len(scenarios))
width = 0.32

fig, ax = plt.subplots(figsize=(8.5, 5.0))

bars1 = ax.bar(x - width/2, zhang_f1, width, label='Zhang et al. (Static AG)',
               color=C_ZHANG_LIGHT, edgecolor=C_ZHANG, linewidth=1.5, zorder=3)
bars2 = ax.bar(x + width/2, ftag_f1, width, label='F-TAG (Ours, $\\delta=1$)',
               color=C_FTAG_LIGHT, edgecolor=C_FTAG, linewidth=1.5, zorder=3)

# Value labels on top of bars
for bar in bars2:
    height = bar.get_height()
    if height > 0:
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.025,
                f'{height:.2f}', ha='center', va='bottom',
                fontsize=12, fontweight='bold', color=C_FTAG)

for bar in bars1:
    height = bar.get_height()
    if height > 0:
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.025,
                f'{height:.2f}', ha='center', va='bottom',
                fontsize=12, fontweight='bold', color=C_ZHANG)

# MISS labels for zero values
# Zhang misses for index 1 and 2
for i in [1, 2]:
    ax.text(x[i] - width/2, 0.03, 'MISS', ha='center', va='bottom',
            fontsize=12, fontweight='bold', color=C_ZHANG,
            bbox=dict(boxstyle='round,pad=0.25', facecolor='#FFCDD2',
                      edgecolor=C_ZHANG, alpha=0.9))

# F-TAG misses for index 0 at delta=1
ax.text(x[0] + width/2, 0.03, 'MISS', ha='center', va='bottom',
        fontsize=12, fontweight='bold', color=C_FTAG,
        bbox=dict(boxstyle='round,pad=0.25', facecolor='#C8E6C9',
                  edgecolor=C_FTAG, alpha=0.9))

ax.set_ylabel('F1 Score', fontweight='bold')
ax.set_xlabel('Adversarial Falsification Strategy', fontweight='bold', labelpad=8)
ax.set_xticks(x)
ax.set_xticklabels(scenarios, fontweight='bold')
ax.set_ylim(0, 1.25)
ax.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
ax.legend(loc='upper right', framealpha=0.95, edgecolor='#BDBDBD')
ax.grid(axis='y', alpha=0.3, linestyle='--', zorder=0)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.set_title("Falsification Detection F1: Full Infrastructure Wipe ($\\delta=1$ Tolerance)",
             fontweight="bold", pad=12)

plt.tight_layout()
plt.savefig('Figures/fig_falsification_detection.png', dpi=DPI, bbox_inches='tight')
plt.close()
print("[OK] Regenerated Figures/fig_falsification_detection.png successfully.")
