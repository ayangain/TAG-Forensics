"""
scratch/regen_fig5_reconciled.py
================================
Regenerate Figure 5 (Figures/fig_fwoc_afconf.png) reconciling panels and caption:
- Panel (a): Plots BOTH FWoC Soundness (Containment) and Tightness across evidence loss
             for LLDOS 1.0 and LLDOS 2.0.2 (using Table 2 values with Wilson 95% CIs).
- Panel (b): Plots the AF_conf ROC curve (AUC = 0.801) reconciled with Table 4 at P(H1) = 0.15:
             Annotates the threshold theta >= 0.50 operating point (TPR=0.852, FPR=0.250)
             and the threshold theta >= 0.70, 0.85 cutoff point at (0, 0) (0 flagged alerts).
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

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.2))

# ════════════════════════════════════════════════════════════════════
# Panel (a): FWoC Soundness AND Tightness vs Evidence Loss
# ════════════════════════════════════════════════════════════════════
x = np.array([25, 50, 75, 100])
x_sound = x - 0.9
x_tight = x + 0.9

# Soundness (Containment) from Table 2: 100% across all levels
# Wilson score intervals from Table 2: [96.3%, 100%] for 25-75%, [100%, 100%] for 100%
soundness_lldos1 = [100.0, 100.0, 100.0, 100.0]
soundness_err_low = [3.7, 3.7, 3.7, 0.0] # 100 - 96.3
soundness_err_high = [0.0, 0.0, 0.0, 0.0]

# Tightness from Table 2: 100% across all levels
tightness_lldos1 = [100.0, 100.0, 100.0, 100.0]

# Plot LLDOS 1.0 Soundness with Wilson errorbars
ax1.errorbar(x_sound, soundness_lldos1, yerr=[soundness_err_low, soundness_err_high],
             fmt='o-', color='#1D3557', markerfacecolor='#457B9D', markeredgecolor='#1D3557',
             markeredgewidth=1.5, capsize=5, capthick=1.5, lw=2.5,
             label='Soundness / Containment (LLDOS 1.0 & 2.0.2)', zorder=4)

# Plot Tightness as distinct dashed line
ax1.plot(x_tight, tightness_lldos1, 's--', color='#E63946', markerfacecolor='#F4A261',
         markeredgecolor='#E63946', markeredgewidth=1.5, lw=2.2,
         label='Tightness / Timeline Span (LLDOS 1.0 & 2.0.2)', zorder=3)

ax1.set_xlabel('Evidence Completeness (%)', fontweight='bold')
ax1.set_ylabel('Percentage (%)', fontweight='bold')
ax1.set_title('(a) FWoC Soundness & Tightness (LLDOS)', fontweight='bold', pad=10)
ax1.set_xticks(x)
ax1.set_xticklabels([f'{c}%' for c in x])
ax1.set_xlim(20, 105)
ax1.set_ylim(85, 105)
ax1.set_yticks([85, 90, 95, 100])
ax1.grid(True, alpha=0.3, linestyle='--')
ax1.legend(loc='lower right', framealpha=0.95, edgecolor='#BDBDBD')
ax1.spines['top'].set_visible(False)
ax1.spines['right'].set_visible(False)

# Annotation for saturation
ax1.text(60, 92.5, 'Soundness = 100% (Containment verified)\nTightness = 100% (Artifact of short capture τ ≤ H)',
         fontsize=10, color='#1D3557', ha='center',
         bbox=dict(boxstyle='round,pad=0.25', facecolor='#E3F2FD', edgecolor='#90CAF9', alpha=0.9))

# ════════════════════════════════════════════════════════════════════
# Panel (b): AF_conf ROC Curve & Table 4 Operating Points
# ════════════════════════════════════════════════════════════════════
fpr = np.array([0.0, 0.250, 1.0])
tpr = np.array([0.0, 0.852, 1.0])

# ROC curve
ax2.plot(fpr, tpr, color='#E65100', lw=3, marker='o', markersize=8,
         markerfacecolor='#FF8F00', markeredgecolor='#E65100', markeredgewidth=1.5,
         label=r'Wipe vs. Random (AUC = 0.801)', zorder=3)

# Diagonal chance line
ax2.plot([0, 1], [0, 1], color='#1A237E', lw=2, linestyle='--',
         alpha=0.6, label='Random Chance (AUC = 0.500)')

# Shaded area under curve
ax2.fill_between(fpr, tpr, alpha=0.10, color='#FF8F00', zorder=2)

# Operating point 1: theta >= 0.50
ax2.plot(0.250, 0.852, marker='*', markersize=16, color='#D84315', zorder=5)
ax2.annotate(r'$\theta \geq 0.50$ (All Root Flagged)' '\n' r'TPR=0.85, FPR=0.25, $F_1=0.81$',
             xy=(0.250, 0.852), xytext=(0.38, 0.68),
             fontsize=10.5, fontweight='bold', color='#BF360C',
             arrowprops=dict(arrowstyle='-|>', color='#BF360C', lw=1.8),
             bbox=dict(boxstyle='round,pad=0.25', facecolor='#FBE9E7', edgecolor='#FF8A65', alpha=0.95))

# Operating point 2: theta >= 0.70, 0.85, 0.90 (at origin)
ax2.plot(0.0, 0.0, marker='X', markersize=12, color='#B71C1C', zorder=5)
ax2.annotate(r'$\theta \geq 0.70, 0.85$ (Zero Flagged)' '\n' r'TPR=0.00, FPR=0.00 (Silent)',
             xy=(0.0, 0.0), xytext=(0.10, 0.18),
             fontsize=10.5, fontweight='bold', color='#B71C1C',
             arrowprops=dict(arrowstyle='-|>', color='#B71C1C', lw=1.8),
             bbox=dict(boxstyle='round,pad=0.25', facecolor='#FFEBEE', edgecolor='#EF9A9A', alpha=0.95))

ax2.set_xlim([-0.02, 1.02])
ax2.set_ylim([-0.02, 1.05])
ax2.set_xlabel('False Positive Rate (FAR on Benign Loss)', fontweight='bold')
ax2.set_ylabel('True Positive Rate (Recall on Wiped Logs)', fontweight='bold')
ax2.set_title(r'(b) $AF_{conf}$ ROC & Operating Points ($P(H_1)=0.15$)', fontweight='bold', pad=10)
ax2.legend(loc='lower right', framealpha=0.95, edgecolor='#BDBDBD')
ax2.grid(True, alpha=0.25, linestyle='--')
ax2.spines['top'].set_visible(False)
ax2.spines['right'].set_visible(False)

plt.tight_layout()
plt.savefig('Figures/fig_fwoc_afconf.png', dpi=DPI, bbox_inches='tight')
plt.close()
print('[OK] Regenerated Figures/fig_fwoc_afconf.png successfully.')
