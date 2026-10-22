"""
scratch/regen_fig3_chokepoint_tmin.py
=====================================
Regenerates Figures/fig_chokepoint_tmin.png as a publication-quality 2-panel figure:
- Panel (a): Topological Breach Window Anchor T_min Stability across evidence loss
             (LLDOS 1.0 stays pinned at T_min=2.0; LLDOS 2.0.2 stays pinned at T_min=0.0)
- Panel (b): Pivot Host Chokepoint Rank & Score chi(h) across evidence loss
             (Physical host rank stays pinned at Rank #1, chi=1.0, with tie-break
              clarification that all compromise states on the pivot host tie for top rank).
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

C_NAVY = '#1D3557'
C_TEAL = '#457B9D'
C_CORAL = '#E63946'
C_AMBER = '#F4A261'
C_GREEN = '#2E7D32'

completeness = [25, 50, 75, 100]

# Panel (a) data: T_min
tmin_lldos1 = [2.0, 2.0, 2.0, 2.0]
tmin_lldos2 = [0.0, 0.0, 0.0, 0.0]

# Panel (b) data: Pivot Host Rank & chi
host_rank = [1.0, 1.0, 1.0, 1.0] # Host-level rank (mill has chi=1.0, locke/pascal have 0.4)
state_rank_ordinal = [2.0, 2.0, 2.0, 2.0] # Ordinal state-level index without tie resolution
chi_score = [1.0, 1.0, 1.0, 1.0]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.8))

# ─── Panel (a): T_min Stability ───────────────────────────────────────────
ax1.plot(completeness, tmin_lldos1, 'o-', color=C_NAVY, markerfacecolor=C_TEAL,
         markeredgecolor=C_NAVY, markeredgewidth=1.5, label='LLDOS 1.0 ($T_{min} = 2.0$)', zorder=3)
ax1.plot(completeness, tmin_lldos2, 's-', color=C_CORAL, markerfacecolor=C_AMBER,
         markeredgecolor=C_CORAL, markeredgewidth=1.5, label='LLDOS 2.0.2 ($T_{min} = 0.0$)', zorder=3)

ax1.set_xlabel('Evidence Completeness (%)', fontweight='bold')
ax1.set_ylabel('Inferred Breach Window ($T_{min}$)', fontweight='bold')
ax1.set_title('(a) Breach Window Anchor Stability', fontweight='bold', pad=10)
ax1.set_xticks(completeness)
ax1.set_xticklabels([f'{c}%' for c in completeness])
ax1.set_xlim(20, 105)
ax1.set_ylim(-0.5, 3.5)
ax1.set_yticks([0, 1, 2, 3])
ax1.grid(True, alpha=0.3, linestyle='--')
ax1.legend(loc='center right', framealpha=0.95, edgecolor='#BDBDBD')
ax1.spines['top'].set_visible(False)
ax1.spines['right'].set_visible(False)

# Annotation for topological invariance
ax1.text(60, 2.25, 'Invariant across total log deletion', fontsize=10.5,
         fontstyle='italic', color='#424242', ha='center',
         bbox=dict(boxstyle='round,pad=0.2', facecolor='#F5F5F5', edgecolor='#BDBDBD', alpha=0.9))

# ─── Panel (b): Pivot Host Rank & Score Stability ─────────────────────────
ax2.plot(completeness, host_rank, 'D-', color=C_GREEN, markerfacecolor='#81C784',
         markeredgecolor=C_GREEN, markeredgewidth=1.5, lw=2.8,
         label=r"Host-Level Rank (Host 'mill': $\chi = 1.00$)", zorder=4)

ax2.plot(completeness, state_rank_ordinal, 'v--', color='#757575', markerfacecolor='#BDBDBD',
         markeredgecolor='#757575', markeredgewidth=1.2, lw=1.8,
         label=r'State-Level Ordinal Rank (Tied at $\chi=1.00$)', zorder=3)

ax2.set_xlabel('Evidence Completeness (%)', fontweight='bold')
ax2.set_ylabel('Pivot Host Rank Position', fontweight='bold')
ax2.set_title('(b) Pivot Host Chokepoint Rank Stability', fontweight='bold', pad=10)
ax2.set_xticks(completeness)
ax2.set_xticklabels([f'{c}%' for c in completeness])
ax2.set_xlim(20, 105)
ax2.set_ylim(0.5, 3.5)
ax2.set_yticks([1, 2, 3])
ax2.invert_yaxis() # Rank 1 at top
ax2.grid(True, alpha=0.3, linestyle='--')
ax2.legend(loc='lower right', framealpha=0.95, edgecolor='#BDBDBD')
ax2.spines['top'].set_visible(False)
ax2.spines['right'].set_visible(False)

# Annotation explaining tie-break
ax2.text(62, 1.35, 'Tied top-priority states on host mill\n(mill:discovered, mill:mstream_master)',
         fontsize=10, color='#1B5E20', ha='center',
         bbox=dict(boxstyle='round,pad=0.25', facecolor='#E8F5E9', edgecolor=C_GREEN, alpha=0.9))

plt.tight_layout()
plt.savefig('Figures/fig_chokepoint_tmin.png', dpi=DPI, bbox_inches='tight')
plt.close()
print('[OK] Regenerated Figures/fig_chokepoint_tmin.png successfully.')
