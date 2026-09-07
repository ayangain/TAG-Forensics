"""
Publication-grade generator for Figure 1: Motivating Example
Complies fully with all reviewer critique:
1. Single timeline spine (no repeated comic-strip topologies)
2. Decoupled colors: Neutral slate/blue-grey for time, strictly Red/Amber/Green for outcomes
3. Consistent node naming: Attacker -> Web Server -> Database (no 'Internet' node)
4. Reduced in-figure text: Clean badges and spatial cues, letting caption explain prose
5. Visual hierarchy: Elevated F-TAG payoff panel at the bottom
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle
import numpy as np

# ── Color Palette ─────────────────────────────────────────────────────────────
# Background & Neutrals
BG_COLOR       = '#ffffff'
CARD_BG        = '#f8fafc'
BORDER_MUTED   = '#cbd5e1'
TEXT_DARK      = '#0f172a'
TEXT_MUTED     = '#475569'
TEXT_LIGHT     = '#64748b'

# Time Progression (Cool neutral slate / blue-grey tones ONLY)
COL_W0_BG      = '#f0f7ff'
COL_W0_BORDER  = '#bae6fd'
COL_W0_HDR     = '#0284c7'

COL_W1_BG      = '#f8fafc'
COL_W1_BORDER  = '#cbd5e1'
COL_W1_HDR     = '#475569'

COL_W2_BG      = '#f1f5f9'
COL_W2_BORDER  = '#94a3b8'
COL_W2_HDR     = '#334155'

# Outcome Palettes (Strictly Red, Amber, Green)
RED_BG         = '#fef2f2'
RED_BORDER     = '#f87171'
RED_PRIMARY    = '#dc2626'
RED_TEXT       = '#991b1b'

AMBER_BG       = '#fffbeb'
AMBER_BORDER   = '#fcd34d'
AMBER_PRIMARY  = '#d97706'
AMBER_TEXT     = '#92400e'

GREEN_BG       = '#f0fdf4'
GREEN_BORDER   = '#86efac'
GREEN_PRIMARY  = '#16a34a'
GREEN_HERO     = '#15803d'
GREEN_TEXT     = '#14532d'

FONT = 'sans-serif'

# ── Helper Functions ──────────────────────────────────────────────────────────
def draw_rounded_card(ax, x, y, w, h, ec, fc, lw=1.5, r=0.08, ls='-', zorder=1):
    box = FancyBboxPatch((x, y), w, h,
                         boxstyle=f'round,pad=0.02,rounding_size={r}',
                         edgecolor=ec, facecolor=fc,
                         linewidth=lw, linestyle=ls, zorder=zorder)
    ax.add_patch(box)
    return box

def draw_badge(ax, x, y, text, bg, fg='white', fs=8.5, pad=0.15, zorder=10):
    ax.text(x, y, f' {text} ', ha='center', va='center', fontsize=fs,
            fontweight='bold', color=fg,
            bbox=dict(boxstyle='round,pad=0.28', facecolor=bg, edgecolor='none'),
            zorder=zorder)

def draw_arrow(ax, x0, y0, x1, y1, color, lw=1.8, ls='-', zorder=5):
    ax.annotate('', xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle='->,head_width=0.25,head_length=0.35',
                                color=color, lw=lw, linestyle=ls),
                zorder=zorder)

# ── Main Generator ────────────────────────────────────────────────────────────
def generate_figure(output_path):
    fig = plt.figure(figsize=(15.5, 9.8), facecolor=BG_COLOR, dpi=300)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 15.5)
    ax.set_ylim(0, 9.8)
    ax.axis('off')

    # 1. Figure Header
    ax.text(7.75, 9.42, 'Figure 1: Motivating Example — The Necessity of Temporal Topology in Forensic Reconstruction',
            ha='center', va='center', fontsize=13.5, fontweight='bold', color=TEXT_DARK)
    ax.text(7.75, 9.15, 'Incident: Attacker breaches Web Server in W₀; patch applied and logs wiped in W₁; pivot triggers IDS alert on Database in W₂.',
            ha='center', va='center', fontsize=10.0, color=TEXT_MUTED, style='italic')

    # Grid Dimensions
    X_LEFT_CARD_L = 0.5
    W_LEFT_CARD   = 3.3
    
    # Timeline column boundaries
    X_W0 = 4.0;  W_COL = 3.6
    X_W1 = 7.8;  
    X_W2 = 11.6; 
    
    # Timeline Header Boxes
    Y_THDR = 8.35
    H_THDR = 0.62
    
    draw_rounded_card(ax, X_W0, Y_THDR, W_COL, H_THDR, COL_W0_BORDER, COL_W0_BG, lw=1.5, r=0.06)
    ax.text(X_W0 + W_COL/2, Y_THDR + H_THDR*0.65, r'$\mathbf{W_0}$ : Week 1 (Exploit)', ha='center', va='center',
            fontsize=10.5, fontweight='bold', color=COL_W0_HDR)
    ax.text(X_W0 + W_COL/2, Y_THDR + H_THDR*0.25, 'CVE Active • Ingress Log Generated', ha='center', va='center',
            fontsize=8.5, color=TEXT_MUTED)

    draw_rounded_card(ax, X_W1, Y_THDR, W_COL, H_THDR, COL_W1_BORDER, COL_W1_BG, lw=1.5, r=0.06)
    ax.text(X_W1 + W_COL/2, Y_THDR + H_THDR*0.65, r'$\mathbf{W_1}$ : Week 2 (Patch & Log Wipe)', ha='center', va='center',
            fontsize=10.5, fontweight='bold', color=COL_W1_HDR)
    ax.text(X_W1 + W_COL/2, Y_THDR + H_THDR*0.25, 'CVE Patched • Ingress Log Deleted', ha='center', va='center',
            fontsize=8.5, color=TEXT_MUTED)

    draw_rounded_card(ax, X_W2, Y_THDR, W_COL, H_THDR, COL_W2_BORDER, COL_W2_BG, lw=1.5, r=0.06)
    ax.text(X_W2 + W_COL/2, Y_THDR + H_THDR*0.65, r'$\mathbf{W_2}$ : Week 3 (Detection)', ha='center', va='center',
            fontsize=10.5, fontweight='bold', color=COL_W2_HDR)
    ax.text(X_W2 + W_COL/2, Y_THDR + H_THDR*0.25, 'Database Alert Fires • Investigation Begins', ha='center', va='center',
            fontsize=8.5, color=TEXT_MUTED)

    # Time arrows between headers
    draw_arrow(ax, X_W0 + W_COL + 0.04, Y_THDR + H_THDR/2, X_W1 - 0.04, Y_THDR + H_THDR/2, TEXT_LIGHT, lw=2.0)
    draw_arrow(ax, X_W1 + W_COL + 0.04, Y_THDR + H_THDR/2, X_W2 - 0.04, Y_THDR + H_THDR/2, TEXT_LIGHT, lw=2.0)

    # Background Vertical Timeline Bands (subtle guides)
    Y_BANDS_BOTTOM = 0.4
    H_BANDS = 7.8
    for (xc, bgc) in [(X_W0, COL_W0_BG), (X_W1, COL_W1_BG), (X_W2, COL_W2_BG)]:
        rect = Rectangle((xc, Y_BANDS_BOTTOM), W_COL, H_BANDS, facecolor=bgc, alpha=0.35, zorder=0)
        ax.add_patch(rect)
        # Subtle dotted boundary lines
        ax.plot([xc, xc], [Y_BANDS_BOTTOM, Y_BANDS_BOTTOM + H_BANDS], color='#e2e8f0', lw=1.0, ls=':', zorder=1)
        ax.plot([xc + W_COL, xc + W_COL], [Y_BANDS_BOTTOM, Y_BANDS_BOTTOM + H_BANDS], color='#e2e8f0', lw=1.0, ls=':', zorder=1)

    # ── ROW 1: Ground Truth Physical Attack & Vulnerability Lifespan ──────────────
    Y_R1 = 6.45
    H_ROW = 1.65

    # Left Card: Ground Truth
    draw_rounded_card(ax, X_LEFT_CARD_L, Y_R1, W_LEFT_CARD, H_ROW, BORDER_MUTED, '#ffffff', lw=1.5)
    ax.text(X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R1 + H_ROW*0.75, 'Physical Reality',
            ha='center', va='center', fontsize=11.5, fontweight='bold', color=TEXT_DARK)
    ax.text(X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R1 + H_ROW*0.48, 'Ground truth incident timeline\nand vulnerability lifecycle',
            ha='center', va='center', fontsize=8.5, color=TEXT_MUTED, linespacing=1.3)
    draw_badge(ax, X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R1 + 0.28, 'GROUND TRUTH', '#475569', fs=8)

    # Ground Truth Content Across Timeline
    # Node boxes: Attacker, Web Server, Database
    # In W0: Attacker -> Web Server
    draw_rounded_card(ax, X_W0 + 0.2, Y_R1 + 0.95, 1.3, 0.48, COL_W0_HDR, '#ffffff', lw=1.5, zorder=3)
    ax.text(X_W0 + 0.85, Y_R1 + 1.19, 'Attacker', ha='center', va='center', fontsize=8.5, fontweight='bold', color=COL_W0_HDR, zorder=4)

    draw_arrow(ax, X_W0 + 1.55, Y_R1 + 1.19, X_W0 + 2.1, Y_R1 + 1.19, COL_W0_HDR, lw=2.0)
    ax.text(X_W0 + 1.82, Y_R1 + 1.42, 'CVE exploit', ha='center', va='center', fontsize=7.5, color=COL_W0_HDR, style='italic')

    draw_rounded_card(ax, X_W0 + 2.15, Y_R1 + 0.95, 1.25, 0.48, COL_W0_HDR, '#ffffff', lw=1.5, zorder=3)
    ax.text(X_W0 + 2.77, Y_R1 + 1.19, 'Web Server', ha='center', va='center', fontsize=8.5, fontweight='bold', color=COL_W0_HDR, zorder=4)

    # In W1: Web Server patched, Log wiped
    draw_rounded_card(ax, X_W1 + 1.15, Y_R1 + 0.95, 1.3, 0.48, '#64748b', '#ffffff', lw=1.5, zorder=3)
    ax.text(X_W1 + 1.8, Y_R1 + 1.19, 'Web Server', ha='center', va='center', fontsize=8.5, fontweight='bold', color='#334155', zorder=4)
    draw_badge(ax, X_W1 + 1.8, Y_R1 + 0.65, 'Log Wiped by Attacker', '#ef4444', fs=7.5, zorder=5)

    # In W2: Web Server -> Database (Alert)
    draw_rounded_card(ax, X_W2 + 0.3, Y_R1 + 0.95, 1.25, 0.48, '#64748b', '#ffffff', lw=1.5, zorder=3)
    ax.text(X_W2 + 0.92, Y_R1 + 1.19, 'Web Server', ha='center', va='center', fontsize=8.5, fontweight='bold', color='#334155', zorder=4)

    draw_arrow(ax, X_W2 + 1.6, Y_R1 + 1.19, X_W2 + 2.15, Y_R1 + 1.19, '#0f172a', lw=2.0)
    ax.text(X_W2 + 1.87, Y_R1 + 1.42, 'Pivot', ha='center', va='center', fontsize=7.5, color=TEXT_DARK, style='italic')

    draw_rounded_card(ax, X_W2 + 2.2, Y_R1 + 0.95, 1.2, 0.48, '#dc2626', '#fef2f2', lw=2.0, zorder=3)
    ax.text(X_W2 + 2.8, Y_R1 + 1.19, 'Database', ha='center', va='center', fontsize=8.5, fontweight='bold', color='#dc2626', zorder=4)
    draw_badge(ax, X_W2 + 2.8, Y_R1 + 0.65, '🚨 IDS Alert Fired', '#dc2626', fs=7.5, zorder=5)

    # Vulnerability Lifespan Bar across the bottom of Row 1
    Y_BAR = Y_R1 + 0.18
    H_BAR = 0.28
    # Active in W0
    draw_rounded_card(ax, X_W0 + 0.2, Y_BAR, W_COL - 0.4, H_BAR, '#0284c7', '#bae6fd', lw=1.2, r=0.04)
    ax.text(X_W0 + W_COL/2, Y_BAR + H_BAR/2, 'CVE Vulnerability Active (Exploitable Edge Open)',
            ha='center', va='center', fontsize=7.5, fontweight='bold', color='#0369a1')

    # Inactive in W1 and W2
    draw_rounded_card(ax, X_W1 + 0.2, Y_BAR, (W_COL*2) - 0.4 + 0.2, H_BAR, '#cbd5e1', '#f1f5f9', lw=1.2, r=0.04)
    ax.text(X_W1 + W_COL, Y_BAR + H_BAR/2, '🔒 CVE Patched — Ingress Edge Permanently Closed Across W₁ and W₂',
            ha='center', va='center', fontsize=7.5, fontweight='bold', color='#64748b')


    # ── ROW 2: Approach (a) — Evidence Graph (Log-Driven) ─────────────────────────
    Y_R2 = 4.45
    draw_rounded_card(ax, X_LEFT_CARD_L, Y_R2, W_LEFT_CARD, H_ROW, RED_BORDER, RED_BG, lw=1.6)
    ax.text(X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R2 + H_ROW*0.75, '(a) Evidence Graph',
            ha='center', va='center', fontsize=11.5, fontweight='bold', color=RED_TEXT)
    ax.text(X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R2 + H_ROW*0.48, 'Reactive backward log chaining\nRequires continuous evidence logs',
            ha='center', va='center', fontsize=8.5, color=TEXT_MUTED, linespacing=1.3)
    draw_badge(ax, X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R2 + 0.28, '✕  STALLS (DEAD END)', RED_PRIMARY, fs=8.5)

    # Evidence Graph Content
    # Container across timeline
    draw_rounded_card(ax, X_W0 + 0.1, Y_R2, (W_COL*3) + 0.6, H_ROW, RED_BORDER, '#ffffff', lw=1.2)

    # W2: Starts at Database Alert
    draw_rounded_card(ax, X_W2 + 2.0, Y_R2 + 0.65, 1.3, 0.5, '#dc2626', '#fef2f2', lw=1.8, zorder=3)
    ax.text(X_W2 + 2.65, Y_R2 + 0.9, 'Database Alert', ha='center', va='center', fontsize=8.5, fontweight='bold', color='#dc2626', zorder=4)

    # Trace backward arrow from W2 Database to W1 Web Server
    draw_arrow(ax, X_W2 + 1.95, Y_R2 + 0.9, X_W1 + 2.5, Y_R2 + 0.9, '#ef4444', lw=2.2, ls='--')
    ax.text(X_W2 + 0.3, Y_R2 + 1.15, 'Traces backward to Web Server...', ha='center', va='center', fontsize=8.0, color='#b91c1c', style='italic')

    # W1: Web Server log is missing! Barrier hit
    draw_rounded_card(ax, X_W1 + 1.0, Y_R2 + 0.65, 1.4, 0.5, '#f87171', '#fee2e2', lw=1.8, zorder=3)
    ax.text(X_W1 + 1.7, Y_R2 + 0.9, 'Web Server', ha='center', va='center', fontsize=8.5, fontweight='bold', color='#991b1b', zorder=4)
    
    # Broken link cross
    ax.text(X_W1 + 0.3, Y_R2 + 0.9, '✕', ha='center', va='center', fontsize=22, fontweight='bold', color='#dc2626')
    ax.text(X_W1 + 0.3, Y_R2 + 0.45, 'Log Missing!', ha='center', va='center', fontsize=8.0, fontweight='bold', color='#dc2626')

    # W0: Unreachable
    draw_rounded_card(ax, X_W0 + 1.0, Y_R2 + 0.65, 1.5, 0.5, '#cbd5e1', '#f8fafc', lw=1.2, ls=':', zorder=3)
    ax.text(X_W0 + 1.75, Y_R2 + 0.9, 'Attacker Ingress (?)', ha='center', va='center', fontsize=8.0, color='#94a3b8', zorder=4)
    ax.text(X_W0 + 1.75, Y_R2 + 0.45, 'Never Reached', ha='center', va='center', fontsize=7.5, style='italic', color='#94a3b8')

    # Explanatory verdict banner at bottom of card
    ax.text(X_W1 + W_COL/2, Y_R2 + 0.22, 'Investigation dead-ends at Web Server. Cannot bound incident window or identify entry point.',
            ha='center', va='center', fontsize=8.5, color='#991b1b', fontweight='bold')


    # ── ROW 3: Approach (b) — Static Attack Graph (Timeless) ──────────────────────
    Y_R3 = 2.45
    draw_rounded_card(ax, X_LEFT_CARD_L, Y_R3, W_LEFT_CARD, H_ROW, AMBER_BORDER, AMBER_BG, lw=1.6)
    ax.text(X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R3 + H_ROW*0.75, '(b) Static Attack Graph',
            ha='center', va='center', fontsize=11.5, fontweight='bold', color=AMBER_TEXT)
    ax.text(X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R3 + H_ROW*0.48, 'Timeless topological reachability\nAll edges treated as permanently active',
            ha='center', va='center', fontsize=8.5, color=TEXT_MUTED, linespacing=1.3)
    draw_badge(ax, X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R3 + 0.28, '⚠  PHANTOM PATH (BLIND)', AMBER_PRIMARY, fs=8.5)

    # Static Graph Content
    draw_rounded_card(ax, X_W0 + 0.1, Y_R3, (W_COL*3) + 0.6, H_ROW, AMBER_BORDER, '#ffffff', lw=1.2)

    # In W0 and W1: Ignored by static correlation
    ax.text(X_W0 + W_COL, Y_R3 + 0.9, '— Static correlation does not evaluate historical time windows —',
            ha='center', va='center', fontsize=8.5, color='#94a3b8', style='italic')

    # In W2: Constructs entire path inside W2!
    draw_rounded_card(ax, X_W2 + 0.1, Y_R3 + 0.65, 1.0, 0.5, AMBER_PRIMARY, '#fffbeb', lw=1.5, zorder=3)
    ax.text(X_W2 + 0.6, Y_R3 + 0.9, 'Attacker', ha='center', va='center', fontsize=8.0, fontweight='bold', color=AMBER_TEXT, zorder=4)

    draw_arrow(ax, X_W2 + 1.15, Y_R3 + 0.9, X_W2 + 1.45, Y_R3 + 0.9, AMBER_PRIMARY, lw=2.0)

    draw_rounded_card(ax, X_W2 + 1.5, Y_R3 + 0.65, 1.0, 0.5, AMBER_PRIMARY, '#fffbeb', lw=1.5, zorder=3)
    ax.text(X_W2 + 2.0, Y_R3 + 0.9, 'Web Server', ha='center', va='center', fontsize=8.0, fontweight='bold', color=AMBER_TEXT, zorder=4)

    draw_arrow(ax, X_W2 + 2.55, Y_R3 + 0.9, X_W2 + 2.85, Y_R3 + 0.9, AMBER_PRIMARY, lw=2.0)

    draw_rounded_card(ax, X_W2 + 2.9, Y_R3 + 0.65, 0.95, 0.5, AMBER_PRIMARY, '#fffbeb', lw=1.5, zorder=3)
    ax.text(X_W2 + 3.37, Y_R3 + 0.9, 'Database', ha='center', va='center', fontsize=8.0, fontweight='bold', color=AMBER_TEXT, zorder=4)

    # Warning Callout
    draw_badge(ax, X_W2 + 2.0, Y_R3 + 1.35, '⚠ IMPOSSIBLE PATH AT W₂: CVE WAS PATCHED IN W₁', '#dc2626', fs=7.5, zorder=10)

    # Explanatory verdict banner
    ax.text(X_W1 + W_COL/2, Y_R3 + 0.22, 'Blind to the W₁ patch. Concludes attacker entered at W₂ via an edge that was already closed.',
            ha='center', va='center', fontsize=8.5, color=AMBER_TEXT, fontweight='bold')


    # ── ROW 4: Approach (c) — F-TAG (Forensic Temporal Attack Graph - Ours) ────────
    # ELEVATED HERO CARD (slightly taller, emerald highlight, thick glowing border)
    Y_R4 = 0.35
    H_HERO = 1.85
    draw_rounded_card(ax, X_LEFT_CARD_L, Y_R4, W_LEFT_CARD, H_HERO, GREEN_PRIMARY, GREEN_BG, lw=2.4)
    ax.text(X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R4 + H_HERO*0.78, '(c) F-TAG (Proposed)',
            ha='center', va='center', fontsize=12.5, fontweight='bold', color=GREEN_HERO)
    ax.text(X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R4 + H_HERO*0.50, 'Temporal topology with FWoC\nTracks edge validity windows across time',
            ha='center', va='center', fontsize=8.5, color=TEXT_MUTED, linespacing=1.3)
    draw_badge(ax, X_LEFT_CARD_L + W_LEFT_CARD/2, Y_R4 + 0.30, '✓  BREACH BOUNDED: [W₀, W₁]', GREEN_PRIMARY, fs=9.0)

    # Hero Content Container
    draw_rounded_card(ax, X_W0 + 0.1, Y_R4, (W_COL*3) + 0.6, H_HERO, GREEN_PRIMARY, '#ffffff', lw=2.0)

    # W2: Structural Contradiction Detected
    draw_rounded_card(ax, X_W2 + 0.2, Y_R4 + 0.85, W_COL - 0.4, 0.75, '#fca5a5', '#fef2f2', lw=1.5, zorder=3)
    ax.text(X_W2 + W_COL/2, Y_R4 + 1.35, r'Path evaluated at $W_2$ : $\mathbf{FWoC = \emptyset}$',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color='#dc2626', zorder=4)
    ax.text(X_W2 + W_COL/2, Y_R4 + 1.05, 'CVE edge closed at W₁ → Structural Contradiction!\nRejects W₂ path as physically impossible',
            ha='center', va='center', fontsize=7.5, color='#991b1b', linespacing=1.2, zorder=4)

    # Temporal Back-Trace Arrow to W0
    draw_arrow(ax, X_W2 + 0.15, Y_R4 + 1.2, X_W1 + 2.0, Y_R4 + 1.2, GREEN_PRIMARY, lw=2.5, ls='-')
    ax.text(X_W1 + 2.6, Y_R4 + 1.45, 'Resolves contradiction backward in time', ha='center', va='center',
            fontsize=8.0, fontweight='bold', color=GREEN_PRIMARY)

    # W0 - W1: Forensic Window of Compromise Bracket
    X_FWOC_START = X_W0 + 0.3
    X_FWOC_END   = X_W1 + W_COL - 0.3
    W_FWOC       = X_FWOC_END - X_FWOC_START

    # Beautiful Highlighted FWoC Box
    draw_rounded_card(ax, X_FWOC_START, Y_R4 + 0.80, W_FWOC, 0.82, GREEN_PRIMARY, '#dcfce7', lw=2.0, r=0.06, zorder=3)
    ax.text(X_FWOC_START + W_FWOC/2, Y_R4 + 1.35, r'$\mathbf{Forensic\;Window\;of\;Compromise\;(FWoC)\;=\;[W_0,\;W_1]}$',
            ha='center', va='center', fontsize=10.0, fontweight='bold', color=GREEN_HERO, zorder=4)
    ax.text(X_FWOC_START + W_FWOC/2, Y_R4 + 1.02, 'Attacker ingress conclusively bounded to W₀ (the only window where CVE edge existed).\nOrigin proven despite completely wiped intermediate logs.',
            ha='center', va='center', fontsize=8.5, color=GREEN_TEXT, zorder=4)

    # Hero Payoff Banner along bottom
    ax.text(X_W1 + W_COL/2, Y_R4 + 0.30,
            '✓ Topological constraints recover the true breach window even when evidence logs are destroyed.',
            ha='center', va='center', fontsize=9.2, fontweight='bold', color=GREEN_HERO)

    plt.savefig(output_path, dpi=300, facecolor=BG_COLOR, edgecolor='none', bbox_inches='tight')
    plt.close()
    print(f'Successfully generated: {output_path}')

if __name__ == '__main__':
    generate_figure('/Users/ayangain/repos/TAG-Forensics/scratch/motivating_example_v4.png')
