"""
Masterpiece generator for Figure 1: Motivating Example
Layout:
Tier 1: Ground Truth Attack Lifecycle
  - Unified Network Topology: Attacker -> Web Server -> Database (drawn ONCE)
  - Dynamic Time Window Strip: W0 (Exploit) -> W1 (Patch & Wipe) -> W2 (Alert)
Tier 2: Comparison of Forensic Paradigms (Side-by-Side Cards)
  - (a) Evidence Graph (Red: Dead End)
  - (b) Static Attack Graph (Amber: Phantom Path)
  - (c) F-TAG [Proposed] (Emerald: Hero Card, Breach Bounded)
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle
import numpy as np

# ── Color Palette ─────────────────────────────────────────────────────────────
BG_COLOR       = '#ffffff'
TEXT_DARK      = '#0f172a'
TEXT_MUTED     = '#475569'
TEXT_LIGHT     = '#64748b'
BORDER_MUTED   = '#cbd5e1'

# Time Progression (Cool neutral slate / blue-grey tones)
COL_W0_BG      = '#eff6ff'
COL_W0_BORDER  = '#93c5fd'
COL_W0_HDR     = '#0284c7'

COL_W1_BG      = '#f8fafc'
COL_W1_BORDER  = '#cbd5e1'
COL_W1_HDR     = '#475569'

COL_W2_BG      = '#f1f5f9'
COL_W2_BORDER  = '#94a3b8'
COL_W2_HDR     = '#1e293b'

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
GREEN_BORDER   = '#22c55e'
GREEN_PRIMARY  = '#16a34a'
GREEN_HERO     = '#15803d'
GREEN_TEXT     = '#14532d'

def draw_rounded_card(ax, x, y, w, h, ec, fc, lw=1.5, r=0.08, ls='-', zorder=1):
    box = FancyBboxPatch((x, y), w, h,
                         boxstyle=f'round,pad=0.02,rounding_size={r}',
                         edgecolor=ec, facecolor=fc,
                         linewidth=lw, linestyle=ls, zorder=zorder)
    ax.add_patch(box)
    return box

def draw_badge(ax, x, y, text, bg, fg='white', fs=8.0, zorder=10):
    ax.text(x, y, f' {text} ', ha='center', va='center', fontsize=fs,
            fontweight='bold', color=fg,
            bbox=dict(boxstyle='round,pad=0.25', facecolor=bg, edgecolor='none'),
            zorder=zorder)

def draw_arrow(ax, x0, y0, x1, y1, color, lw=1.8, ls='-', zorder=5):
    ax.annotate('', xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle='->,head_width=0.22,head_length=0.32',
                                color=color, lw=lw, linestyle=ls),
                zorder=zorder)

def generate_figure(output_path):
    fig = plt.figure(figsize=(15.5, 9.8), facecolor=BG_COLOR, dpi=300)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 15.5)
    ax.set_ylim(0, 9.8)
    ax.axis('off')

    # Figure Header
    ax.text(7.75, 9.50, 'Motivating Scenario: The Necessity of Temporal Topology in Forensic Reconstruction',
            ha='center', va='center', fontsize=13.0, fontweight='bold', color=TEXT_DARK)
    ax.text(7.75, 9.22, 'Incident: Attacker breaches Web Server in W₀; patch applied and logs wiped in W₁; pivot triggers IDS alert on Database in W₂.',
            ha='center', va='center', fontsize=9.2, color=TEXT_MUTED, style='italic')

    # ══════════════════════════════════════════════════════════════════════════
    #  TIER 1: GROUND TRUTH INCIDENT & TEMPORAL TOPOLOGY (Y: 5.00 to 9.02)
    # ══════════════════════════════════════════════════════════════════════════
    Y_T1 = 5.00
    H_T1 = 4.02
    draw_rounded_card(ax, 0.4, Y_T1, 14.7, H_T1, BORDER_MUTED, '#ffffff', lw=1.6, r=0.08)

    # Header Ribbon
    draw_badge(ax, 2.0, Y_T1 + H_T1 - 0.22, 'GROUND TRUTH ATTACK LIFECYCLE', '#334155', fs=8.5)
    ax.text(14.8, Y_T1 + H_T1 - 0.22, 'Physical Network Topology & Temporal Edge Lifespans',
            ha='right', va='center', fontsize=8.5, color=TEXT_MUTED, style='italic')

    # 1. NETWORK TOPOLOGY (Drawn ONCE, clear and spacious)
    Y_TOPO = Y_T1 + 2.35

    # Node 1: Attacker
    draw_rounded_card(ax, 0.9, Y_TOPO, 2.4, 0.75, COL_W0_HDR, '#ffffff', lw=1.8, r=0.06, zorder=3)
    ax.text(2.1, Y_TOPO + 0.48, 'Attacker', ha='center', va='center', fontsize=10.5, fontweight='bold', color=COL_W0_HDR, zorder=4)
    ax.text(2.1, Y_TOPO + 0.20, 'External Ingress', ha='center', va='center', fontsize=7.8, color=TEXT_MUTED, zorder=4)

    # Edge 1: Attacker -> Web Server
    draw_arrow(ax, 3.35, Y_TOPO + 0.38, 6.35, Y_TOPO + 0.38, COL_W0_HDR, lw=2.4)
    ax.text(4.85, Y_TOPO + 0.65, r'Edge $e_1$ : CVE-2021-44228 Exploit', ha='center', va='center',
            fontsize=8.5, fontweight='bold', color=COL_W0_HDR)
    draw_badge(ax, 4.85, Y_TOPO + 0.12, 'Open in W₀  |  Patched at W₁', '#0284c7', fs=7.2)

    # Node 2: Web Server
    draw_rounded_card(ax, 6.4, Y_TOPO, 2.7, 0.75, '#475569', '#ffffff', lw=1.8, r=0.06, zorder=3)
    ax.text(7.75, Y_TOPO + 0.48, 'Web Server', ha='center', va='center', fontsize=10.5, fontweight='bold', color='#1e293b', zorder=4)
    ax.text(7.75, Y_TOPO + 0.20, 'DMZ Application Tier', ha='center', va='center', fontsize=7.8, color=TEXT_MUTED, zorder=4)

    # Edge 2: Web Server -> Database
    draw_arrow(ax, 9.15, Y_TOPO + 0.38, 12.15, Y_TOPO + 0.38, '#0f172a', lw=2.4)
    ax.text(10.65, Y_TOPO + 0.65, r'Edge $e_2$ : Internal Lateral Pivot', ha='center', va='center',
            fontsize=8.5, fontweight='bold', color=TEXT_DARK)
    draw_badge(ax, 10.65, Y_TOPO + 0.12, 'Traversed in W₂  (Alert Fired)', '#dc2626', fs=7.2)

    # Node 3: Database
    draw_rounded_card(ax, 12.2, Y_TOPO, 2.4, 0.75, '#dc2626', '#fef2f2', lw=2.0, r=0.06, zorder=3)
    ax.text(13.4, Y_TOPO + 0.48, 'Database', ha='center', va='center', fontsize=10.5, fontweight='bold', color='#dc2626', zorder=4)
    ax.text(13.4, Y_TOPO + 0.20, 'Internal Target Asset', ha='center', va='center', fontsize=7.8, color='#991b1b', zorder=4)

    # 2. TEMPORAL LIFESPAN STRIP ACROSS W0, W1, W2
    W_COL = 4.65
    X_COLS = [0.65, 5.42, 10.20]
    Y_STRIP = Y_T1 + 0.28
    H_STRIP = 1.65

    # Column W0: Week 1
    draw_rounded_card(ax, X_COLS[0], Y_STRIP, W_COL, H_STRIP, COL_W0_BORDER, COL_W0_BG, lw=1.4, r=0.06)
    ax.text(X_COLS[0] + W_COL/2, Y_STRIP + H_STRIP - 0.24, r'$\mathbf{W_0}$ : Week 1 — Initial Compromise',
            ha='center', va='center', fontsize=9.2, fontweight='bold', color=COL_W0_HDR)
    draw_badge(ax, X_COLS[0] + W_COL/2, Y_STRIP + 1.05, 'Edge e₁ (CVE) : ACTIVE / OPEN', '#0284c7', fs=7.5)
    ax.text(X_COLS[0] + W_COL/2, Y_STRIP + 0.62, '• Attacker exploits Web Server via CVE-2021-44228\n• Exploit logged to server disk upon execution',
            ha='center', va='center', fontsize=7.6, color=TEXT_DARK, linespacing=1.3)
    ax.text(X_COLS[0] + W_COL/2, Y_STRIP + 0.20, 'Vulnerability Window Open', ha='center', va='center',
            fontsize=7.2, color=COL_W0_HDR, style='italic')

    # Column W1: Week 2
    draw_rounded_card(ax, X_COLS[1], Y_STRIP, W_COL, H_STRIP, COL_W1_BORDER, COL_W1_BG, lw=1.4, r=0.06)
    ax.text(X_COLS[1] + W_COL/2, Y_STRIP + H_STRIP - 0.24, r'$\mathbf{W_1}$ : Week 2 — Patch & Anti-Forensics',
            ha='center', va='center', fontsize=9.2, fontweight='bold', color=COL_W1_HDR)
    draw_badge(ax, X_COLS[1] + W_COL/2, Y_STRIP + 1.05, 'Edge e₁ (CVE) : PATCHED / CLOSED', '#64748b', fs=7.5)
    ax.text(X_COLS[1] + W_COL/2, Y_STRIP + 0.62, '• Security admins deploy patch: CVE edge removed\n• Attacker wipes intermediate ingress logs',
            ha='center', va='center', fontsize=7.6, color=TEXT_DARK, linespacing=1.3)
    ax.text(X_COLS[1] + W_COL/2, Y_STRIP + 0.20, 'Ingress Log Destroyed', ha='center', va='center',
            fontsize=7.2, color='#b91c1c', style='italic')

    # Column W2: Week 3
    draw_rounded_card(ax, X_COLS[2], Y_STRIP, W_COL, H_STRIP, COL_W2_BORDER, COL_W2_BG, lw=1.4, r=0.06)
    ax.text(X_COLS[2] + W_COL/2, Y_STRIP + H_STRIP - 0.24, r'$\mathbf{W_2}$ : Week 3 — Detection & Response',
            ha='center', va='center', fontsize=9.2, fontweight='bold', color=COL_W2_HDR)
    draw_badge(ax, X_COLS[2] + W_COL/2, Y_STRIP + 1.05, 'Edge e₂ (Pivot) : ALERT TRIGGERED', '#dc2626', fs=7.5)
    ax.text(X_COLS[2] + W_COL/2, Y_STRIP + 0.62, '• Attacker pivots from Web Server to Database\n• IDS alert fires — Investigator begins triage',
            ha='center', va='center', fontsize=7.6, color=TEXT_DARK, linespacing=1.3)
    ax.text(X_COLS[2] + W_COL/2, Y_STRIP + 0.20, 'Investigator\'s Only Observation', ha='center', va='center',
            fontsize=7.2, color='#b91c1c', style='italic')

    # Time arrows connecting columns
    draw_arrow(ax, X_COLS[0] + W_COL + 0.02, Y_STRIP + H_STRIP - 0.24, X_COLS[1] - 0.02, Y_STRIP + H_STRIP - 0.24, TEXT_LIGHT, lw=2.0)
    draw_arrow(ax, X_COLS[1] + W_COL + 0.02, Y_STRIP + H_STRIP - 0.24, X_COLS[2] - 0.02, Y_STRIP + H_STRIP - 0.24, TEXT_LIGHT, lw=2.0)


    # ══════════════════════════════════════════════════════════════════════════
    #  TIER 2: THREE FORENSIC PARADIGMS COMPARED (Y: 0.35 to 4.78)
    # ══════════════════════════════════════════════════════════════════════════
    Y_T2 = 0.35
    H_T2 = 4.43
    W_CARD = 4.65
    X_CARDS = [0.65, 5.42, 10.20]

    # ──────────────────────────────────────────────────────────────────────────
    #  CARD (a): Evidence Graph (Log-Driven)
    # ──────────────────────────────────────────────────────────────────────────
    draw_rounded_card(ax, X_CARDS[0], Y_T2, W_CARD, H_T2, RED_BORDER, '#ffffff', lw=1.6, r=0.08)
    
    # Header Banner
    draw_rounded_card(ax, X_CARDS[0], Y_T2 + H_T2 - 0.70, W_CARD, 0.70, RED_BORDER, RED_BG, lw=1.4, r=0.06)
    ax.text(X_CARDS[0] + W_CARD/2, Y_T2 + H_T2 - 0.26, '(a) Evidence Graph',
            ha='center', va='center', fontsize=11.0, fontweight='bold', color=RED_TEXT)
    ax.text(X_CARDS[0] + W_CARD/2, Y_T2 + H_T2 - 0.50, 'Reactive Log-Chaining Correlation',
            ha='center', va='center', fontsize=7.8, color=RED_TEXT, style='italic')

    # Step 1: Alert at W2
    draw_rounded_card(ax, X_CARDS[0] + 0.35, Y_T2 + 2.78, 3.95, 0.56, '#dc2626', '#fef2f2', lw=1.5)
    ax.text(X_CARDS[0] + 2.32, Y_T2 + 3.06, '1. Alert Observed on Database (W2)',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color='#dc2626')

    # Step 2: Backward trace arrow
    draw_arrow(ax, X_CARDS[0] + W_CARD/2, Y_T2 + 2.74, X_CARDS[0] + W_CARD/2, Y_T2 + 2.30, '#ef4444', lw=2.0, ls='--')
    ax.text(X_CARDS[0] + W_CARD/2, Y_T2 + 2.52, 'Traces backward along log records...', ha='center', va='center',
            fontsize=7.5, color=RED_TEXT, style='italic')

    # Step 3: Web Server log missing!
    draw_rounded_card(ax, X_CARDS[0] + 0.35, Y_T2 + 1.66, 3.95, 0.60, '#f87171', '#fff1f2', lw=1.5)
    ax.text(X_CARDS[0] + W_CARD/2, Y_T2 + 2.01, '2. Web Server Ingress Log: WIPED',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color='#b91c1c')
    ax.text(X_CARDS[0] + W_CARD/2, Y_T2 + 1.78, 'Evidence chain broken — no record of prior ingress',
            ha='center', va='center', fontsize=7.2, color='#7f1d1d')

    # Step 4: Dead end summary
    ax.text(X_CARDS[0] + W_CARD/2, Y_T2 + 1.22, '✕  Investigation Stalls at W1', ha='center', va='center',
            fontsize=9.0, fontweight='bold', color=RED_PRIMARY)
    ax.text(X_CARDS[0] + W_CARD/2, Y_T2 + 0.92, 'Cannot identify initial ingress or time of compromise.\nAttacker entry in W0 remains completely hidden.',
            ha='center', va='center', fontsize=7.5, color=TEXT_MUTED, linespacing=1.25)

    # Verdict Badge at bottom
    draw_badge(ax, X_CARDS[0] + W_CARD/2, Y_T2 + 0.35, '✕  DEAD END : NO ATTACK PATH RECOVERED', RED_PRIMARY, fs=8.0)


    # ──────────────────────────────────────────────────────────────────────────
    #  CARD (b): Static Attack Graph (Timeless)
    # ──────────────────────────────────────────────────────────────────────────
    draw_rounded_card(ax, X_CARDS[1], Y_T2, W_CARD, H_T2, AMBER_BORDER, '#ffffff', lw=1.6, r=0.08)

    # Header Banner
    draw_rounded_card(ax, X_CARDS[1], Y_T2 + H_T2 - 0.70, W_CARD, 0.70, AMBER_BORDER, AMBER_BG, lw=1.4, r=0.06)
    ax.text(X_CARDS[1] + W_CARD/2, Y_T2 + H_T2 - 0.26, '(b) Static Attack Graph',
            ha='center', va='center', fontsize=11.0, fontweight='bold', color=AMBER_TEXT)
    ax.text(X_CARDS[1] + W_CARD/2, Y_T2 + H_T2 - 0.50, 'Timeless Topological Reachability',
            ha='center', va='center', fontsize=7.8, color=AMBER_TEXT, style='italic')

    # Step 1: Matches Static Graph
    draw_rounded_card(ax, X_CARDS[1] + 0.35, Y_T2 + 2.78, 3.95, 0.56, AMBER_PRIMARY, '#fffbeb', lw=1.5)
    ax.text(X_CARDS[1] + W_CARD/2, Y_T2 + 3.06, '1. Alert on Database Matches Static Graph',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color=AMBER_TEXT)

    # Step 2: Correlates static path
    draw_arrow(ax, X_CARDS[1] + W_CARD/2, Y_T2 + 2.74, X_CARDS[1] + W_CARD/2, Y_T2 + 2.30, AMBER_PRIMARY, lw=2.0)
    ax.text(X_CARDS[1] + W_CARD/2, Y_T2 + 2.52, 'Correlates topological reachability...', ha='center', va='center',
            fontsize=7.5, color=AMBER_TEXT, style='italic')

    # Step 3: Accepts impossible path
    draw_rounded_card(ax, X_CARDS[1] + 0.35, Y_T2 + 1.66, 3.95, 0.60, '#f59e0b', '#fef3c7', lw=1.5)
    ax.text(X_CARDS[1] + W_CARD/2, Y_T2 + 2.01, '2. Accepts Path: Attacker → Web → DB',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color=AMBER_TEXT)
    ax.text(X_CARDS[1] + W_CARD/2, Y_T2 + 1.78, 'Attributes entire breach to W2 detection window',
            ha='center', va='center', fontsize=7.2, color='#78350f')

    # Step 4: Contradiction / Impossible path
    ax.text(X_CARDS[1] + W_CARD/2, Y_T2 + 1.22, '⚠  IMPOSSIBLE : e₁ Patched in W1!', ha='center', va='center',
            fontsize=8.8, fontweight='bold', color='#b45309')
    ax.text(X_CARDS[1] + W_CARD/2, Y_T2 + 0.92, 'Blind to patch history; accepts closed exploit edge.\nAnalyst chases false causal lead on patched service.',
            ha='center', va='center', fontsize=7.5, color=TEXT_MUTED, linespacing=1.25)

    # Verdict Badge at bottom
    draw_badge(ax, X_CARDS[1] + W_CARD/2, Y_T2 + 0.35, '⚠  PHANTOM PATH : BLIND TO TEMPORAL PATCH', AMBER_PRIMARY, fs=8.0)


    # ──────────────────────────────────────────────────────────────────────────
    #  CARD (c): F-TAG (Forensic Temporal Attack Graph - Proposed)
    #  *** HERO CARD: Visual Payoff, Elevated Styling, Emerald Theme ***
    # ──────────────────────────────────────────────────────────────────────────
    draw_rounded_card(ax, X_CARDS[2], Y_T2, W_CARD, H_T2, GREEN_PRIMARY, '#ffffff', lw=2.4, r=0.08)

    # Header Banner (Hero gradient/fill)
    draw_rounded_card(ax, X_CARDS[2], Y_T2 + H_T2 - 0.70, W_CARD, 0.70, GREEN_PRIMARY, GREEN_BG, lw=2.0, r=0.06)
    ax.text(X_CARDS[2] + W_CARD/2, Y_T2 + H_T2 - 0.26, '(c) F-TAG (Proposed)',
            ha='center', va='center', fontsize=11.5, fontweight='bold', color=GREEN_HERO)
    ax.text(X_CARDS[2] + W_CARD/2, Y_T2 + H_T2 - 0.50, 'Temporal Topology & Window Bounding (FWoC)',
            ha='center', va='center', fontsize=7.8, color=GREEN_TEXT, style='italic')

    # Step 1: Detects structural contradiction at W2
    draw_rounded_card(ax, X_CARDS[2] + 0.35, Y_T2 + 2.78, 3.95, 0.56, '#fca5a5', '#fef2f2', lw=1.5)
    ax.text(X_CARDS[2] + W_CARD/2, Y_T2 + 3.06, r'1. Path at $W_2$ : $\mathbf{FWoC = \emptyset}$ (Edge Closed)',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color='#dc2626')
    ax.text(X_CARDS[2] + W_CARD/2, Y_T2 + 2.86, 'Rejects W2 entry: e₁ did not exist during W2!',
            ha='center', va='center', fontsize=7.2, color='#991b1b')

    # Step 2: Resolves contradiction backward
    draw_arrow(ax, X_CARDS[2] + W_CARD/2, Y_T2 + 2.74, X_CARDS[2] + W_CARD/2, Y_T2 + 2.30, GREEN_PRIMARY, lw=2.2)
    ax.text(X_CARDS[2] + W_CARD/2, Y_T2 + 2.52, 'Queries temporal topology backward...', ha='center', va='center',
            fontsize=7.5, fontweight='bold', color=GREEN_HERO)

    # Step 3: Conclusively bounds to [W0, W1]
    draw_rounded_card(ax, X_CARDS[2] + 0.30, Y_T2 + 1.40, 4.05, 0.86, GREEN_PRIMARY, '#dcfce7', lw=1.8, r=0.06)
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 2.02, r'2. Validates Historical Ingress at $W_0$',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color=GREEN_HERO)
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 1.74, r'$\mathbf{Forensic\;Window\;of\;Compromise\;:\;[W_0,\;W_1]}$',
            ha='center', va='center', fontsize=9.2, fontweight='bold', color=GREEN_TEXT)
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 1.50, 'Topology proves origin at W0 despite wiped logs!',
            ha='center', va='center', fontsize=7.2, color=GREEN_TEXT)

    # Step 4: Payoff description
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 1.15, '✓ Rigorous Temporal Reconstruction', ha='center', va='center',
            fontsize=8.8, fontweight='bold', color=GREEN_HERO)
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 0.88, 'Topological lifespan constraints bound the exact breach\nwindow even when anti-forensic log wiping occurs.',
            ha='center', va='center', fontsize=7.5, color=TEXT_MUTED, linespacing=1.25)

    # Hero Verdict Badge at bottom
    draw_badge(ax, X_CARDS[2] + W_CARD/2, Y_T2 + 0.35, '✓  BREACH BOUNDED : FWoC = [W₀, W₁]', GREEN_PRIMARY, fs=8.5)

    plt.savefig(output_path, dpi=300, facecolor=BG_COLOR, edgecolor='none', bbox_inches='tight')
    plt.close()
    print(f'Successfully generated: {output_path}')

if __name__ == '__main__':
    out_fig = '/Users/ayangain/repos/TAG-Forensics/Figures/fig_motivating_example.png'
    out_art = '/Users/ayangain/.gemini/antigravity-ide/brain/d2d2fde4-787e-4784-a709-66d623e97758/fig_motivating_example.png'
    out_preview = '/Users/ayangain/.gemini/antigravity-ide/brain/d2d2fde4-787e-4784-a709-66d623e97758/motivating_example_v7.png'
    generate_figure(out_fig)
    import shutil
    shutil.copyfile(out_fig, out_art)
    shutil.copyfile(out_fig, out_preview)
    print(f'Saved to {out_fig} and artifacts.')
