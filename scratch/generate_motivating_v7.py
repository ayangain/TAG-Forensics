"""
Masterpiece generator for Figure 1: Motivating Example
Layout Style 1: Consolidated Two-Tier Architecture
Tier 1: Ground Truth Incident Timeline (W0 -> W1 -> W2)
Tier 2: Three Forensic Paradigms Compared Side-by-Side:
        (a) Evidence Graph (Red: Dead End)
        (b) Static Attack Graph (Amber: Phantom Path)
        (c) F-TAG [Proposed] (Emerald: Breach Bounded - Hero Card)
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle
import numpy as np

# ── Color Palette ─────────────────────────────────────────────────────────────
BG_COLOR       = '#ffffff'
CARD_BG        = '#f8fafc'
BORDER_MUTED   = '#cbd5e1'
TEXT_DARK      = '#0f172a'
TEXT_MUTED     = '#475569'
TEXT_LIGHT     = '#64748b'

# Time Progression (Neutral cool slate / blue-grey tones)
COL_W0_BG      = '#eff6ff'
COL_W0_BORDER  = '#93c5fd'
COL_W0_HDR     = '#0369a1'

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
GREEN_BORDER   = '#4ade80'
GREEN_PRIMARY  = '#16a34a'
GREEN_HERO     = '#15803d'
GREEN_TEXT     = '#14532d'

FONT = 'sans-serif'

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

    # Subtitle / Header (No "Figure 1:" prefix to avoid caption redundancy)
    ax.text(7.75, 9.50, 'Motivating Scenario: The Necessity of Temporal Topology in Forensic Reconstruction',
            ha='center', va='center', fontsize=13.0, fontweight='bold', color=TEXT_DARK)
    ax.text(7.75, 9.22, 'Incident: Attacker breaches Web Server in W₀; patch applied and logs wiped in W₁; pivot triggers IDS alert on Database in W₂.',
            ha='center', va='center', fontsize=9.2, color=TEXT_MUTED, style='italic')

    # ══════════════════════════════════════════════════════════════════════════
    #  TIER 1: GROUND TRUTH INCIDENT TIMELINE (Y: 5.15 to 9.00)
    # ══════════════════════════════════════════════════════════════════════════
    Y_T1 = 5.15
    H_T1 = 3.85
    draw_rounded_card(ax, 0.4, Y_T1, 14.7, H_T1, BORDER_MUTED, '#ffffff', lw=1.6, r=0.08)

    # Tier 1 Label / Banner
    draw_badge(ax, 1.8, Y_T1 + H_T1 - 0.22, 'GROUND TRUTH INCIDENT TIMELINE', '#334155', fs=8.5)
    ax.text(14.8, Y_T1 + H_T1 - 0.22, 'Physical Reality across Dynamic Windows', ha='right', va='center',
            fontsize=8.5, color=TEXT_MUTED, style='italic')

    # Three Timeline Columns
    W_COL = 4.65
    X_COLS = [0.65, 5.42, 10.20]
    
    # 1. Timeline Column Headers
    Y_HDR = Y_T1 + 3.00
    H_HDR = 0.48
    
    # W0 Header
    draw_rounded_card(ax, X_COLS[0], Y_HDR, W_COL, H_HDR, COL_W0_BORDER, COL_W0_BG, lw=1.4, r=0.05)
    ax.text(X_COLS[0] + W_COL/2, Y_HDR + H_HDR*0.62, r'$\mathbf{W_0}$ : Week 1 — Initial Compromise',
            ha='center', va='center', fontsize=9.5, fontweight='bold', color=COL_W0_HDR)
    ax.text(X_COLS[0] + W_COL/2, Y_HDR + H_HDR*0.22, 'CVE Exploit Active • Ingress Log Created',
            ha='center', va='center', fontsize=7.5, color=TEXT_MUTED)

    # W1 Header
    draw_rounded_card(ax, X_COLS[1], Y_HDR, W_COL, H_HDR, COL_W1_BORDER, COL_W1_BG, lw=1.4, r=0.05)
    ax.text(X_COLS[1] + W_COL/2, Y_HDR + H_HDR*0.62, r'$\mathbf{W_1}$ : Week 2 — Patch & Anti-Forensics',
            ha='center', va='center', fontsize=9.5, fontweight='bold', color=COL_W1_HDR)
    ax.text(X_COLS[1] + W_COL/2, Y_HDR + H_HDR*0.22, 'Patch Applied (Edge Closes) • Ingress Log Deleted',
            ha='center', va='center', fontsize=7.5, color=TEXT_MUTED)

    # W2 Header
    draw_rounded_card(ax, X_COLS[2], Y_HDR, W_COL, H_HDR, COL_W2_BORDER, COL_W2_BG, lw=1.4, r=0.05)
    ax.text(X_COLS[2] + W_COL/2, Y_HDR + H_HDR*0.62, r'$\mathbf{W_2}$ : Week 3 — Detection & Investigation',
            ha='center', va='center', fontsize=9.5, fontweight='bold', color=COL_W2_HDR)
    ax.text(X_COLS[2] + W_COL/2, Y_HDR + H_HDR*0.22, 'Lateral Pivot to DB • IDS Alert Fired',
            ha='center', va='center', fontsize=7.5, color=TEXT_MUTED)

    # Time arrows between headers
    draw_arrow(ax, X_COLS[0] + W_COL + 0.03, Y_HDR + H_HDR/2, X_COLS[1] - 0.03, Y_HDR + H_HDR/2, TEXT_LIGHT, lw=2.0)
    draw_arrow(ax, X_COLS[1] + W_COL + 0.03, Y_HDR + H_HDR/2, X_COLS[2] - 0.03, Y_HDR + H_HDR/2, TEXT_LIGHT, lw=2.0)

    # 2. Network Events across W0, W1, W2
    Y_EVENT = Y_T1 + 1.65

    # --- W0 Event Details ---
    # Attacker -> Web Server
    draw_rounded_card(ax, X_COLS[0] + 0.35, Y_EVENT + 0.35, 1.4, 0.52, COL_W0_HDR, '#ffffff', lw=1.5, zorder=3)
    ax.text(X_COLS[0] + 1.05, Y_EVENT + 0.61, 'Attacker', ha='center', va='center', fontsize=9.0, fontweight='bold', color=COL_W0_HDR, zorder=4)

    draw_arrow(ax, X_COLS[0] + 1.8, Y_EVENT + 0.61, X_COLS[0] + 2.65, Y_EVENT + 0.61, COL_W0_HDR, lw=2.2)
    ax.text(X_COLS[0] + 2.22, Y_EVENT + 0.88, 'CVE Exploit', ha='center', va='center', fontsize=8.0, fontweight='bold', color=COL_W0_HDR)

    draw_rounded_card(ax, X_COLS[0] + 2.7, Y_EVENT + 0.35, 1.5, 0.52, COL_W0_HDR, '#ffffff', lw=1.5, zorder=3)
    ax.text(X_COLS[0] + 3.45, Y_EVENT + 0.61, 'Web Server', ha='center', va='center', fontsize=9.0, fontweight='bold', color=COL_W0_HDR, zorder=4)

    draw_badge(ax, X_COLS[0] + 3.45, Y_EVENT + 0.05, 'Log Written: CVE Executed', '#0284c7', fs=7.2)

    # --- W1 Event Details ---
    # Patch applied, Log wiped
    draw_rounded_card(ax, X_COLS[1] + 1.45, Y_EVENT + 0.35, 1.7, 0.52, '#64748b', '#ffffff', lw=1.5, zorder=3)
    ax.text(X_COLS[1] + 2.30, Y_EVENT + 0.61, 'Web Server', ha='center', va='center', fontsize=9.0, fontweight='bold', color='#334155', zorder=4)

    draw_badge(ax, X_COLS[1] + 2.30, Y_EVENT + 1.05, '[PATCHED] CVE Edge Removed', '#475569', fs=7.2)
    draw_badge(ax, X_COLS[1] + 2.30, Y_EVENT + 0.05, 'ANTI-FORENSICS: Log Wiped', '#dc2626', fs=7.2)

    # --- W2 Event Details ---
    # Web Server -> Database (Alert)
    draw_rounded_card(ax, X_COLS[2] + 0.35, Y_EVENT + 0.35, 1.5, 0.52, '#64748b', '#ffffff', lw=1.5, zorder=3)
    ax.text(X_COLS[2] + 1.10, Y_EVENT + 0.61, 'Web Server', ha='center', va='center', fontsize=9.0, fontweight='bold', color='#334155', zorder=4)

    draw_arrow(ax, X_COLS[2] + 1.9, Y_EVENT + 0.61, X_COLS[2] + 2.65, Y_EVENT + 0.61, '#0f172a', lw=2.2)
    ax.text(X_COLS[2] + 2.27, Y_EVENT + 0.88, 'Lateral Pivot', ha='center', va='center', fontsize=8.0, fontweight='bold', color=TEXT_DARK)

    draw_rounded_card(ax, X_COLS[2] + 2.7, Y_EVENT + 0.35, 1.5, 0.52, '#dc2626', '#fef2f2', lw=2.0, zorder=3)
    ax.text(X_COLS[2] + 3.45, Y_EVENT + 0.61, 'Database', ha='center', va='center', fontsize=9.0, fontweight='bold', color='#dc2626', zorder=4)

    draw_badge(ax, X_COLS[2] + 3.45, Y_EVENT + 0.05, '[ALERT] IDS Detected Pivot', '#dc2626', fs=7.2)

    # 3. CVE Vulnerability Lifecycle Ribbon across bottom of Tier 1
    Y_RIBBON = Y_T1 + 0.32
    H_RIBBON = 0.52

    # Active in W0
    draw_rounded_card(ax, X_COLS[0] + 0.15, Y_RIBBON, W_COL - 0.3, H_RIBBON, '#0284c7', '#dbeafe', lw=1.4, r=0.05)
    ax.text(X_COLS[0] + W_COL/2, Y_RIBBON + H_RIBBON*0.62, 'CVE Exploit Edge: ACTIVE / OPEN',
            ha='center', va='center', fontsize=8.2, fontweight='bold', color='#0369a1')
    ax.text(X_COLS[0] + W_COL/2, Y_RIBBON + H_RIBBON*0.24, 'Attacker successfully exploits DMZ entry point',
            ha='center', va='center', fontsize=7.2, color=TEXT_MUTED)

    # Inactive / Patched across W1 and W2
    W_CLOSED = (W_COL * 2) + (X_COLS[1] - (X_COLS[0] + W_COL)) - 0.3
    draw_rounded_card(ax, X_COLS[1] + 0.15, Y_RIBBON, W_CLOSED, H_RIBBON, '#94a3b8', '#f1f5f9', lw=1.4, r=0.05, ls='--')
    ax.text(X_COLS[1] + W_COL, Y_RIBBON + H_RIBBON*0.62, '[CLOSED] CVE Patched at W1 — Exploit Edge Permanently Non-Existent in W1 and W2',
            ha='center', va='center', fontsize=8.2, fontweight='bold', color='#475569')
    ax.text(X_COLS[1] + W_COL, Y_RIBBON + H_RIBBON*0.24, 'Any forensic path requiring this CVE edge during W1 or W2 is structurally impossible',
            ha='center', va='center', fontsize=7.2, color=TEXT_MUTED, style='italic')


    # ══════════════════════════════════════════════════════════════════════════
    #  TIER 2: THREE FORENSIC PARADIGMS COMPARED (Y: 0.35 to 4.90)
    # ══════════════════════════════════════════════════════════════════════════
    Y_T2 = 0.35
    H_T2 = 4.55
    W_CARD = 4.65
    X_CARDS = [0.65, 5.42, 10.20]

    # ──────────────────────────────────────────────────────────────────────────
    #  CARD (a): Evidence Graph (Log-Driven)
    # ──────────────────────────────────────────────────────────────────────────
    draw_rounded_card(ax, X_CARDS[0], Y_T2, W_CARD, H_T2, RED_BORDER, '#ffffff', lw=1.6, r=0.08)
    
    # Header Banner
    draw_rounded_card(ax, X_CARDS[0], Y_T2 + H_T2 - 0.72, W_CARD, 0.72, RED_BORDER, RED_BG, lw=1.4, r=0.06)
    ax.text(X_CARDS[0] + W_CARD/2, Y_T2 + H_T2 - 0.28, '(a) Evidence Graph',
            ha='center', va='center', fontsize=11.0, fontweight='bold', color=RED_TEXT)
    ax.text(X_CARDS[0] + W_CARD/2, Y_T2 + H_T2 - 0.52, 'Log-Driven Correlation (Reactive)',
            ha='center', va='center', fontsize=8.0, color=RED_TEXT, style='italic')

    # Mechanism illustration inside Card (a)
    # Step 1: Alert at W2
    draw_rounded_card(ax, X_CARDS[0] + 0.4, Y_T2 + 2.85, 3.85, 0.58, '#dc2626', '#fef2f2', lw=1.5)
    ax.text(X_CARDS[0] + 2.32, Y_T2 + 3.14, '1. Alert Observed on Database (W2)',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color='#dc2626')

    # Step 2: Backward trace arrow
    draw_arrow(ax, X_CARDS[0] + 2.32, Y_T2 + 2.82, X_CARDS[0] + 2.32, Y_T2 + 2.35, '#ef4444', lw=2.0, ls='--')
    ax.text(X_CARDS[0] + 2.45, Y_T2 + 2.58, ' Traces backward to Web Server...', ha='left', va='center',
            fontsize=7.5, color=RED_TEXT, style='italic')

    # Step 3: Web Server log missing!
    draw_rounded_card(ax, X_CARDS[0] + 0.4, Y_T2 + 1.70, 3.85, 0.60, '#f87171', '#fff1f2', lw=1.5)
    ax.text(X_CARDS[0] + 2.32, Y_T2 + 2.05, '2. Web Server Logs: WIPED / MISSING',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color='#b91c1c')
    ax.text(X_CARDS[0] + 2.32, Y_T2 + 1.82, 'Evidence chain broken — no prior connection logged',
            ha='center', va='center', fontsize=7.2, color='#7f1d1d')

    # Step 4: Dead end
    ax.text(X_CARDS[0] + 2.32, Y_T2 + 1.25, '[✕]  Investigation Stalls at W1', ha='center', va='center',
            fontsize=9.0, fontweight='bold', color=RED_PRIMARY)
    ax.text(X_CARDS[0] + 2.32, Y_T2 + 0.95, 'Cannot identify initial ingress or time of compromise.\nAttacker entry in W0 remains invisible.',
            ha='center', va='center', fontsize=7.5, color=TEXT_MUTED, linespacing=1.2)

    # Verdict Badge at bottom
    draw_badge(ax, X_CARDS[0] + W_CARD/2, Y_T2 + 0.35, '✕  DEAD END : NO ATTACK PATH RECOVERED', RED_PRIMARY, fs=8.0)


    # ──────────────────────────────────────────────────────────────────────────
    #  CARD (b): Static Attack Graph (Timeless)
    # ──────────────────────────────────────────────────────────────────────────
    draw_rounded_card(ax, X_CARDS[1], Y_T2, W_CARD, H_T2, AMBER_BORDER, '#ffffff', lw=1.6, r=0.08)

    # Header Banner
    draw_rounded_card(ax, X_CARDS[1], Y_T2 + H_T2 - 0.72, W_CARD, 0.72, AMBER_BORDER, AMBER_BG, lw=1.4, r=0.06)
    ax.text(X_CARDS[1] + W_CARD/2, Y_T2 + H_T2 - 0.28, '(b) Static Attack Graph',
            ha='center', va='center', fontsize=11.0, fontweight='bold', color=AMBER_TEXT)
    ax.text(X_CARDS[1] + W_CARD/2, Y_T2 + H_T2 - 0.52, 'Timeless Topology (No Notion of Time)',
            ha='center', va='center', fontsize=8.0, color=AMBER_TEXT, style='italic')

    # Mechanism illustration inside Card (b)
    # Step 1: Receives Alert
    draw_rounded_card(ax, X_CARDS[1] + 0.4, Y_T2 + 2.85, 3.85, 0.58, AMBER_PRIMARY, '#fffbeb', lw=1.5)
    ax.text(X_CARDS[1] + 2.32, Y_T2 + 3.14, '1. Alert on Database Matches Static Graph',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color=AMBER_TEXT)

    # Step 2: Correlates static path
    draw_arrow(ax, X_CARDS[1] + 2.32, Y_T2 + 2.82, X_CARDS[1] + 2.32, Y_T2 + 2.35, AMBER_PRIMARY, lw=2.0)
    ax.text(X_CARDS[1] + 2.45, Y_T2 + 2.58, ' Correlates topological reachability...', ha='left', va='center',
            fontsize=7.5, color=AMBER_TEXT, style='italic')

    # Step 3: Reconstructs path via patched edge!
    draw_rounded_card(ax, X_CARDS[1] + 0.4, Y_T2 + 1.70, 3.85, 0.60, '#f59e0b', '#fef3c7', lw=1.5)
    ax.text(X_CARDS[1] + 2.32, Y_T2 + 2.05, '2. Accepts Path: Attacker → Web → DB',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color=AMBER_TEXT)
    ax.text(X_CARDS[1] + 2.32, Y_T2 + 1.82, 'Attributes entire breach to W2 detection window',
            ha='center', va='center', fontsize=7.2, color='#78350f')

    # Step 4: Contradiction / Impossible path
    ax.text(X_CARDS[1] + 2.32, Y_T2 + 1.25, '[⚠]  IMPOSSIBLE : CVE Patched at W1!', ha='center', va='center',
            fontsize=8.8, fontweight='bold', color='#b45309')
    ax.text(X_CARDS[1] + 2.32, Y_T2 + 0.95, 'Blind to patch history; accepts closed exploit edge.\nAnalyst chases phantom lead on patched service.',
            ha='center', va='center', fontsize=7.5, color=TEXT_MUTED, linespacing=1.2)

    # Verdict Badge at bottom
    draw_badge(ax, X_CARDS[1] + W_CARD/2, Y_T2 + 0.35, '⚠  PHANTOM PATH : BLIND TO TEMPORAL PATCH', AMBER_PRIMARY, fs=8.0)


    # ──────────────────────────────────────────────────────────────────────────
    #  CARD (c): F-TAG (Forensic Temporal Attack Graph - Proposed)
    #  *** HERO CARD: Visual Payoff, Elevated Styling, Emerald Theme ***
    # ──────────────────────────────────────────────────────────────────────────
    draw_rounded_card(ax, X_CARDS[2], Y_T2, W_CARD, H_T2, GREEN_PRIMARY, '#ffffff', lw=2.4, r=0.08)

    # Header Banner (Hero gradient/fill)
    draw_rounded_card(ax, X_CARDS[2], Y_T2 + H_T2 - 0.72, W_CARD, 0.72, GREEN_PRIMARY, GREEN_BG, lw=2.0, r=0.06)
    ax.text(X_CARDS[2] + W_CARD/2, Y_T2 + H_T2 - 0.28, '(c) F-TAG (Proposed)',
            ha='center', va='center', fontsize=11.5, fontweight='bold', color=GREEN_HERO)
    ax.text(X_CARDS[2] + W_CARD/2, Y_T2 + H_T2 - 0.52, 'Temporal Topology & Window Bounding (FWoC)',
            ha='center', va='center', fontsize=8.0, color=GREEN_TEXT, style='italic')

    # Mechanism illustration inside Card (c)
    # Step 1: Detects structural contradiction at W2
    draw_rounded_card(ax, X_CARDS[2] + 0.4, Y_T2 + 2.85, 3.85, 0.58, '#fca5a5', '#fef2f2', lw=1.5)
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 3.14, r'1. Path at $W_2$ : $\mathbf{FWoC = \emptyset}$ (Edge Closed)',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color='#dc2626')
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 2.92, 'Rejects W2 entry: CVE edge did not exist during W2!',
            ha='center', va='center', fontsize=7.2, color='#991b1b')

    # Step 2: Resolves contradiction backward
    draw_arrow(ax, X_CARDS[2] + 2.32, Y_T2 + 2.82, X_CARDS[2] + 2.32, Y_T2 + 2.35, GREEN_PRIMARY, lw=2.2)
    ax.text(X_CARDS[2] + 2.45, Y_T2 + 2.58, ' Queries temporal topology backward...', ha='left', va='center',
            fontsize=7.5, fontweight='bold', color=GREEN_HERO)

    # Step 3: Conclusively bounds to [W0, W1]
    draw_rounded_card(ax, X_CARDS[2] + 0.35, Y_T2 + 1.45, 3.95, 0.85, GREEN_PRIMARY, '#dcfce7', lw=1.8, r=0.06)
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 2.05, r'2. Validates Historical Ingress at $W_0$',
            ha='center', va='center', fontsize=8.5, fontweight='bold', color=GREEN_HERO)
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 1.78, r'$\mathbf{Forensic\;Window\;of\;Compromise\;:\;[W_0,\;W_1]}$',
            ha='center', va='center', fontsize=9.2, fontweight='bold', color=GREEN_TEXT)
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 1.55, 'Topology proves origin at W0 despite wiped logs!',
            ha='center', va='center', fontsize=7.2, color=GREEN_TEXT)

    # Step 4: Payoff description
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 1.15, '✓ Rigorous Temporal Reconstruction', ha='center', va='center',
            fontsize=8.8, fontweight='bold', color=GREEN_HERO)
    ax.text(X_CARDS[2] + 2.32, Y_T2 + 0.88, 'Topological lifespan constraints bound the exact breach\nwindow even when anti-forensic log wiping occurs.',
            ha='center', va='center', fontsize=7.5, color=TEXT_MUTED, linespacing=1.2)

    # Hero Verdict Badge at bottom
    draw_badge(ax, X_CARDS[2] + W_CARD/2, Y_T2 + 0.35, '✓  BREACH BOUNDED : FWoC = [W₀, W₁]', GREEN_PRIMARY, fs=8.5)

    plt.savefig(output_path, dpi=300, facecolor=BG_COLOR, edgecolor='none', bbox_inches='tight')
    plt.close()
    print(f'Successfully generated: {output_path}')

if __name__ == '__main__':
    generate_figure('/Users/ayangain/repos/TAG-Forensics/scratch/motivating_example_v5.png')
