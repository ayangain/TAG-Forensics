import matplotlib.pyplot as plt
import matplotlib.patches as patches

# Setup figure and subplots
fig, axes = plt.subplots(3, 1, figsize=(10, 8), sharex=True)
plt.subplots_adjust(hspace=0.4)

methods = [
    ("Evidence Graph", "Stalls when intermediate logs are missing", "red"),
    ("Static Attack Graph", "Accepts path: Attacker -> Web -> DB at W2", "orange"),
    ("F-TAG", "FWoC = ∅ → Structural contradiction detected", "green")
]

nodes = ["Attacker", "Web Server", "Database"]
y_pos = [2, 1, 0]

for ax, (title, subtitle, color) in zip(axes, methods):
    ax.set_ylim(-0.5, 2.5)
    ax.set_xlim(-0.5, 2.5)
    
    # Hide spines and ticks
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(nodes, fontsize=12, fontweight='bold')
    
    ax.set_xticks([0, 1, 2])
    ax.set_xticklabels(["W0\n(Vulnerable)", "W1\n(Patched)", "W2\n(Alert Fired)"], fontsize=12)
    
    # Draw timeline gradient/background (blue-to-grey gradient concept)
    # W0 is blueish (active), W1 and W2 are greyish
    ax.axvspan(-0.5, 0.5, color='#e6f2ff', alpha=0.5, zorder=0)
    ax.axvspan(0.5, 2.5, color='#f2f2f2', alpha=0.5, zorder=0)
    
    # Draw vulnerability window (Web -> DB)
    # Active only in W0
    rect = patches.Rectangle((-0.4, 0.2), 0.8, 1.6, linewidth=1, edgecolor='blue', facecolor='blue', alpha=0.1, zorder=1)
    ax.add_patch(rect)
    ax.text(0, 0.5, "CVE Active", ha='center', va='center', color='blue', rotation=90, alpha=0.5)

    # Title
    ax.text(-0.5, 2.8, title, fontsize=14, fontweight='bold', color=color, ha='left', va='bottom')
    ax.text(2.5, 2.8, subtitle, fontsize=12, color=color, ha='right', va='bottom')
    
    # Draw points (nodes)
    for x in [0, 1, 2]:
        for y in y_pos:
            ax.plot(x, y, 'o', color='lightgrey', markersize=8, zorder=2)
            
    # Draw specific method paths
    if title == "Evidence Graph":
        # Draw evidence points
        ax.plot(0, 2, 'o', color='red', markersize=12, zorder=3)
        ax.text(0, 2.2, "Log: Init", ha='center', color='red')
        
        ax.plot(2, 0, 'o', color='red', markersize=12, zorder=3)
        ax.text(2, 0.2, "Log: Breach", ha='center', color='red')
        
        # Missing link
        ax.text(1, 1, "?", fontsize=24, color='red', ha='center', va='center')
        ax.annotate('', xy=(0.8, 1.2), xytext=(0.2, 1.8), arrowprops=dict(arrowstyle='->', color='red', linestyle='--', lw=2))
        ax.annotate('', xy=(1.8, 0.2), xytext=(1.2, 0.8), arrowprops=dict(arrowstyle='->', color='red', linestyle='--', lw=2))
        
    elif title == "Static Attack Graph":
        # Ignores timeline
        ax.plot([0, 1, 2], [2, 1, 0], 'o-', color='orange', markersize=12, lw=3, zorder=3)
        # Mark W2 DB as the alert
        ax.plot(2, 0, 'o', color='red', markersize=12, zorder=4)
        ax.text(2, -0.3, "Alert", ha='center', color='red', fontweight='bold')
        
    elif title == "F-TAG":
        # Shows contradiction
        ax.plot(0, 2, 'o', color='green', markersize=12, zorder=3)
        ax.plot(1, 1, 'o', color='green', markersize=12, zorder=3)
        ax.annotate('', xy=(1, 1), xytext=(0, 2), arrowprops=dict(arrowstyle='->', color='green', lw=3))
        
        # Hits the wall
        ax.plot(2, 0, 'o', color='red', markersize=12, zorder=4)
        ax.text(2, -0.3, "Alert", ha='center', color='red', fontweight='bold')
        ax.annotate('', xy=(2, 0), xytext=(1, 1), arrowprops=dict(arrowstyle='->', color='red', lw=3, linestyle='--'))
        
        # X mark
        ax.text(1.5, 0.5, "X", color='red', fontsize=24, fontweight='bold', ha='center', va='center')
        ax.text(1.5, 0.2, "Edge Patched", color='red', fontsize=10, ha='center', va='top')

plt.tight_layout()
plt.savefig("motivating_example_timeline.png", dpi=300, bbox_inches='tight')
print("motivating_example_timeline.png created")
