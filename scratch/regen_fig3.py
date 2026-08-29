import matplotlib.pyplot as plt
import matplotlib
import numpy as np

matplotlib.rcParams['font.family'] = 'DejaVu Sans'
matplotlib.rcParams['font.size'] = 12

scenarios = ['Precedence\nSwap', 'State\nRevocation', 'Window\nClosure']

# F1 scores: Zhang (Static) and F-TAG (Ours)
# Precedence Swap: Zhang P=1.0 R=1.0 F1=1.0, F-TAG P=0.50 R=1.0 F1=0.67
# State Revocation: Zhang P=0 R=0 F1=0.0, F-TAG P=1.0 R=1.0 F1=1.0
# Window Closure: Zhang P=0 R=0 F1=0.0, F-TAG P=1.0 R=1.0 F1=1.0
zhang_f1 = [1.0, 0.0, 0.0]
ftag_f1 = [0.67, 1.0, 1.0]

x = np.arange(len(scenarios))
width = 0.30

fig, ax = plt.subplots(figsize=(10, 5))

bars1 = ax.bar(x - width/2, zhang_f1, width, label='Zhang (Static)', color='#EF5350', edgecolor='white', linewidth=0.5)
bars2 = ax.bar(x + width/2, ftag_f1, width, label='F-TAG (Ours)', color='#66BB6A', edgecolor='white', linewidth=0.5)

# Add MISS labels for zero-score bars
for i, val in enumerate(zhang_f1):
    if val == 0.0:
        ax.text(x[i] - width/2, 0.02, 'MISS', ha='center', va='bottom', fontsize=10, fontweight='bold', color='red')

ax.set_ylabel('F1 Score', fontsize=13)
ax.set_xlabel('Falsification Scenario', fontsize=13)
ax.set_xticks(x)
ax.set_xticklabels(scenarios, fontsize=11)
ax.set_ylim(0, 1.15)
ax.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
ax.legend(loc='upper right', fontsize=11)
ax.grid(axis='y', alpha=0.3)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

plt.tight_layout()
plt.savefig('Figures/fig_falsification_detection.png', dpi=200, bbox_inches='tight')
print("Figure saved to Figures/fig_falsification_detection.png")
