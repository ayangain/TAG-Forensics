import math

total_windows = 5
H = 5
completeness_levels = [1.0, 0.75, 0.50, 0.25]

print("H = 5 (MulVAL path length)")
print(f"{'Completeness':<15} | {'N (Evidence)':<15} | {'Old delta_sample':<18} | {'New delta_sample (H-N)':<25}")
print("-" * 85)

for c in completeness_levels:
    N = max(1, int(c * total_windows))
    
    # Old discrete ceiling formula
    old_delta = math.ceil((H - N) / N) if N > 0 else 0
    
    # New continuous bound formula
    new_delta = max(0, H - N)
    
    print(f"{c*100:<14.0f}% | {N:<15} | {old_delta:<18} | {new_delta:<25}")
