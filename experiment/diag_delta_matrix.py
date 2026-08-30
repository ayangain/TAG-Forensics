import math

H_values = [3, 5, 7, 10]
completeness_levels = [1.0, 0.75, 0.50, 0.25]

print("Old discrete formula: ceil((H - N) / N)")
print("New continuous formula: max(0, H - N)")
print()

for H in H_values:
    print(f"--- Path Length H = {H} ---")
    print(f"{'Comp%':<8} | {'N':<5} | {'Old':<5} | {'New':<5}")
    for c in completeness_levels:
        N = max(1, int(c * H))
        old_delta = math.ceil((H - N) / N) if N > 0 else 0
        new_delta = max(0, H - N)
        print(f"{c*100:<7.0f}% | {N:<5} | {old_delta:<5} | {new_delta:<5}")
    print()
