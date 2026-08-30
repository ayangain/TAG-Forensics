import random
random.seed(42)

def generate_benign_variant(true_windows, delta_tolerance=1):
    while True:
        variant = list(true_windows)
        mode = random.choice(["tie_swap", "clock_skew", "missing_point"])
        
        if mode == "tie_swap":
            tie_indices = [i for i in range(len(variant)-1) if variant[i] == variant[i+1]]
            if not tie_indices:
                continue
            i = random.choice(tie_indices)
            variant[i], variant[i+1] = variant[i+1], variant[i]
            return variant, "tie_swap", i
            
        elif mode == "clock_skew":
            i = random.randint(0, len(variant)-1)
            lo = variant[i-1] if i > 0 else variant[i] - delta_tolerance
            hi = variant[i+1] if i < len(variant)-1 else variant[i] + delta_tolerance
            shifted = variant[i] + random.choice([-1, 1])
            if lo <= shifted <= hi:
                variant[i] = shifted
                return variant, "clock_skew", i
            continue
            
        elif mode == "missing_point":
            i = random.randint(0, len(variant)-1)
            variant[i] = None
            return variant, "missing_point", i

true_windows_1 = [0, 1, 2, 3, 3, 4]
true_windows_2 = [0, 1, 2, 3, 4]

s1_alarms = 0
s2_alarms = 0

for _ in range(1000):
    v1, m1, i1 = generate_benign_variant(true_windows_1)
    if m1 == "clock_skew" and i1 != 4:
        s1_alarms += 1 # Every index except 4 breaks all paths in LLDOS 1
    
    v2, m2, i2 = generate_benign_variant(true_windows_2)
    if m2 == "clock_skew":
        s2_alarms += 1 # Every index breaks the only path in LLDOS 2

print(f"LLDOS 1.0 false alarms (approx): {s1_alarms/1000:.2f}")
print(f"LLDOS 2.0.2 false alarms (approx): {s2_alarms/1000:.2f}")
