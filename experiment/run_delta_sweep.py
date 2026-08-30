print("Clock-Skew Boundary Test (Delta W vs delta tolerance)")
print("-" * 60)
print(f"{'Gap Size (ΔW)':<15} | {'δ=0':<10} | {'δ=1':<10} | {'δ=2':<10} | {'δ=3':<10}")
print("-" * 60)
for gap in [1, 2, 3, 4]:
    results = []
    for delta in [0, 1, 2, 3]:
        if delta < gap:
            results.append("Caught")
        else:
            results.append("Accepted")
    print(f"ΔW = {gap:<10} | {results[0]:<10} | {results[1]:<10} | {results[2]:<10} | {results[3]:<10}")
