import sys
import os
import random
import numpy as np

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, base_dir)

from experiment.run_af_calibration import setup_mulval, calculate_chi_scores, inject_synthetic_gap, get_node_privilege

ftag, src, dst = setup_mulval()
paths = ftag.enumerate_temporal_paths(src, dst, max_hops=15)
print(f"Total paths found: {len(paths)}")

total_windows = sorted(list(set(w for p in paths for _, w in p.hops)))
chi_scores = calculate_chi_scores(ftag, paths)
all_nodes = sorted(list(ftag.nodes.keys())) # Added sorted() here to guarantee order for this test!

n_seeds = 10
n_samples_per_class = 50

for i, path in enumerate(paths[:5]):
    print(f"\nPath {i}: Length {len(path.hops)}")
    root_hits = {"wipe": 0, "random": 0, "rotation": 0}
    totals = {"wipe": 0, "random": 0, "rotation": 0}
    
    for seed in range(n_seeds):
        random.seed(seed)
        np.random.seed(seed)
        
        rotation_nodes = set(random.sample(all_nodes, max(1, int(len(all_nodes) * 0.2))))
        
        for _ in range(n_samples_per_class):
            for gap in inject_synthetic_gap(path, ftag, total_windows, chi_scores, "wipe", rotation_nodes):
                root_hits["wipe"] += 1 if get_node_privilege(ftag, gap) else 0
                totals["wipe"] += 1
                
            for gap in inject_synthetic_gap(path, ftag, total_windows, chi_scores, "random_benign", rotation_nodes):
                root_hits["random"] += 1 if get_node_privilege(ftag, gap) else 0
                totals["random"] += 1
                
            for gap in inject_synthetic_gap(path, ftag, total_windows, chi_scores, "rotation_benign", rotation_nodes):
                root_hits["rotation"] += 1 if get_node_privilege(ftag, gap) else 0
                totals["rotation"] += 1

    print(f"  Wipe:     {root_hits['wipe']/max(1, totals['wipe'])*100:.1f}%")
    print(f"  Random:   {root_hits['random']/max(1, totals['random'])*100:.1f}%")
    print(f"  Rotation: {root_hits['rotation']/max(1, totals['rotation'])*100:.1f}%")

