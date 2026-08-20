import os
import random
from experiment.run_af_calibration import setup_mulval, inject_synthetic_gap, calculate_chi_scores

def check_privilege_distribution():
    print("--- Privilege Distribution Check ---")
    ftag, src, dst = setup_mulval()
    paths = ftag.enumerate_temporal_paths(src, dst, max_hops=15)
    target_path = paths[0]
    total_windows = sorted(list(set(w for p in paths for _, w in p.hops)))
    chi_scores = calculate_chi_scores(ftag, paths)
    
    classes = {"wipe": 0, "random_benign": 0, "rotation_benign": 0}
    root_hits = {"wipe": 0, "random_benign": 0, "rotation_benign": 0}
    
    for seed in range(100):
        random.seed(seed)
        all_nodes = list(ftag.nodes.keys())
        rotation_nodes = set(random.sample(all_nodes, max(1, int(len(all_nodes) * 0.2))))
        
        for c in classes:
            for _ in range(50):
                ev = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, c, rotation_nodes)
                missing = set(total_windows) - set(ev)
                if not missing:
                    continue
                classes[c] += 1
                
                has_root = False
                for edge_id, w in target_path.hops:
                    if w in missing:
                        dst_node = ftag.edges[edge_id].dst_node_id
                        if "root" in ftag.nodes[dst_node].state_name.lower():
                            has_root = True
                if has_root:
                    root_hits[c] += 1
                    
    for c in classes:
        print(f"{c}: {root_hits[c]} root hits / {classes[c]} total = {root_hits[c]/classes[c]*100:.1f}%")

if __name__ == "__main__":
    check_privilege_distribution()
