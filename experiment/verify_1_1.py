import random
import numpy as np
from sklearn.metrics import roc_curve, auc
from experiment.run_af_calibration import setup_mulval, inject_synthetic_gap, calculate_chi_scores

# Old AF_conf logic (path-based global window)
def old_af_conf(path, ftag, missing_windows, P_H1=0.15):
    has_root = False
    for edge_id, w in path.hops:
        if w in missing_windows:
            dst_node = ftag.edges[edge_id].dst_node_id
            if "root" in ftag.nodes[dst_node].state_name.lower():
                has_root = True
                break
    
    total = len(ftag.nodes)
    graph_root_count = sum(1 for n in ftag.nodes.values() if "root" in n.state_name.lower() or "admin" in n.state_name.lower())
    P_root_H0 = graph_root_count / total
    
    likelihood_H1 = 0.75 if has_root else 0.25
    likelihood_H0 = P_root_H0 if has_root else (1.0 - P_root_H0)
    
    num = likelihood_H1 * P_H1
    den = num + (likelihood_H0 * (1.0 - P_H1))
    return num / den if den > 0 else 0.0

# New AF_conf logic (per-gap)
def new_af_conf(gap_node, ftag, P_H1=0.15):
    has_root = "root" in ftag.nodes[gap_node].state_name.lower() or "admin" in ftag.nodes[gap_node].state_name.lower()
    
    total = len(ftag.nodes)
    graph_root_count = sum(1 for n in ftag.nodes.values() if "root" in n.state_name.lower() or "admin" in n.state_name.lower())
    P_root_H0 = graph_root_count / total
    
    likelihood_H1 = 0.75 if has_root else 0.25
    likelihood_H0 = P_root_H0 if has_root else (1.0 - P_root_H0)
    
    num = likelihood_H1 * P_H1
    den = num + (likelihood_H0 * (1.0 - P_H1))
    return num / den if den > 0 else 0.0

def run_trace():
    ftag, src, dst = setup_mulval()
    paths = ftag.enumerate_temporal_paths(src, dst, max_hops=15)
    target_path = paths[0]
    total_windows = sorted(list(set(w for p in paths for _, w in p.hops)))
    chi_scores = calculate_chi_scores(ftag, paths)
    
    y_true_rand, y_true_rot = [], []
    y_old_rand, y_old_rot = [], []
    y_new_rand, y_new_rot = [], []
    
    random.seed(42)
    np.random.seed(42)
    
    all_nodes = list(ftag.nodes.keys())
    rotation_nodes = set(random.sample(all_nodes, max(1, int(len(all_nodes) * 0.2))))
    
    # 500 samples per class
    for _ in range(500):
        # Wipe
        gap_nodes = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "wipe", rotation_nodes)
        for g in gap_nodes:
            # We map the gap node back to its window for the old logic
            w_miss = next((w for e, w in target_path.hops if ftag.edges[e].dst_node_id == g), -1)
            y_true_rand.append(1)
            y_true_rot.append(1)
            y_old_rand.append(old_af_conf(target_path, ftag, [w_miss]))
            y_old_rot.append(old_af_conf(target_path, ftag, [w_miss]))
            y_new_rand.append(new_af_conf(g, ftag))
            y_new_rot.append(new_af_conf(g, ftag))
            
        # Random
        gap_nodes = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "random_benign", rotation_nodes)
        for g in gap_nodes:
            w_miss = next((w for e, w in target_path.hops if ftag.edges[e].dst_node_id == g), -1)
            y_true_rand.append(0)
            y_old_rand.append(old_af_conf(target_path, ftag, [w_miss]))
            y_new_rand.append(new_af_conf(g, ftag))
            
        # Rotation
        gap_nodes = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "rotation_benign", rotation_nodes)
        if not gap_nodes:
            continue
        for g in gap_nodes:
            w_miss = next((w for e, w in target_path.hops if ftag.edges[e].dst_node_id == g), -1)
            y_true_rot.append(0)
            y_old_rot.append(old_af_conf(target_path, ftag, [w_miss]))
            y_new_rot.append(new_af_conf(g, ftag))
            
    fpr, tpr, _ = roc_curve(y_true_rand, y_old_rand)
    print(f"Old Logic - Wipe vs Random AUC: {auc(fpr, tpr):.4f}")
    fpr, tpr, _ = roc_curve(y_true_rot, y_old_rot)
    print(f"Old Logic - Wipe vs Rotation AUC: {auc(fpr, tpr):.4f}")
    
    fpr, tpr, _ = roc_curve(y_true_rand, y_new_rand)
    print(f"New Logic - Wipe vs Random AUC: {auc(fpr, tpr):.4f}")
    fpr, tpr, _ = roc_curve(y_true_rot, y_new_rot)
    print(f"New Logic - Wipe vs Rotation AUC: {auc(fpr, tpr):.4f}")

if __name__ == "__main__":
    run_trace()
