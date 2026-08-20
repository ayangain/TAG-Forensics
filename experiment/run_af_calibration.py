import os
import sys
import random
import numpy as np
try:
    from sklearn.metrics import roc_curve, auc, brier_score_loss, confusion_matrix
except ImportError:
    print("Please install scikit-learn: pip3 install --break-system-packages scikit-learn")
    sys.exit(1)

from experiment.mulval_engine import generate_mulval_input, run_mulval_docker, parse_mulval_output, build_ftag_from_mulval
from experiment.lldos_tag_builder import build_all_lldos_tags
from experiment.ftag_metrics import anti_forensics_confidence_score, temporal_chokepoint_score


def get_node_privilege(ftag, node_id):
    return "root" in ftag.nodes[node_id].state_name.lower() or "admin" in ftag.nodes[node_id].state_name.lower()

def calculate_chi_scores(ftag, paths):
    chi_scores = {}
    for nid in ftag.nodes:
        chi_scores[nid] = temporal_chokepoint_score(nid, paths, ftag)
    return chi_scores


def inject_synthetic_gap(path, ftag, total_windows, chi_scores, injection_type, rotation_nodes):
    gap_nodes = []
    path_nodes = []
    for edge_id, w in path.hops:
        dst = ftag.edges[edge_id].dst_node_id
        path_nodes.append(dst)
        
    if injection_type == "wipe":
        # Bias toward root/admin AND high chi score
        weights = []
        for dst in path_nodes:
            is_root = get_node_privilege(ftag, dst)
            chi = chi_scores.get(dst, 0.0)
            weight = (10.0 if is_root else 1.0) * (chi + 0.1)
            weights.append(weight)
            
        total_weight = sum(weights)
        if total_weight > 0:
            probs = [w / total_weight for w in weights]
            target_idx = np.random.choice(len(path_nodes), p=probs)
            gap_nodes.append(path_nodes[target_idx])
                
    elif injection_type == "random_benign":
        # Drop 1 node uniformly at random
        if path_nodes:
            target = random.choice(path_nodes)
            gap_nodes.append(target)
            
    elif injection_type == "rotation_benign":
        # Drop evidence if the node happens to be a rotation node
        for dst in path_nodes:
            if dst in rotation_nodes:
                gap_nodes.append(dst)
                    
    return gap_nodes


def run_experiment_for_graph(graph_name, ftag, src_node, dst_node):
    print(f"\n{'=' * 80}")
    print(f" GRAPH: {graph_name}")
    print(f"{'=' * 80}")
    
    paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=15)
    if not paths:
        print(f"[ERROR] No paths found for {graph_name}")
        return
        
    target_path = paths[0] # Representative path
    total_windows = sorted(list(set(w for p in paths for _, w in p.hops)))
    chi_scores = calculate_chi_scores(ftag, paths)
    
    priors = [0.05, 0.15, 0.30]
    n_seeds = 10
    n_samples_per_class = 50
    
    for prior in priors:
        print(f"\n--- Prior P(H1) = {prior:.2f} ---")
        
        # Results aggregation
        y_true_rand = []
        y_score_rand = []
        
        y_true_rot = []
        y_score_rot = []
        
        # Diagnostics
        root_hits = {"wipe": 0, "random": 0, "rotation": 0}
        totals = {"wipe": 0, "random": 0, "rotation": 0}
        
        for seed in range(n_seeds):
            random.seed(seed)
            np.random.seed(seed)
            
            # Pre-select rotation nodes (e.g. 20% of all nodes have aggressive rotation)
            all_nodes = list(ftag.nodes.keys())
            rotation_nodes = set(random.sample(all_nodes, max(1, int(len(all_nodes) * 0.2))))
            
            # Generate Wipe (H1)
            for _ in range(n_samples_per_class):
                gap_nodes = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "wipe", rotation_nodes)
                for gap_node in gap_nodes:
                    score = anti_forensics_confidence_score(gap_node, ftag, P_H1=prior)
                    y_true_rand.append(1)
                    y_score_rand.append(score)
                    y_true_rot.append(1)
                    y_score_rot.append(score)
                    root_hits["wipe"] += 1 if get_node_privilege(ftag, gap_node) else 0
                    totals["wipe"] += 1
                
            # Generate Random-Benign (H0)
            for _ in range(n_samples_per_class):
                gap_nodes = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "random_benign", rotation_nodes)
                for gap_node in gap_nodes:
                    score = anti_forensics_confidence_score(gap_node, ftag, P_H1=prior)
                    y_true_rand.append(0)
                    y_score_rand.append(score)
                    root_hits["random"] += 1 if get_node_privilege(ftag, gap_node) else 0
                    totals["random"] += 1
                
            # Generate Rotation-Benign (H0)
            for _ in range(n_samples_per_class):
                gap_nodes = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "rotation_benign", rotation_nodes)
                for gap_node in gap_nodes:
                    score = anti_forensics_confidence_score(gap_node, ftag, P_H1=prior)
                    y_true_rot.append(0)
                    y_score_rot.append(score)
                    root_hits["rotation"] += 1 if get_node_privilege(ftag, gap_node) else 0
                    totals["rotation"] += 1
                    
        print(f"  [Diagnostics - Root Privilege Target Rate]")
        print(f"    - Wipe:            {root_hits['wipe']}/{totals['wipe']} ({root_hits['wipe']/max(1, totals['wipe'])*100:.1f}%)")
        print(f"    - Random-Benign:   {root_hits['random']}/{totals['random']} ({root_hits['random']/max(1, totals['random'])*100:.1f}%)")
        print(f"    - Rotation-Benign: {root_hits['rotation']}/{totals['rotation']} ({root_hits['rotation']/max(1, totals['rotation'])*100:.1f}%)")
        
        # Evaluate Wipe vs Random
        evaluate_and_print("Wipe vs Random-Benign", y_true_rand, y_score_rand)
        
        # Evaluate Wipe vs Rotation
        evaluate_and_print("Wipe vs Rotation-Benign", y_true_rot, y_score_rot)

def evaluate_and_print(comparison_name, y_true, y_score):
    if not y_true:
        return
        
    fpr, tpr, _ = roc_curve(y_true, y_score)
    roc_auc = auc(fpr, tpr)
    brier = brier_score_loss(y_true, y_score)
    
    print(f"\n  [ {comparison_name} ]")
    print(f"    - ROC AUC:     {roc_auc:.4f}")
    print(f"    - Brier Score: {brier:.4f}")
    
    print(f"    - False Accusation Rate (FAR):")
    for thresh in [0.5, 0.7, 0.85]:
        benign_indices = [i for i, y in enumerate(y_true) if y == 0]
        if benign_indices:
            far = sum(1 for i in benign_indices if y_score[i] >= thresh) / len(benign_indices)
            print(f"        @ {thresh:.2f}: {far*100:.1f}%")
            
    # Reliability Deciles
    print(f"    - Reliability Diagram (Deciles):")
    bins = np.linspace(0, 1, 11)
    indices = np.digitize(y_score, bins) - 1
    for i in range(10):
        bin_idx = [j for j, idx in enumerate(indices) if idx == i]
        if bin_idx:
            mean_pred = np.mean([y_score[j] for j in bin_idx])
            emp_rate = np.mean([y_true[j] for j in bin_idx])
            print(f"        Bin {bins[i]:.1f}-{bins[i+1]:.1f}: Pred={mean_pred:.2f}, Emp={emp_rate:.2f} (Count: {len(bin_idx)})")

def setup_mulval():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output")
    if not os.path.exists(output_dir):
        generate_mulval_input(output_dir)
        run_mulval_docker(output_dir)
    graphs_per_window = parse_mulval_output(output_dir)
    ftag = build_ftag_from_mulval(graphs_per_window)
    
    src = next((nid for nid, n in ftag.nodes.items() if "attackerLocated" in n.state_name), None)
    dst = next((nid for nid, n in ftag.nodes.items() if "execCode(workstation,root)" in n.state_name), None)
    return ftag, src, dst

def setup_lldos():
    tags = build_all_lldos_tags()
    ftag = tags.get("LLDOS_1.0")
    attacker_ip = "202.77.162.213"
    target_ip = "172.16.115.20"
    src = next((nid for nid, n in ftag.nodes.items() if n.host_ip == attacker_ip), None)
    dst = next((nid for nid, n in ftag.nodes.items() if n.host_ip == target_ip), None)
    return ftag, src, dst

def main():
    print("Preparing MulVAL graph...")
    ftag_mulval, src_mulval, dst_mulval = setup_mulval()
    run_experiment_for_graph("Synthetic MulVAL", ftag_mulval, src_mulval, dst_mulval)
    
    print("\nPreparing LLDOS 1.0 graph...")
    ftag_lldos, src_lldos, dst_lldos = setup_lldos()
    run_experiment_for_graph("DARPA LLDOS 1.0", ftag_lldos, src_lldos, dst_lldos)

if __name__ == "__main__":
    main()
