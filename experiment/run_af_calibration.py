import os
import sys
import random
import numpy as np
try:
    from sklearn.metrics import roc_curve, auc, brier_score_loss, confusion_matrix
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    print("Please install scikit-learn and matplotlib: pip3 install --break-system-packages scikit-learn matplotlib")
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
    
    paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=30)
    if not paths:
        print(f"[ERROR] No paths found for {graph_name}")
        return
        
    total_windows = sorted(list(set(w for p in paths for _, w in p.hops)))
    chi_scores = calculate_chi_scores(ftag, paths)
    
    priors = [0.05, 0.15, 0.30]
    n_seeds = 10
    n_samples_per_class = 50
    samples_per_path = max(1, n_samples_per_class // len(paths))
    
    for prior in priors:
        print(f"\n--- Prior P(H1) = {prior:.2f} ---")
        
        seed_metrics = {
            "wipe_root": [],
            "rand_root": [],
            "rot_root": [],
            "auc_rand": [],
            "auc_rot": [],
            "far_rand_50": [],
            "far_rand_70": [],
            "far_rot_50": [],
            "far_rot_70": []
        }
        
        overall_y_true_rand = []
        overall_y_score_rand = []
        
        for seed in range(n_seeds):
            random.seed(seed)
            np.random.seed(seed)
            
            all_nodes = list(ftag.nodes.keys())
            rotation_nodes = set(random.sample(all_nodes, max(1, int(len(all_nodes) * 0.2))))
            
            y_true_rand_seed = []
            y_score_rand_seed = []
            y_true_rot_seed = []
            y_score_rot_seed = []
            
            root_hits = {"wipe": 0, "random": 0, "rotation": 0}
            totals = {"wipe": 0, "random": 0, "rotation": 0}
            
            for target_path in paths:
                # Generate Wipe
                for _ in range(samples_per_path):
                    gap_nodes = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "wipe", rotation_nodes)
                    for gap_node in gap_nodes:
                        score = anti_forensics_confidence_score(gap_node, ftag, P_H1=prior)
                        y_true_rand_seed.append(1)
                        y_score_rand_seed.append(score)
                        y_true_rot_seed.append(1)
                        y_score_rot_seed.append(score)
                        root_hits["wipe"] += 1 if get_node_privilege(ftag, gap_node) else 0
                        totals["wipe"] += 1
                        overall_y_true_rand.append(1)
                        overall_y_score_rand.append(score)
                        
                # Generate Random
                for _ in range(samples_per_path):
                    gap_nodes = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "random_benign", rotation_nodes)
                    for gap_node in gap_nodes:
                        score = anti_forensics_confidence_score(gap_node, ftag, P_H1=prior)
                        y_true_rand_seed.append(0)
                        y_score_rand_seed.append(score)
                        root_hits["random"] += 1 if get_node_privilege(ftag, gap_node) else 0
                        totals["random"] += 1
                        overall_y_true_rand.append(0)
                        overall_y_score_rand.append(score)
                        
                # Generate Rotation
                for _ in range(samples_per_path):
                    gap_nodes = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "rotation_benign", rotation_nodes)
                    for gap_node in gap_nodes:
                        score = anti_forensics_confidence_score(gap_node, ftag, P_H1=prior)
                        y_true_rot_seed.append(0)
                        y_score_rot_seed.append(score)
                        root_hits["rotation"] += 1 if get_node_privilege(ftag, gap_node) else 0
                        totals["rotation"] += 1

            seed_metrics["wipe_root"].append(root_hits["wipe"] / max(1, totals["wipe"]))
            seed_metrics["rand_root"].append(root_hits["random"] / max(1, totals["random"]))
            seed_metrics["rot_root"].append(root_hits["rotation"] / max(1, totals["rotation"]))
            
            if len(set(y_true_rand_seed)) > 1:
                fpr, tpr, _ = roc_curve(y_true_rand_seed, y_score_rand_seed)
                seed_metrics["auc_rand"].append(auc(fpr, tpr))
            if len(set(y_true_rot_seed)) > 1:
                fpr, tpr, _ = roc_curve(y_true_rot_seed, y_score_rot_seed)
                seed_metrics["auc_rot"].append(auc(fpr, tpr))
                
            benign_idx_rand = [i for i, y in enumerate(y_true_rand_seed) if y == 0]
            if benign_idx_rand:
                seed_metrics["far_rand_50"].append(sum(1 for i in benign_idx_rand if y_score_rand_seed[i] >= 0.50) / len(benign_idx_rand))
                seed_metrics["far_rand_70"].append(sum(1 for i in benign_idx_rand if y_score_rand_seed[i] >= 0.70) / len(benign_idx_rand))
                seed_metrics.setdefault("far_rand_85", []).append(sum(1 for i in benign_idx_rand if y_score_rand_seed[i] >= 0.85) / len(benign_idx_rand))
                seed_metrics.setdefault("far_rand_90", []).append(sum(1 for i in benign_idx_rand if y_score_rand_seed[i] >= 0.90) / len(benign_idx_rand))
            benign_idx_rot = [i for i, y in enumerate(y_true_rot_seed) if y == 0]
            if benign_idx_rot:
                seed_metrics["far_rot_50"].append(sum(1 for i in benign_idx_rot if y_score_rot_seed[i] >= 0.50) / len(benign_idx_rot))
                seed_metrics["far_rot_70"].append(sum(1 for i in benign_idx_rot if y_score_rot_seed[i] >= 0.70) / len(benign_idx_rot))
                seed_metrics.setdefault("far_rot_85", []).append(sum(1 for i in benign_idx_rot if y_score_rot_seed[i] >= 0.85) / len(benign_idx_rot))
                seed_metrics.setdefault("far_rot_90", []).append(sum(1 for i in benign_idx_rot if y_score_rot_seed[i] >= 0.90) / len(benign_idx_rot))
                
        def format_ci(arr):
            if not arr: return "N/A"
            mean = np.mean(arr)
            ci = 1.96 * np.std(arr) / np.sqrt(len(arr))
            return f"{mean*100:.1f}% (95% CI: [{max(0, (mean-ci)*100):.1f}, {min(100, (mean+ci)*100):.1f}])"
            
        def format_auc_ci(arr):
            if not arr: return "N/A"
            mean = np.mean(arr)
            ci = 1.96 * np.std(arr) / np.sqrt(len(arr))
            return f"{mean:.3f} (95% CI: [{mean-ci:.3f}, {min(1.0, mean+ci):.3f}])"
            
        print(f"  [Diagnostics - Aggregated Root Privilege Target Rate]")
        print(f"    - Wipe:            {format_ci(seed_metrics['wipe_root'])}")
        print(f"    - Random-Benign:   {format_ci(seed_metrics['rand_root'])}")
        print(f"    - Rotation-Benign: {format_ci(seed_metrics['rot_root'])}")
        
        print(f"\n  [ Wipe vs Random-Benign ]")
        print(f"    - ROC AUC:     {format_auc_ci(seed_metrics['auc_rand'])}")
        print(f"    - FAR @ 0.50:  {format_ci(seed_metrics['far_rand_50'])}")
        print(f"    - FAR @ 0.70:  {format_ci(seed_metrics['far_rand_70'])}")
        print(f"    - FAR @ 0.85:  {format_ci(seed_metrics.get('far_rand_85', []))}")
        print(f"    - FAR @ 0.90:  {format_ci(seed_metrics.get('far_rand_90', []))}")
        
        print(f"\n  [ Wipe vs Rotation-Benign ]")
        print(f"    - ROC AUC:     {format_auc_ci(seed_metrics['auc_rot'])}")
        print(f"    - FAR @ 0.50:  {format_ci(seed_metrics['far_rot_50'])}")
        print(f"    - FAR @ 0.70:  {format_ci(seed_metrics['far_rot_70'])}")
        print(f"    - FAR @ 0.85:  {format_ci(seed_metrics.get('far_rot_85', []))}")
        print(f"    - FAR @ 0.90:  {format_ci(seed_metrics.get('far_rot_90', []))}")
        
        if prior == 0.30:
            fpr, tpr, _ = roc_curve(overall_y_true_rand, overall_y_score_rand)
            roc_auc = auc(fpr, tpr)
            plt.figure(figsize=(5, 4))
            plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'Baseline (AUC = {roc_auc:.3f})')
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('AF_conf ROC (Prior=0.30)')
            plt.legend(loc="lower right")
            out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiment", "results")
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, "afconf_roc.png")
            plt.savefig(out_path, dpi=300, bbox_inches="tight")
            print(f"\n  [!] Saved aggregate ROC plot to {out_path}")
            plt.close()

def setup_mulval():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        generate_mulval_input(output_dir)
        run_mulval_docker(output_dir)
    graphs_per_window = parse_mulval_output(output_dir)
    ftag = build_ftag_from_mulval(graphs_per_window, prune=False)
    
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
    print("Preparing MulVAL graph (Unpruned for AF_conf calibration)...")
    ftag_mulval, src_mulval, dst_mulval = setup_mulval()
    run_experiment_for_graph("Synthetic MulVAL (Unpruned)", ftag_mulval, src_mulval, dst_mulval)

    print("\nPreparing LLDOS 1.0 graph...")
    ftag_lldos, src_lldos, dst_lldos = setup_lldos()
    run_experiment_for_graph("DARPA LLDOS 1.0", ftag_lldos, src_lldos, dst_lldos)

if __name__ == "__main__":
    main()
