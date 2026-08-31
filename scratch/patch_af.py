import sys
import os

with open("experiment/run_af_calibration.py", "r") as f:
    content = f.read()

import re

# We will replace run_experiment_for_graph and evaluate_and_print
# Find the start of run_experiment_for_graph
start_idx = content.find("def run_experiment_for_graph(graph_name, ftag, src_node, dst_node):")
# Find the end (which is the start of setup_mulval)
end_idx = content.find("def setup_mulval():")

new_func = """def run_experiment_for_graph(graph_name, ftag, src_node, dst_node):
    print(f"\\n{'=' * 80}")
    print(f" GRAPH: {graph_name}")
    print(f"{'=' * 80}")
    
    paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=15)
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
        print(f"\\n--- Prior P(H1) = {prior:.2f} ---")
        
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
            benign_idx_rot = [i for i, y in enumerate(y_true_rot_seed) if y == 0]
            if benign_idx_rot:
                seed_metrics["far_rot_50"].append(sum(1 for i in benign_idx_rot if y_score_rot_seed[i] >= 0.50) / len(benign_idx_rot))
                seed_metrics["far_rot_70"].append(sum(1 for i in benign_idx_rot if y_score_rot_seed[i] >= 0.70) / len(benign_idx_rot))
                
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
        
        print(f"\\n  [ Wipe vs Random-Benign ]")
        print(f"    - ROC AUC:     {format_auc_ci(seed_metrics['auc_rand'])}")
        print(f"    - FAR @ 0.50:  {format_ci(seed_metrics['far_rand_50'])}")
        print(f"    - FAR @ 0.70:  {format_ci(seed_metrics['far_rand_70'])}")
        
        print(f"\\n  [ Wipe vs Rotation-Benign ]")
        print(f"    - ROC AUC:     {format_auc_ci(seed_metrics['auc_rot'])}")
        print(f"    - FAR @ 0.50:  {format_ci(seed_metrics['far_rot_50'])}")
        print(f"    - FAR @ 0.70:  {format_ci(seed_metrics['far_rot_70'])}")
        
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
            print(f"\\n  [!] Saved aggregate ROC plot to {out_path}")
            plt.close()

"""

new_content = content[:start_idx] + new_func + content[end_idx:]

with open("experiment/run_af_calibration.py", "w") as f:
    f.write(new_content)

