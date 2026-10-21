"""
run_table3_30seeds.py
=====================
Reruns the Table 3 adversarial falsification detection benchmark across
30 independent seeds (50 trials per seed = 1,500 trials per scenario)
and reports the mean and 95% confidence intervals for Precision and Recall
for both Zhang et al. (static baseline) and F-TAG (temporal).
"""
import os
import sys
import random
import copy
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiment.lldos_tag_builder import build_all_lldos_tags
from experiment.ftag_metrics import path_alignment_score

N_SEEDS = 30
N_TRIALS_PER_SEED = 50

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
            return variant
            
        elif mode == "clock_skew":
            i = random.randint(0, len(variant)-1)
            lo = variant[i-1] if i > 0 else variant[i] - delta_tolerance
            hi = variant[i+1] if i < len(variant)-1 else variant[i] + delta_tolerance
            shifted = variant[i] + random.choice([-1, 1])
            if lo <= shifted <= hi:
                variant[i] = shifted
                return variant
            continue
            
        elif mode == "missing_point":
            i = random.randint(0, len(variant)-1)
            variant[i] = None
            return variant

def eval_zhang(windows):
    concrete = [w for w in windows if w is not None]
    if len(concrete) < 2:
        return False
    return any(concrete[j] > concrete[j+1] for j in range(len(concrete)-1))

def eval_ftag(ftag_graph, src_nid, dst_nid):
    paths = ftag_graph.enumerate_temporal_paths(src_nid, dst_nid)
    if len(paths) == 0:
        return True # Detected structurally (FWoC empty)
    
    for p in paths:
        align_score = path_alignment_score(p, ftag_graph)
        if align_score == 1.0:
            return False # Found a valid, perfectly aligned path
    return True

def calc_metrics(tampered_detect, clean_detect):
    tp = 1.0 if tampered_detect else 0.0
    fp = 1.0 if clean_detect else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    rec = tp / 1.0 
    return prec, rec

def mean_ci95(data):
    arr = np.array(data)
    mean = np.mean(arr)
    se = np.std(arr, ddof=1) / np.sqrt(len(arr)) if len(arr) > 1 else 0.0
    margin = 1.96 * se
    return mean, margin

def run_30_seed_experiment():
    print(f"Building LLDOS TAG models...")
    tags = build_all_lldos_tags(use_mulval_for_lldos1=False)
    
    datasets = {
        "LLDOS 1.0 (Single-Zombie Wipe)": {
            "tag": tags["LLDOS_1.0"],
            "src": "attacker:ext",
            "dst": "ddos_target:impact",
            "true_edges": [["E_ipsweep_mill"], ["E_sadmind_probe_mill"], ["E_sadmind_exploit_mill"], ["E_mstream_install_mill"], ["E_rsh_lateral_locke"], ["E_ddos_launch_locke"]],
            "true_windows": [0, 1, 2, 3, 3, 4]
        },
        "LLDOS 1.0 (Full Infrastructure Wipe)": {
            "tag": tags["LLDOS_1.0"],
            "src": "attacker:ext",
            "dst": "ddos_target:impact",
            "true_edges": [["E_ipsweep_mill"], ["E_sadmind_probe_mill"], ["E_sadmind_exploit_mill"], ["E_mstream_install_mill"], ["E_rsh_lateral_locke", "E_rsh_lateral_pascal"], ["E_ddos_launch_locke", "E_ddos_launch_pascal", "E_ddos_launch_mill"]],
            "true_windows": [0, 1, 2, 3, 3, 4]
        },
        "LLDOS 2.0.2": {
            "tag": tags["LLDOS_2.0.2"],
            "src": "attacker:ext",
            "dst": "attacker:exfil_received",
            "true_edges": [["E_dns_recon"], ["E_sadmind_exploit_mill"], ["E_ftp_upload_mill"], ["E_ssh_lateral_pascal"], ["E_mail_exfil"]],
            "true_windows": [0, 1, 2, 3, 4]
        }
    }

    print(f"\nRunning 30-Seed Monte Carlo ({N_SEEDS} seeds x {N_TRIALS_PER_SEED} trials = {N_SEEDS*N_TRIALS_PER_SEED} trials/scenario)...")
    
    # Store per-seed metrics: dict[ds_name][scenario][metric] -> list of length 30
    overall_results = {}

    for ds_name, ds_info in datasets.items():
        print(f"\nProcessing {ds_name}...")
        ftag = ds_info["tag"]
        true_edges = ds_info["true_edges"]
        true_windows = ds_info["true_windows"]
        src_id = ds_info["src"]
        dst_id = ds_info["dst"]
        
        src_nids = [nid for nid, n in ftag.nodes.items() if nid == src_id or n.host_ip == src_id.split(":")[0]]
        dst_nids = [nid for nid, n in ftag.nodes.items() if nid == dst_id or n.host_ip == dst_id.split(":")[0]]
        src_nid, dst_nid = src_nids[0], dst_nids[0]

        seed_means = {
            "s1": {"zp": [], "zr": [], "fp": [], "fr": []},
            "s2": {"zp": [], "zr": [], "fp": [], "fr": []},
            "s3": {"zp": [], "zr": [], "fp": [], "fr": []},
        }

        for seed in range(N_SEEDS):
            random.seed(seed * 1000 + 42)
            np.random.seed(seed * 1000 + 42)

            cur_s1 = {"zp": [], "zr": [], "fp": [], "fr": []}
            cur_s2 = {"zp": [], "zr": [], "fp": [], "fr": []}
            cur_s3 = {"zp": [], "zr": [], "fp": [], "fr": []}

            for trial in range(N_TRIALS_PER_SEED):
                # Benign clean variant
                clean_windows = generate_benign_variant(true_windows)
                clean_z_detect = eval_zhang(clean_windows)
                
                ftag_clean = copy.deepcopy(ftag)
                for edge_group, w in zip(true_edges, clean_windows):
                    if w is not None:
                        for edge_id in edge_group:
                            if edge_id in ftag_clean.edges:
                                ftag_clean.edges[edge_id].observed_window = w
                clean_f_detect = eval_ftag(ftag_clean, src_nid, dst_nid)

                # Scenario 1: Precedence Swap
                tampered_windows = list(true_windows)
                while True:
                    swap_idx = random.randint(0, len(true_windows)-2)
                    if tampered_windows[swap_idx] != tampered_windows[swap_idx+1]:
                        if tampered_windows[swap_idx] < tampered_windows[swap_idx+1]:
                            tampered_windows[swap_idx], tampered_windows[swap_idx+1] = tampered_windows[swap_idx+1], tampered_windows[swap_idx]
                        break
                tamp_z_1 = eval_zhang(tampered_windows)
                ftag_t1 = copy.deepcopy(ftag)
                for edge_group, w in zip(true_edges, tampered_windows):
                    for edge_id in edge_group:
                        if edge_id in ftag_t1.edges:
                            ftag_t1.edges[edge_id].observed_window = w
                tamp_f_1 = eval_ftag(ftag_t1, src_nid, dst_nid)
                zp, zr = calc_metrics(tamp_z_1, clean_z_detect)
                fp, fr = calc_metrics(tamp_f_1, clean_f_detect)
                cur_s1["zp"].append(zp); cur_s1["zr"].append(zr)
                cur_s1["fp"].append(fp); cur_s1["fr"].append(fr)

                # Scenario 2: Intermediate Edge Revocation
                edge_idx_2 = random.randint(0, len(true_edges)-2)
                target_edge_group_2 = true_edges[edge_idx_2]
                target_window_2 = true_windows[edge_idx_2]
                ftag_t2 = copy.deepcopy(ftag)
                for edge_group, w in zip(true_edges, true_windows):
                    for edge_id in edge_group:
                        if edge_id in ftag_t2.edges:
                            ftag_t2.edges[edge_id].observed_window = w
                for edge_id in target_edge_group_2:
                    if edge_id in ftag_t2.edges and target_window_2 in ftag_t2.edges[edge_id].active_windows:
                        ftag_t2.edges[edge_id].active_windows.remove(target_window_2)
                tamp_z_2 = False
                tamp_f_2 = eval_ftag(ftag_t2, src_nid, dst_nid)
                zp, zr = calc_metrics(tamp_z_2, clean_z_detect)
                fp, fr = calc_metrics(tamp_f_2, clean_f_detect)
                cur_s2["zp"].append(zp); cur_s2["zr"].append(zr)
                cur_s2["fp"].append(fp); cur_s2["fr"].append(fr)

                # Scenario 3: Final Edge Closure
                edge_idx_3 = len(true_edges)-1
                target_edge_group_3 = true_edges[edge_idx_3]
                target_window_3 = true_windows[edge_idx_3]
                ftag_t3 = copy.deepcopy(ftag)
                for edge_group, w in zip(true_edges, true_windows):
                    for edge_id in edge_group:
                        if edge_id in ftag_t3.edges:
                            ftag_t3.edges[edge_id].observed_window = w
                for edge_id in target_edge_group_3:
                    if edge_id in ftag_t3.edges and target_window_3 in ftag_t3.edges[edge_id].active_windows:
                        ftag_t3.edges[edge_id].active_windows.remove(target_window_3)
                tamp_z_3 = False
                tamp_f_3 = eval_ftag(ftag_t3, src_nid, dst_nid)
                zp, zr = calc_metrics(tamp_z_3, clean_z_detect)
                fp, fr = calc_metrics(tamp_f_3, clean_f_detect)
                cur_s3["zp"].append(zp); cur_s3["zr"].append(zr)
                cur_s3["fp"].append(fp); cur_s3["fr"].append(fr)

            for sc, cur in [("s1", cur_s1), ("s2", cur_s2), ("s3", cur_s3)]:
                for k in ["zp", "zr", "fp", "fr"]:
                    seed_means[sc][k].append(np.mean(cur[k]))

        overall_results[ds_name] = seed_means

    print("\n" + "="*80)
    print(f" TABLE 3 RE-RUN: 30 SEEDS ({N_SEEDS} independent seeds, 50 trials/seed)")
    print("="*80)
    for ds_name, sm in overall_results.items():
        print(f"\n{ds_name}:")
        for sc, sc_title in [("s1", "Precedence Swap"), ("s2", "Vulnerability Patching"), ("s3", "Connectivity Expiration")]:
            zp_m, zp_ci = mean_ci95(sm[sc]["zp"])
            zr_m, zr_ci = mean_ci95(sm[sc]["zr"])
            fp_m, fp_ci = mean_ci95(sm[sc]["fp"])
            fr_m, fr_ci = mean_ci95(sm[sc]["fr"])
            print(f"  {sc_title:<25} Zhang: P={zp_m:.2f} ± {zp_ci:.2f}, R={zr_m:.2f} ± {zr_ci:.2f}  |  F-TAG: P={fp_m:.2f} ± {fp_ci:.2f}, R={fr_m:.2f} ± {fr_ci:.2f}")

if __name__ == "__main__":
    run_30_seed_experiment()
