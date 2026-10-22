"""
experiment/run_delta_sweep.py
==============================
Deterministic replication script for Table 3:
1. Headlined F-TAG performance at operational tolerance delta=1 (skew in {-1, 0, +1}).
2. Tolerance parameter sweep (delta in {0, 1, 2, 3}) on LLDOS 2.0.2 with strategy-decoupled recall.
3. Noise stress test with unmodeled skew in {-2, 0, +2} at delta=1.
"""

import os
import sys
import copy
import random
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiment.lldos_tag_builder import build_all_lldos_tags
from experiment.run_track_a_experiments import mean_ci95

def per_hop_alignment_delta(path, ftag, delta=1):
    for edge_id, w_used in path.hops:
        edge = ftag.edges[edge_id]
        if edge.observed_window is not None:
            if abs(edge.observed_window - w_used) > delta:
                return False
    return True

def eval_ftag_delta(ftag_graph, src_nid, dst_nid, delta=1):
    paths = ftag_graph.enumerate_temporal_paths(src_nid, dst_nid)
    if len(paths) == 0:
        return True # Empty FWoC -> Detected structurally
    for p in paths:
        if per_hop_alignment_delta(p, ftag_graph, delta=delta):
            return False # Valid path found within delta tolerance
    return True

def eval_zhang(windows):
    concrete = [w for w in windows if w is not None]
    if len(concrete) < 2:
        return False
    return any(concrete[j] > concrete[j+1] for j in range(len(concrete)-1))

def generate_benign_variant(true_windows, delta_noise=1):
    variant = list(true_windows)
    mode = random.choice(["tie_swap", "clock_skew", "missing_point"])
    if mode == "tie_swap":
        tie_indices = [i for i in range(len(variant)-1) if variant[i] == variant[i+1]]
        if tie_indices:
            i = random.choice(tie_indices)
            variant[i], variant[i+1] = variant[i+1], variant[i]
            return variant
    elif mode == "clock_skew":
        i = random.randint(0, len(variant)-1)
        variant[i] += random.choice([-delta_noise, delta_noise])
        return variant
    elif mode == "missing_point":
        i = random.randint(0, len(variant)-1)
        variant[i] = None
        return variant
    return variant

def run_falsification_benchmark(n_trials=500):
    print("=" * 85)
    print(" REPLICATING TABLE 3: FALSIFICATION DETECTION & TOLERANCE SWEEP")
    print("=" * 85)
    
    tags = build_all_lldos_tags(use_mulval_for_lldos1=False)
    
    datasets = {
        "LLDOS 1.0 (Full Wipe)": {
            "tag": tags["LLDOS_1.0"],
            "src": "attacker:ext", "dst": "ddos_target:impact",
            "true_edges": [["E_ipsweep_mill"], ["E_sadmind_probe_mill"], ["E_sadmind_exploit_mill"], ["E_mstream_install_mill"], ["E_rsh_lateral_locke", "E_rsh_lateral_pascal"], ["E_ddos_launch_locke", "E_ddos_launch_pascal", "E_ddos_launch_mill"]],
            "true_windows": [0, 1, 2, 3, 3, 4]
        },
        "LLDOS 2.0.2 (Serial)": {
            "tag": tags["LLDOS_2.0.2"],
            "src": "attacker:ext", "dst": "attacker:exfil_received",
            "true_edges": [["E_dns_recon"], ["E_sadmind_exploit_mill"], ["E_ftp_upload_mill"], ["E_ssh_lateral_pascal"], ["E_mail_exfil"]],
            "true_windows": [0, 1, 2, 3, 4]
        }
    }

    print("\n--- 1. Headlined Performance at delta=1 (Clock Skew in {-1, 0, +1}) ---")
    print(f"{'Scenario / Dataset':<38} | {'Zhang Baseline (P, R)':<22} | {'F-TAG Ours (P, R)':<22}")
    print("-" * 85)

    for ds_name, ds_info in datasets.items():
        ftag = ds_info["tag"]
        true_edges = ds_info["true_edges"]
        true_windows = ds_info["true_windows"]
        src_id, dst_id = ds_info["src"], ds_info["dst"]
        src_nid = [nid for nid, n in ftag.nodes.items() if nid == src_id or n.host_ip == src_id.split(":")[0]][0]
        dst_nid = [nid for nid, n in ftag.nodes.items() if nid == dst_id or n.host_ip == dst_id.split(":")[0]][0]

        for sc in ["Precedence", "Patching", "Expiration"]:
            p_list, r_list = [], []
            zp_list, zr_list = [], []
            random.seed(42)

            for _ in range(n_trials):
                # Clean
                clean_w = generate_benign_variant(true_windows, delta_noise=1)
                clean_z = eval_zhang(clean_w)
                ftag_c = copy.deepcopy(ftag)
                for eg, w in zip(true_edges, clean_w):
                    if w is not None:
                        for eid in eg:
                            if eid in ftag_c.edges: ftag_c.edges[eid].observed_window = w
                clean_f = eval_ftag_delta(ftag_c, src_nid, dst_nid, delta=1)

                # Tampered
                if sc == "Precedence":
                    tamp_w = list(true_windows)
                    swap_candidates = [i for i in range(len(tamp_w)-1) if tamp_w[i] < tamp_w[i+1]]
                    if swap_candidates:
                        idx = random.choice(swap_candidates)
                        tamp_w[idx], tamp_w[idx+1] = tamp_w[idx+1], tamp_w[idx]
                    tamp_z = eval_zhang(tamp_w)
                    ftag_t = copy.deepcopy(ftag)
                    for eg, w in zip(true_edges, tamp_w):
                        for eid in eg:
                            if eid in ftag_t.edges: ftag_t.edges[eid].observed_window = w
                    tamp_f = eval_ftag_delta(ftag_t, src_nid, dst_nid, delta=1)

                elif sc == "Patching":
                    idx = random.randint(0, len(true_edges)-2)
                    tamp_z = False
                    ftag_t = copy.deepcopy(ftag)
                    for eg, w in zip(true_edges, true_windows):
                        for eid in eg:
                            if eid in ftag_t.edges: ftag_t.edges[eid].observed_window = w
                    for eid in true_edges[idx]:
                        if eid in ftag_t.edges and true_windows[idx] in ftag_t.edges[eid].active_windows:
                            ftag_t.edges[eid].active_windows.remove(true_windows[idx])
                    tamp_f = eval_ftag_delta(ftag_t, src_nid, dst_nid, delta=1)

                elif sc == "Expiration":
                    idx = len(true_edges)-1
                    tamp_z = False
                    ftag_t = copy.deepcopy(ftag)
                    for eg, w in zip(true_edges, true_windows):
                        for eid in eg:
                            if eid in ftag_t.edges: ftag_t.edges[eid].observed_window = w
                    for eid in true_edges[idx]:
                        if eid in ftag_t.edges and true_windows[idx] in ftag_t.edges[eid].active_windows:
                            ftag_t.edges[eid].active_windows.remove(true_windows[idx])
                    tamp_f = eval_ftag_delta(ftag_t, src_nid, dst_nid, delta=1)

                tp = 1.0 if tamp_f else 0.0
                fp = 1.0 if clean_f else 0.0
                p_list.append(tp / (tp + fp) if (tp + fp) > 0 else 1.0)
                r_list.append(tp)

                ztp = 1.0 if tamp_z else 0.0
                zfp = 1.0 if clean_z else 0.0
                zp_list.append(ztp / (ztp + zfp) if (ztp + zfp) > 0 else 1.0)
                zr_list.append(ztp)

            fp_m, fp_l, fp_h = mean_ci95(p_list)
            fr_m, fr_l, fr_h = mean_ci95(r_list)
            zp_m, zp_l, zp_h = mean_ci95(zp_list)
            zr_m, zr_l, zr_h = mean_ci95(zr_list)

            label = f"{ds_name} ({sc})"
            print(f"{label:<38} | {zp_m:.2f} ± {zp_h-zp_m:.2f}, {zr_m:.2f} ± {zr_h-zr_m:.2f} | {fp_m:.2f} ± {fp_h-fp_m:.2f}, {fr_m:.2f} ± {fr_h-fr_m:.2f}")

    # Part 2: Delta Sweep on LLDOS 2.0.2
    print("\n--- 2. Tolerance Parameter and Noise Stress Sweep on LLDOS 2.0.2 ---")
    print(f"{'Configuration':<35} | {'Precision':<10} | {'Rec (Preced.)':<13} | {'Rec (Patch.)':<12} | {'Rec (Expir.)':<12}")
    print("-" * 85)

    ds_info = datasets["LLDOS 2.0.2 (Serial)"]
    ftag = ds_info["tag"]
    true_edges = ds_info["true_edges"]
    true_windows = ds_info["true_windows"]
    src_id, dst_id = ds_info["src"], ds_info["dst"]
    src_nid = [nid for nid, n in ftag.nodes.items() if nid == src_id or n.host_ip == src_id.split(":")[0]][0]
    dst_nid = [nid for nid, n in ftag.nodes.items() if nid == dst_id or n.host_ip == dst_id.split(":")[0]][0]

    sweep_configs = [
        ("delta = 0 (Strict, skew ±1)", 0, 1),
        ("delta = 1 (Operational, skew ±1)", 1, 1),
        ("delta = 2 (Relaxed, skew ±1)", 2, 1),
        ("delta = 3 (Permissive, skew ±1)", 3, 1),
        ("delta = 1 (Stress: skew ±2)", 1, 2),
    ]

    for label, delta, noise in sweep_configs:
        random.seed(42)
        prec_list, rec_prec, rec_patch, rec_exp = [], [], [], []

        for _ in range(n_trials):
            # Clean
            clean_w = generate_benign_variant(true_windows, delta_noise=noise)
            ftag_c = copy.deepcopy(ftag)
            for eg, w in zip(true_edges, clean_w):
                if w is not None:
                    for eid in eg:
                        if eid in ftag_c.edges: ftag_c.edges[eid].observed_window = w
            clean_f = eval_ftag_delta(ftag_c, src_nid, dst_nid, delta=delta)

            # Precedence
            tamp_w = list(true_windows)
            swap_candidates = [i for i in range(len(tamp_w)-1) if tamp_w[i] < tamp_w[i+1]]
            if swap_candidates:
                idx = random.choice(swap_candidates)
                tamp_w[idx], tamp_w[idx+1] = tamp_w[idx+1], tamp_w[idx]
            ftag_t = copy.deepcopy(ftag)
            for eg, w in zip(true_edges, tamp_w):
                for eid in eg:
                    if eid in ftag_t.edges: ftag_t.edges[eid].observed_window = w
            tamp_f1 = eval_ftag_delta(ftag_t, src_nid, dst_nid, delta=delta)

            # Patching
            idx = random.randint(0, len(true_edges)-2)
            ftag_t = copy.deepcopy(ftag)
            for eg, w in zip(true_edges, true_windows):
                for eid in eg:
                    if eid in ftag_t.edges: ftag_t.edges[eid].observed_window = w
            for eid in true_edges[idx]:
                if eid in ftag_t.edges and true_windows[idx] in ftag_t.edges[eid].active_windows:
                    ftag_t.edges[eid].active_windows.remove(true_windows[idx])
            tamp_f2 = eval_ftag_delta(ftag_t, src_nid, dst_nid, delta=delta)

            # Expiration
            idx = len(true_edges)-1
            ftag_t = copy.deepcopy(ftag)
            for eg, w in zip(true_edges, true_windows):
                for eid in eg:
                    if eid in ftag_t.edges: ftag_t.edges[eid].observed_window = w
            for eid in true_edges[idx]:
                if eid in ftag_t.edges and true_windows[idx] in ftag_t.edges[eid].active_windows:
                    ftag_t.edges[eid].active_windows.remove(true_windows[idx])
            tamp_f3 = eval_ftag_delta(ftag_t, src_nid, dst_nid, delta=delta)

            # Precision computed from all trials
            all_tp = (1.0 if tamp_f1 else 0.0) + (1.0 if tamp_f2 else 0.0) + (1.0 if tamp_f3 else 0.0)
            all_fp = 3.0 * (1.0 if clean_f else 0.0)
            prec_list.append(all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 1.0)
            rec_prec.append(1.0 if tamp_f1 else 0.0)
            rec_patch.append(1.0 if tamp_f2 else 0.0)
            rec_exp.append(1.0 if tamp_f3 else 0.0)

        p_m, _, _ = mean_ci95(prec_list)
        r1_m, _, _ = mean_ci95(rec_prec)
        r2_m, _, _ = mean_ci95(rec_patch)
        r3_m, _, _ = mean_ci95(rec_exp)

        print(f"{label:<35} | {p_m:.2f}       | {r1_m:.2f}         | {r2_m:.2f}        | {r3_m:.2f}")

    print("\n" + "=" * 85)
    print(" [OK] Table 3 replication complete.")
    print("=" * 85)

if __name__ == "__main__":
    run_falsification_benchmark()
