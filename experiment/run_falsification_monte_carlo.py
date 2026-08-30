import os
import sys
import random
import numpy as np
import copy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiment.lldos_tag_builder import build_all_lldos_tags
from experiment.run_track_a_experiments import mean_ci95
from experiment.ftag_metrics import path_alignment_score

# Fixed random seed for complete reproducibility
random.seed(42)

def generate_benign_variant(true_windows, delta_tolerance=1):
    """Produces a plausible, NON-falsified variant of the evidence timeline."""
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
    """Zhang detects causal inversion if any w_i > w_{i+1}."""
    concrete = [w for w in windows if w is not None]
    if len(concrete) < 2:
        return False
    return any(concrete[j] > concrete[j+1] for j in range(len(concrete)-1))

def eval_ftag(ftag_graph, src_nid, dst_nid):
    """F-TAG detects falsification if path enum fails or alignment fails."""
    paths = ftag_graph.enumerate_temporal_paths(src_nid, dst_nid)
    if len(paths) == 0:
        return True # Detected structurally
    
    # Check alignment
    detects = True
    for p in paths:
        align_score = path_alignment_score(p, ftag_graph)
        if align_score == 1.0:
            detects = False # Found a perfectly aligned path, didn't detect
            break
    return detects

def calc_metrics(tampered_detect, clean_detect):
    tp = 1.0 if tampered_detect else 0.0
    fp = 1.0 if clean_detect else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    rec = tp / 1.0 
    return prec, rec

def run_real_falsification_sweep(n_trials=50):
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
    
    results = {}
    
    for ds_name, ds_info in datasets.items():
        print(f"\nEvaluating {ds_name}...")
        ftag = ds_info["tag"]
        true_edges = ds_info["true_edges"] # List of lists
        true_windows = ds_info["true_windows"]
        src_id = ds_info["src"]
        dst_id = ds_info["dst"]
        
        src_nids = [nid for nid, n in ftag.nodes.items() if nid == src_id or n.host_ip == src_id.split(":")[0]]
        dst_nids = [nid for nid, n in ftag.nodes.items() if nid == dst_id or n.host_ip == dst_id.split(":")[0]]
        assert len(src_nids) == 1
        assert len(dst_nids) == 1
        src_nid, dst_nid = src_nids[0], dst_nids[0]
        
        all_z_p1, all_z_r1, all_f_p1, all_f_r1 = [], [], [], []
        all_z_p2, all_z_r2, all_f_p2, all_f_r2 = [], [], [], []
        all_z_p3, all_z_r3, all_f_p3, all_f_r3 = [], [], [], []
        
        for i in range(n_trials):
            # Baseline (Clean Variant)
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
            
            tamp_z_detect_1 = eval_zhang(tampered_windows)
            
            ftag_tamp_1 = copy.deepcopy(ftag)
            for edge_group, w in zip(true_edges, tampered_windows):
                for edge_id in edge_group:
                    if edge_id in ftag_tamp_1.edges:
                        ftag_tamp_1.edges[edge_id].observed_window = w
            tamp_f_detect_1 = eval_ftag(ftag_tamp_1, src_nid, dst_nid)
            
            zp, zr = calc_metrics(tamp_z_detect_1, clean_z_detect)
            fp, fr = calc_metrics(tamp_f_detect_1, clean_f_detect)
            all_z_p1.append(zp); all_z_r1.append(zr)
            all_f_p1.append(fp); all_f_r1.append(fr)

            # Scenario 2: Intermediate Edge Revocation
            edge_idx_2 = random.randint(0, len(true_edges)-2) # interior edge group
            target_edge_group_2 = true_edges[edge_idx_2]
            target_window_2 = true_windows[edge_idx_2]
            
            ftag_tamp_2 = copy.deepcopy(ftag) 
            for edge_group, w in zip(true_edges, true_windows):
                for edge_id in edge_group:
                    if edge_id in ftag_tamp_2.edges:
                        ftag_tamp_2.edges[edge_id].observed_window = w

            for edge_id in target_edge_group_2:
                if edge_id in ftag_tamp_2.edges:
                    if target_window_2 in ftag_tamp_2.edges[edge_id].active_windows:
                        ftag_tamp_2.edges[edge_id].active_windows.remove(target_window_2)
            
            tamp_z_detect_2 = False 
            tamp_f_detect_2 = eval_ftag(ftag_tamp_2, src_nid, dst_nid)
            
            zp, zr = calc_metrics(tamp_z_detect_2, clean_z_detect)
            fp, fr = calc_metrics(tamp_f_detect_2, clean_f_detect)
            all_z_p2.append(zp); all_z_r2.append(zr)
            all_f_p2.append(fp); all_f_r2.append(fr)
            
            # Scenario 3: Final Edge Closure
            edge_idx_3 = len(true_edges)-1 
            target_edge_group_3 = true_edges[edge_idx_3]
            target_window_3 = true_windows[edge_idx_3]
            
            ftag_tamp_3 = copy.deepcopy(ftag)
            for edge_group, w in zip(true_edges, true_windows):
                for edge_id in edge_group:
                    if edge_id in ftag_tamp_3.edges:
                        ftag_tamp_3.edges[edge_id].observed_window = w

            for edge_id in target_edge_group_3:
                if edge_id in ftag_tamp_3.edges:
                    if target_window_3 in ftag_tamp_3.edges[edge_id].active_windows:
                        ftag_tamp_3.edges[edge_id].active_windows.remove(target_window_3)
                    
            tamp_z_detect_3 = False
            tamp_f_detect_3 = eval_ftag(ftag_tamp_3, src_nid, dst_nid)
            
            zp, zr = calc_metrics(tamp_z_detect_3, clean_z_detect)
            fp, fr = calc_metrics(tamp_f_detect_3, clean_f_detect)
            all_z_p3.append(zp); all_z_r3.append(zr)
            all_f_p3.append(fp); all_f_r3.append(fr)
        
        results[ds_name] = {
            "z_p1": all_z_p1, "z_r1": all_z_r1, "f_p1": all_f_p1, "f_r1": all_f_r1,
            "z_p2": all_z_p2, "z_r2": all_z_r2, "f_p2": all_f_p2, "f_r2": all_f_r2,
            "z_p3": all_z_p3, "z_r3": all_z_r3, "f_p3": all_f_p3, "f_r3": all_f_r3
        }

    print("\n" + "=" * 60)
    print(" GENUINE FALSIFICATION MONTE CARLO SWEEP (Seed=42)")
    print("=" * 60)
    
    print("\n" + "=" * 60)
    print(" GENUINE FALSIFICATION MONTE CARLO SWEEP (Seed=42)")
    print("=" * 60)
    
    for ds_name, ds_res in results.items():
        print(f"\n{ds_name}")
        
        fp1_m, fp1_l, fp1_h = mean_ci95(ds_res['f_p1'])
        fp2_m, fp2_l, fp2_h = mean_ci95(ds_res['f_p2'])
        fp3_m, fp3_l, fp3_h = mean_ci95(ds_res['f_p3'])
        
        fr1_m, fr1_l, fr1_h = mean_ci95(ds_res['f_r1'])
        fr2_m, fr2_l, fr2_h = mean_ci95(ds_res['f_r2'])
        fr3_m, fr3_l, fr3_h = mean_ci95(ds_res['f_r3'])
        
        zp1_m, zp1_l, zp1_h = mean_ci95(ds_res['z_p1'])
        zp2_m, zp2_l, zp2_h = mean_ci95(ds_res['z_p2'])
        zp3_m, zp3_l, zp3_h = mean_ci95(ds_res['z_p3'])
        
        zr1_m, zr1_l, zr1_h = mean_ci95(ds_res['z_r1'])
        zr2_m, zr2_l, zr2_h = mean_ci95(ds_res['z_r2'])
        zr3_m, zr3_l, zr3_h = mean_ci95(ds_res['z_r3'])
        
        print(f"  [S1: Precedence Swap]  Zhang: P={zp1_m:.2f} ± {zp1_h-zp1_m:.2f}, R={zr1_m:.2f} ± {zr1_h-zr1_m:.2f} | F-TAG: P={fp1_m:.2f} ± {fp1_h-fp1_m:.2f}, R={fr1_m:.2f} ± {fr1_h-fr1_m:.2f}")
        print(f"  [S2: State Revoc]      Zhang: P={zp2_m:.2f} ± {zp2_h-zp2_m:.2f}, R={zr2_m:.2f} ± {zr2_h-zr2_m:.2f} | F-TAG: P={fp2_m:.2f} ± {fp2_h-fp2_m:.2f}, R={fr2_m:.2f} ± {fr2_h-fr2_m:.2f}")
        print(f"  [S3: Window Closure]   Zhang: P={zp3_m:.2f} ± {zp3_h-zp3_m:.2f}, R={zr3_m:.2f} ± {zr3_h-zr3_m:.2f} | F-TAG: P={fp3_m:.2f} ± {fp3_h-fp3_m:.2f}, R={fr3_m:.2f} ± {fr3_h-fr3_m:.2f}")

if __name__ == "__main__":
    run_real_falsification_sweep(n_trials=50)
