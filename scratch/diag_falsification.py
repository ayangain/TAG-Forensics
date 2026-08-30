import os, sys, random, copy
sys.path.insert(0, os.path.dirname(os.path.abspath("experiment/run_falsification_monte_carlo.py")))
from experiment.lldos_tag_builder import build_all_lldos_tags
from experiment.ftag_metrics import path_alignment_score

tags = build_all_lldos_tags(use_mulval_for_lldos1=False)

ds = {
    "LLDOS 1.0": {"tag": tags["LLDOS_1.0"], "src": "attacker:ext", "dst": "ddos_target:impact", "true_edges": ["E_ipsweep_mill", "E_sadmind_probe_mill", "E_sadmind_exploit_mill", "E_mstream_install_mill", "E_rsh_lateral_locke", "E_ddos_launch_locke"], "true_windows": [0, 1, 2, 3, 3, 4]},
    "LLDOS 2.0.2": {"tag": tags["LLDOS_2.0.2"], "src": "attacker:ext", "dst": "attacker:exfil_received", "true_edges": ["E_dns_recon", "E_sadmind_exploit_mill", "E_ftp_upload_mill", "E_ssh_lateral_pascal", "E_mail_exfil"], "true_windows": [0, 1, 2, 3, 4]}
}

for ds_name, ds_info in ds.items():
    print(f"\nEvaluating {ds_name}...")
    ftag = ds_info["tag"]
    true_edges = ds_info["true_edges"]
    true_windows = ds_info["true_windows"]
    src_id, dst_id = ds_info["src"], ds_info["dst"]
    
    src_nids = [nid for nid, n in ftag.nodes.items() if nid == src_id or n.host_ip == src_id.split(":")[0]]
    dst_nids = [nid for nid, n in ftag.nodes.items() if nid == dst_id or n.host_ip == dst_id.split(":")[0]]
    src_nid, dst_nid = src_nids[0], dst_nids[0]

    for i in range(2):
        print(f"\n--- Trial {i} ---")
        
        # Scenario 1
        tampered_windows = list(true_windows)
        tampered_windows[0], tampered_windows[1] = tampered_windows[1], tampered_windows[0]
        ftag_tamp_1 = copy.deepcopy(ftag)
        for edge_id, w in zip(true_edges, tampered_windows):
            if edge_id in ftag_tamp_1.edges:
                ftag_tamp_1.edges[edge_id].observed_window = w
        paths1 = ftag_tamp_1.enumerate_temporal_paths(src_nid, dst_nid)
        print(f"[{ds_name} S1] tampered_windows={tampered_windows}, paths_found={len(paths1)}")
        
        # Scenario 2
        edge_idx_2 = 1 # pick index 1 just for diag
        target_edge_id_2 = true_edges[edge_idx_2]
        target_window_2 = true_windows[edge_idx_2]
        
        ftag_tamp_2 = copy.deepcopy(ftag)
        for edge_id, w in zip(true_edges, true_windows):
            if edge_id in ftag_tamp_2.edges:
                ftag_tamp_2.edges[edge_id].observed_window = w
        
        active_before_2 = set(ftag_tamp_2.edges[target_edge_id_2].active_windows)
        if target_edge_id_2 in ftag_tamp_2.edges and target_window_2 in ftag_tamp_2.edges[target_edge_id_2].active_windows:
            ftag_tamp_2.edges[target_edge_id_2].active_windows.remove(target_window_2)
        active_after_2 = set(ftag_tamp_2.edges[target_edge_id_2].active_windows)
        
        print(f"[{ds_name} S2] edge={target_edge_id_2}, window_removed={target_window_2}, active_before={active_before_2}, active_after={active_after_2}")
        
        # Scenario 3
        edge_idx_3 = len(true_edges)-1 
        target_edge_id_3 = true_edges[edge_idx_3]
        target_window_3 = true_windows[edge_idx_3]
        
        ftag_tamp_3 = copy.deepcopy(ftag)
        for edge_id, w in zip(true_edges, true_windows):
            if edge_id in ftag_tamp_3.edges:
                ftag_tamp_3.edges[edge_id].observed_window = w

        active_before_3 = set(ftag_tamp_3.edges[target_edge_id_3].active_windows)
        if target_edge_id_3 in ftag_tamp_3.edges and target_window_3 in ftag_tamp_3.edges[target_edge_id_3].active_windows:
            ftag_tamp_3.edges[target_edge_id_3].active_windows.remove(target_window_3)
        active_after_3 = set(ftag_tamp_3.edges[target_edge_id_3].active_windows)
        
        print(f"[{ds_name} S3] edge={target_edge_id_3}, window_removed={target_window_3}, active_before={active_before_3}, active_after={active_after_3}")
        
        paths3 = ftag_tamp_3.enumerate_temporal_paths(src_nid, dst_nid)
        print(f"[{ds_name} S3 paths] paths_found={len(paths3)}")

