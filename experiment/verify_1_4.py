import random
import numpy as np
from experiment.run_af_calibration import setup_lldos, setup_mulval, inject_synthetic_gap, calculate_chi_scores, get_node_privilege
from experiment.lldos_tag_builder import build_all_lldos_tags

def check_graph(name, ftag, src_node, dst_node):
    print(f"\n--- Graph: {name} ---")
    paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=15)
    if not paths:
        print("No paths found.")
        return
    target_path = paths[0]
    total_windows = sorted(list(set(w for p in paths for _, w in p.hops)))
    chi_scores = calculate_chi_scores(ftag, paths)
    classes = {"wipe": 0, "random": 0, "rotation": 0}
    root_hits = {"wipe": 0, "random": 0, "rotation": 0}
    
    for seed in range(10):
        random.seed(seed)
        np.random.seed(seed)
        all_nodes = list(ftag.nodes.keys())
        rotation_nodes = set(random.sample(all_nodes, max(1, int(len(all_nodes) * 0.2))))
        
        for _ in range(50):
            # random
            gaps = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "random_benign", rotation_nodes)
            for g in gaps:
                classes["random"] += 1
                if get_node_privilege(ftag, g): root_hits["random"] += 1
                
            # rotation
            gaps = inject_synthetic_gap(target_path, ftag, total_windows, chi_scores, "rotation_benign", rotation_nodes)
            for g in gaps:
                classes["rotation"] += 1
                if get_node_privilege(ftag, g): root_hits["rotation"] += 1

    print(f"Random:   {root_hits['random']}/{classes['random']} ({(root_hits['random']/max(1,classes['random']))*100:.1f}%)")
    print(f"Rotation: {root_hits['rotation']}/{classes['rotation']} ({(root_hits['rotation']/max(1,classes['rotation']))*100:.1f}%)")

def main():
    tags = build_all_lldos_tags()
    
    # LLDOS 1.0
    ftag_1 = tags.get("LLDOS_1.0")
    src_1 = next((nid for nid, n in ftag_1.nodes.items() if n.host_ip == "202.77.162.213"), None)
    dst_1 = next((nid for nid, n in ftag_1.nodes.items() if n.host_ip == "172.16.115.20"), None)
    check_graph("LLDOS 1.0", ftag_1, src_1, dst_1)
    
    # LLDOS 2.0.2
    ftag_2 = tags.get("LLDOS_2.0.2")
    src_2 = next((nid for nid, n in ftag_2.nodes.items() if n.host_ip == "202.77.162.213"), None)
    dst_2 = next((nid for nid, n in ftag_2.nodes.items() if n.host_ip == "172.16.115.20"), None)
    check_graph("LLDOS 2.0.2", ftag_2, src_2, dst_2)
    
    # MulVAL
    ftag_m, src_m, dst_m = setup_mulval()
    check_graph("MulVAL", ftag_m, src_m, dst_m)

if __name__ == "__main__":
    main()
