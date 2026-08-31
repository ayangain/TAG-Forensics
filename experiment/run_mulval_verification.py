import os
import sys
import shutil
from collections import Counter
from experiment.mulval_engine import generate_mulval_input, run_mulval_docker, parse_mulval_output, build_ftag_from_mulval

def verify_mulval():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output_t20")
    
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    print("1. Generating MulVAL inputs...")
    generate_mulval_input(output_dir, num_windows=20, attack_start=8, attack_end=13)
    
    print("2. Running MulVAL Docker (this will take a moment)...")
    success = run_mulval_docker(output_dir, num_windows=20)
    if not success:
        print("[ERROR] Docker execution failed.")
        sys.exit(1)
        
    print("3. Parsing MulVAL outputs...")
    graphs_per_window = parse_mulval_output(output_dir, num_windows=20)
    ftag = build_ftag_from_mulval(graphs_per_window)
    
    print("\n--- CHECK 1: Node Hash Collisions ---")
    name_to_ids = {}
    for node_id, node in ftag.nodes.items():
        if node.state_name not in name_to_ids:
            name_to_ids[node.state_name] = []
        name_to_ids[node.state_name].append(node_id)
        
    collisions_found = False
    for state_name, ids in name_to_ids.items():
        if len(set(ids)) > 1:
            print(f"[COLLISION] State '{state_name}' mapped to multiple IDs: {ids}")
            collisions_found = True
            
    id_to_states = {}
    for node_id, node in ftag.nodes.items():
        if node_id not in id_to_states:
            id_to_states[node_id] = []
        id_to_states[node_id].append(node.state_name)
        
    for node_id, states in id_to_states.items():
        if len(set(states)) > 1:
            print(f"[COLLISION] Hash '{node_id}' used for multiple distinct states: {states}")
            collisions_found = True
            
    if not collisions_found:
        print(f"Zero collisions detected across {len(ftag.nodes)} unique nodes.")
    else:
        print("Collisions were found!")
        
    print("\n--- CHECK 2: Temporal Path Enumeration ---")
    src_node = None
    dst_node = None
    for nid, node in ftag.nodes.items():
        if "attackerLocated" in node.state_name:
            src_node = nid
        if "execCode(workstation,root)" in node.state_name.replace(" ", ""):
            dst_node = nid
            
    if not src_node or not dst_node:
        print("[ERROR] Source or destination node not found.")
        sys.exit(1)
        
    paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=15)
    print(f"Found {len(paths)} surviving path(s).")
    
    for i, p in enumerate(paths):
        print(f"\nPath {i+1} (H={len(p.hops)}):")
        for step_idx, (edge_id, w) in enumerate(p.hops):
            edge = ftag.edges[edge_id]
            print(f"  Hop {step_idx+1}: {edge.src_node_id} -> {edge.dst_node_id} (Window {w})")
            
    print("\n--- CHECK 3: Confirm H ---")
    if len(paths) == 1:
        H = len(paths[0].hops)
        if H == 5:
            print(f"H = {H}. Confirmed 5-hop path.")
        else:
            print(f"H = {H}. EXPECTED 5 HOPS!")
    else:
        print(f"Multiple paths found, unable to trivially confirm H.")

if __name__ == "__main__":
    verify_mulval()
