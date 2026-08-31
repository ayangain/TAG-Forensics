import os
import sys
import shutil
import random
from experiment.mulval_engine import generate_mulval_input, run_mulval_docker, parse_mulval_output, build_ftag_from_mulval
from experiment.run_track_a_experiments import experiment_1_fwoc

def run_dormant_sweep():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output_dormant")
    
    # if os.path.exists(output_dir):
    #     shutil.rmtree(output_dir)
    # os.makedirs(output_dir, exist_ok=True)
    
    num_windows = 30
    
    print("1. Using cached MulVAL inputs (30 windows)...")
    # generate_mulval_input(output_dir, num_windows=num_windows, attack_start=8, attack_end=28)
    
    print("2. Skipping Docker execution, using cached outputs...")
    # success = run_mulval_docker(output_dir, num_windows=num_windows)
    # if not success:
    #     print("[ERROR] Docker execution failed.")
    #     sys.exit(1)
        
    print("3. Parsing MulVAL outputs...")
    graphs_per_window = parse_mulval_output(output_dir, num_windows=num_windows)
    ftag = build_ftag_from_mulval(graphs_per_window)
    
    src_node = None
    dst_node = None
    for nid, node in ftag.nodes.items():
        if "attackerLocated" in node.state_name:
            src_node = nid
        if "execCode(workstation,root)" in node.state_name.replace(" ", ""):
            dst_node = nid
            
    paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=15)
    if not paths:
        print("No paths found.")
        sys.exit(1)
        
    true_edge_ids = [eid for eid, _ in paths[0].hops]
    
    # Deliberately select a dormant APT path with a large temporal gap
    # TAC = [8, 28], width = 20. H = 5.
    true_windows = [8, 8, 9, 27, 28]
    true_compromise_interval = (9, 28)
    
    # Inject the evidence into the graph!
    for i, eid in enumerate(true_edge_ids):
        ftag.edges[eid].observed_window = true_windows[i]
        
    experiment_1_fwoc(
        ftag=ftag,
        src_node=src_node,
        dst_node=dst_node,
        true_edge_ids=true_edge_ids,
        true_windows=true_windows,
        true_compromise_interval=true_compromise_interval,
        capture_duration_windows=num_windows,
        dataset_name="MulVAL Dormant APT (H=5, τ=30)"
    )

if __name__ == "__main__":
    run_dormant_sweep()
