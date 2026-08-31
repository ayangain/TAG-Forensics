import os
import sys
import random
from experiment.mulval_engine import parse_mulval_output, build_ftag_from_mulval
from experiment.run_track_a_experiments import experiment_1_fwoc

def run_track_d():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output_t20")
    
    if not os.path.exists(output_dir):
        print("Run verification script first to generate data.")
        sys.exit(1)
        
    graphs_per_window = parse_mulval_output(output_dir, num_windows=20)
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
        
    # All 252 paths share the exact same spatial edge IDs
    true_edge_ids = [eid for eid, _ in paths[0].hops]
    
    # We deliberately choose a moderately spread path: [8, 9, 10, 11, 13]
    # This represents a realistic non-degenerate attack cadence
    true_windows = [8, 9, 10, 11, 13]
    
    # The true compromise occurs in the final window of the path
    true_compromise_interval = (13, 13)
    
    df = experiment_1_fwoc(
        ftag=ftag,
        src_node=src_node,
        dst_node=dst_node,
        true_edge_ids=true_edge_ids,
        true_windows=true_windows,
        true_compromise_interval=true_compromise_interval,
        capture_duration_windows=20,
        dataset_name="MulVAL Synthetic (H=5, τ=20)"
    )

if __name__ == "__main__":
    run_track_d()
