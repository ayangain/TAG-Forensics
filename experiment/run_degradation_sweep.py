import os
import random
import statistics
import sys
from collections import defaultdict
from experiment.mulval_engine import generate_mulval_input, run_mulval_docker, parse_mulval_output, build_ftag_from_mulval
from experiment.ftag_metrics import forensic_window_of_compromise, reconstruction_ambiguity, temporal_search_radius

def run_degradation_sweep():
    print("=" * 70)
    print("  F-TAG Completeness Degradation Sweep (Unpruned MulVAL Graph)")
    print("=" * 70)

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output")
    
    # We assume the docker has already been run and the output exists from earlier case studies
    if not os.path.exists(output_dir):
        print("Running MulVAL first...")
        generate_mulval_input(output_dir)
        run_mulval_docker(output_dir)
        
    graphs_per_window = parse_mulval_output(output_dir)
    ftag = build_ftag_from_mulval(graphs_per_window)
    
    src_node = None
    dst_node = None
    for nid, node in ftag.nodes.items():
        if "attackerLocated" in node.state_name:
            src_node = nid
        if "execCode(workstation,root)" in node.state_name:
            dst_node = nid
            
    if not src_node or not dst_node:
        print("[ERROR] Source or destination node not found.")
        sys.exit(1)
        
    paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=15)
    print(f"Topology built. (Nodes: {len(ftag.nodes)}, Edges: {len(ftag.edges)})")
    print(f"Total valid temporal corridors (100% evidence): {len(paths)}")
    
    completeness_levels = [1.0, 0.75, 0.50, 0.25]
    num_trials = 30
    total_windows = 5
    all_evidence = [0, 1, 2, 3, 4]
    
    # True bounds based on our knowledge of the synthetic attack
    TRUE_START = 2
    TRUE_END = 4
    
    print("\nStarting Monte Carlo Sweep (30 trials per level)...\n")
    print("| Completeness | FWoC Soundness | FWoC Tightness | Ambiguity (k) | T_min |")
    print("|--------------|----------------|----------------|---------------|-------|")

    for c in completeness_levels:
        num_evidence = max(1, int(c * total_windows))
        
        sound_count = 0
        tightnesses = []
        ambiguities = []
        t_mins = []
        
        for _ in range(num_trials):
            evidence = sorted(random.sample(all_evidence, num_evidence))
            
            # FWoC
            fwocs = [forensic_window_of_compromise(p, evidence, small_sample_correction=True) for p in paths]
            valid_fwocs = [f for f in fwocs if f is not None]
            
            if valid_fwocs:
                fwoc_min = min(f[0] for f in valid_fwocs)
                fwoc_max = max(f[1] for f in valid_fwocs)
                
                tightness = fwoc_max - fwoc_min
                tightnesses.append(tightness)
                
                if fwoc_min <= TRUE_START and fwoc_max >= TRUE_END:
                    sound_count += 1
            else:
                tightnesses.append(0) # Empty FWoC is 0 tightness, but unsound
                
            # Ambiguity
            k = reconstruction_ambiguity(paths)
            ambiguities.append(k)
            
            # T_min
            t_min = temporal_search_radius(dst_node, ftag, paths)
            t_mins.append(t_min)
            
        soundness_pct = (sound_count / num_trials) * 100
        avg_tightness = statistics.mean(tightnesses)
        avg_k = statistics.mean(ambiguities)
        avg_t_min = statistics.mean(t_mins)
        
        print(f"| {c*100:3.0f}%        | {soundness_pct:6.1f}%         | {avg_tightness:14.2f} | {avg_k:13.2f} | {avg_t_min:5.1f} |")

if __name__ == "__main__":
    run_degradation_sweep()
