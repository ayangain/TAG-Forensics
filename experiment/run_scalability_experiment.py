import os
import sys
import time

from experiment.generate_scaled_mulval import generate_enterprise_datalog
from experiment.mulval_engine import run_mulval_docker, parse_mulval_output, build_ftag_from_mulval
from experiment.ftag_metrics import (
    structural_tag_metrics,
    forensic_window_of_compromise,
    temporal_chokepoint_score,
    anti_forensics_confidence_score
)

def run_scalability_experiment():
    print("=" * 70)
    print("  F-TAG Scalability Validation (14 to 500 Nodes)")
    print("=" * 70)
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output_scaled")
    
    # User wants pruned graph sizes to be [10, 20, 30, ..., 100]
    target_pruned_sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    results = []
    
    for target_nodes in target_pruned_sizes:
        n = int(round((target_nodes - 2) / 0.6))
        # Ensure we don't have zeros
        n = max(5, n)
        
        print(f"\n[Testing Target Pruned Nodes={target_nodes} (Base N={n})]")
        test_dir = os.path.join(output_dir, f"N_{n}")
        os.makedirs(test_dir, exist_ok=True)
        
        # 1. Generate Input
        generate_enterprise_datalog(n, test_dir)
        
        # 2. Run MulVAL
        start_mulval = time.time()
        success = run_mulval_docker(test_dir)
        mulval_time = time.time() - start_mulval
        
        if not success:
            print(f"  [ERROR] MulVAL failed for N={n}")
            continue
            
        # 3. Parse and Build F-TAG
        graphs_per_window = parse_mulval_output(test_dir)
        ftag = build_ftag_from_mulval(graphs_per_window)
        
        nodes_ftag = len(ftag.nodes)
        edges_ftag = len(ftag.edges)
        print(f"  -> Built F-TAG: {nodes_ftag} Nodes, {edges_ftag} Edges")
        # Phase 1: Proactive Risk
        start_p1 = time.time()
        # L_a, E_a, B_a = structural_tag_metrics(ftag)
        p1_time = time.time() - start_p1
        
        # Phase 2: Reactive Triage (Path Enumeration & FWoC)
        ext_attacker = None
        target = None
        for nid, node in ftag.nodes.items():
            if "attackerLocated(internet)" in node.state_name:
                ext_attacker = nid
            if "execCode(" in node.state_name and "db_" in node.state_name:
                # Find the deepest DB node
                target = nid
                
        if ext_attacker and target:
            start_p2 = time.time()
            paths = ftag.enumerate_temporal_paths(ext_attacker, target, max_hops=3)
            
            # Simulate Evidence (W2 and W4)
            active_evidence = [2, 4]
            if paths:
                fwocs = [forensic_window_of_compromise(p, active_evidence) for p in paths]
                if target:
                    af_score = anti_forensics_confidence_score(target, ftag)
            
            p2_time = time.time() - start_p2
        else:
            p2_time = 0.0
            
        total_metric_time = p1_time + p2_time
        print(f"  -> Metric Execution Time: {total_metric_time:.4f}s (P1: {p1_time:.4f}s, P2: {p2_time:.4f}s)")
        
        results.append({
            'N': n,
            'FTAG_Nodes': nodes_ftag,
            'FTAG_Edges': edges_ftag,
            'MulVAL_Time': mulval_time,
            'Metric_Time': total_metric_time
        })
        
    print("\n" + "=" * 70)
    print("  SCALABILITY RESULTS SUMMARY")
    print("=" * 70)
    print(f"{'Base Nodes (N)':<15} | {'F-TAG Nodes':<12} | {'F-TAG Edges':<12} | {'MulVAL (s)':<12} | {'Metrics (s)':<12}")
    print("-" * 70)
    for r in results:
        print(f"{r['N']:<15} | {r['FTAG_Nodes']:<12} | {r['FTAG_Edges']:<12} | {r['MulVAL_Time']:<12.3f} | {r['Metric_Time']:<12.4f}")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    run_scalability_experiment()
