import sys
from experiment.ftag_model import ForensicTemporalAttackGraph
from experiment.ftag_metrics import forensic_window_of_compromise

def run_delta_matrix():
    print("Clock-Skew Boundary Test (Real DAG execution)")
    print("-" * 60)
    print(f"{'Gap Size (ΔW)':<15} | {'δ=0':<10} | {'δ=1':<10} | {'δ=2':<10} | {'δ=3':<10}")
    print("-" * 60)
    
    for gap in [1, 2, 3, 4]:
        results = []
        for delta in [0, 1, 2, 3]:
            # Build fresh F-TAG
            ftag = ForensicTemporalAttackGraph("test", num_windows=10, window_duration_seconds=1.0)
            ftag.add_node("N_Attacker", "attacker", "attacker")
            ftag.add_node("N_Target", "target", "target")
            
            vuln_window = 5
            evidence_window = vuln_window - gap
            
            ftag.add_edge("E_1", "N_Attacker", "N_Target", "vuln", active_windows={vuln_window}, delta_t_min=0)
            
            paths = ftag.enumerate_temporal_paths("N_Attacker", "N_Target")
            if not paths:
                results.append("Error")
                continue
                
            fwoc = forensic_window_of_compromise(
                path=paths[0],
                evidence_windows=[evidence_window],
                delta_skew=delta,
                small_sample_correction=False
            )
            
            if fwoc is None:
                results.append("Caught")
            else:
                results.append("Accepted")
                
        print(f"ΔW = {gap:<10} | {results[0]:<10} | {results[1]:<10} | {results[2]:<10} | {results[3]:<10}")

if __name__ == "__main__":
    run_delta_matrix()
