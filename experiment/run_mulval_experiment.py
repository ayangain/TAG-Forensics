import os
import sys

from experiment.mulval_engine import (
    generate_mulval_input,
    run_mulval_docker,
    parse_mulval_output,
    build_ftag_from_mulval
)
from experiment.ftag_metrics import (
    tac_aggregated,
    forensic_window_of_compromise,
    reconstruction_ambiguity,
    temporal_chokepoint_score,
    temporal_search_radius,
    corridor_narrowing_ratio,
    path_alignment_score,
    dwell_time_bounds,
    temporal_propagation_rate
)

def run_case_study(ftag, title, src_node, dst_node, active_evidence):
    print("\n" + "═" * 70)
    print(f"  CASE STUDY: {title}")
    print("═" * 70)
    
    if not src_node or not dst_node:
        print("  [ERROR] Invalid source or target node.")
        return
        
    src_state = ftag.nodes[src_node].state_name if src_node in ftag.nodes else "Unknown"
    dst_state = ftag.nodes[dst_node].state_name if dst_node in ftag.nodes else "Unknown"
    print(f"  -> Source: [{src_node}] {src_state}")
    print(f"  -> Target: [{dst_node}] {dst_state}")
    print(f"  -> Evidence Provided (Observed Windows): {active_evidence}")
    
    paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=15)
    print(f"  -> Found {len(paths)} valid temporal attack corridors (Q^a_ij).")
    
    if not paths:
        print("  [ERROR] No valid temporal paths found between source and target.")
        return

    # 1. Forensic Window of Compromise (FWoC)
    fwocs = [forensic_window_of_compromise(p, active_evidence) for p in paths]
    valid_fwocs = [f for f in fwocs if f is not None]
    
    if valid_fwocs:
        fwoc = (min(f[0] for f in valid_fwocs), max(f[1] for f in valid_fwocs))
        fwoc_str = f"[{fwoc[0]}, {fwoc[1]}] (Windows)"
    else:
        fwoc = None
        fwoc_str = "EMPTY / NULL (Contradicts Topology)"
    
    # 2. Ambiguity (k)
    k = reconstruction_ambiguity(paths)
    
    # 3. Chokepoints (chi)
    chokepoints = {}
    for nid in ftag.nodes:
        chokepoints[nid] = temporal_chokepoint_score(nid, paths, ftag)
        
    # 4. Temporal Search Radius (T_min)
    t_min = temporal_search_radius(dst_node, ftag, paths)
    
    # PATH-SPECIFIC METRICS (calculated on the fastest path)
    fastest_path = min(paths, key=lambda p: p.W_end - p.W_b)
    rho = corridor_narrowing_ratio(fastest_path, active_evidence) or 0.0
    alignment = path_alignment_score(fastest_path, ftag)
    dt_lo, dt_hi = dwell_time_bounds(fastest_path, ftag, ftag.window_duration)
    v = temporal_propagation_rate(fastest_path)
    
    print(f"\n  [Tier 1] Timeline Bounding")
    print(f"    - FWoC: {fwoc_str}")
    print(f"    - Corridor Narrowing Ratio (rho): {rho:.2f} (0=perfect, 1=no help)")
    
    print(f"\n  [Tier 2] Evidence Reliability")
    print(f"    - Path Alignment Score (A): {alignment*100:.0f}%")
    
    print(f"\n  [Tier 3] Multi-Path Ambiguity")
    print(f"    - Ambiguity (k): {k}")
    
    print(f"\n  [Tier 4] Attack Tempo (Fastest Path)")
    print(f"    - Dwell Time Bounds: [{dt_lo:.1f}s, {dt_hi:.1f}s]")
    print(f"    - Propagation Rate (v): {v:.2f} hops/window")
    
    print(f"\n  [Tier 5] Host-Level Triage")
    print(f"    - Top 3 Chokepoints (chi):")
    top_3 = sorted(chokepoints.items(), key=lambda x: x[1], reverse=True)[:3]
    for nid, score in top_3:
        if score > 0:
            state = ftag.nodes[nid].state_name
            print(f"        * {state[:30]:<30} : {score:.3f}")
        
    print(f"\n  [Tier 6] Investigation Scoping")
    print(f"    - Temporal Search Radius (T_min): Window {t_min}")
    print("═" * 70 + "\n")

def main():
    print("=" * 70)
    print("  MulVAL Temporal F-TAG Generative Engine (IFIP Case Studies)")
    print("=" * 70)

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output")
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n[1/5] Generating temporal input_w*.P files in {output_dir}...")
    generate_mulval_input(output_dir)

    print("\n[2/5] Running MulVAL Docker per time window...")
    success = run_mulval_docker(output_dir)
    if not success:
        print("\n[ERROR] MulVAL Docker execution failed.")
        sys.exit(1)

    print("\n[3/5] Parsing MulVAL window outputs (VERTICES_w*.CSV, ARCS_w*.CSV)...")
    graphs_per_window = parse_mulval_output(output_dir)
    
    print("\n[4/5] Building Forensic Temporal Attack Graph (F-TAG)...")
    ftag = build_ftag_from_mulval(graphs_per_window)
    print(f"  SUCCESS! Temporal F-TAG built. ({len(ftag.nodes)} Nodes, {len(ftag.edges)} Edges)")
    
    print("\n[5/5] Executing IFIP Case Studies...")
    
    # Identify nodes dynamically
    ext_attacker = None
    insider_attacker = None
    target = None
    for nid, node in ftag.nodes.items():
        if "attackerLocated(internet)" in node.state_name:
            ext_attacker = nid
        if "execCode(webserver,root)" in node.state_name:
            insider_attacker = nid
        if "execCode(workstation,root)" in node.state_name:
            target = nid
            
    # Case Study 1: Normal Missing Evidence 
    run_case_study(
        ftag, 
        title="Standard External Intrusion (Missing Evidence)",
        src_node=ext_attacker, 
        dst_node=target, 
        active_evidence=[2, 4] # Evidence from W2 and W4 (W3 is missing)
    )
    
    # Case Study 2: Contradictory Evidence / False Lead
    run_case_study(
        ftag, 
        title="False-Lead Triage (Contradictory Evidence in W0)",
        src_node=ext_attacker, 
        dst_node=target, 
        active_evidence=[0] # IDS alert fires in W0, but vuln only exists in W2-W4
    )
    
    # Case Study 3: Insider Threat
    run_case_study(
        ftag, 
        title="Insider Threat (Compromised Webserver)",
        src_node=insider_attacker, 
        dst_node=target, 
        active_evidence=[2, 3, 4]
    )

if __name__ == "__main__":
    main()
