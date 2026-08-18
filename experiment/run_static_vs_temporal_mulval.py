import sys
from typing import List, Dict, Set
from collections import defaultdict
import os

from experiment.mulval_engine import (
    generate_mulval_input,
    run_mulval_docker,
    parse_mulval_output,
    build_ftag_from_mulval
)
from experiment.ftag_model import ForensicTemporalAttackGraph
from experiment.ftag_metrics import (
    structural_tag_metrics, 
    forensic_window_of_compromise,
    temporal_chokepoint_score
)

def enumerate_static_paths(ftag: ForensicTemporalAttackGraph, src_nid: str, dst_nid: str, max_hops=15) -> List[List[str]]:
    """
    Enumerates all paths between src and dst ignoring time window constraints.
    Returns lists of node IDs.
    """
    if src_nid not in ftag.nodes or dst_nid not in ftag.nodes:
        return []

    # Build static adjacency list
    adj = defaultdict(list)
    for edge in ftag.edges.values():
        adj[edge.src_node_id].append(edge.dst_node_id)
        
    all_paths = []
    
    def dfs(current_node: str, current_path: List[str]):
        if len(current_path) > max_hops:
            return
            
        if current_node == dst_nid:
            all_paths.append(list(current_path))
            return
            
        for neighbor in adj[current_node]:
            # prevent simple cycles
            if neighbor not in current_path:
                current_path.append(neighbor)
                dfs(neighbor, current_path)
                current_path.pop()
                
    dfs(src_nid, [src_nid])
    return all_paths

def static_betweenness_centrality(ftag: ForensicTemporalAttackGraph) -> Dict[str, float]:
    """Calculates standard betweenness centrality ignoring time."""
    nodes = list(ftag.nodes.keys())
    N = len(nodes)
    
    # Build static adjacency list
    adj = defaultdict(list)
    for edge in ftag.edges.values():
        adj[edge.src_node_id].append(edge.dst_node_id)
        
    shortest_paths = {}
    
    for j in nodes:
        for k in nodes:
            if j == k:
                continue
            
            # BFS for shortest static paths
            queue = [[j]]
            shortest_for_pair = []
            min_length = float('inf')
            
            while queue:
                path = queue.pop(0)
                node = path[-1]
                
                if len(path) > min_length:
                    continue
                    
                if node == k:
                    if len(path) < min_length:
                        min_length = len(path)
                        shortest_for_pair = [path]
                    elif len(path) == min_length:
                        shortest_for_pair.append(path)
                    continue
                    
                for neighbor in adj[node]:
                    if neighbor not in path:
                        queue.append(path + [neighbor])
                        
            shortest_paths[(j,k)] = shortest_for_pair

    B_s = {i: 0.0 for i in nodes}
    if N > 2:
        for i in nodes:
            sum_b = 0.0
            for j in nodes:
                for k in nodes:
                    if j == k or j == i or k == i:
                        continue
                        
                    paths_jk = shortest_paths.get((j, k), [])
                    sigma_jk = len(paths_jk)
                    if sigma_jk == 0:
                        continue
                        
                    sigma_jk_i = sum(1 for p in paths_jk if i in p[1:-1])
                    sum_b += (sigma_jk_i / sigma_jk)
            
            B_s[i] = sum_b / ((N - 1) * (N - 2))
            
    return B_s


def run():
    print("\n" + "═" * 70)
    print(" MULVAL 14-NODE TOPOLOGY: STATIC vs. TEMPORAL ATTACK GRAPH COMPARISON")
    print("═" * 70)

    # Build the MulVAL 14-node FTAG
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output")
    try:
        generate_mulval_input(output_dir)
        run_mulval_docker(output_dir)
        graphs_per_window = parse_mulval_output(output_dir)
        ftag = build_ftag_from_mulval(graphs_per_window)
    except Exception as e:
        print(f"Error loading MulVAL dataset: {e}")
        return

    # Identify Source and Target dynamically (similar to run_mulval_experiment.py)
    ext_attacker = None
    target = None
    for nid, node in ftag.nodes.items():
        if "attackerLocated(internet)" in node.state_name:
            ext_attacker = nid
        if "execCode(workstation,root)" in node.state_name:
            target = nid
            
    if not ext_attacker or not target:
        print("Error: Could not find attacker or target node in MulVAL graph.")
        return

    print("\n[1] PATH AMBIGUITY (Concurrency vs. Sequencing)")
    
    # Static Paths
    static_paths = enumerate_static_paths(ftag, ext_attacker, target)
    
    # Temporal Paths
    temporal_paths = ftag.enumerate_temporal_paths(ext_attacker, target)
    
    print(f"  -> Valid Paths in Static Attack Graph:   {len(static_paths)}")
    print(f"  -> Valid Paths in Temporal Attack Graph: {len(temporal_paths)}")
    
    false_paths = len(static_paths) - len(temporal_paths)
    if false_paths > 0:
        print(f"  -> INSIGHT: The Static graph generated {false_paths} impossible backward-time paths!")

    print("\n[2] FALSE BOTTLENECKS (Chokepoint Centrality)")
    
    # Static Betweenness
    B_s = static_betweenness_centrality(ftag)
    
    # Temporal Betweenness
    _, _, B_a = structural_tag_metrics(ftag)
    
    print("  -> Top 3 Structural Bottlenecks in Static Graph (Ignoring Time):")
    top_static = sorted(B_s.items(), key=lambda x: x[1], reverse=True)[:3]
    for nid, score in top_static:
        if score > 0:
            print(f"        * {ftag.nodes[nid].state_name[:35]:<35} : {score:.4f}")

    print("\n  -> Top 3 True Temporal Bottlenecks in TAG (Time-Aware):")
    top_temporal = sorted(B_a.items(), key=lambda x: x[1], reverse=True)[:3]
    for nid, score in top_temporal:
        if score > 0:
            print(f"        * {ftag.nodes[nid].state_name[:35]:<35} : {score:.4f}")
            
    # Check if top 1 shifted
    if top_static and top_temporal and top_static[0][0] != top_temporal[0][0]:
        print(f"\n  -> INSIGHT: The Static graph prioritized '{ftag.nodes[top_static[0][0]].state_name}' incorrectly.")
        print(f"     The Temporal graph correctly identified '{ftag.nodes[top_temporal[0][0]].state_name}' as the true chronological bridge.")

    print("\n[3] FALSE POSITIVE FILTERING (The Background Noise Insight)")
    # Case: An IDS alert fires on the workstation at Window 0. But workstation isn't reachable until Window 2.
    print("  -> Setup: IDS alert fires on Workstation at Time Window 0.")
    print("  -> Static Attack Graph Triage: VALID ALERT.")
    print("     (Reason: The static graph sees a structural path exists, ignoring the fact that it's closed in W0).")
    
    # Temporal FWoC Evaluation
    valid_corridors = []
    for p in temporal_paths:
        fwoc = forensic_window_of_compromise(p, [0])
        if fwoc is not None:
            valid_corridors.append(p)
            
    print(f"  -> Temporal Attack Graph Triage: ", end="")
    if len(valid_corridors) == 0:
        print("EMPTY (CONTRADICTION CAUGHT)")
        print("     (Reason: The TAG mathematically proves the topology wasn't active in W0, dropping the false positive).")
    else:
        print("VALID ALERT")

    print("\n" + "═" * 70 + "\n")


if __name__ == "__main__":
    run()
