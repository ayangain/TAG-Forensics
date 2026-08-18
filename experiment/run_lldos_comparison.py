import sys
from typing import List, Dict, Set
from collections import defaultdict

from experiment.ftag_model import ForensicTemporalAttackGraph
from experiment.ftag_metrics import structural_tag_metrics, temporal_chokepoint_score

def enumerate_static_paths(ftag: ForensicTemporalAttackGraph, src_ip: str, dst_ip: str, max_hops=15) -> List[List[str]]:
    """
    Enumerates all paths between src and dst ignoring time window constraints.
    Returns lists of node IDs.
    """
    src_nodes = [nid for nid, n in ftag.nodes.items() if n.host_ip == src_ip]
    dst_nodes = [nid for nid, n in ftag.nodes.items() if n.host_ip == dst_ip]
    
    if not src_nodes or not dst_nodes:
        return []

    # Build static adjacency list
    adj = defaultdict(list)
    for edge in ftag.edges.values():
        adj[edge.src_node_id].append(edge.dst_node_id)
        
    all_paths = []
    
    def dfs(current_node: str, current_path: List[str]):
        if len(current_path) > max_hops:
            return
            
        if current_node in dst_nodes:
            all_paths.append(list(current_path))
            return
            
        for neighbor in adj[current_node]:
            # prevent simple cycles
            if neighbor not in current_path:
                current_path.append(neighbor)
                dfs(neighbor, current_path)
                current_path.pop()
                
    for src in src_nodes:
        dfs(src, [src])
        
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


from experiment.lldos_tag_builder import build_all_lldos_tags

def run():
    print("\n" + "═" * 70)
    print(" LLDOS DATASET: STATIC vs. TEMPORAL ATTACK GRAPH COMPARISON")
    print("═" * 70)

    try:
        tags = build_all_lldos_tags()
        ftag = tags.get("LLDOS_1.0")
        if not ftag:
            print("Error: LLDOS_1.0 FTAG not built.")
            return
    except Exception as e:
        print(f"Error: LLDOS dataset not found. Ensure tcpdump_inside and labeling_info exist. {e}")
        return

    # Define Source and Target
    attacker_ip = "202.77.162.213"
    target_ip = "172.16.115.20" # The compromised pascal host
    
    # Identify node IDs
    src_nodes = [nid for nid, n in ftag.nodes.items() if n.host_ip == attacker_ip]
    dst_nodes = [nid for nid, n in ftag.nodes.items() if n.host_ip == target_ip]
    
    src = src_nodes[0] if src_nodes else None
    dst = dst_nodes[0] if dst_nodes else None
    
    if not src or not dst:
        print("Error: Could not find Attacker or Target in the graph.")
        return

    print("\n[1] PATH AMBIGUITY (The 'Impossible Path' Insight)")
    
    # Static Paths
    static_paths = enumerate_static_paths(ftag, attacker_ip, target_ip)
    
    # Temporal Paths
    temporal_paths = ftag.enumerate_temporal_paths(src, dst)
    
    print(f"  -> Valid Paths in Static Attack Graph:   {len(static_paths)}")
    print(f"  -> Valid Paths in Temporal Attack Graph: {len(temporal_paths)}")
    
    false_paths = len(static_paths) - len(temporal_paths)
    if false_paths > 0:
        print(f"  -> INSIGHT: The Static graph generated {false_paths} impossible backward-time paths!")

    print("\n[2] CHOKEPOINT ANALYSIS (The 'False Bottleneck' Insight)")
    
    # Static Betweenness
    B_s = static_betweenness_centrality(ftag)
    
    # Temporal Betweenness
    _, _, B_a = structural_tag_metrics(ftag)
    
    print("  -> Top 3 Structural Bottlenecks in Static Graph (Ignoring Time):")
    top_static = sorted(B_s.items(), key=lambda x: x[1], reverse=True)[:3]
    for nid, score in top_static:
        if score > 0:
            print(f"        * {ftag.nodes[nid].host_ip:<15} ({ftag.nodes[nid].state_name[:15]:<15}) : {score:.4f}")

    print("\n  -> Top 3 True Temporal Bottlenecks in TAG (Time-Aware):")
    top_temporal = sorted(B_a.items(), key=lambda x: x[1], reverse=True)[:3]
    for nid, score in top_temporal:
        if score > 0:
            print(f"        * {ftag.nodes[nid].host_ip:<15} ({ftag.nodes[nid].state_name[:15]:<15}) : {score:.4f}")
            
    # Check if top 1 shifted
    if top_static and top_temporal and top_static[0][0] != top_temporal[0][0]:
        print(f"\n  -> INSIGHT: The Static graph prioritized {ftag.nodes[top_static[0][0]].host_ip} incorrectly.")
        print(f"     The Temporal graph correctly identified {ftag.nodes[top_temporal[0][0]].host_ip} as the true chronological bridge.")


    print("\n[3] ATTACK TEMPO (The 'Blindness' Insight)")
    from experiment.ftag_metrics import dwell_time_bounds
    
    try:
        min_dt, max_dt = dwell_time_bounds(temporal_paths[0], ftag)
        print("  -> Static Attack Graph Dwell Time: UNDEFINED (Blind to Time)")
        print(f"  -> Temporal Attack Graph Dwell Time: [{min_dt}s - {max_dt}s]")
        print("  -> INSIGHT: Only the TAG can bound the temporal speed of the attacker.")
    except Exception as e:
        print(f"  -> Dwell time calculation skipped: {e}")
        
    print("\n" + "═" * 70 + "\n")


if __name__ == "__main__":
    run()
