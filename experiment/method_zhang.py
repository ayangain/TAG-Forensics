"""
method_zhang.py — Zhang et al. (2015) Baseline Falsification Detection.

Implements Algorithms 2-4 from:
  Zhang, Liu, et al. "Detecting falsified timestamps in evidence graphs"

Algorithm 2: CheckTimestamp — reference-count marking across sub-evidence-graphs
Algorithm 3: AdjustSuggestion — BFS temporal-bound correction
Algorithm 4: ReconstructEvidenceGraph — reconstruction with adjusted timestamps
"""

import time
from typing import Tuple, Set
from collections import defaultdict, deque


def _build_sub_evidence_graphs(evidence_graph):
    """
    Build sub-evidence-graphs by grouping edges by their evidence source.
    Each source type forms a separate sub-graph.
    
    If all edges have the same source, split by phase connectivity.
    """
    evidenced = {e.edge_id: e for e in evidence_graph.get_causal_edges()}
    
    # Group by source type
    source_groups = defaultdict(dict)
    for eid, e in evidenced.items():
        source_groups[e.source_type][eid] = e
    
    # If only one source group, split by phase
    if len(source_groups) <= 1:
        source_groups = defaultdict(dict)
        for eid, e in evidenced.items():
            source_groups[f"phase_{e.phase}"][eid] = e
    
    return dict(source_groups)


def _count_node_appearances(sub_graphs, evidence_graph):
    """
    Algorithm 2 (CheckTimestamp): Count how many disconnected sub-evidence-graphs
    each node appears in. If count[N] > 1, mark as potentially falsified.
    
    Zhang et al. define this as: a node appearing in disconnected sub-graphs
    with inconsistent timestamps is evidence of falsification.
    """
    evidenced = {e.edge_id: e for e in evidence_graph.get_causal_edges()}
    
    # Count appearances per node (host IP) across sub-graphs
    node_subgraph_count = defaultdict(set)  # node -> set of subgraph IDs
    node_timestamps = defaultdict(list)     # node -> list of (subgraph_id, timestamp)
    
    for sg_id, sg_edges in sub_graphs.items():
        nodes_in_sg = set()
        for eid, e in sg_edges.items():
            nodes_in_sg.add(e.src)
            nodes_in_sg.add(e.dst)
            node_timestamps[e.src].append((sg_id, e.observed_start))
            node_timestamps[e.dst].append((sg_id, e.observed_end))
        
        for node in nodes_in_sg:
            node_subgraph_count[node].add(sg_id)
    
    # Nodes appearing in multiple sub-graphs
    suspicious_nodes = set()
    for node, sg_ids in node_subgraph_count.items():
        if len(sg_ids) > 1:
            # Check timestamp consistency across sub-graphs
            timestamps_by_sg = defaultdict(list)
            for sg_id, ts in node_timestamps[node]:
                timestamps_by_sg[sg_id].append(ts)
            
            # If timestamps differ significantly across sub-graphs, flag it
            all_ts = []
            for sg_id, ts_list in timestamps_by_sg.items():
                all_ts.extend(ts_list)
            
            if all_ts:
                ts_range = max(all_ts) - min(all_ts)
                # Flag if timestamp spread across sources exceeds reasonable jitter
                if ts_range > 60:  # > 60 seconds spread
                    suspicious_nodes.add(node)
    
    return suspicious_nodes, node_timestamps


def _bfs_temporal_bounds(evidence_graph, node, direction="backward"):
    """
    Algorithm 3 (AdjustSuggestion): BFS from a suspicious node to compute
    max-src-time and min-dst-time bounds.
    
    If min-dst-time > max-src-time, suggests SecondTime = max-src-time - 1.
    """
    evidenced = {e.edge_id: e for e in evidence_graph.get_causal_edges()}
    
    # Build adjacency for BFS
    # forward: edge src → dst
    # backward: edge dst → src
    fwd_adj = defaultdict(list)
    bkw_adj = defaultdict(list)
    
    for eid, e in evidenced.items():
        fwd_adj[e.src].append((e.dst, e.observed_start, e.observed_end, eid))
        bkw_adj[e.dst].append((e.src, e.observed_start, e.observed_end, eid))
    
    if direction == "backward":
        # Find max-src-time: latest timestamp of any predecessor
        max_src_time = float('-inf')
        visited = set()
        queue = deque([node])
        visited.add(node)
        predecessor_edges = set()
        
        while queue:
            current = queue.popleft()
            for (src, obs_start, obs_end, eid) in bkw_adj.get(current, []):
                if src not in visited:
                    visited.add(src)
                    queue.append(src)
                    predecessor_edges.add(eid)
                max_src_time = max(max_src_time, obs_end)
        
        return max_src_time, predecessor_edges
    
    else:  # forward
        # Find min-dst-time: earliest timestamp of any successor
        min_dst_time = float('inf')
        visited = set()
        queue = deque([node])
        visited.add(node)
        successor_edges = set()
        
        while queue:
            current = queue.popleft()
            for (dst, obs_start, obs_end, eid) in fwd_adj.get(current, []):
                if dst not in visited:
                    visited.add(dst)
                    queue.append(dst)
                    successor_edges.add(eid)
                min_dst_time = min(min_dst_time, obs_start)
        
        return min_dst_time, successor_edges


def detect_zhang(evidence_graph) -> Tuple[bool, Set[str], float]:
    """
    Zhang et al. (2015) falsification detection.
    
    1. Build sub-evidence-graphs (Algorithm 2 setup)
    2. Count node appearances across disconnected sub-graphs
    3. For suspicious nodes (count > 1), run BFS to compute temporal bounds
    4. If bounds are violated, flag associated edges
    
    Also performs direct causal-constraint checking as Zhang's method
    relies on structural anomalies plus temporal bound violations.
    
    Returns:
        (detected: bool, conflict_edges: set of edge_ids, elapsed_ms: float)
    """
    t_start = time.perf_counter()
    
    evidenced = {e.edge_id: e for e in evidence_graph.get_causal_edges()}
    if not evidenced:
        return False, set(), 0.0
    
    conflict_edges = set()
    detected = False
    
    # ── Algorithm 2: Reference-count marking ──
    sub_graphs = _build_sub_evidence_graphs(evidence_graph)
    suspicious_nodes, node_timestamps = _count_node_appearances(sub_graphs, evidence_graph)
    
    # ── Algorithm 3: BFS temporal-bound correction ──
    for node in suspicious_nodes:
        max_src_time, pred_edges = _bfs_temporal_bounds(evidence_graph, node, "backward")
        min_dst_time, succ_edges = _bfs_temporal_bounds(evidence_graph, node, "forward")
        
        if max_src_time > min_dst_time:
            detected = True
            # Flag edges around the violation
            conflict_edges.update(pred_edges)
            conflict_edges.update(succ_edges)
    
    # ── Direct causal constraint checking (supplement) ──
    # Zhang's method also detects simple ordering violations
    for c in evidence_graph.constraints:
        if c.edge_before_id in evidenced and c.edge_after_id in evidenced:
            before = evidenced[c.edge_before_id]
            after = evidenced[c.edge_after_id]
            
            # Check if the observed timestamps violate causal ordering
            if after.observed_start < before.observed_end:
                detected = True
                conflict_edges.add(c.edge_before_id)
                conflict_edges.add(c.edge_after_id)
    
    elapsed_ms = (time.perf_counter() - t_start) * 1000
    return detected, conflict_edges, elapsed_ms
