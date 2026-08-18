"""
ftag_metrics.py — Forensic Temporal Attack Graph Metric Suite.

All 13 metrics organized by investigative tier, built on the corrected
corridor formalism (sequential window ordering per Definition 2,
dormant-attacker safe — no intersection bug).

Tier 1 — Timeline Bounding:
  1. Temporal Attack Corridor (TAC)
  2. Forensic Window of Compromise (FWoC)
  3. Corridor Narrowing Ratio (rho)

Tier 2 — Evidence Reliability:
  4. Per-Hop Alignment
  5. Path Alignment Score (A)

Tier 3 — Multi-Path Ambiguity:
  6. Corridor Overlap Index (Omega)
  7. Reconstruction Ambiguity (cluster count)

Tier 4 — Attack Tempo:
  8. Dwell Time Bounds (DT)
  9. Stage Transition Gaps (delta)
  10. Temporal Propagation Rate (v)

Tier 5 — Host-Level Triage:
  11. Temporal Chokepoint Score (chi)
  12. Host Exposure Window

Tier 6 — Investigation Scoping:
  13. Temporal Search Radius (T_min)
"""

from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
import math
from experiment.ftag_model import ForensicTemporalAttackGraph, TemporalPath, TAGEdge


# ─────────────────────────────────────────────────────
# Tier 1 — Timeline Bounding
# ─────────────────────────────────────────────────────

def temporal_attack_corridor(path: TemporalPath) -> Tuple[int, int]:
    """TAC(p) = [W_b(p), W_end(p)]. The window range during which the breach
    could have occurred, derived from topology alone."""
    return path.tac


def tac_aggregated(paths: List[TemporalPath]) -> Tuple[int, int]:
    """TAC_ij = union of all per-path corridors. Returns the widest
    possible window range across all candidate paths."""
    if not paths:
        return (0, 0)
    w_min = min(p.W_b for p in paths)
    w_max = max(p.W_end for p in paths)
    return (w_min, w_max)


# ─────────────────────────────────────────────────────
# Proactive Structural TAG Metrics (Foundational Theory)
# ─────────────────────────────────────────────────────

def structural_tag_metrics(ftag) -> Tuple[float, float, Dict[str, float]]:
    """
    Computes proactive structural metrics on the unconstrained Temporal Attack Graph.
    These metrics represent network vulnerability BEFORE forensic evidence is applied.
    
    Returns:
        L_a: Characteristic Temporal Attack Path Length
        E_a: Temporal Attack Global Efficiency
        B_a: Dict mapping node_id -> TAG Betweenness Centrality
    """
    nodes = list(ftag.nodes.keys())
    N = len(nodes)
    
    # In MulVAL F-TAG, we assume a standard tau=5 time windows for disconnected pairs
    tau = 5 
    
    d_a = {}
    shortest_paths = {}
    
    for j in nodes:
        for k in nodes:
            if j == k:
                continue
            # Find all valid temporal paths
            paths = ftag.enumerate_temporal_paths(j, k, max_hops=15)
            if not paths:
                d_a[(j, k)] = tau
                shortest_paths[(j, k)] = []
            else:
                # Shortest path in TAG is defined by minimum hops
                min_hops = min(len(p.hops) for p in paths)
                d_a[(j, k)] = min_hops
                shortest_paths[(j, k)] = [p for p in paths if len(p.hops) == min_hops]
                
    # Calculate L_a and E_a
    sum_L = sum(d_a.values())
    sum_E = sum(1.0 / d for d in d_a.values() if d > 0)
    
    L_a = sum_L / (N * (N - 1)) if N > 1 else 0.0
    E_a = sum_E / (N * (N - 1)) if N > 1 else 0.0
    
    # Calculate Betweenness Centrality B_a
    B_a = {i: 0.0 for i in nodes}
    if N > 2:
        for i in nodes:
            sum_b = 0.0
            for j in nodes:
                for k in nodes:
                    if j == k or j == i or k == i:
                        continue
                    
                    paths_jk = shortest_paths[(j, k)]
                    sigma_jk = len(paths_jk)
                    if sigma_jk == 0:
                        continue
                        
                    # Count how many shortest paths pass through node i
                    sigma_jk_i = 0
                    for p in paths_jk:
                        intermediate_nodes = set()
                        for edge_id, _ in p.hops[:-1]:
                            intermediate_nodes.add(ftag.edges[edge_id].dst_node_id)
                        if i in intermediate_nodes:
                            sigma_jk_i += 1
                            
                    sum_b += (sigma_jk_i / sigma_jk)
            
            B_a[i] = sum_b / ((N - 1) * (N - 2))
            
    return L_a, E_a, B_a


def forensic_window_of_compromise(
    path: TemporalPath,
    evidence_windows: List[int],
    delta_skew: int = 0,
    small_sample_correction: bool = False
) -> Optional[Tuple[int, int]]:
    """FWoC(p) = TAC(p) ∩ [min(t_i) - delta, max(t_i) + delta].
    delta_skew absorbs NTP clock drift and falsified timestamp uncertainty.
    small_sample_correction widens the bound inversely with completeness.
    Returns None if intersection is empty (evidence inconsistent with corridor)."""
    if not evidence_windows:
        return None
        
    tac = path.tac
    N = len(evidence_windows)
    H = len(path.hops)
    
    delta_sample = 0
    if small_sample_correction and N > 0:
        delta_sample = max(0, math.ceil((H - N) / N))
        
    ev_min = min(evidence_windows) - delta_skew - delta_sample
    ev_max = max(evidence_windows) + delta_skew + delta_sample
    
    fwoc_start = max(tac[0], ev_min)
    fwoc_end = min(tac[1], ev_max)
    
    if fwoc_start > fwoc_end:
        return None  # Evidence is outside the corridor — inconsistency
    return (fwoc_start, fwoc_end)


def anti_forensics_confidence_score(
    path: TemporalPath,
    ftag,
    active_evidence: List[int],
    total_windows: List[int]
) -> float:
    """
    A heuristic scoring function correlating privilege-gap location with anti-forensic likelihood.
    Uses bounded ratios (R_root, R_miss) to prevent arbitrary saturation on deeper graphs.
    """
    missing_windows = set(total_windows) - set(active_evidence)
    if not missing_windows:
        return 0.0
        
    H = len(path.hops)
    if H == 0:
        return 0.0
        
    root_nodes = 0
    for edge_id, _ in path.hops:
        edge = ftag.edges[edge_id]
        dst_node = edge.dst_node_id
        if "root" in ftag.nodes[dst_node].state_name.lower():
            root_nodes += 1
            
    R_root = root_nodes / H
    R_miss = len(missing_windows) / len(total_windows)
    
    if root_nodes == 0:
        return 0.15 # Likely benign logging failure
    else:
        # Base 60% confidence, plus scaled ratios
        score = 0.60 + (0.30 * R_root) + (0.10 * R_miss)
        return min(score, 0.99)

def corridor_narrowing_ratio(
    path: TemporalPath,
    evidence_windows: List[int],
) -> Optional[float]:
    """rho(p) = |FWoC(p)| / |TAC(p)|.
    rho -> 0: evidence pins breach precisely.
    rho -> 1: evidence adds nothing beyond topology.
    Returns None if FWoC is empty."""
    tac = path.tac
    tac_width = tac[1] - tac[0] + 1
    if tac_width <= 0:
        return 0.0
    fwoc = forensic_window_of_compromise(path, evidence_windows)
    if fwoc is None:
        return None
    fwoc_width = fwoc[1] - fwoc[0] + 1
    return fwoc_width / tac_width


# ─────────────────────────────────────────────────────
# Tier 2 — Evidence Reliability
# ─────────────────────────────────────────────────────

def per_hop_alignment(
    path: TemporalPath,
    ftag: ForensicTemporalAttackGraph,
) -> List[Tuple[str, int, bool]]:
    """For each hop (edge_id, window_used), check whether the evidence
    timestamp's window matches the window the hop used.
    Returns list of (edge_id, window_used, is_aligned)."""
    results = []
    for edge_id, w_used in path.hops:
        edge = ftag.edges[edge_id]
        if edge.observed_window is not None:
            # Evidence must be observed in the exact window this hop uses
            aligned = (edge.observed_window == w_used)
        else:
            aligned = True  # No evidence to contradict
        results.append((edge_id, w_used, aligned))
    return results


def path_alignment_score(
    path: TemporalPath,
    ftag: ForensicTemporalAttackGraph,
) -> float:
    """A(p) = |aligned hops| / |p|."""
    hops = per_hop_alignment(path, ftag)
    if not hops:
        return 1.0
    aligned_count = sum(1 for _, _, a in hops if a)
    return aligned_count / len(hops)


# ─────────────────────────────────────────────────────
# Tier 3 — Multi-Path Ambiguity
# ─────────────────────────────────────────────────────

def corridor_overlap_index(p: TemporalPath, q: TemporalPath) -> float:
    """Omega(p, q) = |TAC(p) ∩ TAC(q)| / |TAC(p) ∪ TAC(q)|.
    Jaccard-style overlap between two candidate corridors."""
    tac_p = set(range(p.W_b, p.W_end + 1))
    tac_q = set(range(q.W_b, q.W_end + 1))
    intersection = tac_p & tac_q
    union = tac_p | tac_q
    if not union:
        return 1.0
    return len(intersection) / len(union)


def reconstruction_ambiguity(paths: List[TemporalPath]) -> int:
    """Count mutually non-overlapping corridor clusters among candidate paths.
    k=1: essentially unambiguous (one timeline story).
    k>1: k genuinely distinct, mutually exclusive stories about when the breach happened."""
    if not paths:
        return 0

    # Sort corridors by start window
    corridors = sorted([(p.W_b, p.W_end) for p in paths])

    # Merge overlapping corridors into clusters
    clusters = [corridors[0]]
    for start, end in corridors[1:]:
        last_start, last_end = clusters[-1]
        if start <= last_end:
            # Overlapping — merge
            clusters[-1] = (last_start, max(last_end, end))
        else:
            # Disjoint — new cluster
            clusters.append((start, end))

    return len(clusters)


# ─────────────────────────────────────────────────────
# Tier 4 — Attack Tempo
# ─────────────────────────────────────────────────────

def dwell_time_bounds(
    path: TemporalPath,
    ftag: ForensicTemporalAttackGraph,
    window_duration_seconds: float = 3600.0,
) -> Tuple[float, float]:
    """DT_lower = sum of delta_t_min along path.
    DT_upper = |TAC(p)| in seconds."""
    dt_lower = sum(ftag.edges[eid].delta_t_min for eid, _ in path.hops)
    tac_width_windows = path.W_end - path.W_b + 1
    dt_upper = tac_width_windows * window_duration_seconds
    return (dt_lower, dt_upper)


def stage_transition_gaps(path: TemporalPath) -> List[int]:
    """For consecutive hops: delta_k = W(e_{k+1}) - W(e_k).
    Small gaps = fast/automated movement.
    Large gaps = dormancy/staging period."""
    gaps = []
    for i in range(len(path.hops) - 1):
        _, w_curr = path.hops[i]
        _, w_next = path.hops[i + 1]
        gaps.append(w_next - w_curr)
    return gaps


def temporal_propagation_rate(path: TemporalPath) -> float:
    """v(p) = (|p| - 1) / |TAC(p)| in hops per window.
    High v = scripted/automated intrusion.
    Low v = patient, manual intrusion."""
    tac_width = path.W_end - path.W_b + 1
    if tac_width <= 0:
        return float('inf')
    return (path.length - 1) / tac_width


# ─────────────────────────────────────────────────────
# Tier 5 — Host-Level Triage
# ─────────────────────────────────────────────────────

def temporal_chokepoint_score(
    host_node_id: str,
    surviving_paths: List[TemporalPath],
    ftag: ForensicTemporalAttackGraph,
) -> float:
    """chi(h) = fraction of evidentially surviving candidate paths that pass through host h.
    Incident-specific, not a global topology importance score."""
    if not surviving_paths:
        return 0.0
    count_through_h = 0
    for path in surviving_paths:
        nodes_in_path = set()
        for eid, _ in path.hops:
            edge = ftag.edges[eid]
            nodes_in_path.add(edge.src_node_id)
            nodes_in_path.add(edge.dst_node_id)
        if host_node_id in nodes_in_path:
            count_through_h += 1
    return count_through_h / len(surviving_paths)


def host_exposure_window(
    host_node_id: str,
    ftag: ForensicTemporalAttackGraph,
) -> Set[int]:
    """Windows during which host was both vulnerable (present in some E_t)
    and touched by at least one edge."""
    windows = set()
    for edge in ftag.edges.values():
        if edge.src_node_id == host_node_id or edge.dst_node_id == host_node_id:
            windows.update(edge.active_windows)
    return windows


# ─────────────────────────────────────────────────────
# Tier 6 — Investigation Scoping
# ─────────────────────────────────────────────────────

def temporal_search_radius(
    victim_node_id: str,
    ftag: ForensicTemporalAttackGraph,
    paths: List[TemporalPath],
) -> int:
    """T_min(j*) = min over all backward-reachable paths' W_b.
    The earliest window an investigator needs to search from.
    Purely topology-derived, non-circular."""
    victim_paths = [p for p in paths if p.dst_node == victim_node_id]
    if not victim_paths:
        return 0
    return min(p.W_b for p in victim_paths)


# ─────────────────────────────────────────────────────
# Aggregate: Compute all metrics for a single path
# ─────────────────────────────────────────────────────

def compute_all_path_metrics(
    path: TemporalPath,
    ftag: ForensicTemporalAttackGraph,
    evidence_windows: List[int],
) -> Dict:
    """Compute the full metric suite for a single temporal path."""
    tac = temporal_attack_corridor(path)
    fwoc = forensic_window_of_compromise(path, evidence_windows)
    rho = corridor_narrowing_ratio(path, evidence_windows)
    alignment = path_alignment_score(path, ftag)
    hop_detail = per_hop_alignment(path, ftag)
    dt_lo, dt_hi = dwell_time_bounds(path, ftag, ftag.window_duration)
    gaps = stage_transition_gaps(path)
    v = temporal_propagation_rate(path)

    return {
        "tac": tac,
        "tac_width_windows": tac[1] - tac[0] + 1,
        "fwoc": fwoc,
        "fwoc_width_windows": (fwoc[1] - fwoc[0] + 1) if fwoc else 0,
        "narrowing_ratio_rho": rho,
        "alignment_score_A": alignment,
        "hop_alignment_detail": hop_detail,
        "dwell_time_lower_sec": dt_lo,
        "dwell_time_upper_sec": dt_hi,
        "stage_gaps": gaps,
        "propagation_rate_v": v,
        "path_length_hops": path.length,
    }
