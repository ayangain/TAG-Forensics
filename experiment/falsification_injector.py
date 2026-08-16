"""
falsification_injector.py — Synthetic timestamp falsification injection.

Implements 4 falsification types:
  (a) shift_later: Push event forward in time
  (b) shift_earlier: Push event backward in time
  (c) swap: Swap timestamps of two causally linked events
  (d) adversarial: Shift to make a false alternate path look valid
"""

import numpy as np
from typing import List, Tuple
from experiment.evidence_graph import EvidenceGraph


def inject_falsification(
    evidence_graph: EvidenceGraph,
    magnitude_seconds: float,
    num_falsified: int,
    falsification_type: str,  # "shift_later", "shift_earlier", "swap", "adversarial"
    rng: np.random.Generator,
    target_edge_ids: List[str] = None,
) -> Tuple[EvidenceGraph, set]:
    """
    Inject timestamp falsification into the evidence graph.
    
    Args:
        evidence_graph: Clean evidence graph
        magnitude_seconds: How much to shift (0 = control)
        num_falsified: Number of events to falsify (1, 2, or 3)
        falsification_type: Type of falsification
        rng: Random number generator
        target_edge_ids: Specific edges to falsify (if None, randomly selected)
    
    Returns:
        (modified_graph, set_of_falsified_edge_ids)
    """
    if magnitude_seconds == 0:
        # Control run — no falsification
        eg = evidence_graph.deep_copy()
        return eg, set()
    
    eg = evidence_graph.deep_copy()
    
    # Select edges to falsify
    causal_edges = [e for e in eg.edges.values() if e.has_evidence and e.phase > 0]
    
    if target_edge_ids:
        targets = [eg.edges[eid] for eid in target_edge_ids if eid in eg.edges]
    else:
        # Randomly select from causal (non-noise) edges
        n = min(num_falsified, len(causal_edges))
        indices = rng.choice(len(causal_edges), size=n, replace=False)
        targets = [causal_edges[i] for i in indices]
    
    falsified_ids = set()
    
    if falsification_type == "shift_later":
        for edge in targets:
            edge.observed_start += magnitude_seconds
            edge.observed_end += magnitude_seconds
            edge.is_falsified = True
            falsified_ids.add(edge.edge_id)
    
    elif falsification_type == "shift_earlier":
        for edge in targets:
            edge.observed_start -= magnitude_seconds
            edge.observed_end -= magnitude_seconds
            edge.is_falsified = True
            falsified_ids.add(edge.edge_id)
    
    elif falsification_type == "swap":
        # Swap timestamps between pairs of causally linked events
        if len(targets) >= 2:
            for i in range(0, len(targets) - 1, 2):
                e1 = targets[i]
                e2 = targets[i + 1]
                # Swap observed timestamps
                e1.observed_start, e2.observed_start = e2.observed_start, e1.observed_start
                e1.observed_end, e2.observed_end = e2.observed_end, e1.observed_end
                e1.is_falsified = True
                e2.is_falsified = True
                falsified_ids.add(e1.edge_id)
                falsified_ids.add(e2.edge_id)
        elif len(targets) == 1:
            # With only 1 target, shift it to overlap with a different phase
            edge = targets[0]
            # Find an edge in a different phase
            other_phases = [e for e in causal_edges if e.phase != edge.phase]
            if other_phases:
                other = rng.choice(other_phases)
                edge.observed_start = other.observed_start
                edge.observed_end = other.observed_end
                edge.is_falsified = True
                falsified_ids.add(edge.edge_id)
    
    elif falsification_type == "adversarial":
        # Adversarial: shift timestamps to make a false path look valid
        # Strategy: make it look like the attack went through hume (probed but
        # not actually compromised) instead of through mill
        for edge in targets:
            # Shift the edge so it appears to occur *before* its causal
            # predecessor, creating an impossible ordering that mimics
            # a plausible alternate route
            
            # Find the latest predecessor's end time
            predecessor_end = float('-inf')
            for c in evidence_graph.constraints:
                if c.edge_after_id == edge.edge_id:
                    pred_edge = eg.edges.get(c.edge_before_id)
                    if pred_edge and pred_edge.has_evidence:
                        predecessor_end = max(predecessor_end, pred_edge.observed_end)
            
            if predecessor_end > float('-inf'):
                # Place this edge's start just before the predecessor ends
                # This is calibrated to be subtle — only violates by the magnitude
                edge.observed_start = predecessor_end - magnitude_seconds
                edge.observed_end = edge.observed_start + (edge.true_end - edge.true_start)
            else:
                # No predecessor found, just shift earlier
                edge.observed_start -= magnitude_seconds
                edge.observed_end -= magnitude_seconds
            
            edge.is_falsified = True
            falsified_ids.add(edge.edge_id)
    
    else:
        raise ValueError(f"Unknown falsification type: {falsification_type}")
    
    return eg, falsified_ids


def apply_evidence_completeness(
    evidence_graph: EvidenceGraph,
    completeness: float,
    rng: np.random.Generator,
) -> EvidenceGraph:
    """
    Remove evidence from a fraction of causal edges.
    
    Args:
        completeness: Fraction of edges to keep (1.0 = 100%, 0.25 = 25%)
    """
    eg = evidence_graph.deep_copy()
    
    causal_edges = [e for e in eg.edges.values() if e.phase > 0]  # Skip noise
    n_to_remove = int(len(causal_edges) * (1.0 - completeness))
    
    if n_to_remove > 0 and len(causal_edges) > 0:
        indices = rng.choice(len(causal_edges), size=min(n_to_remove, len(causal_edges)), replace=False)
        for i in indices:
            causal_edges[i].has_evidence = False
    
    return eg
