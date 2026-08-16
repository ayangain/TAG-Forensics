"""
tag_forensic_metrics.py
------------------------
Corrected evaluation metrics for the TAG-vs-Zhang-et-al. falsification
detection experiment.

Fixes relative to the original report:

1. FPR was reported as "1.000 (0 false positives)" -- self-contradictory.
   Corrected FPR = FP / (FP + TN), which is 0.0 when there truly are no
   false positives.

2. Control runs (Delta t = 0, nothing falsified) were scored with
   precision=0.0, recall=1.0 (silently defaulted), producing meaningless
   F1=0.0 rows folded into the main sweep table. These are now handled as
   a dedicated sanity check with an honest "did anything get wrongly
   flagged, yes/no, and what" report -- and are excluded from the main
   F1 aggregation entirely (None, not 0.0 or 1.0).

3. Added a relaxed hop-distance-based accuracy metric alongside strict
   edge-match F1, since strict exact-edge match may be an unnecessarily
   harsh metric for forensic usefulness (flagging the *right region* of
   the graph is still useful to an investigator even if not the exact edge).

4. Added a mean/95% CI aggregator that correctly excludes undefined (None)
   values rather than treating them as 0.0/1.0 before averaging.
"""

from dataclasses import dataclass, field
from typing import Set, Tuple, Dict, List, Optional
import math
import statistics
import networkx as nx


Edge = Tuple[str, str]  # (source_node, target_node)


# ---------------------------------------------------------------------------
# 1. Strict edge-match metrics (corrected)
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """One run's detection output, scored against ground truth."""
    true_falsified_edges: Set[Edge]   # ground truth: which edges were actually falsified
    flagged_edges: Set[Edge]          # what the detector flagged as falsified/conflicting
    all_evidence_edges: Set[Edge]     # every edge carrying evidence in this run


def strict_edge_metrics(result: DetectionResult) -> Dict[str, Optional[float]]:
    """
    Precision / recall / F1 / FPR over edge-level falsification flags,
    with correct handling of the zero-falsification (control) case.
    """
    true_pos = result.flagged_edges & result.true_falsified_edges
    false_pos = result.flagged_edges - result.true_falsified_edges
    false_neg = result.true_falsified_edges - result.flagged_edges
    true_neg = (result.all_evidence_edges
                - result.true_falsified_edges
                - result.flagged_edges)

    n_tp, n_fp, n_fn, n_tn = len(true_pos), len(false_pos), len(false_neg), len(true_neg)
    n_true_falsified = len(result.true_falsified_edges)

    if n_tp + n_fp == 0:
        precision = None
    else:
        precision = n_tp / (n_tp + n_fp)

    if n_true_falsified == 0:
        recall = None
    else:
        recall = n_tp / (n_tp + n_fn)

    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)

    if n_fp + n_tn == 0:
        fpr = None
    else:
        fpr = n_fp / (n_fp + n_tn)

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "tp": n_tp,
        "fp": n_fp,
        "fn": n_fn,
        "tn": n_tn,
    }


# ---------------------------------------------------------------------------
# 2. Control-run sanity check (kept separate from the main sweep table)
# ---------------------------------------------------------------------------

@dataclass
class ControlCheckResult:
    n_control_runs: int
    n_runs_with_any_false_flag: int
    total_false_flags: int
    flagged_details: List[Tuple[int, Set[Edge]]] = field(default_factory=list)

    @property
    def clean_rate(self) -> float:
        """Fraction of control runs with ZERO false flags. Should be 1.0."""
        if self.n_control_runs == 0:
            return float("nan")
        return 1.0 - (self.n_runs_with_any_false_flag / self.n_control_runs)


def run_control_sanity_check(control_results: List[DetectionResult]) -> ControlCheckResult:
    """
    Dedicated check for Delta t = 0 runs: did the detector correctly stay
    silent? Reports clean_rate plus details on false flags.
    """
    n_with_false_flag = 0
    total_false_flags = 0
    details = []

    for i, result in enumerate(control_results):
        assert not result.true_falsified_edges, (
            f"Run {i} passed to control check but has non-empty "
            f"true_falsified_edges -- this is not actually a control run."
        )
        false_flags = result.flagged_edges
        if false_flags:
            n_with_false_flag += 1
            total_false_flags += len(false_flags)
            details.append((i, false_flags))

    return ControlCheckResult(
        n_control_runs=len(control_results),
        n_runs_with_any_false_flag=n_with_false_flag,
        total_false_flags=total_false_flags,
        flagged_details=details,
    )


# ---------------------------------------------------------------------------
# 3. Relaxed hop-distance-based accuracy metric
# ---------------------------------------------------------------------------

def build_edge_adjacency_graph(evidence_edges: Set[Edge]) -> nx.Graph:
    """
    Graph over EDGES of the attack graph (line-graph style):
    two evidence edges are adjacent if they share a host endpoint.
    """
    nodes = list(evidence_edges)
    G = nx.Graph()
    G.add_nodes_from(nodes)
    for i, e1 in enumerate(nodes):
        for e2 in nodes[i + 1:]:
            if set(e1) & set(e2):
                G.add_edge(e1, e2)
    return G


def hop_distance_between_edges(graph: nx.Graph, e1: Edge, e2: Edge) -> Optional[int]:
    if e1 == e2:
        return 0
    try:
        return nx.shortest_path_length(graph, e1, e2)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None


def relaxed_hop_accuracy(
    result: DetectionResult,
    max_hop_tolerance: int = 1,
) -> Dict[str, Optional[float]]:
    """
    Credits a flag if it lands within `max_hop_tolerance` attack-graph hops
    of a truly falsified edge.
    """
    if not result.all_evidence_edges:
        return {"hop_tolerance": max_hop_tolerance, "relaxed_precision": None, "relaxed_recall": None, "relaxed_f1": None}

    graph = build_edge_adjacency_graph(result.all_evidence_edges)

    def within_tolerance(flagged: Edge) -> bool:
        return any(
            (d := hop_distance_between_edges(graph, flagged, t)) is not None
            and d <= max_hop_tolerance
            for t in result.true_falsified_edges
        )

    def found_by_some_flag(true_edge: Edge) -> bool:
        return any(
            (d := hop_distance_between_edges(graph, flagged, true_edge)) is not None
            and d <= max_hop_tolerance
            for flagged in result.flagged_edges
        )

    relaxed_true_pos = {e for e in result.flagged_edges if within_tolerance(e)}
    relaxed_false_pos = result.flagged_edges - relaxed_true_pos
    relaxed_found = {t for t in result.true_falsified_edges if found_by_some_flag(t)}

    n_rtp, n_rfp = len(relaxed_true_pos), len(relaxed_false_pos)
    n_found = len(relaxed_found)
    n_true = len(result.true_falsified_edges)

    relaxed_precision = n_rtp / (n_rtp + n_rfp) if (n_rtp + n_rfp) > 0 else None
    relaxed_recall = n_found / n_true if n_true > 0 else None

    if relaxed_precision is not None and relaxed_recall is not None and (relaxed_precision + relaxed_recall) > 0:
        relaxed_f1 = 2 * relaxed_precision * relaxed_recall / (relaxed_precision + relaxed_recall)
    else:
        relaxed_f1 = None

    return {
        "hop_tolerance": max_hop_tolerance,
        "relaxed_precision": relaxed_precision,
        "relaxed_recall": relaxed_recall,
        "relaxed_f1": relaxed_f1,
    }


# ---------------------------------------------------------------------------
# 4. Aggregation: mean +/- 95% CI, correctly excluding undefined values
# ---------------------------------------------------------------------------

_T_TABLE = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776, 6: 2.571, 7: 2.447,
            8: 2.365, 9: 2.306, 10: 2.262, 15: 2.145, 20: 2.093, 30: 2.045}


def mean_ci95(values: List[Optional[float]]) -> Tuple[Optional[float], Optional[float], int]:
    """
    Mean and 95% CI half-width over a list that may contain None entries.
    None values are excluded from the mean rather than coerced to 0.0/1.0.
    """
    clean = [v for v in values if v is not None]
    n = len(clean)
    if n == 0:
        return None, None, 0
    if n == 1:
        return clean[0], None, 1
    m = statistics.mean(clean)
    sd = statistics.stdev(clean)
    mult = _T_TABLE.get(n, 1.96)
    ci = mult * sd / math.sqrt(n)
    return m, ci, n
