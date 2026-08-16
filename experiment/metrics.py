"""
metrics.py — Experiment metrics computation.

Computes per-run: Precision, Recall, F1, Conflict-set accuracy, FPR, Latency.
Computes per-cell: Mean ± 95% CI.
"""

import numpy as np
from typing import Set, Dict, Any


def compute_run_metrics(
    detected: bool,
    conflict_edges: Set[str],
    true_falsified: Set[str],
    elapsed_ms: float,
    is_control: bool = False,
) -> Dict[str, Any]:
    """
    Compute metrics for a single experiment run.
    
    Args:
        detected: Did the method flag falsification?
        conflict_edges: Set of edge IDs flagged by the method
        true_falsified: Set of edge IDs that were actually falsified
        elapsed_ms: Detection latency in milliseconds
        is_control: True if this is a control run (Δt = 0)
    """
    n_flagged = len(conflict_edges)
    n_true = len(true_falsified)
    
    if is_control:
        # Control run: no falsification. Any detection = false positive.
        return {
            "detected": detected,
            "precision": 1.0 if not detected else 0.0,
            "recall": 1.0,  # Nothing to recall
            "f1": 1.0 if not detected else 0.0,
            "conflict_set_accuracy": 1.0 if n_flagged == 0 else 0.0,
            "false_positive": detected,
            "false_positive_rate": 1.0 if detected else 0.0,
            "latency_ms": elapsed_ms,
            "n_flagged": n_flagged,
            "n_true_falsified": 0,
        }
    
    # True positives: flagged AND actually falsified
    tp = len(conflict_edges & true_falsified)
    # False positives: flagged but NOT actually falsified
    fp = len(conflict_edges - true_falsified)
    # False negatives: actually falsified but NOT flagged
    fn = len(true_falsified - conflict_edges)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if n_true == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if n_true == 0 else 0.0)
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    # Conflict set accuracy: exact match (flagged set == true falsified set)
    conflict_set_accuracy = 1.0 if conflict_edges == true_falsified else 0.0
    
    return {
        "detected": detected,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "conflict_set_accuracy": conflict_set_accuracy,
        "false_positive": fp > 0,
        "false_positive_rate": fp / max(n_flagged, 1),
        "latency_ms": elapsed_ms,
        "n_flagged": n_flagged,
        "n_true_falsified": n_true,
    }


def aggregate_metrics(run_results: list) -> Dict[str, Any]:
    """
    Aggregate metrics across multiple runs (e.g., 30 trials per cell).
    
    Returns mean ± 95% CI for each metric.
    """
    if not run_results:
        return {}
    
    metric_keys = ["precision", "recall", "f1", "conflict_set_accuracy",
                    "false_positive_rate", "latency_ms"]
    
    aggregated = {}
    n = len(run_results)
    
    for key in metric_keys:
        values = [r[key] for r in run_results if key in r]
        if not values:
            continue
        
        arr = np.array(values, dtype=float)
        mean = np.mean(arr)
        std = np.std(arr, ddof=1) if len(arr) > 1 else 0.0
        ci_95 = 1.96 * std / np.sqrt(n) if n > 1 else 0.0
        
        aggregated[key] = {
            "mean": mean,
            "std": std,
            "ci_95": ci_95,
            "min": np.min(arr),
            "max": np.max(arr),
            "n": n,
        }
    
    # Detection rate (fraction of runs where falsification was detected)
    detected_values = [1.0 if r["detected"] else 0.0 for r in run_results]
    arr = np.array(detected_values)
    aggregated["detection_rate"] = {
        "mean": np.mean(arr),
        "std": np.std(arr, ddof=1) if n > 1 else 0.0,
        "ci_95": 1.96 * (np.std(arr, ddof=1) / np.sqrt(n)) if n > 1 else 0.0,
        "n": n,
    }
    
    return aggregated


def format_metric(agg: dict, key: str) -> str:
    """Format an aggregated metric as 'mean ± CI'."""
    if key not in agg:
        return "N/A"
    m = agg[key]
    return f"{m['mean']:.3f} ± {m['ci_95']:.3f}"
