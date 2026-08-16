"""
run_experiment.py — Main experiment runner for LLDOS falsification detection.

Integrates tag_forensic_metrics.py:
- Control runs (Delta t = 0) are evaluated separately via run_control_sanity_check()
- Non-control runs compute both strict edge-match metrics and relaxed 1-hop accuracy
- Mean ± 95% CI is computed using mean_ci95() which correctly excludes None entries
"""

import os
import sys
import json
import time
import itertools
import numpy as np
import pandas as pd
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiment.evidence_graph import EvidenceGraph
from experiment.parse_lldos_data import build_lldos10_evidence_graph
from experiment.synthetic_sources import split_to_sources, inject_noise
from experiment.falsification_injector import inject_falsification, apply_evidence_completeness
from experiment.method_stn import detect_falsification
from experiment.method_zhang import detect_zhang
from experiment.tag_forensic_metrics import (
    DetectionResult, strict_edge_metrics, relaxed_hop_accuracy,
    run_control_sanity_check, mean_ci95
)

MAGNITUDES = {
    "1min": 60,
    "10min": 600,
    "1hr": 3600,
    "6hr": 21600,
}

NUM_FALSIFIED = [1, 2, 3]
FALSIFICATION_TYPES = ["shift_later", "shift_earlier", "swap", "adversarial"]
COMPLETENESS_LEVELS = [1.0, 0.75, 0.50, 0.25]
NOISE_RATIO = 10.0
TRIALS_PER_CELL = 30
BASE_SEED = 42


def run_single_trial(
    base_graph: EvidenceGraph,
    magnitude_seconds: float,
    num_falsified: int,
    falsification_type: str,
    completeness: float,
    noise_ratio: float,
    trial_seed: int,
) -> dict:
    """Run a single trial and return DetectionResults for both methods."""
    rng = np.random.default_rng(trial_seed)

    eg = apply_evidence_completeness(base_graph, completeness, rng)
    eg = split_to_sources(eg, rng)
    eg = inject_noise(eg, noise_ratio, rng)
    eg, true_falsified_ids = inject_falsification(
        eg, magnitude_seconds, num_falsified, falsification_type, rng
    )

    all_edges = {(e.src, e.dst) for e in eg.edges.values() if e.has_evidence}
    true_edges = {(eg.edges[eid].src, eg.edges[eid].dst) for eid in true_falsified_ids if eid in eg.edges}

    # Our method
    stn_det, stn_ids, stn_ms = detect_falsification(eg, method="both")
    stn_edges = {(eg.edges[eid].src, eg.edges[eid].dst) for eid in stn_ids if eid in eg.edges}
    stn_res = DetectionResult(true_edges, stn_edges, all_edges)

    # Zhang method
    zh_det, zh_ids, zh_ms = detect_zhang(eg)
    zh_edges = {(eg.edges[eid].src, eg.edges[eid].dst) for eid in zh_ids if eid in eg.edges}
    zh_res = DetectionResult(true_edges, zh_edges, all_edges)

    return {
        "stn_res": stn_res,
        "zh_res": zh_res,
        "stn_ms": stn_ms,
        "zh_ms": zh_ms,
        "stn_det": stn_det,
        "zh_det": zh_det,
    }


def run_control_check(base_graph: EvidenceGraph, n_trials: int = 50) -> dict:
    """Run dedicated control sanity check (Delta t = 0) with zero falsification."""
    stn_control = []
    zh_control = []

    for trial in range(n_trials):
        seed = BASE_SEED + trial
        res = run_single_trial(
            base_graph, magnitude_seconds=0, num_falsified=0,
            falsification_type="shift_later", completeness=1.0,
            noise_ratio=NOISE_RATIO, trial_seed=seed
        )
        stn_control.append(res["stn_res"])
        zh_control.append(res["zh_res"])

    stn_check = run_control_sanity_check(stn_control)
    zh_check = run_control_sanity_check(zh_control)

    return {
        "our_method": {
            "n_control_runs": stn_check.n_control_runs,
            "clean_rate": stn_check.clean_rate,
            "false_flag_runs": stn_check.n_runs_with_any_false_flag,
        },
        "zhang_baseline": {
            "n_control_runs": zh_check.n_control_runs,
            "clean_rate": zh_check.clean_rate,
            "false_flag_runs": zh_check.n_runs_with_any_false_flag,
        }
    }


def aggregate_cell_runs(runs: list) -> dict:
    """Aggregate DetectionResults for a cell into strict and relaxed metrics."""
    stn_results = [r["stn_res"] for r in runs]
    zh_results = [r["zh_res"] for r in runs]

    def calc_metrics(res_list, ms_list):
        strict_list = [strict_edge_metrics(r) for r in res_list]
        relaxed_list = [relaxed_hop_accuracy(r, max_hop_tolerance=1) for r in res_list]

        p_m, p_ci, _ = mean_ci95([s["precision"] for s in strict_list])
        r_m, r_ci, _ = mean_ci95([s["recall"] for s in strict_list])
        f1_m, f1_ci, n_u = mean_ci95([s["f1"] for s in strict_list])
        fpr_m, fpr_ci, _ = mean_ci95([s["fpr"] for s in strict_list])

        rp_m, rp_ci, _ = mean_ci95([s["relaxed_precision"] for s in relaxed_list])
        rr_m, rr_ci, _ = mean_ci95([s["relaxed_recall"] for s in relaxed_list])
        rf1_m, rf1_ci, _ = mean_ci95([s["relaxed_f1"] for s in relaxed_list])

        lat_m, lat_ci, _ = mean_ci95(ms_list)

        return {
            "precision_mean": p_m, "precision_ci95": p_ci,
            "recall_mean": r_m, "recall_ci95": r_ci,
            "f1_mean": f1_m, "f1_ci95": f1_ci,
            "fpr_mean": fpr_m, "fpr_ci95": fpr_ci,
            "relaxed_precision_mean": rp_m, "relaxed_precision_ci95": rp_ci,
            "relaxed_recall_mean": rr_m, "relaxed_recall_ci95": rr_ci,
            "relaxed_f1_mean": rf1_m, "relaxed_f1_ci95": rf1_ci,
            "latency_ms_mean": lat_m, "latency_ms_ci95": lat_ci,
            "n_used": n_u,
        }

    return {
        "our_method": calc_metrics(stn_results, [r["stn_ms"] for r in runs]),
        "zhang_baseline": calc_metrics(zh_results, [r["zh_ms"] for r in runs]),
    }


def run_sweep_1(base_graph: EvidenceGraph) -> list:
    """Sweep 1: Fix completeness=100%, sweep magnitude × type × count."""
    results = []
    completeness = 1.0

    cells = list(itertools.product(
        MAGNITUDES.items(), FALSIFICATION_TYPES, NUM_FALSIFIED
    ))

    print(f"\n═══ Sweep 1: Magnitude × Type × Count (completeness=100%) ═══")
    print(f"    {len(cells)} cells × {TRIALS_PER_CELL} trials = {len(cells)*TRIALS_PER_CELL} runs")

    for (mag_name, mag_sec), f_type, n_fals in cells:
        cell_runs = []
        for trial in range(TRIALS_PER_CELL):
            seed = BASE_SEED + hash((mag_name, f_type, n_fals, trial)) % (2**31)
            res = run_single_trial(
                base_graph, mag_sec, n_fals, f_type, completeness, NOISE_RATIO, seed
            )
            cell_runs.append(res)

        agg = aggregate_cell_runs(cell_runs)

        results.append({
            "sweep": 1,
            "magnitude": mag_name,
            "magnitude_seconds": mag_sec,
            "falsification_type": f_type,
            "num_falsified": n_fals,
            "completeness": completeness,
            "our_method": agg["our_method"],
            "zhang_baseline": agg["zhang_baseline"],
        })

    return results


def run_sweep_2(base_graph: EvidenceGraph) -> list:
    """Sweep 2: Fix type=adversarial, sweep completeness × magnitude × count."""
    results = []
    f_type = "adversarial"

    cells = list(itertools.product(
        COMPLETENESS_LEVELS, MAGNITUDES.items(), NUM_FALSIFIED
    ))

    print(f"\n═══ Sweep 2: Completeness × Magnitude × Count (type=adversarial) ═══")
    print(f"    {len(cells)} cells × {TRIALS_PER_CELL} trials = {len(cells)*TRIALS_PER_CELL} runs")

    for compl, (mag_name, mag_sec), n_fals in cells:
        cell_runs = []
        for trial in range(TRIALS_PER_CELL):
            seed = BASE_SEED + hash((compl, mag_name, n_fals, trial)) % (2**31)
            res = run_single_trial(
                base_graph, mag_sec, n_fals, f_type, compl, NOISE_RATIO, seed
            )
            cell_runs.append(res)

        agg = aggregate_cell_runs(cell_runs)

        results.append({
            "sweep": 2,
            "magnitude": mag_name,
            "magnitude_seconds": mag_sec,
            "falsification_type": f_type,
            "num_falsified": n_fals,
            "completeness": compl,
            "our_method": agg["our_method"],
            "zhang_baseline": agg["zhang_baseline"],
        })

    return results


def export_csv(results: list, output_path: str):
    rows = []
    for r in results:
        for m_name in ["our_method", "zhang_baseline"]:
            agg = r[m_name]
            row = {
                "sweep": r["sweep"],
                "method": m_name,
                "magnitude": r["magnitude"],
                "magnitude_seconds": r["magnitude_seconds"],
                "falsification_type": r["falsification_type"],
                "num_falsified": r["num_falsified"],
                "completeness": r["completeness"],
            }
            row.update(agg)
            rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv(output_path, index=False)
    print(f"CSV exported to {output_path}")


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_path = os.path.join(base_dir, "LLS_DDOS_1.0")
    results_dir = os.path.join(base_dir, "experiment", "results")
    os.makedirs(results_dir, exist_ok=True)

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  DARPA LLDOS 1.0 Falsification Detection Experiment (Corrected)║")
    print("╚══════════════════════════════════════════════════════════════╝")

    base_graph = build_lldos10_evidence_graph(dataset_path)

    print("\n[1/3] Running Control Sanity Check (Delta t = 0)...")
    ctrl_res = run_control_check(base_graph)
    print(f"  Our Method Control Clean Rate: {ctrl_res['our_method']['clean_rate']:.1%} "
          f"({ctrl_res['our_method']['false_flag_runs']}/{ctrl_res['our_method']['n_control_runs']} false flags)")
    print(f"  Zhang Baseline Control Clean Rate: {ctrl_res['zhang_baseline']['clean_rate']:.1%} "
          f"({ctrl_res['zhang_baseline']['false_flag_runs']}/{ctrl_res['zhang_baseline']['n_control_runs']} false flags)")

    print("\n[2/3] Running Sweep 1 & Sweep 2...")
    res1 = run_sweep_1(base_graph)
    res2 = run_sweep_2(base_graph)

    all_res = res1 + res2

    out_csv = os.path.join(results_dir, "lldos_1.0_results.csv")
    export_csv(all_res, out_csv)

    ctrl_json = os.path.join(results_dir, "lldos_1.0_control_check.json")
    with open(ctrl_json, "w") as f:
        json.dump(ctrl_res, f, indent=2)

    print("\nExperiment completed successfully.")


if __name__ == "__main__":
    main()
