"""
run_lldos2_experiment.py — Replication experiment runner for LLDOS 2.0.2 (stealthy scenario).

Integrates tag_forensic_metrics.py:
- Dedicated control sanity check (Delta t = 0)
- Strict and relaxed 1-hop accuracy evaluation
- None-aware mean/95% CI aggregation
"""

import os
import sys
import json
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiment.parse_lldos_data import build_lldos202_evidence_graph
from experiment.run_experiment import run_sweep_1, run_sweep_2, run_control_check, export_csv


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_path = os.path.join(base_dir, "LLDOS 2.0.2")
    results_dir = os.path.join(base_dir, "experiment", "results")
    os.makedirs(results_dir, exist_ok=True)

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  DARPA LLDOS 2.0.2 Stealthy Scenario Experiment (Corrected)   ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    base_graph = build_lldos202_evidence_graph(dataset_path)

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

    out_csv = os.path.join(results_dir, "lldos_2.0.2_results.csv")
    export_csv(all_res, out_csv)

    ctrl_json = os.path.join(results_dir, "lldos_2.0.2_control_check.json")
    with open(ctrl_json, "w") as f:
        json.dump(ctrl_res, f, indent=2)

    print("\nLLDOS 2.0.2 Experiment completed successfully.")


if __name__ == "__main__":
    main()
