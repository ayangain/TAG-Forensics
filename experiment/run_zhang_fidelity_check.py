"""
run_zhang_fidelity_check.py — Re-evaluate Zhang et al. (2015) baseline
under low noise (0x and 10x) to verify baseline fidelity.
"""

import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiment.parse_lldos_data import build_lldos10_evidence_graph
from experiment.synthetic_sources import split_to_sources, inject_noise
from experiment.falsification_injector import inject_falsification
from experiment.method_zhang import detect_zhang
from experiment.tag_forensic_metrics import DetectionResult, strict_edge_metrics, relaxed_hop_accuracy, mean_ci95


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_path = os.path.join(base_dir, "LLS_DDOS_1.0")
    base_graph = build_lldos10_evidence_graph(dataset_path)

    print("=== Zhang et al. Baseline Fidelity Check (0x vs 10x noise) ===")

    noise_levels = [0.0, 10.0]
    magnitudes = [60, 600, 3600, 21600]
    f_types = ["shift_later", "swap", "adversarial"]

    rows = []

    for noise in noise_levels:
        for mag in magnitudes:
            for f_type in f_types:
                results_strict_f1 = []
                results_relaxed_f1 = []
                results_prec = []
                results_rec = []

                for trial in range(30):
                    rng = np.random.default_rng(42 + trial)
                    eg = split_to_sources(base_graph, rng)
                    eg = inject_noise(eg, noise, rng)
                    eg, falsified_ids = inject_falsification(eg, mag, 2, f_type, rng)

                    all_edges = {(e.src, e.dst) for e in eg.edges.values() if e.has_evidence}
                    true_edges = {(eg.edges[eid].src, eg.edges[eid].dst) for eid in falsified_ids if eid in eg.edges}

                    det, flagged_ids, _ = detect_zhang(eg)
                    flagged_edges = {(eg.edges[eid].src, eg.edges[eid].dst) for eid in flagged_ids if eid in eg.edges}

                    res = DetectionResult(true_edges, flagged_edges, all_edges)
                    sm = strict_edge_metrics(res)
                    rm = relaxed_hop_accuracy(res, 1)

                    results_strict_f1.append(sm["f1"])
                    results_relaxed_f1.append(rm["relaxed_f1"])
                    results_prec.append(sm["precision"])
                    results_rec.append(sm["recall"])

                f1_m, f1_ci, _ = mean_ci95(results_strict_f1)
                rf1_m, rf1_ci, _ = mean_ci95(results_relaxed_f1)
                p_m, _, _ = mean_ci95(results_prec)
                r_m, _, _ = mean_ci95(results_rec)

                rows.append({
                    "noise_ratio": f"{noise:.0f}x",
                    "magnitude": f"{mag}s",
                    "falsification_type": f_type,
                    "precision": f"{p_m:.3f}" if p_m is not None else "N/A",
                    "recall": f"{r_m:.3f}" if r_m is not None else "N/A",
                    "strict_f1": f"{f1_m:.3f} ± {f1_ci:.3f}" if f1_m is not None else "N/A",
                    "relaxed_f1": f"{rf1_m:.3f} ± {rf1_ci:.3f}" if rf1_m is not None else "N/A",
                })

    df = pd.DataFrame(rows)
    print("\n" + df.to_string(index=False))

    out_path = os.path.join(base_dir, "experiment", "results", "zhang_fidelity_check.csv")
    df.to_csv(out_path, index=False)
    print(f"\nFidelity check saved to {out_path}")


if __name__ == "__main__":
    main()
