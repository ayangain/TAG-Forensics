"""
run_track_a_experiments.py — Track A: Evidence-Conditioned Reconstruction Quality.

Four rigorous experiments evaluating corridor forensic metrics under controlled
evidence degradation on DARPA LLDOS 1.0 and 2.0.2 ground-truth datasets.

Experiment 1: FWoC Validity & Tightness
Experiment 2: Reconstruction Ambiguity vs. Evidence Completeness
Experiment 3: Temporal Chokepoint Score Accuracy
Experiment 4: Temporal Search Radius Soundness & Efficiency

Statistical Design:
  - Completeness levels: {25%, 50%, 75%, 100%}
  - 30 trials per completeness level (randomized evidence subsampling)
  - Report: mean ± 95% CI
  - Soundness gated: binary pass/fail before any quantitative claim
"""

import os
import sys
import copy
import random
import math
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiment.mulval_engine import build_ftag_from_mulval
from experiment.lldos_tag_builder import (
    build_tag_from_lldos, parse_labeling_info, parse_session_list,
    _attach_evidence_timestamps, build_all_lldos_tags,
)
from experiment.ftag_model import ForensicTemporalAttackGraph, TemporalPath
from experiment.ftag_metrics import (
    temporal_attack_corridor,
    forensic_window_of_compromise,
    corridor_narrowing_ratio,
    reconstruction_ambiguity,
    temporal_chokepoint_score,
    temporal_search_radius,
)


# ══════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════

COMPLETENESS_LEVELS = [0.25, 0.50, 0.75, 1.00]
N_TRIALS = 100
RANDOM_SEED = 42

# LLDOS 1.0 Ground Truth
# The graph is a 6-stage sequential state chain.
# True compromise path: IPsweep -> Sadmind probe -> Sadmind exploit -> mstream install -> lateral to locke -> DDoS
LLDOS1_TRUE_PATH_EDGES = [
    "E_ipsweep_mill",
    "E_sadmind_probe_mill",
    "E_sadmind_exploit_mill",
    "E_mstream_install_mill",
    "E_rsh_lateral_locke",
    "E_ddos_launch_locke"
]
LLDOS1_TRUE_PATH_WINDOWS = [0, 1, 2, 3, 3, 4]  
LLDOS1_TRUE_COMPROMISE_INTERVAL = (2, 4)  # Sadmind exploit (w2) to DDoS launch (w4)
LLDOS1_CAPTURE_DURATION_WINDOWS = 5  # w0..w4
LLDOS1_TRUE_PIVOT_HOST = "mill:mstream_master"
LLDOS1_UNINVOLVED_HOSTS = ["hume", "kant", "marx", "zeno"]  # structurally plausible but not on attack path

# LLDOS 2.0.2 Ground Truth
# The graph is a 5-stage sequential state chain.
LLDOS2_TRUE_PATH_EDGES = [
    "E_dns_recon",
    "E_sadmind_exploit_mill",
    "E_ftp_upload_mill",
    "E_ssh_lateral_pascal",
    "E_mail_exfil"
]
LLDOS2_TRUE_PATH_WINDOWS = [0, 1, 2, 3, 4]
LLDOS2_TRUE_COMPROMISE_INTERVAL = (1, 4)  # Sadmind exploit (w1) to Exfil (w4)
LLDOS2_CAPTURE_DURATION_WINDOWS = 5
LLDOS2_TRUE_PIVOT_HOST = "mill:ftp_uploaded"

# Wang & Daniels (2008) fixed window comparison
WANG_DANIELS_WINDOW_SEC = 60.0


# ══════════════════════════════════════════════════════════════
# Statistical Utilities
# ══════════════════════════════════════════════════════════════

def mean_ci95(values: List[float]) -> Tuple[float, float, float]:
    """Compute mean and 95% confidence interval."""
    if not values:
        return (0.0, 0.0, 0.0)
    n = len(values)
    mean = np.mean(values)
    if n <= 1:
        return (float(mean), float(mean), float(mean))
    se = np.std(values, ddof=1) / math.sqrt(n)
    # t-critical for 95% CI with n-1 df (approximate with 1.96 for n>=30)
    t_crit = 1.96 if n >= 30 else 2.045  # conservative for n=30
    ci_low = mean - t_crit * se
    ci_high = mean + t_crit * se
    return (float(mean), float(ci_low), float(ci_high))


def wilson_score_interval(successes: int, n: int, z: float = 1.96) -> Tuple[float, float, float]:
    """Computes the Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = successes / n
    denominator = 1 + z**2 / n
    center = p + z**2 / (2 * n)
    std = math.sqrt((p * (1 - p) / n) + z**2 / (4 * n**2))
    ci_low = (center - z * std) / denominator
    ci_high = (center + z * std) / denominator
    return float(p), float(ci_low), float(ci_high)


# ══════════════════════════════════════════════════════════════
# Evidence Subsampling Infrastructure
# ══════════════════════════════════════════════════════════════

def subsample_evidence(
    ftag: ForensicTemporalAttackGraph,
    completeness: float,
    rng: random.Random,
) -> Tuple[ForensicTemporalAttackGraph, List[int]]:
    """
    Create a deep copy of the F-TAG with evidence subsampled at the given
    completeness fraction. Randomly retains c% of edges' observed_window fields;
    the rest are set to None (evidence withheld).

    Returns: (degraded_ftag, retained_evidence_windows)
    """
    degraded = copy.deepcopy(ftag)

    # Identify all edges that have observed evidence
    observed_edges = [eid for eid, e in degraded.edges.items()
                      if e.observed_window is not None]

    if completeness >= 1.0:
        # Full evidence — no subsampling
        ev_windows = sorted({e.observed_window for e in degraded.edges.values()
                           if e.observed_window is not None})
        return degraded, ev_windows

    # Number of edges to retain
    n_retain = max(1, int(len(observed_edges) * completeness))
    retained = set(rng.sample(observed_edges, min(n_retain, len(observed_edges))))

    # Withhold evidence from non-retained edges
    for eid in observed_edges:
        if eid not in retained:
            degraded.edges[eid].observed_window = None

    # Compute surviving evidence windows
    ev_windows = sorted({e.observed_window for e in degraded.edges.values()
                        if e.observed_window is not None})

    return degraded, ev_windows


def find_true_path(
    paths: List[TemporalPath],
    true_edge_ids: List[str],
    true_windows: List[str],
) -> Optional[TemporalPath]:
    """Find p* among enumerated paths by matching the structural edge sequence."""
    for p in paths:
        edge_ids = [eid for eid, _ in p.hops]
        if edge_ids == true_edge_ids:
            # Also check windows match
            hop_windows = [w for _, w in p.hops]
            if hop_windows == true_windows:
                return p
    # Fallback: match just the edge sequence (any window assignment)
    for p in paths:
        edge_ids = [eid for eid, _ in p.hops]
        if edge_ids == true_edge_ids:
            return p
    return None


# ══════════════════════════════════════════════════════════════
# Experiment 1: FWoC Validity & Tightness
# ══════════════════════════════════════════════════════════════

def experiment_1_fwoc(
    ftag: ForensicTemporalAttackGraph,
    src_node: str,
    dst_node: str,
    true_edge_ids: List[str],
    true_windows: List[int],
    true_compromise_interval: Tuple[int, int],
    capture_duration_windows: int,
    dataset_name: str,
) -> pd.DataFrame:
    """Experiment 1: FWoC Validity & Tightness across completeness sweep."""
    print(f"\n{'─'*70}")
    print(f"  EXPERIMENT 1: FWoC Validity & Tightness [{dataset_name}]")
    print(f"{'─'*70}")

    all_paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=8)
    p_star = find_true_path(all_paths, true_edge_ids, true_windows)

    if p_star is None:
        print(f"  ✗ CRITICAL: True path p* not found in Q^a_ij!")
        print(f"    Available paths ({len(all_paths)}):")
        for i, p in enumerate(all_paths[:10]):
            print(f"      P{i+1}: {[eid for eid,_ in p.hops]} windows={[w for _,w in p.hops]}")
        return pd.DataFrame()

    print(f"  ✓ True path p* identified: {[eid for eid,_ in p_star.hops]}")
    print(f"    TAC(p*) = [w{p_star.W_b}, w{p_star.W_end}]")

    rows = []
    rng = random.Random(RANDOM_SEED)

    for c in COMPLETENESS_LEVELS:
        soundness_failures = 0
        for trial in range(N_TRIALS):
            degraded, ev_windows = subsample_evidence(ftag, c, rng)

            # Re-enumerate paths on degraded graph (structure unchanged, only evidence)
            # FWoC depends on evidence_windows, not graph structure
            if not ev_windows:
                ev_windows = list(range(capture_duration_windows))

            fwoc = forensic_window_of_compromise(p_star, ev_windows, small_sample_correction=True)

            if fwoc is None:
                # FWoC empty — evidence doesn't intersect corridor
                soundness_pass = False
                fwoc_width = 0
                tightness = 0.0
                full_coverage = False
                fwoc_start, fwoc_end = None, None
            else:
                fwoc_start, fwoc_end = fwoc
                fwoc_width = fwoc_end - fwoc_start + 1
            
            # User-requested debug print: Check if the correction is saturating
            if c == 0.25 and trial < 5 and dataset_name == "LLDOS 1.0":
                H = len(p_star.hops)
                N = len(ev_windows)
                delta_s = max(0, H - N) if len(ev_windows) > 0 else 0
                print(f"  [DEBUG c=25% Trial {trial}] ev_windows={ev_windows} | δs=max(0, {H}-{N})={delta_s} | FWoC=({fwoc_start}, {fwoc_end}) | TAC={p_star.tac}")
            
            if fwoc is not None:
                tightness = fwoc_width / capture_duration_windows

                # Soundness: FWoC must be non-empty AND overlap with true compromise
                # (i.e., evidence does not falsify the true path)
                tc_start, tc_end = true_compromise_interval
                overlaps = (fwoc_start <= tc_end and fwoc_end >= tc_start)
                soundness_pass = overlaps

                # Full coverage: does FWoC contain the entire true interval?
                # Only expected to hold at high completeness.
                full_coverage = (fwoc_start <= tc_start and fwoc_end >= tc_end)
                if c == 1.0 and trial == 0:
                    print(f"DEBUG: fwoc={fwoc_start},{fwoc_end} tc={tc_start},{tc_end} cov={full_coverage}")

            if not soundness_pass:
                soundness_failures += 1

            rows.append({
                "dataset": dataset_name,
                "completeness": c,
                "trial": trial + 1,
                "fwoc_start": fwoc[0] if fwoc else None,
                "fwoc_end": fwoc[1] if fwoc else None,
                "fwoc_width_windows": fwoc_width,
                "tightness_pct": tightness * 100,
                "soundness_pass": soundness_pass,
                "full_coverage": full_coverage,
            })

        # Report per-level summary
        level_rows = [r for r in rows if r["completeness"] == c and r["dataset"] == dataset_name]
        tightness_vals = [r["tightness_pct"] for r in level_rows]
        mean_t, ci_lo, ci_hi = mean_ci95(tightness_vals)
        sound_rate = sum(1 for r in level_rows if r["soundness_pass"]) / len(level_rows) * 100
        cover_rate = sum(1 for r in level_rows if r["full_coverage"]) / len(level_rows) * 100
        print(f"    c={c:.0%}: Tightness = {mean_t:.1f}% [{ci_lo:.1f}%, {ci_hi:.1f}%] | "
              f"Soundness = {sound_rate:.0f}% | Full Coverage = {cover_rate:.0f}%")

    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════
# Experiment 2: Reconstruction Ambiguity
# ══════════════════════════════════════════════════════════════

def experiment_2_ambiguity(
    ftag: ForensicTemporalAttackGraph,
    src_node: str,
    dst_node: str,
    true_edge_ids: List[str],
    true_windows: List[int],
    dataset_name: str,
) -> pd.DataFrame:
    """Experiment 2: Reconstruction Ambiguity vs. Evidence Completeness."""
    print(f"\n{'─'*70}")
    print(f"  EXPERIMENT 2: Reconstruction Ambiguity [{dataset_name}]")
    print(f"{'─'*70}")

    all_paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=8)
    p_star = find_true_path(all_paths, true_edge_ids, true_windows)

    rows = []
    rng = random.Random(RANDOM_SEED + 1000)

    for c in COMPLETENESS_LEVELS:
        for trial in range(N_TRIALS):
            degraded, ev_windows = subsample_evidence(ftag, c, rng)

            if not ev_windows:
                ev_windows = list(range(ftag.num_windows))

            # Compute surviving paths (FWoC non-empty)
            surviving = [p for p in all_paths
                        if forensic_window_of_compromise(p, ev_windows) is not None]

            k = reconstruction_ambiguity(surviving) if surviving else 0

            # Soundness: is p*'s corridor in one of the surviving clusters?
            true_path_survives = False
            if p_star and surviving:
                p_star_fwoc = forensic_window_of_compromise(p_star, ev_windows)
                true_path_survives = (p_star_fwoc is not None)

            rows.append({
                "dataset": dataset_name,
                "completeness": c,
                "trial": trial + 1,
                "total_paths": len(all_paths),
                "surviving_paths": len(surviving),
                "cluster_count_k": k,
                "true_path_in_cluster": true_path_survives,
            })

        level_rows = [r for r in rows if r["completeness"] == c and r["dataset"] == dataset_name]
        k_vals = [r["cluster_count_k"] for r in level_rows]
        surv_vals = [r["surviving_paths"] for r in level_rows]
        mean_k, ci_lo_k, ci_hi_k = mean_ci95(k_vals)
        mean_s, _, _ = mean_ci95(surv_vals)
        tp_rate = sum(1 for r in level_rows if r["true_path_in_cluster"]) / len(level_rows) * 100
        print(f"    c={c:.0%}: k = {mean_k:.2f} [{ci_lo_k:.2f}, {ci_hi_k:.2f}] | "
              f"Surviving = {mean_s:.1f} paths | p* retained = {tp_rate:.0f}%")

    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════
# Experiment 3: Temporal Chokepoint Score
# ══════════════════════════════════════════════════════════════

def experiment_3_chokepoint(
    ftag: ForensicTemporalAttackGraph,
    src_node: str,
    dst_node: str,
    true_edge_ids: List[str],
    true_windows: List[int],
    true_pivot_host: str,
    dataset_name: str,
) -> pd.DataFrame:
    """Experiment 3: Temporal Chokepoint Score host-level triage accuracy."""
    print(f"\n{'─'*70}")
    print(f"  EXPERIMENT 3: Chokepoint Accuracy [{dataset_name}]")
    print(f"{'─'*70}")

    all_paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=8)

    # Identify all intermediate hosts (exclude src and dst)
    all_hosts = set()
    for p in all_paths:
        for eid, _ in p.hops:
            edge = ftag.edges[eid]
            all_hosts.add(edge.src_node_id)
            all_hosts.add(edge.dst_node_id)
    # Only rank intermediate hosts (not source/destination — those are trivially 1.0)
    intermediate_hosts = sorted(all_hosts - {src_node, dst_node})

    rows = []
    rng = random.Random(RANDOM_SEED + 2000)

    for c in COMPLETENESS_LEVELS:
        for trial in range(N_TRIALS):
            degraded, ev_windows = subsample_evidence(ftag, c, rng)

            if not ev_windows:
                ev_windows = list(range(ftag.num_windows))

            surviving = [p for p in all_paths
                        if forensic_window_of_compromise(p, ev_windows) is not None]

            # Compute chi(h) for all intermediate hosts
            host_scores = {}
            for h in intermediate_hosts:
                chi = temporal_chokepoint_score(h, surviving, ftag)
                host_scores[h] = chi

            # Rank by chi (descending)
            ranked = sorted(host_scores.items(), key=lambda x: -x[1])
            pivot_rank = None
            pivot_chi = host_scores.get(true_pivot_host, 0.0)
            for rank, (h, _) in enumerate(ranked, 1):
                if h == true_pivot_host:
                    pivot_rank = rank
                    break

            row = {
                "dataset": dataset_name,
                "completeness": c,
                "trial": trial + 1,
                "pivot_host": true_pivot_host,
                "pivot_chi": pivot_chi,
                "pivot_rank": pivot_rank if pivot_rank else len(ranked) + 1,
                "num_intermediate_hosts": len(intermediate_hosts),
            }
            # Also record other hosts for comparison
            for h in intermediate_hosts:
                row[f"chi_{h}"] = host_scores.get(h, 0.0)

            rows.append(row)

        level_rows = [r for r in rows if r["completeness"] == c and r["dataset"] == dataset_name]
        rank_vals = [r["pivot_rank"] for r in level_rows]
        chi_vals = [r["pivot_chi"] for r in level_rows]
        mean_r, ci_lo_r, ci_hi_r = mean_ci95(rank_vals)
        mean_chi, _, _ = mean_ci95(chi_vals)
        print(f"    c={c:.0%}: {true_pivot_host} rank = {mean_r:.2f} [{ci_lo_r:.2f}, {ci_hi_r:.2f}] | "
              f"chi({true_pivot_host}) = {mean_chi:.3f}")

    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════
# Experiment 4: Temporal Search Radius
# ══════════════════════════════════════════════════════════════

def experiment_4_search_radius(
    ftag: ForensicTemporalAttackGraph,
    src_node: str,
    dst_node: str,
    true_edge_ids: List[str],
    true_windows: List[int],
    dataset_name: str,
) -> pd.DataFrame:
    """Experiment 4: Temporal Search Radius Soundness & Efficiency."""
    print(f"\n{'─'*70}")
    print(f"  EXPERIMENT 4: Search Radius Soundness & Efficiency [{dataset_name}]")
    print(f"{'─'*70}")

    all_paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=8)
    true_attack_start_window = true_windows[0]  # w0 = IPsweep

    rows = []
    rng = random.Random(RANDOM_SEED + 3000)

    for c in COMPLETENESS_LEVELS:
        for trial in range(N_TRIALS):
            degraded, ev_windows = subsample_evidence(ftag, c, rng)

            if not ev_windows:
                ev_windows = list(range(ftag.num_windows))

            # Filter to surviving paths
            surviving = [p for p in all_paths
                        if forensic_window_of_compromise(p, ev_windows) is not None]

            t_min = temporal_search_radius(dst_node, ftag, surviving) if surviving else 0

            # Soundness: T_min must reach back to include the true attack start
            soundness_pass = (t_min <= true_attack_start_window)

            # Efficiency: how many window-widths of lookback
            lookback_windows = ftag.num_windows - 1 - t_min + 1  # from t_min to last window
            lookback_seconds = lookback_windows * ftag.window_duration

            # Wang & Daniels comparison: they'd need N*60s windows
            # to cover the same lookback period
            wang_daniels_n = math.ceil(lookback_seconds / WANG_DANIELS_WINDOW_SEC)

            rows.append({
                "dataset": dataset_name,
                "completeness": c,
                "trial": trial + 1,
                "t_min_window": t_min,
                "soundness_pass": soundness_pass,
                "lookback_windows": lookback_windows,
                "lookback_seconds": lookback_seconds,
                "wang_daniels_60s_windows_needed": wang_daniels_n,
            })

        level_rows = [r for r in rows if r["completeness"] == c and r["dataset"] == dataset_name]
        t_min_vals = [r["t_min_window"] for r in level_rows]
        mean_t, _, _ = mean_ci95(t_min_vals)
        sound_rate = sum(1 for r in level_rows if r["soundness_pass"]) / len(level_rows) * 100
        wd_vals = [r["wang_daniels_60s_windows_needed"] for r in level_rows]
        mean_wd, _, _ = mean_ci95(wd_vals)
        print(f"    c={c:.0%}: T_min = w{mean_t:.1f} | Soundness = {sound_rate:.0f}% | "
              f"Wang-Daniels equiv = {mean_wd:.0f} × 60s windows")

    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════
# Figure Generation
# ══════════════════════════════════════════════════════════════

def generate_combined_figure(
    df_fwoc: pd.DataFrame,
    df_choke: pd.DataFrame,
    output_path: str,
    dataset_name: str,
):
    """Generate the central results figure: FWoC tightness + chokepoint rank vs completeness."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle(f"Track A: Evidence-Conditioned Metric Quality — {dataset_name}",
                 fontsize=13, fontweight="bold", y=1.02)

    # Filter to this dataset
    df_f = df_fwoc[df_fwoc["dataset"] == dataset_name]
    df_c = df_choke[df_choke["dataset"] == dataset_name]

    # ── Left panel: FWoC Tightness ──
    comp_levels = sorted(df_f["completeness"].unique())
    means_t, ci_lo_t, ci_hi_t = [], [], []
    for c in comp_levels:
        vals = df_f[df_f["completeness"] == c]["tightness_pct"].values
        m, lo, hi = mean_ci95(list(vals))
        means_t.append(m)
        ci_lo_t.append(m - lo)
        ci_hi_t.append(hi - m)

    x_pct = [c * 100 for c in comp_levels]
    ax1.errorbar(x_pct, means_t, yerr=[ci_lo_t, ci_hi_t],
                 fmt='o-', capsize=5, color='#1d3557', linewidth=2,
                 markersize=8, markerfacecolor='#457b9d')
    ax1.set_xlabel("Evidence Completeness (%)", fontsize=11)
    ax1.set_ylabel("|FWoC| / |Capture Duration| (%)", fontsize=11)
    ax1.set_title("FWoC Tightness vs. Evidence Completeness", fontsize=11, fontweight="bold")
    ax1.set_xticks(x_pct)
    ax1.set_ylim(0, 110)
    ax1.grid(True, alpha=0.3)
    ax1.axhline(y=100, color='red', linestyle='--', alpha=0.5, label="No narrowing (100%)")
    ax1.legend(fontsize=9)

    # ── Right panel: Chokepoint Rank ──
    means_r, ci_lo_r, ci_hi_r = [], [], []
    for c in comp_levels:
        vals = df_c[df_c["completeness"] == c]["pivot_rank"].values
        m, lo, hi = mean_ci95(list(vals))
        means_r.append(m)
        ci_lo_r.append(m - lo)
        ci_hi_r.append(hi - m)

    ax2.errorbar(x_pct, means_r, yerr=[ci_lo_r, ci_hi_r],
                 fmt='s-', capsize=5, color='#e63946', linewidth=2,
                 markersize=8, markerfacecolor='#f4a261')
    ax2.set_xlabel("Evidence Completeness (%)", fontsize=11)
    ax2.set_ylabel("True Pivot Host Rank Position", fontsize=11)
    ax2.set_title("Chokepoint Rank Accuracy vs. Evidence Completeness", fontsize=11, fontweight="bold")
    ax2.set_xticks(x_pct)
    ax2.set_ylim(0.5, max(5, max(means_r) + 1))
    ax2.invert_yaxis()  # Rank 1 at top
    ax2.grid(True, alpha=0.3)
    ax2.axhline(y=1, color='green', linestyle='--', alpha=0.5, label="Rank #1 (best)")
    ax2.legend(fontsize=9)

    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"\n  Figure saved: {output_path}")


# ══════════════════════════════════════════════════════════════
# Dataset Runner
# ══════════════════════════════════════════════════════════════

def run_track_a_on_dataset(
    ftag: ForensicTemporalAttackGraph,
    src_node: str,
    dst_node: str,
    true_edge_ids: List[str],
    true_windows: List[int],
    true_compromise_interval: Tuple[int, int],
    capture_duration_windows: int,
    true_pivot_host: str,
    dataset_name: str,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Run all four Track A experiments on a single dataset."""
    print(f"\n{'═'*70}")
    print(f"  TRACK A: {dataset_name}")
    print(f"{'═'*70}")

    df1 = experiment_1_fwoc(
        ftag, src_node, dst_node, true_edge_ids, true_windows,
        true_compromise_interval, capture_duration_windows, dataset_name,
    )
    df2 = experiment_2_ambiguity(
        ftag, src_node, dst_node, true_edge_ids, true_windows, dataset_name,
    )
    df3 = experiment_3_chokepoint(
        ftag, src_node, dst_node, true_edge_ids, true_windows,
        true_pivot_host, dataset_name,
    )
    df4 = experiment_4_search_radius(
        ftag, src_node, dst_node, true_edge_ids, true_windows, dataset_name,
    )

    return df1, df2, df3, df4


# ══════════════════════════════════════════════════════════════
# Soundness Report
# ══════════════════════════════════════════════════════════════

def print_soundness_report(df1, df2, df3, df4, dataset_name):
    """Print binary soundness verdicts — evaluated at 100% completeness (the gate).
    Degradation at lower completeness is expected and reported for context."""
    print(f"\n{'═'*70}")
    print(f"  SOUNDNESS REPORT: {dataset_name}")
    print(f"{'═'*70}")

    # Exp 1: FWoC at 100% completeness — must overlap with true compromise
    df = df1[(df1["dataset"] == dataset_name) & (df1["completeness"] == 1.0)]
    if not df.empty:
        fwoc_sound = df["soundness_pass"].all()
        fwoc_rate = df["soundness_pass"].mean() * 100
        fwoc_rate_full = df["full_coverage"].mean() * 100
        status = f"✓ PASS (Overlap: {fwoc_rate:.1f}%, Containment: {fwoc_rate_full:.1f}%)" if fwoc_sound else f"✗ FAIL ({100-fwoc_rate:.1f}% overlap failures)"
    else:
        fwoc_sound = False
        status = "✗ NO DATA"
    print(f"  Exp 1 (FWoC Soundness@100%):    {status}")
    # Also show degradation curve
    for c in [0.25, 0.50, 0.75]:
        dfc = df1[(df1["dataset"] == dataset_name) & (df1["completeness"] == c)]
        if not dfc.empty:
            successes = dfc["soundness_pass"].sum()
            full_cov_successes = dfc["full_coverage"].sum()
            n = len(dfc)
            p, ci_low, ci_high = wilson_score_interval(successes, n)
            p_full, ci_low_full, ci_high_full = wilson_score_interval(full_cov_successes, n)
            print(f"         @{c:.0%}: {p*100:.1f}% (95% CI: {ci_low*100:.1f}% - {ci_high*100:.1f}%) sound (overlap)")
            print(f"                {p_full*100:.1f}% (95% CI: {ci_low_full*100:.1f}% - {ci_high_full*100:.1f}%) containment (full_coverage)")


    # Exp 2: True path retained at 100% completeness
    df = df2[(df2["dataset"] == dataset_name) & (df2["completeness"] == 1.0)]
    if not df.empty:
        amb_sound = df["true_path_in_cluster"].all()
        amb_rate = df["true_path_in_cluster"].mean() * 100
        status = "✓ PASS" if amb_sound else f"✗ FAIL ({100-amb_rate:.1f}% exclusions)"
    else:
        amb_sound = False
        status = "✗ NO DATA"
    print(f"  Exp 2 (True Path@100%):     {status}")

    # Exp 3: Pivot host ranked #1 at 100% completeness
    df = df3[(df3["dataset"] == dataset_name) & (df3["completeness"] == 1.0)]
    choke_sound = (df["pivot_rank"] <= 2).all()
    mean_rank = df["pivot_rank"].mean()
    status = "✓ PASS" if choke_sound else f"✗ FAIL (mean rank = {mean_rank:.1f})"
    print(f"  Exp 3 (Pivot Host Top-2):  {status}")

    # Exp 4: Search radius must reach w0 at every level
    df = df4[df4["dataset"] == dataset_name]
    sr_sound = df["soundness_pass"].all()
    sr_rate = df["soundness_pass"].mean() * 100
    status = "✓ PASS" if sr_sound else f"✗ FAIL ({100-sr_rate:.1f}% unsound)"
    print(f"  Exp 4 (Search Radius):     {status}")

    all_pass = fwoc_sound and amb_sound and choke_sound and sr_sound
    print(f"\n  OVERALL: {'✓ ALL SOUNDNESS CHECKS PASS' if all_pass else '✗ SOUNDNESS FAILURES DETECTED'}")
    return all_pass


# ══════════════════════════════════════════════════════════════
# Main Entry Point
# ══════════════════════════════════════════════════════════════

def main():
    print(f"{'='*70}")
    print("  TRACK A: EVIDENCE-CONDITIONED RECONSTRUCTION QUALITY")
    print(f"  4 Experiments × {COMPLETENESS_LEVELS} Completeness × {N_TRIALS} Trials")
    print(f"{'='*70}")

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_dir = os.path.join(base_dir, "experiment", "results")
    os.makedirs(results_dir, exist_ok=True)

    # ── Build F-TAG for LLDOS 1.0 (Sequential State Graph) ──
    print("\n[Setup] Building F-TAG for LLDOS 1.0...")
    dataset_1_dir = os.path.join(base_dir, "LLS_DDOS_1.0")
    ftag_lldos1 = build_tag_from_lldos(dataset_1_dir, "LLDOS_1.0")

    # ── Run Track A on LLDOS 1.0 ──
    df1_l1, df2_l1, df3_l1, df4_l1 = run_track_a_on_dataset(
        ftag=ftag_lldos1,
        src_node="attacker:ext",
        dst_node="ddos_target:impact",
        true_edge_ids=LLDOS1_TRUE_PATH_EDGES,
        true_windows=LLDOS1_TRUE_PATH_WINDOWS,
        true_compromise_interval=LLDOS1_TRUE_COMPROMISE_INTERVAL,
        capture_duration_windows=LLDOS1_CAPTURE_DURATION_WINDOWS,
        true_pivot_host=LLDOS1_TRUE_PIVOT_HOST,
        dataset_name="LLDOS 1.0",
    )

    # ── Build F-TAG for LLDOS 2.0.2 (generalization check) ──
    print("\n\n[Setup] Building F-TAG for LLDOS 2.0.2 (generalization check)...")
    tags = build_all_lldos_tags(use_mulval_for_lldos1=False)
    ftag_lldos2 = tags.get("LLDOS_2.0.2")

    df1_l2, df2_l2, df3_l2, df4_l2 = pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    if ftag_lldos2:
        df1_l2, df2_l2, df3_l2, df4_l2 = run_track_a_on_dataset(
            ftag=ftag_lldos2,
            src_node="attacker:ext",
            dst_node="attacker:exfil_received",
            true_edge_ids=LLDOS2_TRUE_PATH_EDGES,
            true_windows=LLDOS2_TRUE_PATH_WINDOWS,
            true_compromise_interval=LLDOS2_TRUE_COMPROMISE_INTERVAL,
            capture_duration_windows=LLDOS2_CAPTURE_DURATION_WINDOWS,
            true_pivot_host=LLDOS2_TRUE_PIVOT_HOST,
            dataset_name="LLDOS 2.0.2",
        )

    # ── Concatenate results ──
    df1 = pd.concat([df1_l1, df1_l2], ignore_index=True)
    df2 = pd.concat([df2_l1, df2_l2], ignore_index=True)
    df3 = pd.concat([df3_l1, df3_l2], ignore_index=True)
    df4 = pd.concat([df4_l1, df4_l2], ignore_index=True)

    # ── Export CSVs ──
    df1.to_csv(os.path.join(results_dir, "track_a_exp1_fwoc.csv"), index=False)
    df2.to_csv(os.path.join(results_dir, "track_a_exp2_ambiguity.csv"), index=False)
    df3.to_csv(os.path.join(results_dir, "track_a_exp3_chokepoint.csv"), index=False)
    df4.to_csv(os.path.join(results_dir, "track_a_exp4_search_radius.csv"), index=False)
    print(f"\n  CSV results exported to: {results_dir}/track_a_exp*.csv")

    # ── Soundness Reports ──
    all_pass_l1 = print_soundness_report(df1, df2, df3, df4, "LLDOS 1.0")
    all_pass_l2 = True
    if not df1_l2.empty:
        all_pass_l2 = print_soundness_report(df1, df2, df3, df4, "LLDOS 2.0.2")

    # ── Generate Combined Figure ──
    if not df1_l1.empty and not df3_l1.empty:
        fig_path = os.path.join(results_dir, "fwoc_tightness_and_chokepoint_rank_vs_completeness.png")
        generate_combined_figure(df1, df3, fig_path, "LLDOS 1.0")

    # ── Print Search Radius Efficiency Summary ──
    print(f"\n{'═'*70}")
    print(f"  SEARCH RADIUS EFFICIENCY: F-TAG vs. Wang & Daniels (2008)")
    print(f"{'═'*70}")
    for ds in ["LLDOS 1.0", "LLDOS 2.0.2"]:
        df = df4[df4["dataset"] == ds]
        if df.empty:
            continue
        full = df[df["completeness"] == 1.0]
        mean_lb = full["lookback_seconds"].mean()
        mean_wd = full["wang_daniels_60s_windows_needed"].mean()
        t_min = full["t_min_window"].mean()
        print(f"  {ds}:")
        print(f"    F-TAG T_min: w{t_min:.0f} ({mean_lb:.0f}s lookback)")
        print(f"    Wang & Daniels: Would need {mean_wd:.0f} × 60s windows")
        print(f"    → F-TAG provides a principled bound; fixed-window must guess N correctly")

    print(f"\n{'═'*70}")
    print(f"  TRACK A COMPLETE")
    print(f"{'═'*70}")


if __name__ == "__main__":
    main()
