"""
run_afconf_operating_points.py
===============================
Two sub-experiments requested by reviewer:

(A) Operating-point table: for thresholds 0.50, 0.70, 0.85, 0.90, report
    precision, recall, F1, and absolute number of flagged samples.
    If 0.85 flags nothing, expose that and reframe as 'binary privilege
    gives exactly two score levels'.

(B) Root-weight sweep: vary the wipe generator's root-node bias weight
    (1x, 2x, 5x, 10x) and report how AUC changes. If AUC tracks the
    weight monotonically, report that honestly as a limitation.

All results are printed in a format ready to be transcribed into the paper.
"""
import os, sys, random
import numpy as np

try:
    from sklearn.metrics import roc_auc_score, precision_recall_fscore_support
except ImportError:
    print("pip3 install scikit-learn")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiment.mulval_engine import (
    generate_mulval_input, run_mulval_docker,
    parse_mulval_output, build_ftag_from_mulval,
)
from experiment.ftag_metrics import anti_forensics_confidence_score, temporal_chokepoint_score

PRIOR = 0.15          # fixed for this experiment
N_SEEDS = 30
THRESHOLDS = [0.50, 0.70, 0.85, 0.90]
ROOT_WEIGHTS = [1, 2, 5, 10]


# ── helpers ──────────────────────────────────────────────────────────────────

def is_root(ftag, nid):
    name = ftag.nodes[nid].state_name.lower()
    return "root" in name or "admin" in name

def calc_chi(ftag, paths):
    return {nid: temporal_chokepoint_score(nid, paths, ftag) for nid in ftag.nodes}

def inject_wipe(path, ftag, chi, root_weight):
    nodes = [ftag.edges[eid].dst_node_id for eid, _ in path.hops]
    weights = [(root_weight if is_root(ftag, n) else 1.0) * (chi.get(n, 0) + 0.1)
               for n in nodes]
    total = sum(weights)
    if total == 0:
        return None
    probs = [w / total for w in weights]
    return np.random.choice(nodes, p=probs)

def inject_random(path, ftag):
    nodes = [ftag.edges[eid].dst_node_id for eid, _ in path.hops]
    return random.choice(nodes) if nodes else None

def collect_scores(ftag, paths, chi, root_weight, n_per_path, seed):
    random.seed(seed); np.random.seed(seed)
    y_true, y_score = [], []
    for path in paths:
        for _ in range(n_per_path):
            n = inject_wipe(path, ftag, chi, root_weight)
            if n is not None:
                y_true.append(1)
                y_score.append(anti_forensics_confidence_score(n, ftag, P_H1=PRIOR))
            n = inject_random(path, ftag)
            if n is not None:
                y_true.append(0)
                y_score.append(anti_forensics_confidence_score(n, ftag, P_H1=PRIOR))
    return np.array(y_true), np.array(y_score)


# ── sub-experiment A: operating points ───────────────────────────────────────

def run_operating_points(ftag, paths, chi, root_weight=10, n_per_path=5):
    print(f"\n{'='*70}")
    print(f" SUB-EXPERIMENT A: Operating-Point Table (root_weight={root_weight}x, prior={PRIOR})")
    print(f"{'='*70}")

    # Collect all scores across seeds
    all_y_true, all_y_score = [], []
    for seed in range(N_SEEDS):
        yt, ys = collect_scores(ftag, paths, chi, root_weight, n_per_path, seed)
        all_y_true.extend(yt); all_y_score.extend(ys)

    all_y_true  = np.array(all_y_true)
    all_y_score = np.array(all_y_score)

    # Unique score levels
    unique_scores = sorted(set(all_y_score))
    print(f"\n  Unique AF_conf score levels in data: {[f'{s:.4f}' for s in unique_scores]}")
    if len(unique_scores) == 2:
        print("  ⚠  Binary privilege model yields exactly TWO score levels.")
        print("     Threshold behaviour is a step function, not a continuous ROC.")

    print(f"\n  {'Threshold':>10}  {'#Flagged':>9}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}  {'FAR':>8}")
    print(f"  {'-'*65}")
    total_pos  = int((all_y_true == 1).sum())
    total_neg  = int((all_y_true == 0).sum())
    for thr in THRESHOLDS:
        pred = (all_y_score >= thr).astype(int)
        flagged = int(pred.sum())
        tp = int(((pred == 1) & (all_y_true == 1)).sum())
        fp = int(((pred == 1) & (all_y_true == 0)).sum())
        fn = int(((pred == 0) & (all_y_true == 1)).sum())
        prec   = tp / (tp + fp) if (tp + fp) > 0 else float('nan')
        rec    = tp / (tp + fn) if (tp + fn) > 0 else float('nan')
        f1     = (2*prec*rec / (prec+rec)) if (prec+rec) > 0 else float('nan')
        far    = fp / total_neg if total_neg > 0 else float('nan')
        print(f"  {thr:>10.2f}  {flagged:>9d}  {prec:>10.3f}  {rec:>8.3f}  {f1:>8.3f}  {far:>8.3f}")

    print(f"\n  Total samples: {len(all_y_true)}  (positive={total_pos}, negative={total_neg})")
    if len(set(all_y_true)) > 1:
        auc = roc_auc_score(all_y_true, all_y_score)
        print(f"  Overall AUC: {auc:.4f}")


# ── sub-experiment B: root-weight sweep ──────────────────────────────────────

def run_weight_sweep(ftag, paths, chi, n_per_path=5):
    print(f"\n{'='*70}")
    print(f" SUB-EXPERIMENT B: Root-Weight Sweep (prior={PRIOR}, {N_SEEDS} seeds)")
    print(f"{'='*70}")

    print(f"\n  {'Root weight':>12}  {'Mean AUC':>10}  {'95% CI':>22}  {'Root-in-wipe %':>16}")
    print(f"  {'-'*68}")

    for rw in ROOT_WEIGHTS:
        aucs, root_rates = [], []
        for seed in range(N_SEEDS):
            yt, ys = collect_scores(ftag, paths, chi, rw, n_per_path, seed)
            if len(set(yt)) < 2:
                continue
            aucs.append(roc_auc_score(yt, ys))
            # root rate in wipe class
            wipe_nodes_root = sum(
                1 for i, y in enumerate(yt) if y == 1 and ys[i] > np.median(ys)
            )
            root_rates.append(wipe_nodes_root / max(1, int((yt == 1).sum())))

        aucs = np.array(aucs)
        mean_auc = np.mean(aucs)
        ci       = 1.96 * np.std(aucs) / np.sqrt(len(aucs))
        rr       = np.mean(root_rates) * 100
        print(f"  {rw:>12}x  {mean_auc:>10.4f}  [{mean_auc-ci:.4f}, {mean_auc+ci:.4f}]  {rr:>14.1f}%")

    print("""
  Interpretation: if AUC increases monotonically with root weight, the
  discriminative power is driven by the wipe generator's own privilege bias,
  not by F-TAG's privilege model independently. Report this honestly and
  recommend a privilege-agnostic wipe baseline in future work.
""")


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(base, "experiment", "mulval_output")
    if not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        generate_mulval_input(out_dir)
        run_mulval_docker(out_dir)

    graphs = parse_mulval_output(out_dir)
    ftag   = build_ftag_from_mulval(graphs, prune=False)

    src = next((nid for nid, n in ftag.nodes.items() if "attackerLocated" in n.state_name), None)
    dst = next((nid for nid, n in ftag.nodes.items() if "execCode(workstation,root)" in n.state_name), None)

    if src is None or dst is None:
        print("[ERROR] Could not find src/dst nodes. Check MulVAL output.")
        sys.exit(1)

    paths = ftag.enumerate_temporal_paths(src, dst, max_hops=30)
    if not paths:
        print("[ERROR] No temporal paths found.")
        sys.exit(1)

    chi = calc_chi(ftag, paths)
    print(f"Graph: {len(ftag.nodes)} nodes, {len(ftag.edges)} edges, {len(paths)} temporal paths")

    run_operating_points(ftag, paths, chi, root_weight=10, n_per_path=5)
    run_weight_sweep(ftag, paths, chi, n_per_path=5)


if __name__ == "__main__":
    main()
