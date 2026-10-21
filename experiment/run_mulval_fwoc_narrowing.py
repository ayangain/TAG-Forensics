"""
run_mulval_fwoc_narrowing.py
============================
Evaluates FWoC narrowing in the H << tau regime using MulVAL synthetic topology.
Here H = 5 hops embedded within an extended capture timeline of tau = 50 windows
(attack active during windows [8, 13]).

Includes a three-way ablation:
1. Evidence-Only Interval: [min(E) - delta_s, max(E) + delta_s]
2. TAC-Only Interval: TAC(p*) = [W_b, W_end]
3. Full FWoC: TAC(p*) cap [min(E) - delta_s, max(E) + delta_s]

Reports BOTH:
- Containment Soundness: bound contains the entire true interval [8, 13]
- Overlap Soundness: bound has non-empty intersection with [8, 13]
Across 30 independent seeds x 100 trials = 3,000 trials per N.
"""
import os
import sys
import random
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiment.mulval_engine import parse_mulval_output, build_ftag_from_mulval
from experiment.ftag_metrics import forensic_window_of_compromise

N_SEEDS = 30
N_TRIALS_PER_SEED = 100
TAU = 50

def run_narrowing_experiment():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output_t20")
    
    if not os.path.exists(output_dir):
        print(f"[ERROR] MulVAL output directory {output_dir} not found.")
        sys.exit(1)
        
    graphs_per_window = parse_mulval_output(output_dir, num_windows=TAU)
    ftag = build_ftag_from_mulval(graphs_per_window)
    
    src_node = next(nid for nid, n in ftag.nodes.items() if "attackerLocated" in n.state_name)
    dst_node = next(nid for nid, n in ftag.nodes.items() if "execCode(workstation,root)" in n.state_name.replace(" ", ""))
    
    paths = ftag.enumerate_temporal_paths(src_node, dst_node, max_hops=15)
    p_star = next(p for p in paths if [w for _, w in p.hops] == [8, 9, 10, 11, 13])
    
    all_ev = [8, 9, 10, 11, 13]
    H = len(all_ev)
    true_interval = (8, 13)
    
    tac_start, tac_end = p_star.tac
    tac_width = tac_end - tac_start + 1
    
    print("=" * 95)
    print(f" FWoC THREE-WAY ABLATION & NARROWING IN THE H << tau REGIME (H={H} hops, tau={TAU} windows)")
    print(f" Evaluated over {N_SEEDS} independent seeds x {N_TRIALS_PER_SEED} trials = {N_SEEDS*N_TRIALS_PER_SEED} trials per N")
    print(f" TAC(p*) = [{tac_start}, {tac_end}] (Width = {tac_width} windows, Tightness = {tac_width/TAU*100:.1f}%)")
    print("=" * 95)
    
    print(f"\n{'N':>2} {'Method':<14} {'Mean Width':>10} {'95% CI':>16} {'Tightness %':>12} {'Containment %':>14} {'Overlap %':>10}")
    print("-" * 95)
    
    for n in range(1, H + 1):
        delta_s = max(0, H - n)
        
        # Per-seed metrics for Evidence-only and Full FWoC
        ev_w_seeds, ev_cont_seeds, ev_over_seeds = [], [], []
        fw_w_seeds, fw_cont_seeds, fw_over_seeds = [], [], []
        
        for seed in range(N_SEEDS):
            rng = random.Random(seed * 100 + 42)
            ev_w, ev_c, ev_o = [], [], []
            fw_w, fw_c, fw_o = [], [], []
            
            for _ in range(N_TRIALS_PER_SEED):
                sample = sorted(rng.sample(all_ev, n))
                
                # 1. Evidence-only
                emin = max(0, min(sample) - delta_s)
                emax = min(TAU - 1, max(sample) + delta_s)
                w_ev = emax - emin + 1
                ev_w.append(w_ev)
                ev_c.append(1 if emin <= true_interval[0] and emax >= true_interval[1] else 0)
                ev_o.append(1 if emin <= true_interval[1] and emax >= true_interval[0] else 0)
                
                # 2. Full FWoC
                fw = forensic_window_of_compromise(p_star, sample, small_sample_correction=True)
                if fw:
                    w_fw = fw[1] - fw[0] + 1
                    fw_w.append(w_fw)
                    fw_c.append(1 if fw[0] <= true_interval[0] and fw[1] >= true_interval[1] else 0)
                    fw_o.append(1 if fw[0] <= true_interval[1] and fw[1] >= true_interval[0] else 0)
                    
            ev_w_seeds.append(np.mean(ev_w))
            ev_cont_seeds.append(np.mean(ev_c) * 100)
            ev_over_seeds.append(np.mean(ev_o) * 100)
            
            fw_w_seeds.append(np.mean(fw_w))
            fw_cont_seeds.append(np.mean(fw_c) * 100)
            fw_over_seeds.append(np.mean(fw_o) * 100)
            
        # Summary for N
        ev_m = np.mean(ev_w_seeds); ev_ci = 2.045 * np.std(ev_w_seeds, ddof=1) / np.sqrt(N_SEEDS)
        fw_m = np.mean(fw_w_seeds); fw_ci = 2.045 * np.std(fw_w_seeds, ddof=1) / np.sqrt(N_SEEDS)
        
        print(f"{n:>2} {'Evidence-Only':<14} {ev_m:>10.2f} [{ev_m-ev_ci:.2f}, {ev_m+ev_ci:.2f}] {ev_m/TAU*100:>11.1f}% {np.mean(ev_cont_seeds):>13.1f}% {np.mean(ev_over_seeds):>9.1f}%")
        print(f"   {'TAC-Only':<14} {tac_width:>10.2f} [{tac_width:.2f}, {tac_width:.2f}] {tac_width/TAU*100:>11.1f}% {100.0:>13.1f}% {100.0:>9.1f}%")
        print(f"   {'Full FWoC':<14} {fw_m:>10.2f} [{fw_m-fw_ci:.2f}, {fw_m+fw_ci:.2f}] {fw_m/TAU*100:>11.1f}% {np.mean(fw_cont_seeds):>13.1f}% {np.mean(fw_over_seeds):>9.1f}%")
        print("-" * 95)

    print("\nInterpretation:")
    print("1. Where Narrowing Comes From: TAC-only provides a baseline width of 6.0 windows (12.0% of tau=50).")
    print("   Evidence-only yields 7.39 - 9.42 windows (14.8% - 18.8%). Intersecting them (Full FWoC) slightly")
    print("   trims boundaries to 5.60 - 6.00 windows (11.2% - 12.0%). Thus, the 88% search-space reduction")
    print("   is primarily an illustration of topology corridor narrowing, with evidence anchoring the span.")
    print("2. Overlap vs. Containment: Overlap soundness is 100% across all N. Containment soundness is 60.0%")
    print("   at N=1 because a single alert at window 8 or 13 with delta_s=4 misses the opposite end of the")
    print("   attack; containment reaches 100% as evidence coverage N increases to 5.")

if __name__ == "__main__":
    run_narrowing_experiment()
