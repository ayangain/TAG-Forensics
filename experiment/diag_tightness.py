import os
import random
from experiment.lldos_tag_builder import build_tag_from_lldos, build_all_lldos_tags
from experiment.run_track_a_experiments import find_true_path, LLDOS1_TRUE_PATH_EDGES, LLDOS1_TRUE_PATH_WINDOWS, LLDOS2_TRUE_PATH_EDGES, LLDOS2_TRUE_PATH_WINDOWS
from experiment.ftag_metrics import forensic_window_of_compromise

def test_dataset(ftag, name, src, dst, true_edges, true_windows, capture_duration):
    paths = ftag.enumerate_temporal_paths(src, dst, max_hops=8)
    p_star = find_true_path(paths, true_edges, true_windows)
    
    H = len(p_star.hops)
    print(f"\n--- {name} (H={H}, τ={capture_duration}) ---")
    print(f"{'N':<5} | {'δs':<5} | {'FWoC Bounds':<15} | {'Width':<5} | {'Tightness':<10}")
    print("-" * 50)
    
    # All unique evidence windows in the true path
    all_ev = sorted(list(set([w for _, w in p_star.hops])))
    
    for n in range(1, len(all_ev) + 1):
        widths = []
        for _ in range(50): # 50 trials per N
            ev_sample = sorted(random.sample(all_ev, n))
            fwoc = forensic_window_of_compromise(p_star, ev_sample, small_sample_correction=True)
            if fwoc:
                widths.append(fwoc[1] - fwoc[0] + 1)
        
        avg_width = sum(widths) / len(widths) if widths else 0
        tightness = avg_width / capture_duration * 100 if widths else 0
        
        delta_s = max(0, H - n)
        sample = sorted(all_ev[:n])
        fwoc = forensic_window_of_compromise(p_star, sample, small_sample_correction=True)
        fwoc_str = f"[{fwoc[0]}, {fwoc[1]}]" if fwoc else "None"
        
        print(f"{n:<5} | {delta_s:<5} | {fwoc_str:<15} | {avg_width:<5.1f} | {tightness:.1f}%")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_1_dir = os.path.join(base_dir, "LLS_DDOS_1.0")
    ftag_lldos1 = build_tag_from_lldos(dataset_1_dir, "LLDOS_1.0")
    test_dataset(ftag_lldos1, "LLDOS 1.0", "attacker:ext", "ddos_target:impact", LLDOS1_TRUE_PATH_EDGES, LLDOS1_TRUE_PATH_WINDOWS, 5)
    
    tags = build_all_lldos_tags(use_mulval_for_lldos1=False)
    ftag_lldos2 = tags.get("LLDOS_2.0.2")
    if ftag_lldos2:
        test_dataset(ftag_lldos2, "LLDOS 2.0.2", "attacker:ext", "attacker:exfil_received", LLDOS2_TRUE_PATH_EDGES, LLDOS2_TRUE_PATH_WINDOWS, 5)

