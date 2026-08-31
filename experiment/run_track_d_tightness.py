from experiment.ftag_model import TemporalPath
from experiment.ftag_metrics import forensic_window_of_compromise
import random

def synthetic_tightness_sweep(H, tau, attack_start):
    print(f"\n--- Synthetic MulVAL (H={H}, τ={tau}, Attack=[{attack_start}, {attack_start+H-1}]) ---")
    print(f"{'N':<5} | {'δs':<5} | {'FWoC Bounds':<15} | {'Width':<5} | {'Tightness':<10}")
    print("-" * 50)
    
    # Simulate a fast attack where hops happen in consecutive windows
    windows = [attack_start + i for i in range(H)]
    
    # Create the path
    hops = [(f"e{i}", windows[i]) for i in range(H)]
    p_star = TemporalPath(hops, "src", "dst")
    # Manually set TAC to full capture [0, tau-1] because TAC is structural
    
    all_ev = windows
    
    for n in range(1, len(all_ev) + 1):
        widths = []
        for _ in range(100):
            ev_sample = sorted(random.sample(all_ev, n))
            # The TAC of the path is strictly bounded by (0, 19).
            # But the forensic_window_of_compromise reads path.tac.
            # In Python, we can mock path.tac by monkey patching or just overriding it in the function.
            pass
            
        widths = []
        for _ in range(100):
            ev_sample = sorted(random.sample(all_ev, n))
            delta_s = max(0, H - n)
            ev_min = min(ev_sample) - delta_s
            ev_max = max(ev_sample) + delta_s
            
            # structural bound
            fwoc_start = max(0, ev_min)
            fwoc_end = min(tau - 1, ev_max)
            widths.append(fwoc_end - fwoc_start + 1)
        
        avg_width = sum(widths) / len(widths) if widths else 0
        tightness = avg_width / tau * 100 if widths else 0
        
        delta_s = max(0, H - n)
        sample = sorted(all_ev[:n])
        ev_min = min(sample) - delta_s
        ev_max = max(sample) + delta_s
        fwoc_start = max(0, ev_min)
        fwoc_end = min(tau - 1, ev_max)
        fwoc_str = f"[{fwoc_start}, {fwoc_end}]"
        
        print(f"{n:<5} | {delta_s:<5} | {fwoc_str:<15} | {avg_width:<5.1f} | {tightness:.1f}%")

if __name__ == "__main__":
    synthetic_tightness_sweep(H=5, tau=20, attack_start=8)
    synthetic_tightness_sweep(H=6, tau=30, attack_start=12)
