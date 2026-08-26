import os
import sys

from experiment.ftag_metrics import ai_path_ranking_score
from experiment.ftag_model import ForensicTemporalAttackGraph, TemporalPath
from experiment.ftag_path_predictor import FTAGPathPredictor
from experiment.lldos_tag_builder import build_all_lldos_tags

def run_lldos_ai_test():
    print("--- LLDOS Ground Truth AI Test ---")
    print("WARNING: Testing a model trained on circular synthetic data against real ground truth.")
    
    # 1. Load the F-TAG
    ftags = build_all_lldos_tags()
    ftag = ftags['LLDOS_1.0']
    
    # 2. Define the known true path (Attacker -> mill -> pascal -> locke -> ddos_target)
    # The LLDOS builder maps these as edges with temporal windows.
    # We will manually construct a TemporalPath object representing this.
    # Note: In LLDOS, path length is 4 hops.
    true_path = TemporalPath(
        hops=[('e_attack_mill', 0), ('e_mill_pascal', 1), ('e_pascal_locke', 2), ('e_locke_target', 3)],
        src_node='N_Attacker',
        dst_node='N_ddos_target'
    )
    
    # Define an impossible artifact path (e.g., instant propagation across all hops in window 0)
    artifact_path = TemporalPath(
        hops=[('e_attack_mill', 0), ('e_mill_pascal', 0), ('e_pascal_locke', 0), ('e_locke_target', 0)],
        src_node='N_Attacker',
        dst_node='N_ddos_target'
    )
    
    # 3. Load the predictor
    predictor = FTAGPathPredictor()
    if not predictor.load_model():
        print("Failed to load model. Ensure it was trained first.")
        return
        
    # 4. Predict
    true_score = ai_path_ranking_score(true_path, ftag, predictor)
    artifact_score = ai_path_ranking_score(artifact_path, ftag, predictor)
    
    print(f"\nLLDOS True Path Score (P_true): {true_score:.4f}")
    print(f"LLDOS Artifact Path Score (P_true): {artifact_score:.4f}")
    
    print("\nResult Analysis:")
    if true_score > artifact_score:
        print("SUCCESS: The model successfully ranked the real path higher than the artifact path.")
    else:
        print("NULL RESULT: The model failed to rank the true path higher. This confirms the synthetic training data does not generalize to real-world structural data.")

if __name__ == "__main__":
    run_lldos_ai_test()
