import pandas as pd
import numpy as np
import random
import os

# ==============================================================================
# WARNING: SCIENTIFIC INTEGRITY LIMITATION
# ==============================================================================
# The labeling logic in this synthetic generator is fundamentally circular.
# The 'is_true_path' labels are generated using hand-coded heuristics over the 
# exact same feature distributions (tac_width, privilege_score) that the Random 
# Forest classifier will later train on. 
#
# Because the labels are derived directly from the features, the resulting model 
# is simply reverse-engineering this python script, rather than learning true 
# attacker behavior. High AUC/Accuracy scores on this dataset represent a 
# mathematical tautology and cannot be claimed as validated scientific results.
#
# This script is retained strictly as a proof-of-concept for the software 
# architecture of the AI pipeline, NOT as a valid generative model.
# ==============================================================================

def generate_synthetic_paths(num_samples=15000, random_seed=42):
    np.random.seed(random_seed)
    random.seed(random_seed)
    
    data = []
    for i in range(num_samples):
        # 1 = True Path (Realistic), 0 = False Path (Topological Artifact)
        label = np.random.choice([0, 1], p=[0.7, 0.3])
        
        path_length = random.randint(2, 10)
        
        if label == 1:
            # Realistic path
            # TAC width is usually slightly larger than path length
            tac_width = path_length - 1 + random.randint(0, 3)
            # Privilege score is high for true attack paths as they target critical infrastructure
            privilege_score = np.clip(np.random.normal(0.8, 0.15), 0, 1)
            # Dwell time (seconds)
            dwell_lower = path_length * random.randint(10, 60)
        else:
            # Artifact path
            # TAC width can be extremely large (dormant illusion) or 0 (impossible instantaneous)
            if random.random() < 0.5:
                tac_width = path_length - 1 + random.randint(10, 50)
            else:
                tac_width = random.randint(0, max(0, path_length - 2))
                
            # Privilege score is random / lower
            privilege_score = np.clip(np.random.normal(0.4, 0.3), 0, 1)
            dwell_lower = path_length * random.randint(1, 10)

        # Prevent division by zero
        safe_tac_width = max(1, tac_width)
        propagation_v = (path_length - 1) / safe_tac_width
        
        data.append({
            'path_length': path_length,
            'tac_width': tac_width,
            'dwell_lower_s': dwell_lower,
            'propagation_v': propagation_v,
            'privilege_score': privilege_score,
            'is_true_path': label
        })
        
    df = pd.DataFrame(data)
    
    # Add some noise to make it realistic
    noise_mask = np.random.rand(len(df)) < 0.05
    df.loc[noise_mask, 'is_true_path'] = 1 - df.loc[noise_mask, 'is_true_path']
    
    output_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(output_dir, 'results', 'synthetic_ai_training_data.csv')
    
    os.makedirs(os.path.join(output_dir, 'results'), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Generated {num_samples} synthetic path samples at {output_path}")
    
    print("\nClass Distribution:")
    print(df['is_true_path'].value_counts(normalize=True))

if __name__ == "__main__":
    generate_synthetic_paths()
