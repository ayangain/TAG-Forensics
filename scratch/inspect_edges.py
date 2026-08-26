import os
import json
from collections import defaultdict
from experiment.mulval_engine import build_ftag_from_mulval

def inspect_pruned_edges():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output_scaled")
    test_dir = os.path.join(output_dir, "N_163") # Target 100 nodes
    
    graphs_per_window = {}
    for w in range(5):
        w_dir = test_dir
        arcs_file = os.path.join(w_dir, f"ARCS_w{w}.CSV")
        vertices_file = os.path.join(w_dir, f"VERTICES_w{w}.CSV")
        
        # In run_scalability_experiment, it saves them with these names!
        if os.path.exists(arcs_file) and os.path.exists(vertices_file):
            vertices = {}
            with open(vertices_file, "r") as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 3:
                        v_id = parts[0]
                        v_type = parts[1]
                        v_text = ','.join(parts[2:])
                        vertices[v_id] = {"type": v_type, "text": v_text}
            
            arcs = []
            with open(arcs_file, "r") as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        arcs.append((parts[0], parts[1]))
            graphs_per_window[w] = (vertices, arcs)
            
    print(f"Loaded {len(graphs_per_window)} windows.")
    
    ftag = build_ftag_from_mulval(graphs_per_window)
    print(f"Pruned Nodes: {len(ftag.nodes)}")
    print(f"Pruned Edges: {len(ftag.edges)}")
    
    # Analyze who connects to who
    connections = defaultdict(int)
    for e in ftag.edges.values():
        src_name = ftag.nodes[e.src_node_id].state_name
        dst_name = ftag.nodes[e.dst_node_id].state_name
        
        src_type = "internet" if "internet" in src_name else src_name.split('(')[1].split('_')[0]
        dst_type = "internet" if "internet" in dst_name else dst_name.split('(')[1].split('_')[0]
        
        connections[f"{src_type} -> {dst_type}"] += 1
        
    for k, v in sorted(connections.items()):
        print(f"{k}: {v} edges")

if __name__ == '__main__':
    inspect_pruned_edges()
