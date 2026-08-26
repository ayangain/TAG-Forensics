import os
from experiment.mulval_engine import build_ftag_from_mulval, parse_mulval_output

def compare_density(target_nodes, base_n):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output_scaled")
    test_dir = os.path.join(output_dir, f"N_{base_n}")
    
    graphs_per_window = parse_mulval_output(test_dir)
    
    unpruned_nodes = set()
    unpruned_edges = set()
    
    for w, (vertices, arcs) in graphs_per_window.items():
        for v_data in vertices.values():
            unpruned_nodes.add(v_data["text"])
        for u, v in arcs:
            if u in vertices and v in vertices:
                unpruned_edges.add((vertices[u]["text"], vertices[v]["text"]))
                
    ftag = build_ftag_from_mulval(graphs_per_window)
    
    print(f"\n--- TARGET {target_nodes} PRUNED NODES (BASE N={base_n}) ---")
    print(f"Pre-Pruning Unique Logical Nodes: {len(unpruned_nodes)}")
    print(f"Pre-Pruning Unique Logical Edges: {len(unpruned_edges)}")
    print(f"Post-Pruning Unique Physical Nodes: {len(ftag.nodes)}")
    print(f"Post-Pruning Unique Physical Edges: {len(ftag.edges)}")

if __name__ == '__main__':
    compare_density(10, 13)
    compare_density(50, 80)
    compare_density(100, 163)
