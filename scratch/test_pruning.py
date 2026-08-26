import os

from experiment.generate_scaled_mulval import generate_enterprise_datalog

def test_pruning():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output_scaled")
    
    # Target 20 nodes -> N=30
    n = 30
    test_dir = os.path.join(output_dir, f"test_N_{n}")
    os.makedirs(test_dir, exist_ok=True)
    
    # 1. Generate Datalog
    generate_enterprise_datalog(n, test_dir)
    
    import subprocess
    from experiment.mulval_engine import run_mulval_docker, build_ftag_from_mulval
    
    graphs_per_window = {}
    for w in range(5):
        w_dir = os.path.join(test_dir, f"W{w}")
        # Run MulVAL logic generation using the pre-built Docker image
        run_mulval_docker(w_dir)
        
        # Read the raw output
        arcs_file = os.path.join(w_dir, "AttackGraph.txt")
        vertices_file = os.path.join(w_dir, "VERTICES.TXT")
        
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
    
    out_degree = {n: 0 for n in ftag.nodes}
    in_degree = {n: 0 for n in ftag.nodes}
    for e in ftag.edges.values():
        out_degree[e.src_node_id] += 1
        in_degree[e.dst_node_id] += 1
        
    print("Sample of out degrees:")
    for nid, deg in list(out_degree.items())[:5]:
        node_name = ftag.nodes[nid].state_name
        print(f"  {node_name}: {deg} out-edges")

    print("\nTotal active window instances across all edges:")
    total_active = sum(len(e.active_windows) for e in ftag.edges.values())
    print(f"  {total_active}")

if __name__ == '__main__':
    test_pruning()
