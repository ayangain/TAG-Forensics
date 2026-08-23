import os
from experiment.mulval_engine import parse_mulval_output, build_ftag_from_mulval

def verify_reversal():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output")
    graphs_per_window = parse_mulval_output(output_dir)
    
    # Check the first window where an edge appears
    for window, (vertices, arcs) in graphs_per_window.items():
        if len(arcs) > 0:
            u, v = arcs[0]
            # U is Goal, V is Precondition in MulVAL's original output.
            # E.g. U depends on V.
            # So the causal flow is V -> U.
            print(f"RAW (Window {window}): Edge {u} -> {v}")
            # Map U and V to their texts
            text_u = vertices[u]['text'].replace('"', '').strip()
            text_v = vertices[v]['text'].replace('"', '').strip()
            print(f"Mapped Semantic: {text_u} -> {text_v}")
            break

    # The actual reversal and window attachment happens in build_ftag_from_mulval
    ftag = build_ftag_from_mulval(graphs_per_window)
    
    print("\nTracing edge in final FTAG:")
    # We want to find the causal edge corresponding to V -> U
    target_edge = None
    for edge_id, edge in ftag.edges.items():
        src_text = ftag.nodes[edge.src_node_id].state_name
        dst_text = ftag.nodes[edge.dst_node_id].state_name
        if src_text == text_v and dst_text == text_u:
            target_edge = edge
            break
            
    if target_edge:
        print(f"FTAG Edge ID: {target_edge.edge_id}")
        print(f"Direction: {target_edge.src_node_id} -> {target_edge.dst_node_id}")
        print(f"Active Windows: {target_edge.active_windows}")
        
        # Verify the window in which we found U->V is actually in active_windows
        if window in target_edge.active_windows:
            print(f"VERDICT: PASS. Window {window} successfully traveled with the reversed edge.")
        else:
            print(f"VERDICT: FAIL. Window {window} is missing from active_windows.")
    else:
        print(f"VERDICT: FAIL. Could not find reversed edge {v} -> {u} in FTAG.")

if __name__ == "__main__":
    verify_reversal()
