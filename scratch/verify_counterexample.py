from experiment.mulval_engine import build_ftag_from_mulval

def run_counterexample():
    # Mocking the MulVAL graphs_per_window output
    # Window 0: Empty
    # Window 1: Attacker reaches intermediate rule node
    # Window 2: Attacker reaches intermediate rule node (persists)
    # Window 3: Intermediate rule node reaches target server
    # Window 4: Both edges persist
    
    graphs_per_window = {}
    
    # Define common nodes
    vertices = {
        "1": {"type": "LEAF", "text": "attackerLocated(internet)"},
        "2": {"type": "OR", "text": "rule_node"},
        "3": {"type": "OR", "text": "execCode(server, root)"}
    }
    
    graphs_per_window[0] = (vertices, [])
    
    # W1: Attacker -> rule (in MulVAL, Goal -> Precondition, so rule -> attacker)
    graphs_per_window[1] = (vertices, [("2", "1")])
    
    graphs_per_window[2] = (vertices, [("2", "1")])
    
    # W3: rule -> server (in MulVAL, server -> rule)
    graphs_per_window[3] = (vertices, [("2", "1"), ("3", "2")])
    
    graphs_per_window[4] = (vertices, [("2", "1"), ("3", "2")])
    
    print("Running Pruning Algorithm on Counterexample...")
    ftag = build_ftag_from_mulval(graphs_per_window)
    
    print("\n--- Pruned F-TAG Edges ---")
    for e in ftag.edges.values():
        src_name = ftag.nodes[e.src_node_id].state_name
        dst_name = ftag.nodes[e.dst_node_id].state_name
        print(f"Edge: {src_name} -> {dst_name}")
        print(f"Active Windows: {e.active_windows}")
        
    # Validation assertion
    edges_list = list(ftag.edges.values())
    if len(edges_list) == 1:
        e = edges_list[0]
        if e.active_windows == {3, 4}:
            print("\n[VALIDATION PASSED] Pruning perfectly maintained active window sequence without naive intersection!")
        else:
            print("\n[VALIDATION FAILED] Active windows are incorrect.")
    else:
        print("\n[VALIDATION FAILED] Incorrect number of edges.")

if __name__ == '__main__':
    run_counterexample()
