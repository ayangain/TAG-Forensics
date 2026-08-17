import os
from experiment.mulval_engine import build_ftag_from_mulval, parse_mulval_output

def generate_mermaid():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output")
    graphs = parse_mulval_output(output_dir)
    ftag = build_ftag_from_mulval(graphs)
    
    print("```mermaid")
    print("graph TD")
    print("    classDef attacker fill:#f96,stroke:#333,stroke-width:2px;")
    print("    classDef target fill:#f66,stroke:#333,stroke-width:2px;")
    print("    classDef normal fill:#9cf,stroke:#333,stroke-width:1px;")
    
    for nid, node in ftag.nodes.items():
        name = node.state_name.replace('"', '').replace('(', ' ').replace(')', ' ').replace(',', ' ')
        safe_name = name[:40] + "..." if len(name) > 40 else name
        
        # apply styles
        if "attacker" in name.lower():
            print(f"    {nid}[\"{safe_name}\"]:::attacker")
        elif "root" in name.lower() and "workstation" in name.lower():
            print(f"    {nid}[\"{safe_name}\"]:::target")
        else:
            print(f"    {nid}[\"{safe_name}\"]:::normal")
            
    for eid, edge in ftag.edges.items():
        active_str = ",".join([f"w{x}" for x in sorted(edge.active_windows)])
        print(f"    {edge.src_node_id} -->|{active_str}| {edge.dst_node_id}")
        
    print("```")

generate_mermaid()
