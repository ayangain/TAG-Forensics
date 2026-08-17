import sys
from experiment.mulval_engine import build_ftag_from_mulval, parse_mulval_output
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.join(base_dir, "experiment", "mulval_output")
graphs = parse_mulval_output(output_dir)
ftag = build_ftag_from_mulval(graphs)

for eid, edge in ftag.edges.items():
    src = ftag.nodes[edge.src_node_id].state_name
    dst = ftag.nodes[edge.dst_node_id].state_name
    print(f"{src[:40]} -> {dst[:40]}")
