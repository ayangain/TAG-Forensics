import sys
from experiment.mulval_engine import build_ftag_from_mulval, parse_mulval_output
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.join(base_dir, "experiment", "mulval_output")
graphs = parse_mulval_output(output_dir)
ftag = build_ftag_from_mulval(graphs)

for nid, node in ftag.nodes.items():
    print(f"{nid}: {node.state_name}")
