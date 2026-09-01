import sys
import os

from experiment.mulval_engine import (
    generate_mulval_input,
    run_mulval_docker,
    parse_mulval_output,
    build_ftag_from_mulval
)

base_dir = "/Users/ayangain/repos/TAG-Forensics"
output_dir = os.path.join(base_dir, "experiment", "mulval_output")
graphs_per_window = parse_mulval_output(output_dir, prune=False)
ftag = build_ftag_from_mulval(graphs_per_window)
print(f"Nodes: {len(ftag.nodes)}")
