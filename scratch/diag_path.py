import os, sys, copy
sys.path.insert(0, os.path.dirname(os.path.abspath("experiment/run_falsification_monte_carlo.py")))
from experiment.lldos_tag_builder import build_all_lldos_tags
tags = build_all_lldos_tags(use_mulval_for_lldos1=False)

ftag = tags["LLDOS_1.0"]
true_edges = ["E_ipsweep_mill", "E_sadmind_probe_mill", "E_sadmind_exploit_mill", "E_mstream_install_mill", "E_rsh_lateral_locke", "E_ddos_launch_locke"]
true_windows = [0, 1, 2, 3, 3, 4]
src_nid, dst_nid = 0, 13 # Known IDs for LLDOS 1.0 attacker:ext (0) -> ddos_target:impact (13)

ftag_tamp = copy.deepcopy(ftag)
for eid, w in zip(true_edges, true_windows):
    ftag_tamp.edges[eid].observed_window = w

# Before removal
paths_before = ftag_tamp.enumerate_temporal_paths(src_nid, dst_nid)
print(f"Before removal: {len(paths_before)} paths")

# Remove last edge's window
ftag_tamp.edges["E_ddos_launch_locke"].active_windows.remove(4)

# After removal
paths_after = ftag_tamp.enumerate_temporal_paths(src_nid, dst_nid)
print(f"After removal: {len(paths_after)} paths")
for p in paths_after:
    print(f"  Path: {p}")
