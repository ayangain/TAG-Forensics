import os, sys, copy
sys.path.insert(0, os.path.dirname(os.path.abspath("experiment/run_falsification_monte_carlo.py")))
from experiment.lldos_tag_builder import build_all_lldos_tags

tags = build_all_lldos_tags(use_mulval_for_lldos1=False)
ftag = tags["LLDOS_1.0"]
true_edges = ["E_ipsweep_mill", "E_sadmind_probe_mill", "E_sadmind_exploit_mill", "E_mstream_install_mill", "E_rsh_lateral_locke", "E_ddos_launch_locke"]
true_windows = [0, 1, 2, 3, 3, 4]

src_id, dst_id = "attacker:ext", "ddos_target:impact"
src_nids = [nid for nid, n in ftag.nodes.items() if nid == src_id or n.host_ip == src_id.split(":")[0]]
dst_nids = [nid for nid, n in ftag.nodes.items() if nid == dst_id or n.host_ip == dst_id.split(":")[0]]
src_nid, dst_nid = src_nids[0], dst_nids[0]

ftag_tamp = copy.deepcopy(ftag)
for eid, w in zip(true_edges, true_windows):
    ftag_tamp.edges[eid].observed_window = w

ftag_tamp.edges["E_ddos_launch_locke"].active_windows.remove(4)

paths = ftag_tamp.enumerate_temporal_paths(src_nid, dst_nid)
for i, p in enumerate(paths):
    # p is likely a list of edge_ids, or a list of tuples (u, v, edge_id). Let's just print it!
    print(f"Path {i}: {p}")
