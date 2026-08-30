import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath("experiment/run_falsification_monte_carlo.py")))
from experiment.lldos_tag_builder import build_all_lldos_tags

tags = build_all_lldos_tags(use_mulval_for_lldos1=False)
ftag = tags["LLDOS_1.0"]

src_id, dst_id = "attacker:ext", "ddos_target:impact"
src_nids = [nid for nid, n in ftag.nodes.items() if nid == src_id or n.host_ip == src_id.split(":")[0]]
dst_nids = [nid for nid, n in ftag.nodes.items() if nid == dst_id or n.host_ip == dst_id.split(":")[0]]
src_nid, dst_nid = src_nids[0], dst_nids[0]

paths = ftag.enumerate_temporal_paths(src_nid, dst_nid)
for i, p in enumerate(paths):
    print(f"Path {i}: {p}")

