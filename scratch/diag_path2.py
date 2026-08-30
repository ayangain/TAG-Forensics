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

paths_before = ftag_tamp.enumerate_temporal_paths(src_nid, dst_nid)
print(f"LLDOS 1.0 Before removal: {len(paths_before)} paths")

ftag_tamp.edges["E_ddos_launch_locke"].active_windows.remove(4)

paths_after = ftag_tamp.enumerate_temporal_paths(src_nid, dst_nid)
print(f"LLDOS 1.0 After removal: {len(paths_after)} paths")


ftag2 = tags["LLDOS_2.0.2"]
true_edges2 = ["E_dns_recon", "E_sadmind_exploit_mill", "E_ftp_upload_mill", "E_ssh_lateral_pascal", "E_mail_exfil"]
true_windows2 = [0, 1, 2, 3, 4]
src_id2, dst_id2 = "attacker:ext", "attacker:exfil_received"
src_nids2 = [nid for nid, n in ftag2.nodes.items() if nid == src_id2 or n.host_ip == src_id2.split(":")[0]]
dst_nids2 = [nid for nid, n in ftag2.nodes.items() if nid == dst_id2 or n.host_ip == dst_id2.split(":")[0]]
src_nid2, dst_nid2 = src_nids2[0], dst_nids2[0]

ftag_tamp2 = copy.deepcopy(ftag2)
for eid, w in zip(true_edges2, true_windows2):
    ftag_tamp2.edges[eid].observed_window = w

paths_before2 = ftag_tamp2.enumerate_temporal_paths(src_nid2, dst_nid2)
print(f"\nLLDOS 2.0.2 Before removal: {len(paths_before2)} paths")

ftag_tamp2.edges["E_mail_exfil"].active_windows.remove(4)
paths_after2 = ftag_tamp2.enumerate_temporal_paths(src_nid2, dst_nid2)
print(f"LLDOS 2.0.2 After removal: {len(paths_after2)} paths")
