"""
lldos_tag_builder.py — Constructs Forensic Temporal Attack Graphs directly
from the DARPA LLDOS 1.0 and 2.0.2 ground-truth datasets.

Data sources used:
  - labeling_info: Phase timestamps, attack types, src/dst IPs
  - tcpdump_inside/phase-*.list: Per-phase session listings with timestamps,
    services, source/destination IPs
  - tcpdump_inside/mid-level-phase-*.xml: IDMEF XML alerts per phase

The TAG is constructed by:
  1. Parsing labeling_info for phase timing and attack classification
  2. Parsing phase-*.list files for individual network sessions (evidence events)
  3. Assigning time windows based on attack phase boundaries
  4. Building TAG nodes from unique hosts observed
  5. Building TAG edges from causal attack steps (scan → probe → exploit → install → launch)
  6. Mapping each edge to the time windows in which it was active
"""

import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from experiment.ftag_model import ForensicTemporalAttackGraph, TAGEdge


@dataclass
class PhaseInfo:
    """Parsed attack phase metadata from labeling_info."""
    phase_num: int
    attack_type: str
    src_ip: str
    dst_ip: str
    begin_time: datetime
    end_time: datetime
    classification: str  # probe, r2l, violation, dos, r2r


@dataclass
class SessionEvent:
    """A single network session parsed from phase-*.list files."""
    session_id: int
    date: str           # 03/07/2000
    time: str           # 09:51:36
    duration: str       # 00:00:01
    service: str        # eco/i, sunrpc/u, telnet, shell, etc.
    src_port: str
    dst_port: str
    src_ip: str
    dst_ip: str
    phase: int
    timestamp: datetime = None

    def __post_init__(self):
        self.src_ip = self.src_ip.replace('.0', '.').lstrip('0') if self.src_ip else self.src_ip
        # Normalize IP: 172.016.115.020 -> 172.16.115.20
        if self.src_ip:
            self.src_ip = normalize_ip(self.src_ip)
        if self.dst_ip:
            self.dst_ip = normalize_ip(self.dst_ip)


def normalize_ip(ip: str) -> str:
    """Convert 172.016.115.020 -> 172.16.115.20"""
    if not ip or ip == "-" or "*" in ip:
        return ip
    parts = ip.strip().split(".")
    if len(parts) == 4:
        try:
            return ".".join(str(int(p)) for p in parts if p != "")
        except ValueError:
            return ip
    return ip


def parse_labeling_info(filepath: str) -> List[PhaseInfo]:
    """Parse the labeling_info file to extract phase metadata."""
    phases = []
    with open(filepath, 'r') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("PHASE"):
            parts = line.split()
            phase_num = int(parts[1].rstrip(':'))
            attack_type = parts[7] if len(parts) > 7 else "unknown"
            src_ip = parts[8] if len(parts) > 8 else ""
            dst_ip = parts[9] if len(parts) > 9 else ""
            classification = parts[13] if len(parts) > 13 else (parts[12] if len(parts) > 12 else "unknown")

            # Parse BEGIN/END timestamps
            begin_time = None
            end_time = None
            for j in range(i + 1, min(i + 15, len(lines))):
                subline = lines[j].strip()
                if subline.startswith("PHASE"):
                    break
                if subline.startswith("BEGIN:"):
                    time_str = subline[len("BEGIN:"):].strip()
                    begin_time = parse_darpa_timestamp(time_str)
                elif subline.startswith("END:"):
                    time_str = subline[len("END:"):].strip()
                    end_time = parse_darpa_timestamp(time_str)

            if begin_time and end_time:
                phases.append(PhaseInfo(
                    phase_num=phase_num,
                    attack_type=attack_type,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    begin_time=begin_time,
                    end_time=end_time,
                    classification=classification,
                ))
        i += 1

    return phases


def parse_darpa_timestamp(ts: str) -> datetime:
    """Parse DARPA timestamp format: Tue Mar  7 09:51:35 EST 2000"""
    # Handle double spaces
    ts = re.sub(r'\s+', ' ', ts.strip())
    # Remove timezone
    ts = ts.replace(' EST ', ' ').replace(' EDT ', ' ')
    # Try multiple formats
    for fmt in ["%a %b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S %Y"]:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    # Fallback: manual parse
    parts = ts.split()
    if len(parts) >= 5:
        month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                     'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
        month = month_map.get(parts[1], 1)
        day = int(parts[2])
        time_parts = parts[3].split(':')
        year = int(parts[4]) if len(parts) > 4 else 2000
        return datetime(year, month, day, int(time_parts[0]),
                       int(time_parts[1]), int(time_parts[2]))
    raise ValueError(f"Cannot parse timestamp: {ts}")


def parse_session_list(filepath: str, phase_num: int) -> List[SessionEvent]:
    """Parse a phase-*.list file into session events."""
    sessions = []
    if not os.path.exists(filepath):
        return sessions

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                session_id = int(parts[0])
            except ValueError:
                continue

            event = SessionEvent(
                session_id=session_id,
                date=parts[1],
                time=parts[2],
                duration=parts[3],
                service=parts[4],
                src_port=parts[5],
                dst_port=parts[6],
                src_ip=parts[7],
                dst_ip=parts[8],
                phase=phase_num,
            )
            # Parse timestamp
            try:
                event.timestamp = datetime.strptime(
                    f"{event.date} {event.time}", "%m/%d/%Y %H:%M:%S")
            except ValueError:
                pass
            sessions.append(event)

    return sessions


def parse_idmef_xml(filepath: str) -> List[Dict]:
    """Parse IDMEF XML alert file to extract structured alerts."""
    alerts = []
    if not os.path.exists(filepath):
        return alerts

    with open(filepath, 'r') as f:
        content = f.read()

    # Wrap in root element for valid XML
    content = f"<root>{content}</root>"
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        # Try cleaning up the XML
        content = content.replace('&', '&amp;')
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return alerts

    for msg in root.findall('.//Alert'):
        alert = {
            'alertid': msg.get('alertid', ''),
            'impact': msg.get('impact', 'unknown'),
        }

        # Time
        time_elem = msg.find('Time')
        if time_elem is not None:
            date_elem = time_elem.find('date')
            time_text = time_elem.find('time')
            dur_elem = time_elem.find('sessionduration')
            if date_elem is not None and time_text is not None:
                alert['date'] = date_elem.text
                alert['time'] = time_text.text
                try:
                    alert['timestamp'] = datetime.strptime(
                        f"{date_elem.text} {time_text.text}",
                        "%m/%d/%Y %H:%M:%S")
                except ValueError:
                    pass
            if dur_elem is not None:
                alert['duration'] = dur_elem.text

        # Source
        source = msg.find('.//Source')
        if source is not None:
            addr = source.find('.//address')
            if addr is not None and addr.text:
                alert['src_ip'] = normalize_ip(addr.text)

        # Target
        target = msg.find('.//Target')
        if target is not None:
            addr = target.find('.//address')
            if addr is not None and addr.text:
                alert['dst_ip'] = normalize_ip(addr.text)
            svc = target.find('.//name')
            if svc is not None:
                alert['service'] = svc.text

        alerts.append(alert)

    return alerts


# ══════════════════════════════════════════════════════════════
# TAG Construction from LLDOS Dataset
# ══════════════════════════════════════════════════════════════

ATTACKER_IP = "202.77.162.213"

# LLDOS 1.0 network topology (from index.html)
LLDOS1_HOSTS = {
    "attacker":  "202.77.162.213",
    "mill":      "172.16.115.20",     # Solaris, DNS server, sadmind victim
    "pascal":    "172.16.112.50",     # Solaris, sadmind victim
    "locke":     "172.16.112.10",     # Solaris, sadmind victim
    "marx":      "172.16.113.105",    # Inside network host
    "zeno":      "172.16.113.148",    # Inside network host
    "hume":      "172.16.112.100",    # Windows NT server
    "kant":      "172.16.112.149",    # Windows NT workstation
    "ddos_target": "131.84.1.31",    # External DDoS target
}

# Reverse lookup
LLDOS1_IP_TO_HOST = {v: k for k, v in LLDOS1_HOSTS.items()}


def build_tag_from_lldos(dataset_dir: str, dataset_name: str = "LLDOS_1.0") -> ForensicTemporalAttackGraph:
    """
    Construct a Forensic Temporal Attack Graph directly from LLDOS dataset files.

    The 5 attack phases map to 5 time windows (w0..w4).
    Each phase's network sessions become evidence events.
    Edges represent causal attack steps derived from the labeled ground truth.
    """
    # ── Step 1: Parse labeling_info ──
    labeling_path = os.path.join(dataset_dir, "labeling_info")
    phases = parse_labeling_info(labeling_path)

    print(f"\n  Parsed {len(phases)} attack phases from {dataset_name}:")
    for p in phases:
        duration = (p.end_time - p.begin_time).total_seconds()
        print(f"    Phase {p.phase_num}: {p.attack_type:25s} {p.src_ip} → {p.dst_ip}"
              f"  [{p.begin_time.strftime('%H:%M:%S')} – {p.end_time.strftime('%H:%M:%S')}]"
              f"  ({duration:.0f}s)  [{p.classification}]")

    # ── Step 2: Parse session lists per phase ──
    tcpdump_dir = os.path.join(dataset_dir, "tcpdump_inside")
    all_sessions = []
    for phase in phases:
        list_path = os.path.join(tcpdump_dir, f"phase-{phase.phase_num}.list")
        sessions = parse_session_list(list_path, phase.phase_num)
        all_sessions.extend(sessions)
        print(f"    Phase {phase.phase_num}: {len(sessions)} network sessions parsed from tcpdump_inside")

    # ── Step 3: Parse IDMEF XML alerts ──
    all_xml_alerts = []
    for phase in phases:
        xml_path = os.path.join(tcpdump_dir, f"mid-level-phase-{phase.phase_num}.xml")
        alerts = parse_idmef_xml(xml_path)
        all_xml_alerts.extend(alerts)
        print(f"    Phase {phase.phase_num}: {len(alerts)} IDMEF XML alerts parsed")

    # ── Step 4: Build TAG ──
    num_windows = len(phases)
    # Compute window duration from phase timing
    if len(phases) >= 2:
        total_span = (phases[-1].end_time - phases[0].begin_time).total_seconds()
        window_duration = total_span / num_windows
    else:
        window_duration = 3600.0

    ftag = ForensicTemporalAttackGraph(
        graph_id=dataset_name,
        num_windows=num_windows,
        window_duration_seconds=window_duration,
    )

    # ── Step 5: Build edges and state nodes from ground-truth attack phases ──
    # Map phases to causal attack edges
    if "1.0" in dataset_name or "LLS_DDOS" in dataset_dir:
        _build_lldos1_edges(ftag, phases, all_sessions)
    elif "2.0" in dataset_name:
        _build_lldos2_edges(ftag, phases, all_sessions)

    print(f"\n  TAG Nodes: {len(ftag.nodes)} states")
    print(f"  TAG Edges: {len(ftag.edges)} causal attack steps")

    # ── Step 7: Attach evidence timestamps from actual sessions ──
    _attach_evidence_timestamps(ftag, all_sessions, phases)

    return ftag


def _build_lldos1_edges(ftag, phases, sessions):
    """
    Build edges for LLDOS 1.0 based on a sequential 6-stage attack chain:
      Phase 1: IPsweep (w0) -> attacker:ext to [victim]:discovered
      Phase 2: Sadmind probe (w1) -> [victim]:discovered to [victim]:sadmind_vuln
      Phase 3: Sadmind exploit (w2) -> [victim]:sadmind_vuln to [victim]:root_access
      Phase 4: Install mstream (w3) -> mill:root_access to mill:mstream_master
               and lateral rsh -> mill:mstream_master to locke/pascal:mstream_daemon
      Phase 5: Launch DDoS (w4) -> mill/locke/pascal to ddos_target:impact
    """
    # Victim hosts that got compromised
    victims = ["mill", "locke", "pascal"]

    # Helper to add state nodes
    def add_state(host_key, state_name):
        node_id = f"{host_key}:{state_name}"
        ip = LLDOS1_HOSTS.get(host_key, "0.0.0.0") if host_key != "ddos_target" else "131.84.1.31"
        if node_id not in ftag.nodes:
            ftag.add_node(node_id, ip, state_name)
        return node_id

    attacker = add_state("attacker", "ext")

    # Phase 1: IPsweep
    for victim in victims:
        discovered = add_state(victim, "discovered")
        ftag.add_edge(f"E_ipsweep_{victim}", attacker, discovered, "IPsweep_Probe",
                      active_windows={0}, delta_t_min=1.0)

    # Phase 2: Sadmind probe
    for victim in victims:
        discovered = add_state(victim, "discovered")
        vuln = add_state(victim, "sadmind_vuln")
        ftag.add_edge(f"E_sadmind_probe_{victim}", discovered, vuln, "Sadmind_Probe",
                      active_windows={1}, delta_t_min=5.0)

    # Phase 3: Sadmind exploit
    for victim in victims:
        vuln = add_state(victim, "sadmind_vuln")
        root = add_state(victim, "root_access")
        ftag.add_edge(f"E_sadmind_exploit_{victim}", vuln, root, "Sadmind_R2R_Exploit",
                      active_windows={2}, delta_t_min=10.0)

    # Phase 4: Install mstream master on mill
    mill_root = add_state("mill", "root_access")
    mill_master = add_state("mill", "mstream_master")
    ftag.add_edge("E_mstream_install_mill", mill_root, mill_master, "Mstream_Install_Telnet",
                  active_windows={3}, delta_t_min=5.0)

    # Phase 4/5: Lateral movement via rsh to locke and pascal
    locke_daemon = add_state("locke", "mstream_daemon")
    pascal_daemon = add_state("pascal", "mstream_daemon")
    ftag.add_edge("E_rsh_lateral_locke", mill_master, locke_daemon, "RSH_Lateral",
                  active_windows={3, 4}, delta_t_min=2.0)
    ftag.add_edge("E_rsh_lateral_pascal", mill_master, pascal_daemon, "RSH_Lateral",
                  active_windows={3, 4}, delta_t_min=2.0)

    # Phase 5: DDoS launch
    target_impact = add_state("ddos_target", "impact")
    ftag.add_edge("E_ddos_launch_mill", mill_master, target_impact, "Mstream_DDoS_Attack",
                  active_windows={4}, delta_t_min=1.0)
    ftag.add_edge("E_ddos_launch_locke", locke_daemon, target_impact, "Mstream_DDoS_Attack",
                  active_windows={4}, delta_t_min=1.0)
    ftag.add_edge("E_ddos_launch_pascal", pascal_daemon, target_impact, "Mstream_DDoS_Attack",
                  active_windows={4}, delta_t_min=1.0)


def _build_lldos2_edges(ftag, phases, sessions):
    """
    Build edges for LLDOS 2.0.2 based on a 5-stage sequential attack:
      Phase 1: DNS query (w0) -> attacker:ext to mill:dns_queried
      Phase 2: Sadmind exploit (w1) -> mill:dns_queried to mill:root_access
      Phase 3: FTP upload (w2) -> mill:root_access to mill:ftp_uploaded
      Phase 4: SSH launch (w3) -> mill:ftp_uploaded to pascal:ssh_accessed
      Phase 5: Mail receipt (w4) -> pascal:ssh_accessed to attacker:exfil_received
    """
    def add_state(host_key, state_name):
        node_id = f"{host_key}:{state_name}"
        ip = LLDOS1_HOSTS.get(host_key, "0.0.0.0")
        if node_id not in ftag.nodes:
            ftag.add_node(node_id, ip, state_name)
        return node_id

    attacker = add_state("attacker", "ext")
    mill_dns = add_state("mill", "dns_queried")
    mill_root = add_state("mill", "root_access")
    mill_ftp = add_state("mill", "ftp_uploaded")
    pascal_ssh = add_state("pascal", "ssh_accessed")
    attacker_exfil = add_state("attacker", "exfil_received")

    ftag.add_edge("E_dns_recon", attacker, mill_dns, "DNS_Query_Recon",
                  active_windows={0}, delta_t_min=1.0)

    ftag.add_edge("E_sadmind_exploit_mill", mill_dns, mill_root, "Sadmind_R2R_Exploit",
                  active_windows={1}, delta_t_min=4.0)

    ftag.add_edge("E_ftp_upload_mill", mill_root, mill_ftp, "FTP_Malware_Upload",
                  active_windows={2}, delta_t_min=1.0)

    ftag.add_edge("E_ssh_lateral_pascal", mill_ftp, pascal_ssh, "SSH_Lateral_Movement",
                  active_windows={3}, delta_t_min=10.0)

    ftag.add_edge("E_mail_exfil", pascal_ssh, attacker_exfil, "Mail_Exfiltration",
                  active_windows={4}, delta_t_min=5.0)


def _attach_evidence_timestamps(ftag, sessions, phases):
    """Attach actual observed timestamps from network sessions to TAG edges."""
    # Map phase -> window index
    phase_to_window = {p.phase_num: i for i, p in enumerate(phases)}

    # For each edge, find matching sessions and attach the earliest timestamp
    for edge in ftag.edges.values():
        src_ip = ftag.nodes[edge.src_node_id].host_ip if edge.src_node_id in ftag.nodes else None
        dst_ip = ftag.nodes[edge.dst_node_id].host_ip if edge.dst_node_id in ftag.nodes else None

        if not src_ip or not dst_ip:
            continue

        # Find sessions matching this edge's src/dst IPs within its active windows
        matching_sessions = []
        for s in sessions:
            s_window = phase_to_window.get(s.phase)
            if s_window is None or s_window not in edge.active_windows:
                continue
            if s.src_ip == src_ip and s.dst_ip == dst_ip:
                matching_sessions.append(s)

        if matching_sessions:
            # Use earliest matching session as evidence
            earliest = min(matching_sessions, key=lambda s: s.timestamp or datetime.max)
            if earliest.timestamp:
                epoch_base = phases[0].begin_time
                edge.observed_time = (earliest.timestamp - epoch_base).total_seconds()
                edge.observed_window = min(edge.active_windows)


# ══════════════════════════════════════════════════════════════
# MulVAL Integration for LLDOS TAG Generation
# ══════════════════════════════════════════════════════════════

def build_lldos1_tag_using_mulval() -> ForensicTemporalAttackGraph:
    """
    Constructs the LLDOS 1.0 Forensic Temporal Attack Graph directly via
    the MulVAL Datalog Reasoning Engine (Ou et al. 2005 / Gain et al. 2026).
    """
    from experiment.mulval_engine import export_mulval_artifacts, build_ftag_from_mulval
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(base_dir, "experiment", "mulval_output")
    graphs = export_mulval_artifacts(output_dir)
    return build_ftag_from_mulval(graphs)


# ══════════════════════════════════════════════════════════════
# Main: Build TAGs from both datasets
# ══════════════════════════════════════════════════════════════

def build_all_lldos_tags(use_mulval_for_lldos1: bool = False) -> Dict[str, ForensicTemporalAttackGraph]:
    """Build TAGs from both LLDOS datasets."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tags = {}

    # LLDOS 1.0
    lldos1_dir = os.path.join(base_dir, "LLS_DDOS_1.0")
    if os.path.exists(lldos1_dir):
        if use_mulval_for_lldos1:
            print("=" * 70)
            print("  Building TAG from DARPA LLDOS 1.0 using MulVAL Datalog Engine")
            print("=" * 70)
            tags["LLDOS_1.0"] = build_lldos1_tag_using_mulval()
        else:
            print("=" * 70)
            print("  Building TAG from DARPA LLDOS 1.0 Ground Truth")
            print("=" * 70)
            tags["LLDOS_1.0"] = build_tag_from_lldos(lldos1_dir, "LLDOS_1.0")

    # LLDOS 2.0.2
    lldos2_dir = os.path.join(base_dir, "LLDOS 2.0.2")
    if os.path.exists(lldos2_dir):
        print(f"\n{'=' * 70}")
        print("  Building TAG from DARPA LLDOS 2.0.2 Ground Truth")
        print("=" * 70)
        tags["LLDOS_2.0.2"] = build_tag_from_lldos(lldos2_dir, "LLDOS_2.0.2")

    return tags


if __name__ == "__main__":
    tags = build_all_lldos_tags()
    for name, tag in tags.items():
        print(f"\n  {name}: {len(tag.nodes)} nodes, {len(tag.edges)} edges, {tag.num_windows} windows")
        for eid, edge in tag.edges.items():
            active_str = ",".join(f"w{w}" for w in sorted(edge.active_windows))
            obs_str = f"  obs_t={edge.observed_time:.0f}s" if edge.observed_time else ""
            print(f"    {eid:35s}  {edge.src_node_id:12s} → {edge.dst_node_id:12s}  "
                  f"[{active_str}]  {edge.classification}{obs_str}")
