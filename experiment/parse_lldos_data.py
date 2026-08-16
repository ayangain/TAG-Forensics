"""
parse_lldos_data.py — Parse DARPA 2000 LLDOS dataset files.

Extracts ground-truth attack events from:
  - labeling_info: Phase timestamps
  - mid-level-phase-{1-5}.xml: IDMEF XML alerts with source/target/time/service
  - phase-{1-5}.list: Session list files
"""

import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from dataclasses import dataclass


@dataclass
class LLDOSPhase:
    """Ground-truth metadata for a single attack phase."""
    phase_num: int
    attack_type: str
    begin_time: datetime
    end_time: datetime
    attacker_ip: str
    target_pattern: str
    label: str

    @property
    def begin_epoch(self) -> float:
        return self.begin_time.timestamp()

    @property
    def end_epoch(self) -> float:
        return self.end_time.timestamp()

    @property
    def duration_seconds(self) -> float:
        return self.end_epoch - self.begin_epoch


@dataclass
class IDMEFAlert:
    """A single IDMEF alert parsed from XML labeling."""
    alert_id: str
    date: str
    time: str
    duration: str
    source_ip: str
    target_ip: str
    service: str
    analyzer: str

    @property
    def timestamp(self) -> datetime:
        dt_str = f"{self.date} {self.time}"
        return datetime.strptime(dt_str, "%m/%d/%Y %H:%M:%S")

    @property
    def epoch(self) -> float:
        return self.timestamp.timestamp()

    @property
    def duration_seconds(self) -> float:
        parts = self.duration.split(":")
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        return 0.0


def parse_labeling_info(dataset_path: str) -> list:
    """
    Parse the labeling_info file to extract ground-truth phase timing.

    Returns list of LLDOSPhase objects.
    """
    labeling_path = os.path.join(dataset_path, "labeling_info")
    phases = []
    current_phase = {}

    with open(labeling_path, "r") as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue

            # Phase header line
            phase_match = re.match(
                r"PHASE\s+(\d+):\s+\d+\s+\d+\s+\w+\s+[\d:]+\s+[\d:]+\s+(\S+)\s+(\S+)\s+(\S+)",
                line
            )
            if phase_match:
                current_phase = {
                    "phase_num": int(phase_match.group(1)),
                    "attack_type": phase_match.group(2),
                    "attacker_ip": phase_match.group(3),
                    "target_pattern": phase_match.group(4),
                }
                continue

            # BEGIN timestamp
            begin_match = re.match(r"\s+BEGIN:\s+(.+)", line)
            if begin_match and current_phase:
                ts_str = begin_match.group(1).strip()
                # Format: "Tue Mar  7 09:51:35 EST 2000" or "Sun Apr 16 15:05:46 EDT 2000"
                ts_clean = re.sub(r"\s+(EST|EDT)\s+", " ", ts_str)
                ts_clean = re.sub(r"\s+", " ", ts_clean).strip()
                try:
                    current_phase["begin_time"] = datetime.strptime(
                        ts_clean, "%a %b %d %H:%M:%S %Y"
                    )
                except ValueError:
                    current_phase["begin_time"] = datetime.strptime(
                        ts_clean, "%a %b %d %H:%M:%S %Y"
                    )
                continue

            # END timestamp
            end_match = re.match(r"\s+END:\s+(.+)", line)
            if end_match and current_phase:
                ts_str = end_match.group(1).strip()
                ts_clean = re.sub(r"\s+(EST|EDT)\s+", " ", ts_str)
                ts_clean = re.sub(r"\s+", " ", ts_clean).strip()
                try:
                    current_phase["end_time"] = datetime.strptime(
                        ts_clean, "%a %b %d %H:%M:%S %Y"
                    )
                except ValueError:
                    pass

                # Build phase object if we have all fields
                if all(k in current_phase for k in
                       ["phase_num", "attack_type", "begin_time", "end_time",
                        "attacker_ip", "target_pattern"]):
                    phases.append(LLDOSPhase(
                        phase_num=current_phase["phase_num"],
                        attack_type=current_phase["attack_type"],
                        begin_time=current_phase["begin_time"],
                        end_time=current_phase["end_time"],
                        attacker_ip=current_phase["attacker_ip"],
                        target_pattern=current_phase["target_pattern"],
                        label=f"Phase {current_phase['phase_num']}: {current_phase['attack_type']}",
                    ))
                continue

    return phases


def parse_idmef_xml(xml_path: str) -> list:
    """
    Parse an IDMEF XML file to extract alerts.

    The LLDOS XML files are not well-formed XML (multiple root elements),
    so we wrap them and parse iteratively.
    """
    alerts = []

    with open(xml_path, "r", errors="replace") as f:
        content = f.read()

    # Wrap in a root element for valid XML
    wrapped = f"<root>{content}</root>"

    # Fix common issues in LLDOS XML
    wrapped = wrapped.replace("&", "&amp;")

    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        # Fallback: regex-based extraction
        return _parse_idmef_regex(content)

    for msg in root.findall(".//IDMEF-Message"):
        alert_elem = msg.find("Alert")
        if alert_elem is None:
            continue

        alert_id = alert_elem.get("alertid", "")

        # Time
        time_elem = alert_elem.find("Time")
        date_str = time_elem.findtext("date", "") if time_elem is not None else ""
        time_str = time_elem.findtext("time", "") if time_elem is not None else ""
        duration = time_elem.findtext("sessionduration", "00:00:00") if time_elem is not None else "00:00:00"

        # Analyzer
        analyzer_elem = alert_elem.find("Analyzer")
        analyzer = analyzer_elem.findtext("name", "") if analyzer_elem is not None else ""

        # Source
        source_elem = alert_elem.find("Source")
        src_ip = ""
        if source_elem is not None:
            addr = source_elem.find(".//address")
            if addr is not None:
                src_ip = addr.text or ""

        # Target
        target_elem = alert_elem.find("Target")
        dst_ip = ""
        service = ""
        if target_elem is not None:
            addr = target_elem.find(".//address")
            if addr is not None:
                dst_ip = addr.text or ""
            svc = target_elem.find(".//Service/name")
            if svc is not None:
                service = svc.text or ""

        if date_str and time_str:
            alerts.append(IDMEFAlert(
                alert_id=alert_id,
                date=date_str,
                time=time_str,
                duration=duration,
                source_ip=src_ip,
                target_ip=dst_ip,
                service=service,
                analyzer=analyzer,
            ))

    return alerts


def _parse_idmef_regex(content: str) -> list:
    """Fallback regex-based IDMEF parser for malformed XML."""
    alerts = []
    alert_blocks = re.findall(
        r"<Alert\s+alertid=\"(\d+)\".*?</Alert>", content, re.DOTALL
    )

    for block_match in re.finditer(r"<Alert\s+alertid=\"(\d+)\".*?</Alert>", content, re.DOTALL):
        block = block_match.group(0)
        alert_id = block_match.group(1)

        date_m = re.search(r"<date>(.*?)</date>", block)
        time_m = re.search(r"<time>(.*?)</time>", block)
        dur_m = re.search(r"<sessionduration>(.*?)</sessionduration>", block)
        src_m = re.search(r"<Source.*?<address>(.*?)</address>", block, re.DOTALL)
        dst_m = re.search(r"<Target.*?<address>(.*?)</address>", block, re.DOTALL)
        svc_m = re.search(r"<Service>\s*<name>(.*?)</name>", block, re.DOTALL)
        ana_m = re.search(r"<Analyzer.*?<name>(.*?)</name>", block, re.DOTALL)

        if date_m and time_m:
            alerts.append(IDMEFAlert(
                alert_id=alert_id,
                date=date_m.group(1),
                time=time_m.group(1),
                duration=dur_m.group(1) if dur_m else "00:00:00",
                source_ip=src_m.group(1) if src_m else "",
                target_ip=dst_m.group(1) if dst_m else "",
                service=svc_m.group(1) if svc_m else "",
                analyzer=ana_m.group(1) if ana_m else "",
            ))

    return alerts


def parse_list_file(list_path: str) -> list:
    """
    Parse a LLDOS phase list file (1999 listfile format).
    
    Format: ID  DATE  TIME  DURATION  SERVICE  -  -  SRC_IP  DST_IP  BYTES  FLAG
    """
    entries = []
    with open(list_path, "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 10:
                entries.append({
                    "id": parts[0],
                    "date": parts[1],
                    "time": parts[2],
                    "duration": parts[3],
                    "service": parts[4],
                    "src_ip": parts[7],
                    "dst_ip": parts[8],
                    "bytes": parts[9],
                })
    return entries


def load_lldos_scenario(dataset_path: str, sensor: str = "tcpdump_inside") -> dict:
    """
    Load a complete LLDOS scenario.
    
    Returns dict with:
      - phases: list of LLDOSPhase
      - alerts: dict of {phase_num: [IDMEFAlert, ...]}
      - list_entries: dict of {phase_num: [dict, ...]}
    """
    phases = parse_labeling_info(dataset_path)

    alerts = {}
    list_entries = {}
    sensor_dir = os.path.join(dataset_path, sensor)

    for phase_num in range(1, 6):
        # Parse XML alerts
        xml_path = os.path.join(sensor_dir, f"mid-level-phase-{phase_num}.xml")
        if os.path.exists(xml_path):
            alerts[phase_num] = parse_idmef_xml(xml_path)
        else:
            alerts[phase_num] = []

        # Parse list files
        list_path = os.path.join(sensor_dir, f"phase-{phase_num}.list")
        if os.path.exists(list_path):
            list_entries[phase_num] = parse_list_file(list_path)
        else:
            list_entries[phase_num] = []

    return {
        "phases": phases,
        "alerts": alerts,
        "list_entries": list_entries,
        "dataset_path": dataset_path,
        "sensor": sensor,
    }


# ── LLDOS 1.0 Network Topology Constants ────────────────────────────────

LLDOS_10_HOSTS = {
    "attacker":     "202.77.162.213",
    "mill":         "172.16.115.20",
    "pascal":       "172.16.112.50",
    "locke":        "172.16.112.10",
    "hume":         "172.16.112.100",
    "kant":         "172.16.112.105",
    "marx":         "172.16.113.148",
    "zeno":         "172.16.113.50",
    "ddos_target":  "131.84.1.31",
}

LLDOS_10_COMPROMISED = ["mill", "pascal", "locke"]

# Causal attack edges with ground-truth phase assignment
LLDOS_10_ATTACK_EDGES = [
    # Phase 1: IPsweep — attacker probes all subnets
    {"id": "E1_ipsweep",      "src": "attacker", "dst": "mill",    "phase": 1, "service": "icmp-echo"},
    {"id": "E2_ipsweep",      "src": "attacker", "dst": "pascal",  "phase": 1, "service": "icmp-echo"},
    {"id": "E3_ipsweep",      "src": "attacker", "dst": "locke",   "phase": 1, "service": "icmp-echo"},
    # Phase 2: Sadmind ping — RPC probe for sadmind service
    {"id": "E4_sadmind_ping", "src": "attacker", "dst": "mill",    "phase": 2, "service": "sunrpc-sadmind"},
    {"id": "E5_sadmind_ping", "src": "attacker", "dst": "pascal",  "phase": 2, "service": "sunrpc-sadmind"},
    {"id": "E6_sadmind_ping", "src": "attacker", "dst": "locke",   "phase": 2, "service": "sunrpc-sadmind"},
    # Phase 3: Sadmind break-in — buffer overflow exploit
    {"id": "E7_sadmind_exploit",  "src": "attacker", "dst": "mill",    "phase": 3, "service": "sadmind-exploit"},
    {"id": "E8_sadmind_exploit",  "src": "attacker", "dst": "pascal",  "phase": 3, "service": "sadmind-exploit"},
    {"id": "E9_sadmind_exploit",  "src": "attacker", "dst": "locke",   "phase": 3, "service": "sadmind-exploit"},
    # Phase 4: Mstream install — telnet + rcp + rsh
    {"id": "E10_telnet_login",    "src": "attacker", "dst": "mill",    "phase": 4, "service": "telnet"},
    {"id": "E11_rcp_mstream",     "src": "attacker", "dst": "mill",    "phase": 4, "service": "rcp"},
    {"id": "E12_telnet_login",    "src": "attacker", "dst": "pascal",  "phase": 4, "service": "telnet"},
    {"id": "E13_rcp_mstream",     "src": "attacker", "dst": "pascal",  "phase": 4, "service": "rcp"},
    {"id": "E14_telnet_login",    "src": "attacker", "dst": "locke",   "phase": 4, "service": "telnet"},
    {"id": "E15_rcp_mstream",     "src": "attacker", "dst": "locke",   "phase": 4, "service": "rcp"},
    # Phase 5: DDoS launch — mstream master/server communication + DDoS
    {"id": "E16_mstream_master",  "src": "attacker", "dst": "mill",    "phase": 5, "service": "mstream-master"},
    {"id": "E17_ddos_launch",     "src": "mill",     "dst": "ddos_target", "phase": 5, "service": "mstream-ddos"},
    {"id": "E18_ddos_launch",     "src": "pascal",   "dst": "ddos_target", "phase": 5, "service": "mstream-ddos"},
    {"id": "E19_ddos_launch",     "src": "locke",    "dst": "ddos_target", "phase": 5, "service": "mstream-ddos"},
]

# Causal precedence constraints (phase ordering)
LLDOS_10_CAUSAL_CONSTRAINTS = [
    # Phase 1 → Phase 2 (must sweep before probing sadmind)
    ("E1_ipsweep", "E4_sadmind_ping"),
    ("E2_ipsweep", "E5_sadmind_ping"),
    ("E3_ipsweep", "E6_sadmind_ping"),
    # Phase 2 → Phase 3 (must probe before exploiting)
    ("E4_sadmind_ping", "E7_sadmind_exploit"),
    ("E5_sadmind_ping", "E8_sadmind_exploit"),
    ("E6_sadmind_ping", "E9_sadmind_exploit"),
    # Phase 3 → Phase 4 (must exploit before installing)
    ("E7_sadmind_exploit", "E10_telnet_login"),
    ("E7_sadmind_exploit", "E11_rcp_mstream"),
    ("E8_sadmind_exploit", "E12_telnet_login"),
    ("E8_sadmind_exploit", "E13_rcp_mstream"),
    ("E9_sadmind_exploit", "E14_telnet_login"),
    ("E9_sadmind_exploit", "E15_rcp_mstream"),
    # Phase 4 → Phase 5 (must install before launching)
    ("E11_rcp_mstream", "E16_mstream_master"),
    ("E11_rcp_mstream", "E17_ddos_launch"),
    ("E13_rcp_mstream", "E18_ddos_launch"),
    ("E15_rcp_mstream", "E19_ddos_launch"),
    ("E16_mstream_master", "E17_ddos_launch"),
    ("E16_mstream_master", "E18_ddos_launch"),
    ("E16_mstream_master", "E19_ddos_launch"),
]


def build_lldos10_evidence_graph(dataset_path: str) -> 'EvidenceGraph':
    """
    Build the ground-truth evidence graph for LLDOS 1.0.
    
    Uses phase timing from labeling_info and the known attack structure.
    """
    import sys
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    from experiment.evidence_graph import EvidenceGraph, EvidenceEdge, CausalConstraint

    phases = parse_labeling_info(dataset_path)
    phase_times = {p.phase_num: p for p in phases}

    eg = EvidenceGraph(scenario="LLDOS_1.0")
    eg.metadata["dataset_path"] = dataset_path
    eg.metadata["phases"] = {p.phase_num: {
        "begin": p.begin_epoch, "end": p.end_epoch,
        "attack_type": p.attack_type, "label": p.label,
    } for p in phases}

    # Add attack edges with ground-truth timestamps
    for edge_def in LLDOS_10_ATTACK_EDGES:
        phase = phase_times.get(edge_def["phase"])
        if phase is None:
            continue

        # Distribute edge timestamps within the phase window
        phase_duration = phase.duration_seconds
        edges_in_phase = [e for e in LLDOS_10_ATTACK_EDGES if e["phase"] == edge_def["phase"]]
        idx = edges_in_phase.index(edge_def)
        n_edges = len(edges_in_phase)

        # Evenly space edges within phase window
        slot_duration = phase_duration / max(n_edges, 1)
        edge_start = phase.begin_epoch + idx * slot_duration
        edge_end = edge_start + min(slot_duration * 0.8, phase_duration)

        src_ip = LLDOS_10_HOSTS[edge_def["src"]]
        dst_ip = LLDOS_10_HOSTS[edge_def["dst"]]

        eg.add_edge(EvidenceEdge(
            edge_id=edge_def["id"],
            src=src_ip,
            dst=dst_ip,
            phase=edge_def["phase"],
            true_start=edge_start,
            true_end=edge_end,
            service=edge_def["service"],
        ))

    # Add causal constraints (with -10s tolerance to account for sensor jitter)
    for before_id, after_id in LLDOS_10_CAUSAL_CONSTRAINTS:
        eg.add_constraint(CausalConstraint(
            edge_before_id=before_id,
            edge_after_id=after_id,
            min_gap=-10.0,  # Allows up to 10s sensor jitter on control runs
        ))

    return eg


# ── LLDOS 2.0.2 Stealthy Scenario Constants ──────────────────────────────

LLDOS_202_HOSTS = {
    "attacker":     "202.77.162.213",
    "mill":         "172.16.115.20",
    "pascal":       "172.16.112.50",
    "hume":         "172.16.112.100",
    "ddos_target":  "131.84.1.31",
}

LLDOS_202_ATTACK_EDGES = [
    # Phase 1: DNS query — targeted lookup (no IPsweep!)
    {"id": "E1_dns_query",       "src": "attacker", "dst": "mill",    "phase": 1, "service": "dns"},
    # Phase 2: Sadmind exploit — targeted exploit on mill (no probe!)
    {"id": "E2_sadmind_exploit", "src": "attacker", "dst": "mill",    "phase": 2, "service": "sadmind-exploit"},
    # Phase 3: FTP upload — mstream binary uploaded via FTP
    {"id": "E3_ftp_upload",      "src": "attacker", "dst": "mill",    "phase": 3, "service": "ftp"},
    # Phase 4: SSH lateral movement — mill → pascal
    {"id": "E4_ssh_lateral",     "src": "mill",     "dst": "pascal",  "phase": 4, "service": "ssh"},
    {"id": "E5_rcp_mstream",     "src": "mill",     "dst": "pascal",  "phase": 4, "service": "rcp"},
    # Phase 5: DDoS launch — mstream master/servers launch attack
    {"id": "E6_mstream_master",  "src": "attacker", "dst": "mill",    "phase": 5, "service": "mstream-master"},
    {"id": "E7_ddos_launch",     "src": "mill",     "dst": "ddos_target", "phase": 5, "service": "mstream-ddos"},
    {"id": "E8_ddos_launch",     "src": "pascal",   "dst": "ddos_target", "phase": 5, "service": "mstream-ddos"},
]

LLDOS_202_CAUSAL_CONSTRAINTS = [
    ("E1_dns_query", "E2_sadmind_exploit"),
    ("E2_sadmind_exploit", "E3_ftp_upload"),
    ("E3_ftp_upload", "E4_ssh_lateral"),
    ("E3_ftp_upload", "E5_rcp_mstream"),
    ("E4_ssh_lateral", "E6_mstream_master"),
    ("E5_rcp_mstream", "E6_mstream_master"),
    ("E6_mstream_master", "E7_ddos_launch"),
    ("E6_mstream_master", "E8_ddos_launch"),
]


def build_lldos202_evidence_graph(dataset_path: str) -> 'EvidenceGraph':
    """
    Build the ground-truth evidence graph for LLDOS 2.0.2 (stealthy scenario).
    """
    import sys
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    from experiment.evidence_graph import EvidenceGraph, EvidenceEdge, CausalConstraint

    phases = parse_labeling_info(dataset_path)
    phase_times = {p.phase_num: p for p in phases}

    eg = EvidenceGraph(scenario="LLDOS_2.0.2")
    eg.metadata["dataset_path"] = dataset_path
    eg.metadata["phases"] = {p.phase_num: {
        "begin": p.begin_epoch, "end": p.end_epoch,
        "attack_type": p.attack_type, "label": p.label,
    } for p in phases}

    for edge_def in LLDOS_202_ATTACK_EDGES:
        phase = phase_times.get(edge_def["phase"])
        if phase is None:
            continue

        phase_duration = phase.duration_seconds
        edges_in_phase = [e for e in LLDOS_202_ATTACK_EDGES if e["phase"] == edge_def["phase"]]
        idx = edges_in_phase.index(edge_def)
        n_edges = len(edges_in_phase)

        slot_duration = phase_duration / max(n_edges, 1)
        edge_start = phase.begin_epoch + idx * slot_duration
        edge_end = edge_start + min(slot_duration * 0.8, max(phase_duration, 1.0))

        src_ip = LLDOS_202_HOSTS[edge_def["src"]]
        dst_ip = LLDOS_202_HOSTS[edge_def["dst"]]

        eg.add_edge(EvidenceEdge(
            edge_id=edge_def["id"],
            src=src_ip,
            dst=dst_ip,
            phase=edge_def["phase"],
            true_start=edge_start,
            true_end=edge_end,
            service=edge_def["service"],
        ))

    for before_id, after_id in LLDOS_202_CAUSAL_CONSTRAINTS:
        eg.add_constraint(CausalConstraint(
            edge_before_id=before_id,
            edge_after_id=after_id,
            min_gap=-10.0,
        ))

    return eg


if __name__ == "__main__":
    import sys
    dataset = sys.argv[1] if len(sys.argv) > 1 else "LLS_DDOS_1.0"
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_path = os.path.join(base, dataset)

    print(f"=== Parsing {dataset} ===")
    phases = parse_labeling_info(dataset_path)
    for p in phases:
        print(f"  Phase {p.phase_num}: {p.attack_type}")
        print(f"    {p.begin_time} → {p.end_time} ({p.duration_seconds:.0f}s)")
        print(f"    Attacker: {p.attacker_ip} → Target: {p.target_pattern}")

    print(f"\n=== Building LLDOS 1.0 evidence graph ===")
    eg1 = build_lldos10_evidence_graph(os.path.join(base, "LLS_DDOS_1.0"))
    print(f"  {eg1.summary()}")

    print(f"\n=== Building LLDOS 2.0.2 evidence graph ===")
    eg2 = build_lldos202_evidence_graph(os.path.join(base, "LLDOS 2.0.2"))
    print(f"  {eg2.summary()}")

