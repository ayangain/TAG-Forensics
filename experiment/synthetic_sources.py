"""
synthetic_sources.py — Synthetic multi-source splitting and noise injection.

Splits single-sensor evidence into 3 pseudo-sources (IDS-like, NetFlow-like,
Host-log-like) with independent timestamp jitter, and injects background noise
at configurable ratios.

LIMITATION: The raw LLDOS capture is single-sensor. This synthetic split is
explicitly stated as a limitation in all results.
"""

import numpy as np
from typing import List
from experiment.evidence_graph import EvidenceGraph, EvidenceEdge


# Source configuration
SOURCE_CONFIGS = {
    "ids": {
        "name": "IDS-like",
        "jitter_std": 2.0,       # ±2s Gaussian jitter
        "sample_rate": 0.9,       # 90% of events visible to IDS
    },
    "netflow": {
        "name": "NetFlow-like",
        "jitter_std": 30.0,       # ±30s granularity (5-min aggregated flows)
        "sample_rate": 0.7,       # 70% — flow records miss some sessions
    },
    "hostlog": {
        "name": "Host-log-like",
        "jitter_std": 1.0,        # ±1s jitter (BSM audit precision)
        "sample_rate": 0.8,       # 80% — not all hosts have BSM enabled
    },
}


def split_to_sources(
    evidence_graph: EvidenceGraph,
    rng: np.random.Generator,
) -> EvidenceGraph:
    """
    Split single-sensor evidence into 3 pseudo-sources with independent jitter.
    
    Each edge is assigned to one of the 3 sources (round-robin by phase),
    and its observed timestamps are jittered according to the source config.
    
    Returns a new EvidenceGraph with jittered timestamps and source_type set.
    """
    new_eg = evidence_graph.deep_copy()
    
    source_keys = list(SOURCE_CONFIGS.keys())
    
    for i, (eid, edge) in enumerate(new_eg.edges.items()):
        # Assign source round-robin
        source_key = source_keys[i % len(source_keys)]
        config = SOURCE_CONFIGS[source_key]
        
        edge.source_type = source_key
        
        # Apply jitter
        jitter_start = rng.normal(0, config["jitter_std"])
        jitter_end = rng.normal(0, config["jitter_std"])
        
        edge.observed_start = edge.true_start + jitter_start
        edge.observed_end = edge.true_end + jitter_end
        
        # Ensure end >= start
        if edge.observed_end < edge.observed_start:
            edge.observed_end = edge.observed_start + abs(jitter_end)
        
        # Sampling: randomly drop some evidence per source sampling rate
        if rng.random() > config["sample_rate"]:
            edge.has_evidence = False
    
    return new_eg


def inject_noise(
    evidence_graph: EvidenceGraph,
    noise_ratio: float,
    rng: np.random.Generator,
    scenario_start: float = None,
    scenario_end: float = None,
) -> EvidenceGraph:
    """
    Inject background noise alerts at a given ratio.
    
    Args:
        evidence_graph: Base evidence graph
        noise_ratio: Multiplier on number of true causal events (e.g., 10.0 = 10x)
        rng: Random number generator
        scenario_start: Start of scenario window (epoch). If None, inferred.
        scenario_end: End of scenario window (epoch). If None, inferred.
    
    Returns new EvidenceGraph with noise edges added.
    """
    if noise_ratio <= 0:
        return evidence_graph.deep_copy()
    
    new_eg = evidence_graph.deep_copy()
    
    # Infer scenario time window
    all_starts = [e.true_start for e in new_eg.edges.values()]
    all_ends = [e.true_end for e in new_eg.edges.values()]
    if scenario_start is None:
        scenario_start = min(all_starts) - 600  # 10 min before first event
    if scenario_end is None:
        scenario_end = max(all_ends) + 600      # 10 min after last event
    
    n_true = len([e for e in new_eg.edges.values() if e.has_evidence])
    n_noise = int(n_true * noise_ratio)
    
    # Generate noise edges
    hosts = list(new_eg.hosts)
    if len(hosts) < 2:
        return new_eg
    
    noise_services = ["http", "ssh", "dns", "smtp", "ftp", "snmp", "ntp"]
    
    for i in range(n_noise):
        src = hosts[rng.integers(0, len(hosts))]
        dst = hosts[rng.integers(0, len(hosts))]
        while dst == src:
            dst = hosts[rng.integers(0, len(hosts))]
        
        t_start = rng.uniform(scenario_start, scenario_end)
        duration = rng.exponential(5.0)  # Mean 5 seconds
        
        noise_edge = EvidenceEdge(
            edge_id=f"noise_{i}",
            src=src,
            dst=dst,
            phase=0,  # Noise has no attack phase
            true_start=t_start,
            true_end=t_start + duration,
            observed_start=t_start + rng.normal(0, 2.0),
            observed_end=t_start + duration + rng.normal(0, 2.0),
            service=noise_services[rng.integers(0, len(noise_services))],
            source_type=["ids", "netflow", "hostlog"][rng.integers(0, 3)],
            is_falsified=False,
            has_evidence=True,
        )
        new_eg.add_edge(noise_edge)
    
    return new_eg
