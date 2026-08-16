"""
evidence_graph.py — Core data structures for temporal evidence graphs.

Defines EvidenceEdge, EvidenceGraph, and CausalConstraint used by both
detection methods and the experiment runner.
"""

from dataclasses import dataclass, field
from typing import Optional
import copy


@dataclass
class EvidenceEdge:
    """A single piece of evidence linking two hosts at a specific time."""
    edge_id: str
    src: str           # source host IP or name
    dst: str           # destination host IP or name
    phase: int         # attack phase (1-5)
    true_start: float  # ground-truth start timestamp (epoch seconds)
    true_end: float    # ground-truth end timestamp (epoch seconds)
    observed_start: float = 0.0   # observed (possibly falsified) start
    observed_end: float = 0.0     # observed (possibly falsified) end
    service: str = ""             # service name (e.g., sadmind, telnet)
    source_type: str = "ground_truth"  # ids, netflow, hostlog, ground_truth
    is_falsified: bool = False    # ground-truth label for evaluation
    has_evidence: bool = True     # False if evidence removed (completeness < 100%)

    def __post_init__(self):
        if self.observed_start == 0.0:
            self.observed_start = self.true_start
        if self.observed_end == 0.0:
            self.observed_end = self.true_end


@dataclass
class CausalConstraint:
    """A temporal precedence constraint: edge_before must occur before edge_after."""
    edge_before_id: str
    edge_after_id: str
    min_gap: float = 0.0  # minimum time gap in seconds (default: just strict ordering)

    def to_difference_constraint(self):
        """Returns (var_after, var_before, -min_gap) for Bellman-Ford."""
        return (self.edge_after_id, self.edge_before_id, -self.min_gap)


@dataclass
class EvidenceGraph:
    """
    A temporal evidence graph with causal constraints.

    Edges represent observed evidence (IDS alerts, log entries, etc.)
    Constraints represent causal precedence from the attack graph structure.
    """
    edges: dict = field(default_factory=dict)          # edge_id -> EvidenceEdge
    constraints: list = field(default_factory=list)     # list of CausalConstraint
    hosts: set = field(default_factory=set)
    attack_graph_vertices: dict = field(default_factory=dict)  # MulVAL vertex data
    attack_graph_arcs: list = field(default_factory=list)      # MulVAL arc data
    scenario: str = ""
    metadata: dict = field(default_factory=dict)

    def add_edge(self, edge: EvidenceEdge):
        self.edges[edge.edge_id] = edge
        self.hosts.add(edge.src)
        self.hosts.add(edge.dst)

    def add_constraint(self, constraint: CausalConstraint):
        self.constraints.append(constraint)

    def get_edge(self, edge_id: str) -> Optional[EvidenceEdge]:
        return self.edges.get(edge_id)

    def get_edges_by_phase(self, phase: int) -> list:
        return [e for e in self.edges.values() if e.phase == phase]

    def get_causal_edges(self) -> list:
        """Returns edges that have evidence attached (for constraint checking)."""
        return [e for e in self.edges.values() if e.has_evidence]

    def get_falsified_edge_ids(self) -> set:
        """Returns IDs of edges that are marked as falsified (ground truth)."""
        return {eid for eid, e in self.edges.items() if e.is_falsified}

    def deep_copy(self):
        """Create a deep copy for injection experiments."""
        return copy.deepcopy(self)

    def build_stn_graph(self):
        """
        Build the Simple Temporal Network as an adjacency list.
        
        Each evidence edge contributes two temporal variables:
          - start(edge_id): observed_start
          - end(edge_id): observed_end
        
        Each causal constraint adds a difference edge.
        Each edge's own duration adds: end >= start (i.e., end - start >= 0).
        
        Returns: dict of {node: [(neighbor, weight), ...]} for Bellman-Ford
        """
        graph = {}
        evidenced_edges = self.get_causal_edges()

        # Create temporal variable nodes for each evidence edge
        for e in evidenced_edges:
            s_node = f"start_{e.edge_id}"
            e_node = f"end_{e.edge_id}"
            if s_node not in graph:
                graph[s_node] = []
            if e_node not in graph:
                graph[e_node] = []
            # Duration constraint: end - start >= 0 → start - end <= 0
            graph[e_node].append((s_node, 0))

        # Causal precedence constraints
        edge_map = {e.edge_id: e for e in evidenced_edges}
        for c in self.constraints:
            if c.edge_before_id in edge_map and c.edge_after_id in edge_map:
                before_end = f"end_{c.edge_before_id}"
                after_start = f"start_{c.edge_after_id}"
                # after_start - before_end >= min_gap
                # → before_end - after_start <= -min_gap
                if before_end not in graph:
                    graph[before_end] = []
                graph[after_start].append((before_end, -c.min_gap))

        # Add observed timestamp constraints as edges from a reference node
        ref = "__ref__"
        graph[ref] = []
        for e in evidenced_edges:
            s_node = f"start_{e.edge_id}"
            e_node = f"end_{e.edge_id}"
            # start(e) = observed_start → ref → start(e) with weight observed_start
            #                            start(e) → ref with weight -observed_start
            graph[ref].append((s_node, e.observed_start))
            if s_node not in graph:
                graph[s_node] = []
            graph[s_node].append((ref, -e.observed_start))
            graph[ref].append((e_node, e.observed_end))
            if e_node not in graph:
                graph[e_node] = []
            graph[e_node].append((ref, -e.observed_end))

        return graph

    def summary(self) -> str:
        n_edges = len(self.edges)
        n_evidenced = len(self.get_causal_edges())
        n_constraints = len(self.constraints)
        n_falsified = len(self.get_falsified_edge_ids())
        return (
            f"EvidenceGraph({self.scenario}): "
            f"{n_edges} edges ({n_evidenced} evidenced), "
            f"{n_constraints} constraints, "
            f"{n_falsified} falsified, "
            f"{len(self.hosts)} hosts"
        )
