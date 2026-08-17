"""
ftag_model.py — Forensic Temporal Attack Graph (F-TAG) Data Model.

Built on Gain et al. (2026) Definition 1 & 2:
  G^a(t_min, t_max) = (G_0, G_1, ..., G_{tau-1})
  where G_t = (V_t, E_t) is the attack graph snapshot at window t.

  A temporal attack path p^a_ij = (n_0^{W_b}, n_1^{W_p}, ..., n_{eta-1}^{W_k})
  satisfies b <= p <= k (sequential window ordering).

Forensic extension: each edge carries the set of time windows in which it exists
(active_windows), enabling Temporal Attack Corridor computation without the
intersection bug (dormant-attacker safe: corridors use sequential ordering,
not per-edge intersection).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, FrozenSet
from collections import defaultdict, deque
from itertools import product


@dataclass
class TAGNode:
    """A host/state node in the Temporal Attack Graph."""
    node_id: str
    host_ip: str
    state_name: str


@dataclass
class TAGEdge:
    """A causal exploit edge existing in specific time windows."""
    edge_id: str
    src_node_id: str
    dst_node_id: str
    classification: str
    active_windows: Set[int] = field(default_factory=set)  # {0, 1, 3} = exists in w0, w1, w3
    delta_t_min: float = 10.0   # Physical minimum execution time (seconds)
    observed_time: Optional[float] = None
    observed_window: Optional[int] = None
    is_falsified: bool = False


@dataclass
class TemporalPath:
    """A temporal attack path: sequence of (edge_id, window_used) pairs."""
    hops: List[Tuple[str, int]]   # [(edge_id, window_index), ...]
    src_node: str
    dst_node: str

    @property
    def W_b(self) -> int:
        """Earliest window used (start of corridor)."""
        return self.hops[0][1]

    @property
    def W_end(self) -> int:
        """Latest window used (end of corridor)."""
        return self.hops[-1][1]

    @property
    def tac(self) -> Tuple[int, int]:
        """Temporal Attack Corridor [W_b, W_end]."""
        return (self.W_b, self.W_end)

    @property
    def length(self) -> int:
        return len(self.hops)


class ForensicTemporalAttackGraph:
    """
    Forensic Temporal Attack Graph built on Gain et al. (2026) G^a(t_min, t_max).

    Supports:
    - Multi-window topology (edges exist in subsets of windows)
    - Temporal path enumeration Q^a_ij with Definition 2 sequential ordering
    - Temporal Attack Corridor computation (dormant-attacker safe)
    """
    def __init__(self, graph_id: str = "FTAG", num_windows: int = 4,
                 window_duration_seconds: float = 3600.0):
        self.graph_id = graph_id
        self.num_windows = num_windows
        self.window_duration = window_duration_seconds
        self.nodes: Dict[str, TAGNode] = {}
        self.edges: Dict[str, TAGEdge] = {}

    def add_node(self, node_id: str, host_ip: str, state_name: str) -> TAGNode:
        node = TAGNode(node_id, host_ip, state_name)
        self.nodes[node_id] = node
        return node

    def add_edge(self, edge_id: str, src_node_id: str, dst_node_id: str,
                 classification: str, active_windows: Set[int],
                 delta_t_min: float = 10.0) -> TAGEdge:
        edge = TAGEdge(
            edge_id=edge_id,
            src_node_id=src_node_id,
            dst_node_id=dst_node_id,
            classification=classification,
            active_windows=active_windows,
            delta_t_min=delta_t_min,
        )
        self.edges[edge_id] = edge
        return edge

    def enumerate_temporal_paths(self, src_node_id: str, dst_node_id: str,
                                 max_hops: int = 10) -> List[TemporalPath]:
        """
        Enumerate all temporal attack paths Q^a_ij following Definition 2:
        each successive hop must use a window >= the previous hop's window.
        """
        # Build adjacency: src_node -> list of TAGEdge
        adj = defaultdict(list)
        for e in self.edges.values():
            adj[e.src_node_id].append(e)

        paths: List[TemporalPath] = []

        # DFS with (current_node, current_window_min, path_so_far, visited_nodes)
        stack: List[Tuple[str, int, List[Tuple[str, int]], Set[str]]] = []
        stack.append((src_node_id, 0, [], {src_node_id}))

        while stack:
            curr_node, min_window, path_so_far, visited = stack.pop()

            if curr_node == dst_node_id and len(path_so_far) > 0:
                paths.append(TemporalPath(
                    hops=list(path_so_far),
                    src_node=src_node_id,
                    dst_node=dst_node_id,
                ))
                continue

            if len(path_so_far) >= max_hops:
                continue

            for edge in adj[curr_node]:
                if edge.dst_node_id in visited:
                    continue
                # Find all valid windows >= min_window for this edge
                valid_windows = sorted(w for w in edge.active_windows if w >= min_window)
                for w in valid_windows:
                    new_path = path_so_far + [(edge.edge_id, w)]
                    new_visited = visited | {edge.dst_node_id}
                    stack.append((edge.dst_node_id, w, new_path, new_visited))

        return paths

    def get_all_static_paths(self, src_node_id: str, dst_node_id: str,
                              max_hops: int = 10) -> int:
        """Count all structurally possible paths ignoring temporal constraints."""
        adj = defaultdict(list)
        for e in self.edges.values():
            adj[e.src_node_id].append(e)

        count = 0
        stack = [(src_node_id, {src_node_id}, 0)]
        while stack:
            curr, visited, depth = stack.pop()
            if curr == dst_node_id and depth > 0:
                count += 1
                continue
            if depth >= max_hops:
                continue
            for edge in adj[curr]:
                if edge.dst_node_id not in visited:
                    stack.append((edge.dst_node_id, visited | {edge.dst_node_id}, depth + 1))
        return count
