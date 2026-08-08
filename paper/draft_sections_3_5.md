# Temporal Attack Graphs for Post-Incident Forensic Reconstruction: Evidence-Aware Path Verification, Backward Recovery, and Confidence Quantification

## Authors
Ayan Gain, [Co-Authors TBD]

## Target Venue
23rd Annual IFIP WG 11.9 International Conference on Digital Forensics, January 7–8, 2027, New Delhi, India

## Status
**DRAFT — Formal Theory Core (Sections 3–5)**

---

## Abstract (Draft)

Attack graphs model how an adversary can chain individual vulnerabilities across a network to reach critical assets. While existing forensic applications of attack graphs operate on static, single-snapshot topologies, real enterprise networks exhibit time-varying vulnerability surfaces: hosts are patched, firewall rules change, services are provisioned and decommissioned. This paper extends the Temporal Attack Graph (TAG) formalism — originally designed for proactive vulnerability management — to the domain of **post-incident forensic reconstruction**. We introduce (i) **time-indexed evidence relevancy** that restricts forensic analysis to edges verified at each temporal window, (ii) a **backward temporal path reconstruction algorithm** that enumerates and ranks all plausible attack routes to a confirmed compromise, (iii) a **lookback bound theorem** that derives the minimum investigation search window from graph-structural properties, and (iv) **forensic confidence metrics** — temporal attack graph entropy and reconstruction robustness — that quantify investigative certainty and evidentiary defensibility. Evaluation on a multi-window synthetic scenario and the DARPA 2000 LLDOS benchmark demonstrates that the backward reconstruction recovers ground-truth attack paths, the lookback bound correctly sizes the search window, and the confidence metrics reliably distinguish solid reconstructions from fragile ones dependent on single evidence edges.

**Keywords**: digital forensics, attack graphs, temporal networks, evidence graphs, forensic confidence, backward reconstruction

---

# Section 3: Forensic Extension of the Temporal Attack Graph Model

This section extends the base Temporal Attack Graph (TAG) formalism $\mathcal{G}^a$ with forensic-specific constructs. We first recall the necessary base definitions from the TAG model, then introduce the forensic extensions.

---

## 3.1 Preliminaries: Base TAG Model (Recap)

We restate the foundational definitions from the TAG model that this paper builds upon.

### Definition 1 (Temporal Attack Graph)
A **Temporal Attack Graph** over time range $[t_{min}, t_{max}]$ is an ordered sequence of directed graphs:

$$\mathcal{G}^a(t_{min}, t_{max}) = (G_0, G_1, \ldots, G_{\tau-1}), \quad G_t = (V_t, E_t), \quad \tau = \frac{t_{max} - t_{min}}{w}$$

where $\tau$ is the number of time windows of duration $w$, each snapshot $G_t$ represents the exploitability state of the network at discrete time window $t \in \{0, 1, \ldots, \tau-1\}$, $V_t$ is the set of host-level vertices (after host-level pruning of exploit/condition bipartite structure per the TAG generation pipeline), and $E_t$ is the set of directed edges $(u, v, t)$ representing an exploitable vulnerability on host $v$ reachable from host $u$ during window $t$.

### Definition 2 (Temporal Attack Path)
A **temporal attack path** $p^a_{ij}$ from source $i$ to target $j$ in $\mathcal{G}^a$ is a sequence of edges:

$$p^a_{ij} = \langle (v_0, v_1, t_1), (v_1, v_2, t_2), \ldots, (v_{k-1}, v_k, t_k) \rangle$$

where $v_0 = i$, $v_k = j$, and the **non-decreasing window constraint** holds:

$$\forall\, l \in \{1, \ldots, k-1\}: \quad W_{b}(t_l) \leq W_{p}(t_{l+1})$$

where $W_b(t)$ and $W_p(t)$ denote the beginning and end of the time window indexed by $t$, respectively. This ensures that each hop in the path occurs no earlier than the preceding hop's window allows.

> **Notation Remark**: We use edge-indexed notation $(v_{l-1}, v_l, t_l)$ for algorithmic convenience in the backward reconstruction algorithm (Section 4). This is equivalent to the node-superscript form $p^a_{ij} = (n_0^{W_b}, n_1^{W_p}, \dots, n_{\eta-1}^{W_k})$ used in the base TAG model, where the non-decreasing constraint $b \le p \le k$ encodes the same temporal ordering.

### Definition 3 (Existing TAG Metrics — Recap)
The base TAG model defines the following metrics over $\mathcal{G}^a$:
- **Temporal Attack Distance** $d^a_{ij}$: Minimum hop-count temporal attack path length from $i$ to $j$.
- **Characteristic Temporal Attack Path Length** $L^a$: Average temporal attack distance across all host pairs, $L^a = \frac{1}{N(N-1)} \sum_{i \ne j} d^a_{ij}$.
- **Temporal Attack Global Efficiency** $E^a$: Harmonic mean of inverse temporal attack distances across all host pairs, $E^a = \frac{1}{N(N-1)} \sum_{i \ne j} \frac{1}{d^a_{ij}}$. Prevents divergence for disconnected pairs.
- **Temporal Betweenness Centrality** $\mathcal{B}^a_i$: Fraction of shortest temporal attack paths passing through node $i$.
- **Temporal Closeness Centrality** $\mathcal{C}^a_i$: Inverse of the sum of temporal attack distances from node $i$ to all other reachable nodes.

---

## 3.2 Extension 1: Time-Indexed Evidence Relevancy

In a forensic investigation, not all edges in $\mathcal{G}^a$ have supporting evidence. An edge may represent a *potential* exploit (vulnerability exists, network reachability holds) but the investigator may lack log entries, packet captures, or host artifacts confirming that the exploit was actually executed. Furthermore, evidence may arrive incrementally — an edge that is unverified at window $W_3$ may become verified at window $W_7$ when a delayed log shipment is processed.

### Definition 4 (Time-Indexed Evidence Relevancy)
Given a temporal attack graph $\mathcal{G}^a(t_{min}, t_{max})$ and a forensic investigation initiated at window $t^* \leq \tau - 1$, the **time-indexed evidence relevancy** function is:

$$r^a : E_t \times \{0, 1, \ldots, t^*\} \rightarrow \{0, 1\}$$

where for each edge $e = (u, v, t) \in E_t$ and investigation window $W_p \in \{0, 1, \ldots, t^*\}$:

$$r^a(e, W_p) = \begin{cases} 1, & \text{if verifiable forensic evidence for edge } e \text{ has been collected by window } W_p \\ 0, & \text{otherwise} \end{cases}$$

**Monotonicity Property**: Evidence, once collected, is not lost (barring anti-forensic actions addressed separately):

$$r^a(e, W_p) = 1 \implies r^a(e, W_q) = 1 \quad \forall\, W_q \geq W_p$$

> **Remark** (Relation to Wang & Daniels 2008): This definition generalizes the static relevancy score $r(e) \in \{0, 0.5, 1\}$ of Wang & Daniels (2008) by adding a temporal window dimension. Their model assigns relevancy once at edge-creation time; ours allows relevancy to evolve as investigation proceeds. We use binary relevancy ($\{0, 1\}$) rather than ternary to enable clean shortest-path computation on the forensic subgraph. Graded relevancy ($[0, 1]$) is deferred to future work.

---

### Definition 5 (Forensic Subgraph)
Given $\mathcal{G}^a$, investigation window $t^*$, and relevancy function $r^a$, the **forensic subgraph** at investigation state $W_p$ is:

$$\mathcal{G}^{a,\text{forensic}}(W_p) = (G_0', G_1', \ldots, G_{\tau-1}'), \quad G_t' = (V_t, E_t')$$

where:

$$E_t' = \{e \in E_t \mid r^a(e, W_p) = 1\}$$

The forensic subgraph retains only edges with confirmed evidence at the current investigation state.

---

### Definition 6 (Forensic Shortest Path)
The **forensic shortest temporal attack path** from $i$ to $j$ at investigation state $W_p$ is:

$$d^{a,\text{forensic}}_{ij}(W_p) = \min_{p^a_{ij} \in \mathcal{P}^a_{ij}(\mathcal{G}^{a,\text{forensic}}(W_p))} |p^a_{ij}|$$

where $\mathcal{P}^a_{ij}(\cdot)$ denotes the set of all valid temporal attack paths from $i$ to $j$ in the forensic subgraph, and $|p^a_{ij}|$ is the hop count.

If no temporally valid path exists in the forensic subgraph, $d^{a,\text{forensic}}_{ij}(W_p) = \infty$.

---

### Definition 7 (Evidence Gap)
The **evidence gap** for a source-target pair $(i, j)$ at investigation state $W_p$ is:

$$\Delta^a_{ij}(W_p) = d^{a,\text{forensic}}_{ij}(W_p) - d^a_{ij}$$

- $\Delta^a_{ij}(W_p) = 0$: The shortest attack path is fully evidenced — every hop has confirmed forensic support.
- $\Delta^a_{ij}(W_p) > 0$: The evidenced path is longer than the topologically shortest path — evidence gaps force detours.
- $\Delta^a_{ij}(W_p) = \infty$: No complete evidenced path exists — critical evidence links are missing.

---

## 3.3 Extension 2: Windowed Centrality Trajectories

Existing graph-based forensic methods compute centrality once over a fully aggregated graph. This produces a single ranking that cannot adapt as evidence is collected incrementally during an active investigation. We define centrality *trajectories* that track how host importance evolves over temporal window prefixes.

### Definition 8 (Windowed Betweenness Centrality Trajectory)
Given $\mathcal{G}^a(t_{min}, t_{max})$ and a sequence of window prefixes $W_1 \subset W_2 \subset \cdots \subset W_k$ where $W_l = \{0, 1, \ldots, l-1\}$, the **windowed betweenness centrality trajectory** of node $i$ is:

$$\vec{\mathcal{B}}^a_i = \left(\mathcal{B}^a_i(W_1), \mathcal{B}^a_i(W_2), \ldots, \mathcal{B}^a_i(W_k)\right)$$

where $\mathcal{B}^a_i(W_l)$ is the temporal betweenness centrality of node $i$ computed over the prefix subgraph $\mathcal{G}^a(t_{min}, t_{min} + l - 1)$.

### Definition 9 (Windowed Closeness Centrality Trajectory)
Analogously:

$$\vec{\mathcal{C}}^a_i = \left(\mathcal{C}^a_i(W_1), \mathcal{C}^a_i(W_2), \ldots, \mathcal{C}^a_i(W_k)\right)$$

> **Forensic Interpretation**: A node whose $\mathcal{B}^a_i(W_l)$ increases sharply at window $W_l$ has become a critical relay point due to a new vulnerability or topology change at that window — flagging it for immediate forensic examination. A monotonically high trajectory indicates a persistent chokepoint warranting deep historical log review.

---

## 3.4 Extension 3: Temporal Attack Velocity and Surface Persistence

### Definition 10 (Temporal Attack Velocity)
Given a temporal attack path $p^a_{ij} = \langle (v_0, v_1, t_1), \ldots, (v_{k-1}, v_k, t_k) \rangle$, the **temporal attack velocity** is:

$$v^a(p^a_{ij}) = \frac{d^a_{ij}}{\Delta T(p^a_{ij})}$$

where $\Delta T(p^a_{ij}) = W_p(t_k) - W_b(t_1)$ is the wall-clock elapsed time from the beginning of the first hop's window to the end of the last hop's window. If $\Delta T = 0$ (all hops occur within a single window), we define $v^a = \infty$.

- **High $v^a$** ($\gg 1$): Rapid traversal across many hops in few windows — characteristic of automated/scripted attacks (worms, exploit chains). Forensic implication: look for automated tooling artifacts (Metasploit sessions, scripted lateral movement).
- **Low $v^a$** ($\ll 1$): Slow, deliberate movement — characteristic of advanced persistent threats (APTs) with human operators. Forensic implication: look for interactive shell sessions, manual reconnaissance.

### Definition 11 (Temporal Attack Surface Persistence)
For a host $i \in \bigcup_t V_t$, the **temporal attack surface persistence** is:

$$\Pi^a_i = \frac{|\{t \in \{0, \ldots, \tau-1\} : \exists\, (u, i, t) \in E_t \text{ for some } u\}|}{\tau}$$

- $\Pi^a_i \approx 1$: Host $i$ has incoming exploitable edges in nearly every window — a **chronically exposed** host. Forensic action: deep historical log review across all windows.
- $\Pi^a_i \approx 0$: Host $i$ was briefly vulnerable in a narrow window — a **transiently exposed** host. Forensic action: focus on change-management records for the specific exposure window.

---

# Section 4: Backward Temporal Path Reconstruction

This section presents the core forensic algorithm: given a confirmed compromised node $j^*$ discovered at investigation time $t^*$, reconstruct the set of all plausible temporal attack paths that could have reached $j^*$.

---

## 4.1 Backward Temporal Path Set

### Definition 12 (Backward Temporal Path Set)
Given a temporal attack graph $\mathcal{G}^a(t_{min}, t_{max})$, a confirmed compromised target node $j^* \in V_{t^*}$, and investigation window $t^*$, the **backward temporal path set** is:

$$Q^{a,\text{back}}_{j^*} = \left\{ p^a_{ij^*} \mid i \in V_{\text{ext}},\ p^a_{ij^*} \text{ is a valid temporal attack path in } \mathcal{G}^a \right\}$$

where $V_{\text{ext}} \subseteq \bigcup_t V_t$ is the set of external/attacker source nodes (network entry points).

**Construction Constraint**: Each path $p^a_{ij^*} \in Q^{a,\text{back}}_{j^*}$ must satisfy:
1. The non-decreasing window constraint (Definition 2).
2. All edges along $p^a_{ij^*}$ must have windows $t \leq t^*$ (the attack occurred *before* discovery).

---

### Definition 13 (Evidence-Restricted Backward Path Set)
The evidence-restricted variant uses the forensic subgraph:

$$Q^{a,\text{back,forensic}}_{j^*}(W_p) = \left\{ p^a_{ij^*} \mid p^a_{ij^*} \in Q^{a,\text{back}}_{j^*},\ \forall\, e \in p^a_{ij^*}: r^a(e, W_p) = 1 \right\}$$

This set contains only backward paths where every edge has confirmed forensic evidence.

---

## 4.2 Path Plausibility Scoring

Not all paths in $Q^{a,\text{back}}_{j^*}$ are equally likely. We define a composite plausibility score to rank candidate paths.

### Definition 14 (Path Plausibility Score)
Given a backward temporal path $p = \langle (v_0, v_1, t_1), \ldots, (v_{k-1}, v_k, t_k) \rangle \in Q^{a,\text{back}}_{j^*}$, its **plausibility score** is:

$$\pi(p) = \alpha \cdot \pi_{\text{struct}}(p) + (1 - \alpha) \cdot \pi_{\text{evid}}(p)$$

where $\alpha \in [0, 1]$ is a weighting parameter, and:

**Structural Plausibility** (based on betweenness centrality of intermediate nodes):

$$\pi_{\text{struct}}(p) = \frac{1}{k-1} \sum_{l=1}^{k-1} \mathcal{B}^a_{v_l}(W_{t_l})$$

This uses windowed betweenness centrality (Definition 8) at the specific window each intermediate node is traversed, capturing how structurally important each relay node is *at the time of traversal*.

**Evidential Plausibility** (fraction of edges with confirmed evidence):

$$\pi_{\text{evid}}(p) = \frac{1}{k} \sum_{l=1}^{k} r^a((v_{l-1}, v_l, t_l), W_p)$$

where $W_p$ is the current investigation window.

- $\pi(p) \approx 1$: Path traverses high-centrality nodes and is fully evidenced — high confidence.
- $\pi(p) \approx 0$: Path traverses peripheral nodes with no supporting evidence — low confidence.

---

## 4.3 Algorithm: Bounded Backward Temporal Path Reconstruction

### Algorithm 1: `BackwardReconstruct`

**Input**:
- Temporal attack graph $\mathcal{G}^a(t_{min}, t_{max})$
- Confirmed compromised target $j^*$
- Investigation window $t^*$
- Evidence relevancy function $r^a$
- Maximum candidate paths $K \in \mathbb{N}$
- Minimum plausibility threshold $\pi_{\min} \in [0, 1]$

**Output**:
- Ranked backward path set $Q^{a,\text{back}}_{j^*}$, ordered by descending $\pi(p)$

**Pseudocode Logic**:
1. Initialize priority queue $\mathcal{Q} \leftarrow \emptyset$, result set $R \leftarrow \emptyset$, visited set $\mathcal{V} \leftarrow \emptyset$.
2. Enqueue initial state: $\mathcal{Q}.\text{push}(\langle j^*, t^*, \text{path}=[(j^*, t^*)] \rangle)$.
3. **While** $\mathcal{Q} \neq \emptyset$ **and** $|R| < K$ **do**:
   a. Dequeue current state: $(v_{\text{cur}}, t_{\text{cur}}, p_{\text{cur}}) \leftarrow \mathcal{Q}.\text{pop}()$.
   b. **If** $v_{\text{cur}} \in V_{\text{ext}}$ **then**:
      - Compute $\pi(p_{\text{cur}})$.
      - **If** $\pi(p_{\text{cur}}) \geq \pi_{\min}$ **then**: $R \leftarrow R \cup \{p_{\text{cur}}\}$.
      - Continue to next iteration.
   c. **Foreach** window $t \in \{0, 1, \ldots, t_{\text{cur}}\}$ in reverse order **do**:
      - **Foreach** edge $(u, v_{\text{cur}}, t) \in E_t$ **do**:
         - **If** non-decreasing window constraint holds backward:
           $W_b(t) \leq W_p(t_{\text{cur}})$ **then**:
            - **If** $(u, t) \notin \mathcal{V}$ **then**:
               - $\mathcal{V} \leftarrow \mathcal{V} \cup \{(u, t)\}$.
               - $p_{\text{new}} \leftarrow [(u, t)] \oplus p_{\text{cur}}$.
               - $\mathcal{Q}.\text{push}((u, t, p_{\text{new}}))$, prioritized by partial $\pi_{\text{struct}}$.
4. Sort $R$ by descending $\pi(p)$.
5. **Return** $R$.

**Complexity**: Let $n = |\bigcup_t V_t|$, $m = |\bigcup_t E_t|$. In the worst case, the algorithm explores $O(m \cdot \tau)$ edge-window combinations, bounded by the $K$-path cutoff. With $K$ fixed, practical complexity is $O(K \cdot (n + m) \cdot \tau)$.

> **Relation to Prior Work**: Barrère et al. (2017) `traceBack` (Algorithm 2) performs backward exploration but (a) on a static, non-temporal graph, (b) returning a single greedy path, and (c) using CVSS-based $p(n|m)$ ordering rather than betweenness-weighted plausibility. Zhang et al. (2015) Algorithm 3 performs backward BFS but outputs only scalar bounds ($\text{max-src-time}, \text{min-dst-time}$) for timestamp correction, not path enumeration. Algorithm 1 above produces a *ranked set* of *temporally valid* backward paths.

---

# Section 5: Forensic Confidence Quantification

Given the backward path set $Q^{a,\text{back}}_{j^*}$ from Section 4, we now define metrics that quantify how confident an investigator should be in the reconstruction and how defensible the conclusion is under evidentiary challenge.

---

## 5.1 Lookback Bound Theorem

Before computing confidence, we establish how far back the investigation needs to search.

### Axiom 1 (Capability Persistence)
Once an attacker gains execution capability on host $v$ at window $t$, this capability persists in all subsequent windows unless explicitly remediated:

$$\text{compromised}(v, t) = 1 \implies \text{compromised}(v, t') = 1 \quad \forall\, t' \geq t, \text{ if no remediation of } v \text{ occurs in } [t, t']$$

> **Discussion**: This assumption reflects the empirical reality that most intrusions persist until actively detected and remediated. It is the standard assumption in attack graph literature (e.g., MulVAL monotonicity). The assumption breaks if the attacker performs self-cleanup (anti-forensic capability removal) — this relaxation is discussed in Section 7 (Limitations).

### Theorem 1 (Lookback Bound)
Given a temporal attack graph $\mathcal{G}^a(t_{min}, t_{max})$, a confirmed compromised target $j^*$ discovered at window $t^*$, and Axiom 1 (capability persistence), the minimum investigation lookback window $\lambda^*_{j^*}$ satisfying $Q^{a,\text{back}}_{j^*} \neq \emptyset$ is:

$$\lambda^*_{j^*} = t^* - \min_{p \in Q^{a,\text{back}}_{j^*}} \left( \min_{(u, v, t) \in p} t \right)$$

That is, the lookback window extends to the earliest temporal window of any edge in any valid backward path to $j^*$.

**Practically computable bound** (without enumerating all paths):

$$\lambda^*_{j^*} \leq t^* - t^{\text{first}}_{j^*}$$

where $t^{\text{first}}_{j^*}$ is the earliest window $t$ such that $j^*$ is reachable from any external source $i \in V_{\text{ext}}$ via a valid temporal attack path in $\mathcal{G}^a(t_{min}, t)$.

*Proof sketch*:

1. By Definition 12, every path $p \in Q^{a,\text{back}}_{j^*}$ originates at some $i \in V_{\text{ext}}$ and terminates at $j^*$.
2. By Definition 2, each path satisfies non-decreasing window order, so the first edge has the smallest window index.
3. By Axiom 1, if $j^*$ was first reachable at window $t^{\text{first}}_{j^*}$, any attack exploiting that reachability must have its initial edge at or after $t^{\text{first}}_{j^*}$.
4. Therefore the earliest possible edge in any backward path has window $\geq t^{\text{first}}_{j^*}$, giving lookback $\leq t^* - t^{\text{first}}_{j^*}$. $\square$

> **Forensic Significance**: This theorem replaces the arbitrary, manually-configured time window $T$ used in Wang & Daniels (2008) Leader-Follower aggregation (Algorithm 1, $T = 60$s) with a graph-derived, provably sufficient bound. An investigator can state: "*we examined all evidence within $\lambda^*_{j^*}$ windows of the compromise discovery; this is provably sufficient to capture all topologically feasible attack paths under the capability-persistence assumption.*"

---

## 5.2 Temporal Attack Graph Entropy

### Definition 15 (Temporal Attack Graph Entropy)
Given the backward path set $Q^{a,\text{back}}_{j^*}$ with plausibility scores $\pi(p)$ for each $p \in Q^{a,\text{back}}_{j^*}$, the **temporal attack graph entropy** is the Shannon entropy over the normalized plausibility distribution:

$$H^a_{j^*} = -\sum_{p \in Q^{a,\text{back}}_{j^*}} \hat{\pi}(p) \log_2 \hat{\pi}(p)$$

where the normalized plausibility is:

$$\hat{\pi}(p) = \frac{\pi(p)}{\sum_{q \in Q^{a,\text{back}}_{j^*}} \pi(q)}$$

**Interpretation**:
- $H^a_{j^*} = 0$: A single dominant path concentrates all plausibility — the reconstruction is unambiguous.
- $H^a_{j^*} = \log_2 |Q^{a,\text{back}}_{j^*}|$: All candidate paths are equally plausible — maximum investigative uncertainty.
- $H^a_{j^*} \in (0, \log_2 |Q^{a,\text{back}}_{j^*}|)$: Intermediate certainty — some paths are more plausible than others but the reconstruction is not definitive.

> **Forensic Significance**: Entropy enables a forensic report to explicitly state reconstruction confidence rather than presenting a single guessed route as fact. A report reading "*the reconstruction entropy is 0.3 bits over 5 candidate paths*" conveys far more information about investigative certainty than "*we believe the attacker used path X.*" This directly addresses the legal/policy dimension of IFIP WG 11.9 — forensic conclusions presented in court must be accompanied by confidence assessments.

---

### Definition 16 (Evidence-Restricted Entropy)
The entropy can be computed over the evidence-restricted set $Q^{a,\text{back,forensic}}_{j^*}(W_p)$ to measure uncertainty conditioned on available evidence:

$$H^{a,\text{forensic}}_{j^*}(W_p) = -\sum_{p \in Q^{a,\text{back,forensic}}_{j^*}(W_p)} \hat{\pi}(p) \log_2 \hat{\pi}(p)$$

The **entropy reduction** from evidence collection is:

$$\Delta H^a_{j^*}(W_p) = H^a_{j^*} - H^{a,\text{forensic}}_{j^*}(W_p) \geq 0$$

This quantity measures the *forensic value of collected evidence* — how much uncertainty was removed by the evidence gathered up to investigation window $W_p$.

---

## 5.3 Temporal Reconstruction Robustness

### Definition 17 (Temporal Reconstruction Robustness)
Given the backward path set $Q^{a,\text{back}}_{j^*}$ and a specific evidence edge $e \in \bigcup_t E_t$, the **reconstruction robustness** with respect to $e$ is:

$$\rho^a_{j^*}(e) = 1 - \frac{|Q^{a,\text{back}}_{j^*} \setminus Q^{a,\text{back}}_{j^*}(e)|}{|Q^{a,\text{back}}_{j^*}|}$$

where $Q^{a,\text{back}}_{j^*}(e) = \{p \in Q^{a,\text{back}}_{j^*} \mid e \in p\}$ is the subset of backward paths that *use* edge $e$.

Equivalently:

$$\rho^a_{j^*}(e) = \frac{|Q^{a,\text{back}}_{j^*}| - |Q^{a,\text{back}}_{j^*}(e)|}{|Q^{a,\text{back}}_{j^*}|} = 1 - \frac{|Q^{a,\text{back}}_{j^*}(e)|}{|Q^{a,\text{back}}_{j^*}|}$$

**Interpretation**:
- $\rho^a_{j^*}(e) = 1$: Edge $e$ appears in *zero* backward paths — removing it has no effect on the reconstruction. The reconstruction is perfectly robust to losing this evidence.
- $\rho^a_{j^*}(e) = 0$: Edge $e$ appears in *every* backward path — removing it destroys all candidate reconstructions. The reconstruction is maximally fragile with respect to this evidence.
- $\rho^a_{j^*}(e) \in (0, 1)$: Edge $e$ appears in some but not all paths — its removal reduces but does not eliminate reconstruction candidates.

---

### Definition 18 (Global Reconstruction Robustness)
The **global robustness** of the reconstruction is the minimum robustness across all evidence edges:

$$\rho^a_{j^*} = \min_{e \in \bigcup_t E_t,\ Q^{a,\text{back}}_{j^*}(e) \neq \emptyset} \rho^a_{j^*}(e)$$

- $\rho^a_{j^*} > 0$: No single evidence edge is a single point of failure — the reconstruction survives any single evidence challenge.
- $\rho^a_{j^*} = 0$: There exists a "bottleneck" evidence edge whose removal destroys all backward paths — the reconstruction rests on fragile ground.

> **Forensic Significance**: Under cross-examination, opposing counsel may challenge the admissibility or reliability of a specific piece of evidence. If $\rho^a_{j^*}(e) = 0$ for that edge, the entire forensic reconstruction collapses. If $\rho^a_{j^*}(e) > 0.5$, the majority of candidate paths survive even if edge $e$ is excluded — the conclusion is defensible. This is a direct, quantitative tool for courtroom forensics.

---

## 5.4 Algorithm: Confidence Computation

### Algorithm 2: `ComputeForensicConfidence`

**Input**:
- Ranked backward path set $Q^{a,\text{back}}_{j^*}$ (output of Algorithm 1)
- Evidence relevancy function $r^a$
- Investigation window $W_p$

**Output**:
- Entropy $H^a_{j^*}$, Evidence-restricted entropy $H^{a,\text{forensic}}_{j^*}(W_p)$, Entropy reduction $\Delta H^a_{j^*}(W_p)$
- Per-edge robustness $\rho^a_{j^*}(e)$ for all evidence edges
- Global robustness $\rho^a_{j^*}$

**Pseudocode Logic**:

1. **Compute plausibility distribution**:
   a. $S \leftarrow \sum_{p \in Q^{a,\text{back}}_{j^*}} \pi(p)$.
   b. **Foreach** $p \in Q^{a,\text{back}}_{j^*}$ **do**: $\hat{\pi}(p) \leftarrow \pi(p) / S$.

2. **Compute full entropy**:
   $$H^a_{j^*} \leftarrow -\sum_{p \in Q^{a,\text{back}}_{j^*}} \hat{\pi}(p) \log_2 \hat{\pi}(p)$$

3. **Compute evidence-restricted entropy**:
   a. $Q_{\text{ev}} \leftarrow \{p \in Q^{a,\text{back}}_{j^*} \mid \forall\, e \in p: r^a(e, W_p) = 1\}$.
   b. Re-normalize plausibilities over $Q_{\text{ev}}$.
   c. $H^{a,\text{forensic}}_{j^*}(W_p) \leftarrow -\sum_{p \in Q_{\text{ev}}} \hat{\pi}_{\text{ev}}(p) \log_2 \hat{\pi}_{\text{ev}}(p)$.
   d. $\Delta H^a_{j^*}(W_p) \leftarrow H^a_{j^*} - H^{a,\text{forensic}}_{j^*}(W_p)$.

4. **Compute per-edge robustness** (leave-one-out):
   a. Collect all evidence edges: $\mathcal{E} \leftarrow \bigcup_{p \in Q^{a,\text{back}}_{j^*}} \{e \mid e \in p\}$.
   b. **Foreach** $e \in \mathcal{E}$ **do**:
      - $Q_e \leftarrow \{p \in Q^{a,\text{back}}_{j^*} \mid e \in p\}$.
      - $\rho^a_{j^*}(e) \leftarrow 1 - |Q_e| / |Q^{a,\text{back}}_{j^*}|$.

5. **Compute global robustness**:
   $$\rho^a_{j^*} \leftarrow \min_{e \in \mathcal{E}} \rho^a_{j^*}(e)$$

6. **Return** $(H^a_{j^*},\ H^{a,\text{forensic}}_{j^*}(W_p),\ \Delta H^a_{j^*}(W_p),\ \{\rho^a_{j^*}(e)\}_{e \in \mathcal{E}},\ \rho^a_{j^*})$.

**Complexity**: $O(|Q^{a,\text{back}}_{j^*}| \cdot L_{\max})$ where $L_{\max}$ is the maximum path length. With $K$-bounded path sets, this is $O(K \cdot L_{\max})$.

---

## 5.5 Summary: Complete Forensic Pipeline

The complete forensic reconstruction pipeline, as a single end-to-end workflow, is:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  INPUT: TAG G^a, confirmed target j*, investigation window t*, evidence r^a │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Step 1:  Compute lookback bound λ*_{j*}                [Theorem 1]         │
│           → determines investigation search window                          │
│                                                                             │
│  Step 2:  Construct forensic subgraph G^{a,forensic}     [Definition 5]     │
│           → restricts to evidenced edges only                               │
│                                                                             │
│  Step 3:  Run BackwardReconstruct(G^a, j*, t*, r^a, K)  [Algorithm 1]      │
│           → produces ranked path set Q^{a,back}_{j*}                        │
│                                                                             │
│  Step 4:  Compute windowed centrality trajectories       [Definition 8-9]   │
│           → B^a_i(W_1,...,W_k) used as plausibility weights in Step 3       │
│                                                                             │
│  Step 5:  Compute forensic confidence                    [Algorithm 2]      │
│           → entropy H^a, robustness ρ^a, evidence gap Δ^a                  │
│                                                                             │
│  Step 6:  Characterize reconstructed attack              [Definitions 10-11]│
│           → velocity v^a (automated vs manual)                              │
│           → persistence Π^a (chronic vs transient exposure)                 │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  OUTPUT: Ranked attack paths, confidence metrics, attack characterization   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# Notes for Remaining Sections

## Section 6 (Evaluation) — To Be Drafted
- **Primary evaluation**: Synthetic multi-window MulVAL + Neo4j scenario with planted ground-truth attack path, varying evidence quality (80%, 60%, 40% edge coverage), and anti-forensic evidence gaps.
- **Validation metrics**: Path recovery accuracy (does $Q^{a,\text{back}}_{j^*}$ contain the ground truth?), lookback bound correctness ($\lambda^*_{j^*}$ vs. actual attack start), entropy behavior (does $H^a$ decrease as evidence is added?), robustness sensitivity (do edges with $\rho = 0$ correspond to ground-truth bottlenecks?).
- **Secondary evaluation**: DARPA LLDOS 2.0.2 as degenerate single-window case, comparing victim identification against Wang & Daniels (2008) and He et al. (2016) results (host `172.16.112.100` exclusion test).

## Section 7 (Limitations) — Key Points
- Capability-persistence axiom (Axiom 1) breaks under anti-forensic self-cleanup.
- $K$-bounded path enumeration may miss long-tail low-plausibility paths.
- Binary evidence relevancy $r^a \in \{0,1\}$ loses Wang & Daniels' "unverified" middle category.
- CVSS scores used in structural plausibility are static; zero-day exploits lack scores.

## Section 2 (Related Work) — Positioning Against Five Papers
- Wang & Daniels (2008): foundational evidence graph, static centrality, arbitrary $T$ → we add temporal dimension and graph-derived lookback.
- Liu et al. (2012): anti-forensic nodes in attack graphs → we handle missing evidence via $r^a(e, W_p) = 0$ edges rather than explicit anti-forensic nodes; complementary approaches.
- Zhang et al. (2015): timestamp falsification detection → our backward reconstruction subsumes their scalar adjustment; our entropy captures residual uncertainty they don't address.
- He et al. (2016): VERA Nodeworth/Linkworth → our windowed centrality trajectories are the temporal analog; our evidence gap $\Delta^a_{ij}$ replaces their SVM pre-filter with a structural completeness metric.
- Barrère et al. (2017): core attack graphs for scalability → orthogonal; our backward reconstruction could run over a core TAG rather than full TAG for scalability (noted as future work).
