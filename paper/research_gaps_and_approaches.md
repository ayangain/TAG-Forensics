# Research Gaps and Proposed Approach: Temporal Attack Graphs for Post-Incident Network Forensics

## Executive Overview

Attack graphs have traditionally been used for **proactive vulnerability management** — identifying host configurations to patch or firewalls to reconfigure before an attack occurs. Our previous work (*Gain & Barik, COSE 2026*) introduced **Temporal Attack Graphs (TAGs)** $\mathcal{G}^a(t_{min}, t_{max}) = (G_0, G_1, \dots, G_{\tau-1})$ to model time-varying vulnerability surfaces and quantify dynamic security risks via temporal path distance ($d^a_{ij}$) and centralities ($\mathcal{B}^a_i, \mathcal{C}^a_i$).

This research shifts the paradigm from **proactive hardening** to **reactive post-incident forensic reconstruction**. When a network intrusion occurs and a compromise is confirmed at a target host $j^*$, forensic investigators face critical challenges:
1. *What was the exact path the attacker took?*
2. *How far back in time must we search the log files?*
3. *Which unverified potential exploits lack supporting forensic evidence?*
4. *How confident can we be in our reconstructed attack scenario under courtroom cross-examination?*

Existing forensic literature (Wang & Daniels 2008, Liu et al. 2012, Zhang et al. 2015, He et al. 2016, Barrère et al. 2017) fails to address these challenges on dynamic networks. This document details the **5 critical research gaps** identified across current literature and presents our **unified theoretical approach** to solve them.

---

## Part 1: Comprehensive Gap Analysis

The table below summarizes the 5 key research gaps, comparing prior state-of-the-art approaches against our proposed solutions:

| # | Research Gap | State-of-the-Art Limitations | Baseline Papers | Our Proposed Approach |
|---|---|---|---|---|
| **1** | **No Temporal Centrality Trajectories for Dynamic Triage** | Centralities are computed once over static or fully-aggregated graphs ($Ax = \lambda x$, $y=H^T Z$). They cannot capture how host criticality shifts across time windows during an active investigation. | Wang & Daniels (2008), He et al. (2016), Gain & Barik (2026) | **Windowed Centrality Trajectories** $\vec{\mathcal{B}}^a_i, \vec{\mathcal{C}}^a_i$: Evaluates host centrality over window prefixes $W_1 \subset W_2 \subset \dots \subset W_k$ to detect newly emerging relay points. |
| **2** | **No Time-Indexed Evidence Verification & Gap Metric** | Relevancy $r(e)$ is static at edge creation. Models do not track incremental evidence arrival or quantify "missing evidence detours." | Wang & Daniels (2008) ($r(e) \in \{0, 0.5, 1\}$), COSE 2026 (No evidence layer) | **Time-Indexed Evidence Relevancy** $r^a(e, W_p)$, **Forensic Subgraph** $\mathcal{G}^{a,\text{forensic}}(W_p)$, and **Evidence Gap Metric** $\Delta^a_{ij}(W_p) = d^{a,\text{forensic}}_{ij} - d^a_{ij}$. |
| **3** | **No Ranked Backward Temporal Path Reconstruction** | Existing methods use forward-only traversal, return scalar bounds, or extract a single greedy static path without temporal window ordering ($W_b \le W_p$). | Zhang et al. (2015) (`AdjustSuggestion`), Barrère et al. (2017) (`traceBack`), COSE 2026 (Forward BFS) | **Backward Temporal Path Set** $Q^{a,\text{back}}_{j^*}$ & **Algorithm 1 (`BackwardReconstruct`)**: Reverses window constraints to produce a ranked set of plausible backward paths using score $\pi(p) = \alpha \pi_{\text{struct}} + (1-\alpha) \pi_{\text{evid}}$. |
| **4** | **No Principled Search-Scope Bound (Lookback Window)** | Forensic search windows are selected arbitrarily or via fixed ad-hoc time limits (e.g., $T=60\text{s}$), risking either missing early attack steps or over-searching logs. | Wang & Daniels (2008) (Self-extending window $T$) | **Lookback Bound Theorem** ($\lambda^*_{j^*} \le t^* - t^{\text{first}}_{j^*}$): Derives a provably sufficient historical search window from TAG reachability and Capability Persistence Axiom. |
| **5** | **No Forensic Confidence & Evidentiary Defensibility Metrics** | Forensic reconstructions present a single route without quantifying uncertainty or identifying single-point-of-failure evidence links under evidentiary challenge. | All 5 prior papers (Zero formal confidence metrics) | **Temporal AG Entropy** ($H^a_{j^*}$), **Entropy Reduction** ($\Delta H^a_{j^*}$), and **Reconstruction Robustness** ($\rho^a_{j^*}(e)$) via **Algorithm 2 (`ComputeForensicConfidence`)**. |

---

## Part 2: Detailed Technical Gaps & Baseline Literature Limitations

### Gap 1: Static Centrality vs. Dynamic Forensic Triage
- **The Problem**: In dynamic enterprise networks, firewall rules change and new vulnerabilities open up over time. A host that was harmless at window $w_0$ may become a critical pivot host at window $w_2$.
- **Prior Work Deficiencies**:
  - *Wang & Daniels (2008)* compute static Eigenvector Centrality $Ax = \lambda x$ over the full evidence graph.
  - *He et al. (2016)* iterate Nodeworth/Linkworth matrix updates to convergence on a static graph.
  - *Gain & Barik (2026)* compute TAG betweenness $\mathcal{B}^a_i$ once over the entire time span $[t_{min}, t_{max}]$.
- **Impact**: Investigators cannot see *when* a host became critical, leading to inefficient log review prioritization.

### Gap 2: Potential Exploits vs. Verified Evidence
- **The Problem**: An attack graph represents *potential* exploit paths based on network connectivity and software vulnerabilities. However, in post-incident forensics, an investigator only cares about paths supported by actual log files, IDS alerts, or disk artifacts.
- **Prior Work Deficiencies**:
  - *Wang & Daniels (2008)* assign static ternary relevancy $r(e) \in \{0, 0.5, 1\}$ at edge creation. As new logs arrive at later windows, relevancy cannot evolve.
  - *COSE 2026 base model* contains no evidence layer — it treats all topological edges as equally real.
- **Impact**: No formal way to measure the "evidence gap" ($\Delta^a_{ij}$) between what *could* happen topologically versus what is *proven* to have happened.

### Gap 3: Forward Reachability vs. Backward Incident Tracing
- **The Problem**: Post-incident forensics starts at the **end** of an attack — a compromised host $j^*$ discovered at window $t^*$. Forensic analysts must trace **backward** in time to find the entry point (patient zero) and lateral steps.
- **Prior Work Deficiencies**:
  - *COSE 2026 Algorithm 1* computes *forward* shortest paths from an initial source host $i$.
  - *Zhang et al. (2015) Algorithm 3* performs backward BFS but outputs only two scalars (`min-dst-time` and `max-src-time`) to fix timestamp falsification — it does not reconstruct attack paths.
  - *Barrère et al. (2017) Algorithm 2 (`traceBack`)* traces backward but operates on a static (non-temporal) graph, returning a single path based on greedy local choices.
- **Impact**: Lack of a temporal backward reconstruction algorithm that yields a ranked candidate set of non-decreasing time paths ($W_b \le W_p$).

### Gap 4: Arbitrary Time Bounds vs. Graph-Derived Lookback Bounds
- **The Problem**: How far back in time should a forensic analyst query SIEM/log systems? Searching 30 days of logs across 10,000 hosts is computationally prohibitive; searching 2 hours might miss the attacker's initial breach weeks prior.
- **Prior Work Deficiencies**:
  - *Wang & Daniels (2008) Algorithm 1* relies on a manually configured hyperparameter $T$ (e.g., $T = 60\text{s}$) to group alerts.
  - No existing paper provides a mathematically proven bound for forensic lookback search.
- **Impact**: Forensic scope selection remains an ad-hoc guessing game.

### Gap 5: Absence of Forensic Confidence & Courtroom Defensibility Quantification
- **The Problem**: In legal proceedings or executive briefings, an investigator cannot simply state "we believe path X occurred." They must answer: *How certain are you?* and *What happens to your conclusion if one log entry is ruled inadmissible?*
- **Prior Work Deficiencies**: None of the 5 baseline papers quantify reconstruction uncertainty or perform sensitivity analysis on evidence edges.
- **Impact**: Forensic reporting lacks quantitative defensibility under evidentiary challenge.

---

## Part 3: Our Proposed Solution & Formal Framework

Our proposed framework builds directly on the base TAG formalism $\mathcal{G}^a(t_{min}, t_{max}) = (G_0, \dots, G_{\tau-1})$ from *Gain & Barik (COSE 2026)* and introduces an end-to-end forensic reconstruction engine:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  INPUT: TAG G^a, confirmed target j*, investigation window t*, evidence r^a │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Step 1:  Compute Lookback Bound λ*_{j*}                [Theorem 1]         │
│           → Determines provably sufficient historical search window         │
│                                                                             │
│  Step 2:  Construct Forensic Subgraph G^{a,forensic}     [Definition 5]     │
│           → Restricts analysis to edges with confirmed evidence (r^a=1)     │
│                                                                             │
│  Step 3:  Run BackwardReconstruct(G^a, j*, t*, r^a, K)  [Algorithm 1]      │
│           → Generates ranked candidate paths Q^{a,back}_{j*}                │
│                                                                             │
│  Step 4:  Compute Windowed Centrality Trajectories       [Definitions 8-9]  │
│           → Tracks B^a_i(W_l) over time prefixes for dynamic triage         │
│                                                                             │
│  Step 5:  Compute Forensic Confidence                    [Algorithm 2]      │
│           → Quantifies Entropy H^a_{j*}, Robustness ρ^a_{j*}(e), Gap Δ^a    │
│                                                                             │
│  Step 6:  Characterize Attack Dynamics                  [Definitions 10-11]│
│           → Computes Velocity v^a (automated vs APT) & Persistence Π^a       │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  OUTPUT: Ranked attack paths, confidence bounds, courtroom-defensible metrics│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Key Theoretical Constructs Implemented in `paper/draft_sections_3_5.md`:

#### 1. Time-Indexed Evidence Layer & Evidence Gap (§3.2)
- **Time-Indexed Evidence Relevancy** $r^a(e, W_p) \in \{0, 1\}$: Models incremental evidence collection up to investigation window $W_p$.
- **Forensic Subgraph** $\mathcal{G}^{a,\text{forensic}}(W_p)$: Subgraph containing only evidenced edges ($r^a = 1$).
- **Evidence Gap Metric** $\Delta^a_{ij}(W_p) = d^{a,\text{forensic}}_{ij}(W_p) - d^a_{ij}$: Quantifies missing evidence links forcing detours.

#### 2. Windowed Centrality Trajectories (§3.3)
- **Trajectory** $\vec{\mathcal{B}}^a_i = (\mathcal{B}^a_i(W_1), \dots, \mathcal{B}^a_i(W_k))$: Computes betweenness centrality over expanding window prefixes $W_l = \{0, \dots, l-1\}$ to identify newly emerging chokepoints during active investigations.

#### 3. Backward Temporal Path Reconstruction (§4)
- **Backward Path Set** $Q^{a,\text{back}}_{j^*}$: Enumerates paths from entry points $V_{\text{ext}}$ to target $j^*$ respecting reverse non-decreasing window constraints ($W_b(t_l) \le W_p(t_{l+1})$ for $t \le t^*$).
- **Plausibility Scoring**:
  $$\pi(p) = \alpha \cdot \pi_{\text{struct}}(p) + (1-\alpha) \cdot \pi_{\text{evid}}(p)$$
  combining windowed intermediate betweenness centrality with evidence fraction.
- **Algorithm 1 (`BackwardReconstruct`)**: Bounded priority-queue traversal running in $O(K \cdot (n+m) \cdot \tau)$ time.

#### 4. The Lookback Bound Theorem (§5.1)
- **Capability Persistence Axiom**: Attacker access persists once gained unless remediated ($\text{access}(v, t) = 1 \implies \text{access}(v, t') = 1 \ \forall t' \ge t$).
- **Theorem 1**: Derives the provable minimum lookback window $\lambda^*_{j^*}$:
  $$\lambda^*_{j^*} \le t^* - t^{\text{first}}_{j^*}$$
  where $t^{\text{first}}_{j^*}$ is the earliest temporal reachability window of target $j^*$.

#### 5. Forensic Confidence & Defensibility Metrics (§5.2 – §5.3)
- **Temporal AG Entropy** $H^a_{j^*}$: Shannon entropy over normalized path plausibilities $\hat{\pi}(p)$. $H^a = 0$ indicates zero ambiguity; $H^a = \log_2 |Q|$ indicates maximum uncertainty.
- **Entropy Reduction** $\Delta H^a_{j^*}(W_p) = H^a_{j^*} - H^{a,\text{forensic}}_{j^*}(W_p)$: Measures the exact information value (in bits) of collected evidence.
- **Reconstruction Robustness** $\rho^a_{j^*}(e) = 1 - \frac{|Q^{a,\text{back}}_{j^*}(e)|}{|Q^{a,\text{back}}_{j^* prob}|}$: Leave-one-out sensitivity testing. If $\rho^a_{j^*}(e) = 0$, edge $e$ is a single point of failure; if $\rho^a_{j^*}(e) > 0.5$, the conclusion is robust to losing evidence edge $e$.
- **Algorithm 2 (`ComputeForensicConfidence`)**: Computes entropy and robustness profiles in $O(K \cdot L_{\max})$ time.

---

## Summary & Next Steps

This framework directly bridges the gap between theoretical attack graph modeling and real-world digital forensics:
- It grounds search scope in **graph theory** (Lookback Bound Theorem) rather than arbitrary limits.
- It transforms forensic reconstruction from **opaque guessing** to **probabilistic path ranking** (Plausibility Score & Backward Algorithm).
- It provides **quantifiable courtroom defensibility** (Entropy and Robustness).

### Phased Roadmap:
1. ✅ **Formal Theory Draft**: Sections 3–5 completed in `paper/draft_sections_3_5.md`.
2. 🔄 **Implementation**: Code algorithms in Python / Neo4j extending the COSE pipeline.
3. 🔄 **Validation**: Run experiments on multi-window synthetic datasets and DARPA 2000 LLDOS benchmark (Section 6).
4. 🔄 **Submission**: Finalize paper for IFIP WG 11.9 (2027) deadline.
