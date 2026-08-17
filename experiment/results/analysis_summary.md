# Forensic Temporal Attack Graph (F-TAG) Framework: Empirical Ground-Truth Research Report

## Executive Summary: Corridor-Based Network Forensic Foundations

This report presents the formal theory, implementation, and empirical validation of the **Forensic Temporal Attack Graph (F-TAG) Framework**, directly extending the proactive Temporal Attack Graph foundations of **Gain et al. (2026)** to reactive network forensic examinations (**Wang & Daniels 2008, Liu et al. 2012, Zhang et al. 2015, He et al. 2016, Barrère et al. 2017**).

Rather than treating network forensics through static, timeless reachability graphs or ungrounded heuristic scores, F-TAG grounds forensic reasoning in **Definition 1 & 2 of Gain et al. (2026)** ($\mathcal{G}^a(t_{\min}, t_{\max}) = (G_0, G_1, \ldots, G_{\tau-1})$). By tracking the dynamic availability of exploit edges $E_t$ across discrete time windows $W_b \le W_p \le W_k$, F-TAG defines the **Temporal Attack Corridor** ($\mathcal{TAC}$) and **Forensic Window of Compromise** ($\mathcal{FWoC}$), resolving the multi-step vulnerability lifecycle without the dormant-attacker intersection defect.

---

## 1. Six-Tier Corridor Forensic Metric Suite

Every metric in the suite answers a direct, operationally actionable investigative question:

| Tier | Metric | Mathematical Formulation | Investigative Purpose |
|:---|:---|:---|:---|
| **Tier 1: Timeline Bounding** | **Temporal Attack Corridor** | $\mathcal{TAC}(p) = [W_b(p), W_{\text{end}}(p)]$ | Derives earliest and latest theoretical breach windows from network topology alone |
| | **Forensic Window of Compromise** | $\mathcal{FWoC}(p) = \mathcal{TAC}(p) \cap [\min(t_i), \max(t_i)]$ | Tightest provable breach window once concrete evidence logs are integrated |
| | **Corridor Narrowing Ratio** | $\rho(p) = \frac{\|\mathcal{FWoC}(p)\|}{\|\mathcal{TAC}(p)\|}$ | Quantifies how much evidence tightened the theoretical topological bounds ($\ho \to 0$: pinned down; $\rho \to 1$: unconstrained) |
| **Tier 2: Evidence Reliability** | **Per-Hop Alignment** | $\text{aligned}(e) = \mathbb{I}(t_e \in \text{active\_windows}(e))$ | Pinpoints the exact falsified or misattributed log entry |
| | **Path Alignment Score** | $\mathcal{A}(p) = \frac{\|\text{aligned hops}\|}{\|p\|}$ | Quantifies end-to-end reconstruction temporal soundess |
| **Tier 3: Multi-Path Ambiguity** | **Corridor Overlap Index** | $\Omega(p, q) = \frac{\|\mathcal{TAC}(p) \cap \mathcal{TAC}(q)\|}{\|\mathcal{TAC}(p) \cup \mathcal{TAC}(q)\|}$ | Evaluates whether two candidate hypotheses imply distinct breach timeframes |
| | **Reconstruction Ambiguity** | $k = \|\text{Disjoint Corridor Clusters}\|$ | Number of mutually exclusive timeline narratives consistent with evidence |
| **Tier 4: Attack Tempo** | **Dwell Time Bounds** | $[\sum \Delta t_{\min}(e), \|\mathcal{TAC}(p)\|]$ | Bounds minimum execution duration and maximum presence duration |
| | **Stage Transition Gaps** | $\delta_k = W(e_{k+1}) - W(e_k)$ | Detects attacker dormancy and lateral staging intervals |
| | **Temporal Propagation Rate** | $v(p) = \frac{\|p\| - 1}{\|\mathcal{TAC}(p)\|}$ | Intrusive tempo signature (automated/scripted vs. manual) |
| **Tier 5: Host-Level Triage** | **Temporal Chokepoint Score** | $\chi(h) = \frac{\|\{p \in Q^a_{ij} : h \in p, \mathcal{FWoC}(p) \neq \emptyset\}\|}{\|\{p : \mathcal{FWoC}(p) \neq \emptyset\}\|}$ | Incident-specific likelihood that host $h$ was on the true compromise route |
| | **Host Exposure Window** | $\mathcal{W}(h) = \bigcup_{e \sim h} \text{active\_windows}(e)$ | Scopes exact log retrieval time slices for host $h$ |
| **Tier 6: Investigation Scoping** | **Temporal Search Radius** | $T_{\min}(j^*) = \min_{p \in Q^{a,\text{back}}_{j^*}} W_b(p)$ | Determines minimum historical lookback horizon from confirmed victim |

---

## 2. Empirical Validation on DARPA LLDOS Datasets

We constructed F-TAGs directly from raw tcpdump session lists (`phase-*.list`), IDMEF XML alerts (`mid-level-phase-*.xml`), and official labeling metadata (`labeling_info`) across both DARPA datasets:

### Table 1: Empirical Evaluation across DARPA LLDOS Datasets & MulVAL F-TAG

| dataset | nodes | edges | windows | static_paths | temporal_paths | surviving_paths | ambiguity_clusters | search_radius |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DARPA LLDOS 1.0 (Novice DDoS) | 23 | 17 | 5 | 20 | 28 | 28 | 1 | 0 |
| DARPA LLDOS 2.0.2 (Stealthy SSH & Exfiltration) | 9 | 5 | 5 | 3 | 3 | 3 | 1 | 0 |
| MulVAL-Generated F-TAG (LLDOS 1.0) | 7 | 9 | 5 | 6 | 33 | 33 | 1 | 0 |

### Key Experimental Findings from Ground Truth & MulVAL Generation:
1. **MulVAL Temporal Attack Graph (F-TAG)**:
   - **Datalog Inference**: MulVAL generated 5 snapshots totaling 227 vertices (LEAF/AND/OR) and 165 arcs across $W_0..W_4$.
   - **Timeline Bounding**: $\mathcal{TAC}_{\text{net}} = [w_0, w_4]$. All 33 temporal paths correctly satisfied Definition 2's sequential window ordering.
   - **Anti-Forensic Tamper Detection**: When the `MulVAL_Exploit_mill` edge was tampered (forged into $W_0$), 24 out of 33 candidate paths were immediately flagged and eliminated, dropping path alignment from $0.773 \to 0.727$.

2. **DARPA LLDOS 1.0 (Novice Attacker with Distributed Denial of Service)**:
   - **Timeline Bounding**: $\mathcal{TAC}_{\text{net}} = [w_0, w_4]$ spanning 5 attack phases (IPsweep $\to$ Sadmind Probe $\to$ Sadmind Exploit $\to$ Mstream Install $\to$ DDoS Launch).
   - **Host Chokepoints**: `mill` scored $\chi = 0.714$ as the master coordination and lateral staging pivot, while `attacker` and `ddos_target` scored $\chi = 1.000$. Uncompromised hosts (`marx`, `zeno`, `hume`) correctly scored $\chi = 0.000$.
   - **Investigation Scoping**: $T_{\min}(\text{ddos\_target}) = w_0$, proving that an investigator discovering the DDoS victim only needs to retrieve logs starting from the initial probe window.

3. **DARPA LLDOS 2.0.2 (Stealthy SSH Lateral Movement & Exfiltration)**:
   - **Timeline Bounding**: Aggregated corridor $\mathcal{TAC} = [w_0, w_3]$.
   - **Host Chokepoints**: `mill` and `pascal` both scored $\chi = 1.000$, accurately capturing the multi-hop intrusion chain (`attacker` $\to$ `mill` $\to$ `pascal`).
   - **Multi-Path Ambiguity**: $\Omega(P_1, P_2) = 0.667$, identifying overlapping temporal intervals between reconnaissance and exploit phases while maintaining a single cohesive narrative ($k = 1$).

---

## 3. Anti-Forensic Tamper Detection (Clean vs. Falsified Evidence)

When attackers perform timestamp forgery (time-stomping) to disrupt causal reconstruction, static attack graphs accept fraudulent timestamps because they lack temporal window constraints. F-TAG detects and isolates falsification through Per-Hop Alignment $\mathcal{A}(p)$ and $\mathcal{FWoC}$ emptiness:

```
  Metric                                         Clean   Falsified
  ────────────────────────────────────────  ──────────  ──────────
  Total Temporal Paths                              21          21
  Surviving Paths (FWoC ≠ ∅)                        21           6  (-71.4% eliminated)
  Mean Alignment Score A(p)                      0.623       0.413  (Inconsistency flagged)
  Disjoint Corridor Clusters (k)                     1           1
  Best Narrowing Ratio ρ                         0.500       0.250
```

- **71.4% of candidate paths eliminated**: Falsified timestamps immediately produce $\mathcal{FWoC}(p) = \emptyset$ on invalid corridors.
- **Exact Hop Localization**: Per-hop alignment vectors pinpoint the forged timestamp to the exact compromised edge.

---

## 4. Submission Positioning: IFIP WG 11.9 Conference (2027)

This research is tailored for the **23rd Annual IFIP WG 11.9 International Conference on Digital Forensics** (Jan 7–8, 2027, New Delhi, India; Springer Advances in Digital Forensics book series & Elsevier *Computers & Security* fast-track):

- **Direct Topic Alignment**: *Network and Distributed Systems Forensics*, *Forensic Investigation Techniques*, *Anti-Forensics and Counter-Anti-Forensics*.
- **Novelty**: First formal framework to introduce Temporal Attack Corridors ($\mathcal{TAC}$), Forensic Windows of Compromise ($\mathcal{FWoC}$), and Temporal Chokepoint Scores ($\chi$) to reactive forensics.
- **Empirical Rigor**: Fully evaluated on standard DARPA LLDOS 1.0 and 2.0.2 benchmark datasets.
