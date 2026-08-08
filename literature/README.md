# Literature Repository: Attack Graph-Based Network Forensics

This repository contains curated research notes, formal models, and comparative analyses of foundational papers in **Attack Graph-Based Network Forensics** and **Temporal Attack Graphs (TAGs)**.

---

## 📚 Summary of Stored Literature

| # | Paper Title | Authors | Year / Venue | Key Contribution / Focus Area | Literature File |
|---|---|---|---|---|---|
| 0 | **Temporal Attack Graph Based Security Metrics** | Ayan Gain, Mridul Sankar Barik | COSE 2026 (*Computers & Security* Draft) | Defines base Temporal Attack Graph (TAG) formalism $\mathcal{G}^a(t_{min}, t_{max})$, non-decreasing time window paths $p^a_{ij}$, path metrics ($d^a_{ij}, L^a, E^a$), and temporal centralities ($\mathcal{B}^a_i, \mathcal{C}^a_i$) for proactive risk assessment. | [00_gain_2026](file:///Users/ayangain/repos/TAG-Forensics/literature/00_gain_2026_temporal_attack_graph_based_security_metrics.md) |
| 1 | **Using Attack Graphs in Forensic Examinations** | Changwei Liu, Anoop Singhal, Duminda Wijesekera | ARES 2012 (NIST / GMU) | Models anti-forensic activity nodes (log erasure, data hiding, payload obfuscation) in MulVAL attack graphs and proposes an Anti-Forensic Vulnerabilities Database. | [01_liu_2012](file:///Users/ayangain/repos/TAG-Forensics/literature/01_liu_2012_using_attack_graphs_in_forensic_examinations.md) |
| 2 | **Tracking the Bad Guys: An Efficient Forensic Methodology To Trace Multi-step Attacks Using Core Attack Graphs** | Martín Barrère, Rodrigo Vieira Steiner, Rabih Mohsen, Emil C. Lupu | IEEE CNS 2017 (Imperial College London) | Introduces Core Attack Graphs (CAGs) using graph-theoretic core path abstraction to reduce network exploration rate to ~20% without sacrificing forensic tracing accuracy. | [02_barrere_2017](file:///Users/ayangain/repos/TAG-Forensics/literature/02_barrere_2017_tracking_the_bad_guys_core_attack_graphs.md) |
| 3 | **Detecting Falsified Timestamps in Evidence Graph via Attack Graph** | Yuqiang Zhang, Jingsha He, Jing Xu | ISCID 2015 (BJUT) | Uses attack graph causality to detect, mark, and adjust falsified timestamps in evidence graphs, restoring chronological event continuity. | [03_zhang_2015](file:///Users/ayangain/repos/TAG-Forensics/literature/03_zhang_2015_detecting_falsified_timestamps_in_evidence_graph.md) |
| 4 | **Network Forensics Method Based on Evidence Graph and Vulnerability Reasoning** | Jingsha He, Chengyue Chang, Peng He, Muhammad Salman Pathan | Future Internet 2016 (BJUT / MDPI) | Combines Event Vector (EV) standardization, SVM packet filtering, and the VERA algorithm (Nodeworth/Linkworth iterative matrix convergence) to reconstruct multi-staged attacks. | [04_he_2016](file:///Users/ayangain/repos/TAG-Forensics/literature/04_he_2016_network_forensics_evidence_graph_vulnerability_reasoning.md) |
| 5 | **A Graph Based Approach Toward Network Forensics Analysis** | Wei Wang, Thomas E. Daniels | ACM TISSEC 2008 (Iowa State University) | Foundational evidence graph model with Leader-Follower alert aggregation, RBFCM local functional state inference, Eigenvector Centrality seed generation, and interactive hypothesis testing. | [05_wang_2008](file:///Users/ayangain/repos/TAG-Forensics/literature/05_wang_2008_graph_based_approach_toward_network_forensics.md) |

---

## 🔬 Cross-Paper Taxonomy & Feature Matrix

| Feature Dimension | Gain & Barik (2026) | Wang & Daniels (2008) | Liu et al. (2012) | Zhang et al. (2015) | He et al. (2016) | Barrère et al. (2017) |
|---|---|---|---|---|---|---|
| **Graph Model** | Temporal Attack Graph $\mathcal{G}^a = (G_0 \dots G_{\tau-1})$ | Evidence Graph $G = (N, E, L_N, L_E)$ | Extended MulVAL Attack Graph | Evidence Graph (IEG) + System AG | Evidence Graph + Vulnerability DB | Core Attack Graph (CAG) |
| **Primary Goal** | Proactive risk assessment & temporal metrics | Evidence aggregation, role inference & group extraction | Explain missing evidence via evidence-wiping paths | Detect & fix anti-forensic timestamp falsification | Deduce attacker/victim via matrix convergence | Scalable backward tracing of multi-step attacks |
| **Local Reasoning** | Non-decreasing window path distance $d^a_{ij}$ | Rule-Based Fuzzy Cognitive Maps (RBFCM) | Threat Path Privilege Escalation Matching | Timestamp sequence consistency checking | Nodeworth score ($y = H^T Z$) initialization | Forensic trust function $e(m) = \frac{1 \pm \lambda c_m}{2}$ |
| **Global Reasoning** | TAG Betweenness $\mathcal{B}^a_i$ & Closeness $\mathcal{C}^a_i$ | Eigenvector Centrality ($Ax = \lambda x$) & Distance Clustering | Attack Path Reconstruction via NVD Graph Traversal | BFS Attack Graph causal chain alignment | Linkworth score ($Z = H y$) matrix convergence | Backwards exploration (`traceBack`) + candidate test $candidate(m,T)$ |
| **Noise Filtering** | Graph Pruning Algorithm 5 | Leader-Follower Alert Aggregation | Manual / Evidence Matching | Chronological anomaly detection | Machine Learning (SVM on KDD/DARPA 41 features) | Acceptance threshold $T$ & refinement $k$ |
| **Anti-Forensics Handling** | Privilege Persistence Axiom | Interactive Hypothesis Testing | Explicit Anti-Forensic Tool/Technique DB | Timestamp correction via AG causal bounds | Unified Event Vectors | N/A (Focuses on graph reduction) |
| **Evaluation Data** | Synthetic networks (39–498 hosts, 4 windows) | Testbed (30 hosts), DARPA 2000 LLDOS 2.0.2, ARDA | Simulated Web/MySQL network | Lab network (Ubuntu/Win) | DARPA 2000 LLDOS 1.0 & 2.0.2 | Naggen (Cyclic, DAG, Scale-Free) & P2P-Gnutella dataset |

---

## 💡 Core Research Insights & Synergies

1. **Repointing TAG Formalism from Proactive to Reactive Forensics**:
   - **Gain & Barik (2026)** established the core temporal attack graph model $\mathcal{G}^a$ for proactive vulnerability management and security metrics ($L^a, E^a, \mathcal{B}^a_i, \mathcal{C}^a_i$).
   - Our new **IFIP WG 11.9 (2027)** proposal extends this exact foundation into **post-incident forensic reconstruction**: adding time-indexed evidence relevancy $r^a(e, W_p)$, backward temporal path set $Q^{a,\text{back}}_{j^*}$, lookback bound theorem $\lambda^*_{j^*}$, and confidence metrics ($H^a_{j^*}, \rho^a_{j^*}(e)$).

2. **Graph Complexity vs. Investigation Overhead**:
   - Static attack graphs suffer from state-space explosion ($O(|V|+|E|)$ growth in dense enterprise topologies).
   - **CAGs (Barrère et al., 2017)** compress alternative paths into core induced paths, while **TAGs (Gain & Barik, 2026)** structure time-varying snapshots into non-decreasing window sequences.

3. **Handling Evidentiary Uncertainty & Anti-Forensics**:
   - Attackers corrupt timestamps (**Zhang et al., 2015**) or erase log files (**Liu et al., 2012**).
   - Combining Wang & Daniels' hypothesis testing, He et al.'s VERA reasoning, and Gain & Barik's temporal betweenness provides a robust, evidence-aware framework for courtroom-defensible incident response.
