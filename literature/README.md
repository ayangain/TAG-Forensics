# Literature Repository: Attack Graph-Based Network Forensics

This repository contains curated research notes, formal models, and comparative analyses of foundational papers in **Attack Graph-Based Network Forensics**.

---

## 📚 Summary of Stored Literature

| # | Paper Title | Authors | Year / Venue | Key Contribution / Focus Area | Literature File |
|---|---|---|---|---|---|
| 1 | **Using Attack Graphs in Forensic Examinations** | Changwei Liu, Anoop Singhal, Duminda Wijesekera | ARES 2012 (NIST / GMU) | Models anti-forensic activity nodes (log erasure, data hiding, payload obfuscation) in MulVAL attack graphs and proposes an Anti-Forensic Vulnerabilities Database. | [01_liu_2012](file:///Users/ayangain/repos/TAG-Forensics/literature/01_liu_2012_using_attack_graphs_in_forensic_examinations.md) |
| 2 | **Tracking the Bad Guys: An Efficient Forensic Methodology To Trace Multi-step Attacks Using Core Attack Graphs** | Martín Barrère, Rodrigo Vieira Steiner, Rabih Mohsen, Emil C. Lupu | IEEE CNS 2017 (Imperial College London) | Introduces Core Attack Graphs (CAGs) using graph-theoretic core path abstraction to reduce network exploration rate to ~20% without sacrificing forensic tracing accuracy. | [02_barrere_2017](file:///Users/ayangain/repos/TAG-Forensics/literature/02_barrere_2017_tracking_the_bad_guys_core_attack_graphs.md) |
| 3 | **Detecting Falsified Timestamps in Evidence Graph via Attack Graph** | Yuqiang Zhang, Jingsha He, Jing Xu | ISCID 2015 (BJUT) | Uses attack graph causality to detect, mark, and adjust falsified timestamps in evidence graphs, restoring chronological event continuity. | [03_zhang_2015](file:///Users/ayangain/repos/TAG-Forensics/literature/03_zhang_2015_detecting_falsified_timestamps_in_evidence_graph.md) |
| 4 | **Network Forensics Method Based on Evidence Graph and Vulnerability Reasoning** | Jingsha He, Chengyue Chang, Peng He, Muhammad Salman Pathan | Future Internet 2016 (BJUT / MDPI) | Combines Event Vector (EV) standardization, SVM packet filtering, and the VERA algorithm (Nodeworth/Linkworth iterative matrix convergence) to reconstruct multi-staged attacks. | [04_he_2016](file:///Users/ayangain/repos/TAG-Forensics/literature/04_he_2016_network_forensics_evidence_graph_vulnerability_reasoning.md) |
| 5 | **A Graph Based Approach Toward Network Forensics Analysis** | Wei Wang, Thomas E. Daniels | ACM TISSEC 2008 (Iowa State University) | Foundational evidence graph model with Leader-Follower alert aggregation, RBFCM local functional state inference, Eigenvector Centrality seed generation, and interactive hypothesis testing. | [05_wang_2008](file:///Users/ayangain/repos/TAG-Forensics/literature/05_wang_2008_graph_based_approach_toward_network_forensics.md) |

---

## 🔬 Cross-Paper Taxonomy & Feature Matrix

| Feature Dimension | Wang & Daniels (2008) | Liu et al. (2012) | Zhang et al. (2015) | He et al. (2016) | Barrère et al. (2017) |
|---|---|---|---|---|---|
| **Graph Model** | Evidence Graph $G = (N, E, L_N, L_E)$ | Extended MulVAL Attack Graph (with Anti-Forensics Nodes) | Evidence Graph (IEG) + System Attack Graph | Evidence Graph (EG) + Network Vulnerability Database | Core Attack Graph (CAG) structural abstraction |
| **Primary Goal** | Automated evidence aggregation, role inference & group extraction | Explain missing evidence via evidence-wiping paths | Detect & fix anti-forensic timestamp falsification | Deduce attacker & victim hosts via iterative reasoning | Scalable backward tracing of multi-step attacks |
| **Local Reasoning** | Rule-Based Fuzzy Cognitive Maps (RBFCM for AT, VI, SS, AF) | Threat Path Privilege Escalation Matching | Timestamp sequence consistency checking | Nodeworth score ($y = H^T Z$) initialization | Forensic trust function $e(m) = \frac{1 \pm \lambda c_m}{2}$ |
| **Global Reasoning** | Eigenvector Centrality ($Ax = \lambda x$) & Single-Linkage Clustering | Attack Path Reconstruction via NVD Graph Traversal | BFS Attack Graph causal chain alignment | Linkworth score ($Z = H y$) matrix convergence | Backwards exploration (`traceBack`) + candidate test $candidate(m,T)$ |
| **Noise Filtering** | Leader-Follower Alert Aggregation (Time Window $T$) | Manual / Evidence Matching | Chronological anomaly detection | Machine Learning (SVM on KDD/DARPA 41 features) | Acceptance threshold $T$ & refinement parameter $k$ |
| **Anti-Forensics Handling** | Interactive Hypothesis Testing $(\text{Assoc}, \text{Class}, \text{Time})$ | Explicit Anti-Forensic Tool/Technique DB (Table 3) | Timestamp correction via attack graph causal bounds | Unified Event Vectors across heterogeneous logs | N/A (Focuses on graph reduction & scalability) |
| **Evaluation Data** | Testbed (30 hosts), DARPA 2000 LLDOS 2.0.2, ARDA Contract Benchmark | Simulated Web/MySQL database network | Lab network with Ubuntu/Windows servers | DARPA 2000 LLDOS 1.0 & LLDOS 2.0.2 benchmark datasets | Naggen generator (Cyclic, DAG, Scale-Free) & P2P-Gnutella dataset |

---

## 💡 Core Research Insights & Synergies

1. **Evolution of Evidence Graphs**:
   - **Wang & Daniels (2008)** established the foundational Evidence Graph model and RBFCM local state reasoning.
   - **He et al. (2016)** extended this model by introducing automated SVM packet filtering and matrix-based iterative reasoning (VERA).

2. **Graph Complexity vs. Investigation Overhead**:
   - Standard Logical Attack Graphs (LAGs) suffer from state-space explosion ($O(|V|+|E|)$ growth in dense enterprise topologies).
   - **CAGs (Barrère et al., 2017)** solve this by compressing alternative paths into core induced paths, reducing investigation search surfaces by 75–80%.

3. **Dealing with Anti-Forensics**:
   - Attackers frequently corrupt evidence timestamps (**Zhang et al., 2015**) or delete/obfuscate logs (**Liu et al., 2012**).
   - Wang & Daniels (2008) addressed missing secondary evidence through interactive hypothesis testing $(\text{Association}, \text{Classification}, \text{Time})$, while Liu et al. (2012) added explicit anti-forensics activity nodes to attack graphs.
