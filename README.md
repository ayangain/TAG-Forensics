# TAG-Forensics (Topology & Attack Graph-Based Network Forensics)

Welcome to the **TAG-Forensics** repository. This repository stores research work, formal graph models, algorithms, and comparative taxonomies on **Attack Graph-Based Network Forensics** and **Temporal Attack Graphs (TAGs)**.

---

## 📌 Foundational Work & Stored Research Notes

Detailed technical notes, mathematical formalisms, algorithms, and case studies for the key literature on attack graph-based network forensics are stored in the [`literature/`](file:///Users/ayangain/repos/TAG-Forensics/literature/README.md) directory:

0. 📄 **[Gain & Barik (2026) - Temporal Attack Graph Based Security Metrics](file:///Users/ayangain/repos/TAG-Forensics/literature/00_gain_2026_temporal_attack_graph_based_security_metrics.md)** *(COSE Manuscript Draft)*
   - *Key Focus*: Base Temporal Attack Graph (TAG) formalism $\mathcal{G}^a(t_{min}, t_{max})$, non-decreasing window paths $p^a_{ij}$, path metrics ($d^a_{ij}, L^a, E^a$), and temporal centralities ($\mathcal{B}^a_i, \mathcal{C}^a_i$) for proactive risk assessment.

1. 📄 **[Liu et al. (2012) - Using Attack Graphs in Forensic Examinations](file:///Users/ayangain/repos/TAG-Forensics/literature/01_liu_2012_using_attack_graphs_in_forensic_examinations.md)**
   - *Key Focus*: Anti-forensic activity nodes, evidence-erasing attack paths, and Anti-Forensics Technique/Tool Database (NVD extension).

2. 📄 **[Barrère et al. (2017) - Tracking the Bad Guys: Core Attack Graphs](file:///Users/ayangain/repos/TAG-Forensics/literature/02_barrere_2017_tracking_the_bad_guys_core_attack_graphs.md)**
   - *Key Focus*: Core Attack Graph (CAG) induced path compression, hierarchical expansion ($\tau_{hexp}$), forensic trust model ($e(m)$), and $O(|V|+|E|)$ linear generation.

3. 📄 **[Zhang et al. (2015) - Detecting Falsified Timestamps in Evidence Graph](file:///Users/ayangain/repos/TAG-Forensics/literature/03_zhang_2015_detecting_falsified_timestamps_in_evidence_graph.md)**
   - *Key Focus*: Detection and automated correction of tampered timestamps using attack graph topological causality.

4. 📄 **[He et al. (2016) - Network Forensics Method Based on Evidence Graph & Vulnerability Reasoning](file:///Users/ayangain/repos/TAG-Forensics/literature/04_he_2016_network_forensics_evidence_graph_vulnerability_reasoning.md)**
   - *Key Focus*: Event Vector (EV) format, SVM packet filtering, and the VERA algorithm (Nodeworth/Linkworth matrix convergence).

5. 📄 **[Wang & Daniels (2008) - A Graph Based Approach Toward Network Forensics Analysis](file:///Users/ayangain/repos/TAG-Forensics/literature/05_wang_2008_graph_based_approach_toward_network_forensics.md)**
   - *Key Focus*: Foundational Evidence Graph model, Leader-Follower alert aggregation, RBFCM local host role inference, Eigenvector Centrality seed selection, and interactive hypothesis testing.

---

## 🎯 Target IFIP WG 11.9 (2027) Proposal

- 📄 **[New Proposal & Scope Evaluation](file:///Users/ayangain/.gemini/antigravity-ide/brain/d2d2fde4-787e-4784-a709-66d623e97758/implementation_plan.md)**
- 📄 **[Draft Paper Core — Sections 3–5](file:///Users/ayangain/repos/TAG-Forensics/paper/draft_sections_3_5.md)**

For a cross-paper taxonomy and comparative feature matrix, see the **[Literature Directory Overview](file:///Users/ayangain/repos/TAG-Forensics/literature/README.md)**.