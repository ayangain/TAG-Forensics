# Paper Analysis: Attack detection and mitigation using Intelligent attack graph model for Forensic in IoT Networks

**Title:** Attack detection and mitigation using Intelligent attack graph model for Forensic in IoT Networks
**Authors:** Sonam Bhardwaj, Mayank Dave
**Publication:** Telecommunication Systems (2024)
**DOI:** 10.1007/s11235-024-01105-w

## 1. Overview and Summary
This paper addresses cybersecurity challenges in resource-constrained IoT environments by proposing a 10-phase security framework. The core innovation is the integration of an Intelligent Attack Graph (IAG) with Artificial Intelligence (AI) to predict attack paths and active mitigation through Virtual Node Injection (VNI). The system predicts "red" (exploitable) and "black" (safe/un-exploitable) attack paths using a Vulnerable Attack Path Predictor (VAPP) module and deploys virtual nodes as drop traps or loop traps to stall or halt attackers before they reach root servers.

## 2. Methodology & Architecture
The proposed model operates in 10 phases, primarily characterized by:
*   **AI-Based Malware Detection:** Continuous IoT traffic monitoring using ensemble classifiers to detect anomalous behavior and malicious packets.
*   **Attack Graph Generator (AGG):** Dynamically constructs instantaneous snapshots of the network to visualize the attacker's progression.
*   **Vulnerable Attack Path Predictor (VAPP):** An AI sub-module that classifies attack paths as *Red* (attacker has or can guess the required private keys to progress) or *Black* (attacker lacks required keys, making the path currently non-exploitable).
*   **Virtual Node Injection (VNI):** Active mitigation response. The system injects virtual nodes into predicted red paths to create:
    *   **Drop Traps:** Lure the attacker to a virtual node and then drop the connections, severely setting back their progress.
    *   **Loop Traps:** Force the attacker into an inescapable cycle of virtual nodes, burning their resources and preventing lateral movement toward the root server (SVR_ROOT).
*   **Security Verification:** Uses ProVerif (a cryptographic protocol verifier) based on the Dolev-Yao model to formally verify that the attacker cannot reach the secret keys after VNI traps are deployed.

## 3. Key Results
*   **VAPP Performance:** Deep Learning outperformed other models (AdaBoost, MLP, KNN, Random Forest), achieving 96% accuracy for black paths and 97% for red paths.
*   **Overall System Metrics:** 
    *   Detection Rate: 98.48%
    *   False Positive Rate: 0.64%
    *   Response Time: 200 ms
    *   Authentication Accuracy: 85%
*   **Comparison:** Outperforms existing models like IDERES, MTISS-IoT, and other attack graph models in detection rate and false positive rate, while maintaining a competitive response time.

## 4. Relevance & Contrast to F-TAG
*   **Active vs. Passive:** Bhardwaj et al. focus on *active, real-time mitigation* (Virtual Node Injection) to stop an ongoing attack. F-TAG focuses on *passive, retrospective forensics* to reconstruct timelines and bound unobserved actions after the fact.
*   **Graph Type:** This paper uses instantaneous snapshot graphs generated iteratively (AGG) but primarily evaluates them based on AI path prediction. F-TAG unifies time windows into a single Temporal Attack Graph that mathematically enforces chronological constraints to prevent backward-time causal loops.
*   **Missing Evidence:** Bhardwaj et al. assume real-time monitoring catches the attacker and do not explicitly model missing evidence or anti-forensic log wiping. F-TAG explicitly models missing logs via the Forensic Window of Compromise (FWoC) and detects log wiping via the $AF_{conf}$ Bayesian metric.
*   **Potential Synergies:** The VAPP module's classification of red/black paths based on compromised keys could be integrated into F-TAG's Phase 2 to further narrow the Temporal Attack Corridors (TAC) by pruning paths where key compromise is deemed impossible. Conversely, F-TAG's strict temporal ordering could improve the accuracy of VAPP by filtering out causally impossible predictions.
