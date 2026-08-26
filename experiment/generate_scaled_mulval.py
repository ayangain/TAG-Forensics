import os

def generate_enterprise_datalog(n: int, output_dir: str):
    """
    Generates a 3-tier enterprise topology for MulVAL with N nodes.
    - Tier 1: DMZ Webservers (approx 20% of nodes)
    - Tier 2: Internal App Servers (approx 40% of nodes)
    - Tier 3: Databases / Workstations (approx 40% of nodes)
    
    Generates 5 distinct time windows where the attack surface gradually opens,
    simulating patching cycles and configuration drift.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    n_dmz = max(1, int(n * 0.2))
    n_app = max(1, int(n * 0.4))
    n_db = n - n_dmz - n_app
    
    # Base facts that exist across all windows
    base_facts = ["attackerLocated(internet)."]
    
    # Goal is to compromise the last DB node
    target_node = f"db_{n_db - 1}"
    base_facts.append(f"attackGoal(execCode({target_node}, root)).")
    
    # Define network services and initial vulnerabilities for each node
    for i in range(n_dmz):
        node = f"dmz_{i}"
        base_facts.append(f"networkServiceInfo({node}, httpd, tcp, 80, root).")
        base_facts.append(f"hacl(internet, {node}, tcp, 80).")
        
    for i in range(n_app):
        node = f"app_{i}"
        base_facts.append(f"networkServiceInfo({node}, tomcat, tcp, 8080, root).")
        # Connect DMZ to App
        for j in range(n_dmz):
            base_facts.append(f"hacl(dmz_{j}, {node}, tcp, 8080).")
            
    for i in range(n_db):
        node = f"db_{i}"
        base_facts.append(f"networkServiceInfo({node}, postgres, tcp, 5432, root).")
        # Connect App to DB
        for j in range(n_app):
            base_facts.append(f"hacl(app_{j}, {node}, tcp, 5432).")
            
    base_facts_str = "\n".join(base_facts) + "\n"
    
    # Define vulnerability states over time
    # W0: Secure baseline
    w0_facts = base_facts_str
    
    # W1: DMZ vulnerability introduced
    w1_vulns = []
    for i in range(n_dmz):
        node = f"dmz_{i}"
        w1_vulns.append(f"hasVuln({node}, vul_web, httpd).\nvulExists({node}, vul_web, httpd).\nvulProperty(vul_web, remoteExploit, privEscalation).")
    w1_facts = base_facts_str + "\n".join(w1_vulns) + "\n"
    
    # W2: DMZ + App vulnerability
    w2_vulns = w1_vulns.copy()
    for i in range(n_app):
        node = f"app_{i}"
        w2_vulns.append(f"hasVuln({node}, vul_app, tomcat).\nvulExists({node}, vul_app, tomcat).\nvulProperty(vul_app, remoteExploit, privEscalation).")
    w2_facts = base_facts_str + "\n".join(w2_vulns) + "\n"
    
    # W3: DMZ + App + DB vulnerability (full path exposed)
    w3_vulns = w2_vulns.copy()
    for i in range(n_db):
        node = f"db_{i}"
        w3_vulns.append(f"hasVuln({node}, vul_db, postgres).\nvulExists({node}, vul_db, postgres).\nvulProperty(vul_db, remoteExploit, privEscalation).")
    w3_facts = base_facts_str + "\n".join(w3_vulns) + "\n"
    
    # W4: Same as W3
    w4_facts = w3_facts
    
    windows = {0: w0_facts, 1: w1_facts, 2: w2_facts, 3: w3_facts, 4: w4_facts}
    
    generated_files = []
    for w in range(5):
        input_path = os.path.join(output_dir, f"input_w{w}.P")
        with open(input_path, 'w') as f:
            f.write(f"% MulVAL input for Window {w} (N={n})\n")
            f.write(windows[w])
        generated_files.append(input_path)
        
    return generated_files
