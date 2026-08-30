with open("author.tex", "r") as f:
    text = f.read()

old_text = r"""\textbf{LLDOS 1.0 (Overt, High Redundancy):} This dataset features a highly noisy, overt attack where the adversary performs network sweeps, exploits the Sadmind vulnerability, installs the Mstream DDoS daemon, and ultimately launches a denial-of-service attack. The sheer volume of background noise and continuous concurrent activity creates a topology rich with chronological redundancy (i.e., multiple contiguous steps occurring within identical time windows). 

\textbf{LLDOS 2.0.2 (Stealth, Strict Serialization):} In contrast, LLDOS 2.0.2 features a stealthy, low-profile attacker executing a strictly serialized chain. The attacker exploits Sadmind, uploads a backdoor via FTP, pivots via SSH, and exfiltrates data via a single, rigid sequence with minimal background noise and zero overlapping active windows."""

new_text = r"""\textbf{LLDOS 1.0 (Overt, Distributed DDoS):} This dataset features a highly noisy, overt attack where the adversary performs network sweeps, exploits the Sadmind vulnerability to compromise three separate Solaris hosts (Mill, Pascal, and Locke), installs the Mstream DDoS daemon on each, and ultimately launches a distributed denial-of-service attack against a single target. The chronological redundancy (thousands of alerts) and the three parallel, converging attack paths create a highly redundant attack topology. 

\textbf{LLDOS 2.0.2 (Stealth, Linear Exfiltration):} In contrast, LLDOS 2.0.2 features a stealthy, low-profile attacker executing a strictly serialized, zero-redundancy chain. The attacker exploits Sadmind, uploads a backdoor via FTP, pivots via SSH, and exfiltrates data via a single, rigid sequence with minimal background noise."""

if old_text in text:
    text = text.replace(old_text, new_text)
    with open("author.tex", "w") as f:
        f.write(text)
    print("Replaced successfully")
else:
    print("Old text not found")
