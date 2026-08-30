import random
random.seed(42)

true_edges = [["E_ipsweep_mill"], ["E_sadmind_probe_mill"], ["E_sadmind_exploit_mill"], ["E_mstream_install_mill"], ["E_rsh_lateral_locke", "E_rsh_lateral_pascal"], ["E_ddos_launch_locke", "E_ddos_launch_pascal", "E_ddos_launch_mill"]]

for i in range(50):
    edge_idx_2 = random.randint(0, len(true_edges)-2) # interior edge group
    # print(edge_idx_2)
    pass
    
print(f"Total choices for index 4 (Lateral Movement): {sum(1 for _ in range(50) if random.randint(0, len(true_edges)-2) == 4)}")
