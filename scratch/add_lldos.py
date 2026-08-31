with open("experiment/run_af_calibration.py", "r") as f:
    content = f.read()

lldos_setup = """
def setup_lldos():
    from experiment.engine import FTAG
    import json
    with open("data/lldos_1.0_raw.json", "r") as f:
        data = json.load(f)
    
    ftag = FTAG()
    for n in data["nodes"]:
        ftag.add_node(n["id"], n["host"], n["name"])
        
    for e in data["edges"]:
        ftag.add_edge(e["source"], e["target"])
        
    src = "0"
    dst = "24"
    return ftag, src, dst
"""

if "def setup_lldos" not in content:
    content = content.replace("def main():", lldos_setup + "\n\ndef main():")
    content = content.replace("run_experiment_for_graph(\"Synthetic MulVAL (Unpruned)\", ftag_mulval, src_mulval, dst_mulval)", "run_experiment_for_graph(\"Synthetic MulVAL (Unpruned)\", ftag_mulval, src_mulval, dst_mulval)\n    print('\\nPreparing LLDOS 1.0 graph...')\n    ftag_lldos, src_lldos, dst_lldos = setup_lldos()\n    run_experiment_for_graph('DARPA LLDOS 1.0', ftag_lldos, src_lldos, dst_lldos)")
    
    with open("experiment/run_af_calibration.py", "w") as f:
        f.write(content)
