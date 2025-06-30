import os
import json
import sys
import subprocess
import matplotlib.pyplot as plt
import shutil

try:
    from graphviz import Digraph
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "graphviz"])
    from graphviz import Digraph

if not shutil.which("dot"):
    print("[!] Graphviz binary not found. Trying to install...")
    if sys.platform.startswith("linux"):
        subprocess.call(["apt-get", "update"])
        subprocess.call(["apt-get", "install", "-y", "graphviz"])
    elif sys.platform == "darwin":
        subprocess.call(["brew", "install", "graphviz"])
    elif sys.platform == "win32":
        print("[!] Install Graphviz manually from https://graphviz.org/download/")
        sys.exit(1)

DEFAULT_TTP_MAP = {
    "Execution": [
        {"id": "T1059", "name": "Command & Scripting Interpreter", "next": ["T1053"]}
    ],
    "Persistence": [
        {"id": "T1053", "name": "Scheduled Task/Job", "next": []}
    ]
}

MITRE_CATEGORIES = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Command and Control"]

def load_ttp_map(path):
    if not os.path.exists(path):
        return DEFAULT_TTP_MAP
    with open(path, 'r') as f:
        return json.load(f)

def generate_graphviz_matrix(ttp_map, output_path):
    dot = Digraph(comment='MITRE ATT&CK Matrix')
    for phase, ttps in ttp_map.items():
        for ttp in ttps:
            node_id = f"{ttp['id']}"
            dot.node(node_id, f"{ttp['id']}\n{ttp['name']}")
            for n in ttp.get("next", []):
                dot.edge(node_id, n)
    dot.render(output_path, format='svg', cleanup=True)

def generate_fallback_plot(ttp_map, output_path):
    fig, ax = plt.subplots(figsize=(15, 8))
    for i, cat in enumerate(MITRE_CATEGORIES):
        ttps = ttp_map.get(cat, [])
        for j, ttp in enumerate(ttps):
            label = f"{ttp['id']}\n{ttp['name']}"
            ax.text(i, -j, label, ha='center', va='center', fontsize=7, bbox=dict(boxstyle="round", facecolor='lightblue'))
    ax.set_xlim(-1, len(MITRE_CATEGORIES))
    ax.set_ylim(-10, 1)
    ax.set_xticks(range(len(MITRE_CATEGORIES)))
    ax.set_xticklabels(MITRE_CATEGORIES, rotation=45, ha='right')
    ax.axis('off')
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches='tight')
    plt.close()

def main():
    os.makedirs("results", exist_ok=True)
    ttp_data = load_ttp_map("input/ttp_map.json")
    try:
        generate_graphviz_matrix(ttp_data, "results/mitre_matrix")
        print("[+] SVG matrix created at results/mitre_matrix.svg")
    except Exception as e:
        print(f"[!] Graphviz failed: {e}\n[!] Falling back to Matplotlib rendering")
        generate_fallback_plot(ttp_data, "results/mitre_matrix_plot.png")
        print("[+] PNG matrix created at results/mitre_matrix_plot.png")

if __name__ == '__main__':
    main()
