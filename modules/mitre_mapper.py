import json
import os
from datetime import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# === Embedded Local MITRE DB Fallback ===
DEFAULT_MITRE_DB = [
    {"tactic": "Initial Access", "technique": "Phishing", "id": "T1566"},
    {"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059"},
    {"tactic": "Persistence", "technique": "Boot or Logon Autostart Execution", "id": "T1547"},
    {"tactic": "Privilege Escalation", "technique": "Process Injection", "id": "T1055"},
    {"tactic": "Defense Evasion", "technique": "Obfuscated Files or Information", "id": "T1027"},
    {"tactic": "Credential Access", "technique": "Credential Dumping", "id": "T1003"},
    {"tactic": "Discovery", "technique": "System Information Discovery", "id": "T1082"},
    {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"},
    {"tactic": "Collection", "technique": "Data from Local System", "id": "T1005"},
    {"tactic": "Exfiltration", "technique": "Exfiltration Over C2 Channel", "id": "T1041"},
    {"tactic": "Command and Control", "technique": "Application Layer Protocol", "id": "T1071"}
]

# === Load MITRE DB or fallback ===
def load_mitre_db(path="data/local_mitre_db.json"):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return DEFAULT_MITRE_DB

# === Parse input detections ===
def load_detections(path="results/telemetry_anomalies.json"):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        data = json.load(f)
        return [entry.get("description", "T1059") for entry in data]  # fallback TTP

# === Build matrix ===
def build_matrix(mitre_db, matches):
    matrix = defaultdict(list)
    for entry in mitre_db:
        tech = entry["technique"]
        tactic = entry["tactic"]
        tid = entry["id"]
        color = "red" if tid in matches else "gray"
        matrix[tactic].append((tech, tid, color))
    return matrix

# === Plot MITRE SVG Matrix ===
def plot_svg(matrix, output="results/mitre_matrix.svg"):
    os.makedirs("results", exist_ok=True)
    tactics = list(matrix.keys())
    fig, ax = plt.subplots(figsize=(len(tactics) * 2, 6))

    for col, tactic in enumerate(tactics):
        ax.text(col + 0.5, len(matrix[tactic]) + 0.5, tactic, ha='center', va='bottom', fontsize=10, weight='bold')
        for row, (tech, tid, color) in enumerate(matrix[tactic]):
            rect = mpatches.Rectangle((col, len(matrix[tactic]) - row - 1), 1, 1, edgecolor='black', facecolor=color)
            ax.add_patch(rect)
            ax.text(col + 0.5, len(matrix[tactic]) - row - 0.5, tech, ha='center', va='center', fontsize=6)

    ax.set_xlim(0, len(tactics))
    ax.set_ylim(0, max(len(v) for v in matrix.values()))
    ax.axis('off')
    plt.title("MITRE ATT&CK Matrix Mapping", fontsize=12)
    plt.tight_layout()
    plt.savefig(output, format='svg')
    plt.close()

# === Main Function ===
def main():
    mitre_db = load_mitre_db()
    detections = load_detections()
    matched_ids = set(detections)
    matrix = build_matrix(mitre_db, matched_ids)
    plot_svg(matrix)
    print(f"[+] MITRE Matrix SVG saved to results/mitre_matrix.svg")

if __name__ == "__main__":
    main()
