import json
import os
from datetime import datetime
import uuid

# === MITRE Tactics and Kill Chain Definitions ===
MITRE_KILL_CHAIN = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]

# === Demo TTP Match Fallback ===
DEMO_EVENTS = [
    {"id": "T1059", "technique": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control"},
    {"id": "T1046", "technique": "Network Service Scanning", "tactic": "Discovery"}
]

def load_ttp_matches(file_path="results/matched_ttp_events.json"):
    if not os.path.exists(file_path):
        os.makedirs("results", exist_ok=True)
        with open(file_path, "w") as f:
            json.dump(DEMO_EVENTS, f, indent=4)
    with open(file_path, "r") as f:
        return json.load(f)

def generate_kill_chain_map(ttps):
    killchain = {}
    for entry in ttps:
        tactic = entry.get("tactic", "Unknown")
        if tactic not in killchain:
            killchain[tactic] = []
        killchain[tactic].append(entry["id"])
    with open("results/mitre_killchain_map.json", "w") as f:
        json.dump(killchain, f, indent=4)

def generate_stix_bundle(ttps):
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": []
    }
    timestamp = datetime.utcnow().isoformat() + "Z"
    for entry in ttps:
        stix_obj = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--{entry['id']}",
            "created": timestamp,
            "modified": timestamp,
            "name": entry["technique"],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": entry["id"],
                    "url": f"https://attack.mitre.org/techniques/{entry['id']}/"
                }
            ]
        }
        bundle["objects"].append(stix_obj)
    with open("results/mitre_stix_bundle.json", "w") as f:
        json.dump(bundle, f, indent=4)

def generate_svg_matrix(ttps):
    svg_content = [
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
        '<svg xmlns="http://www.w3.org/2000/svg" width="1500" height="800">',
        '<style>text{font-size:12px;font-family:monospace;} rect{stroke:black;fill:white;} .hit{fill:red;}</style>'
    ]
    x_spacing, y_spacing = 110, 30
    for i, tactic in enumerate(MITRE_KILL_CHAIN):
        svg_content.append(f'<text x="{i*x_spacing+10}" y="20">{tactic}</text>')
        for j in range(10):  # max 10 TTPs per tactic (adjustable)
            y = j * y_spacing + 40
            rect_x = i * x_spacing
            rect_id = f"{rect_x}_{y}"
            svg_content.append(f'<rect id="rect_{rect_id}" x="{rect_x}" y="{y}" width="100" height="20"/>')

    # Highlight matched TTPs
    for entry in ttps:
        tactic = entry.get("tactic", "Unknown")
        if tactic in MITRE_KILL_CHAIN:
            col = MITRE_KILL_CHAIN.index(tactic)
            idx = ttps.index(entry)
            y = idx * y_spacing + 40
            x = col * x_spacing
            svg_content.append(f'<rect x="{x}" y="{y}" width="100" height="20" class="hit"/>')
            svg_content.append(f'<text x="{x+5}" y="{y+15}">{entry["id"]}</text>')

    svg_content.append('</svg>')
    with open("results/mitre_matrix.svg", "w") as f:
        f.write("\n".join(svg_content))

def main():
    print("[+] Loading TTP events...")
    ttp_data = load_ttp_matches()

    print("[+] Generating kill chain JSON map...")
    generate_kill_chain_map(ttp_data)

    print("[+] Generating STIX bundle...")
    generate_stix_bundle(ttp_data)

    print("[+] Generating MITRE matrix SVG...")
    generate_svg_matrix(ttp_data)

    print("[✓] MITRE mapping artifacts saved to `results/`")

if __name__ == "__main__":
    main()
