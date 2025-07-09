# modules/mitre_mapper.py
import json
import os
from datetime import datetime
from collections import defaultdict
from xml.etree.ElementTree import Element, SubElement, ElementTree
import requests

# === Config ===
MITRE_DB_PATH = "results/local_mitre_db.json"
KILLCHAIN_OUTPUT = "results/mitre_killchain_map.json"
SVG_MATRIX_OUTPUT = "results/mitre_matrix.svg"
WEBHOOK_URL = "http://localhost:5000/webhook"  # change as needed

# === Sample TTP mapping DB auto-generator ===
def generate_default_mitre_db():
    default_data = [
        {"id": "T1003", "name": "Credential Dumping", "phase": "Credential Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "phase": "Execution"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "phase": "Initial Access"},
        {"id": "T1021", "name": "Remote Services", "phase": "Lateral Movement"},
        {"id": "T1486", "name": "Data Encrypted for Impact", "phase": "Impact"},
        {"id": "T1046", "name": "Network Service Scanning", "phase": "Discovery"}
    ]
    os.makedirs("results", exist_ok=True)
    with open(MITRE_DB_PATH, "w") as f:
        json.dump(default_data, f, indent=4)

# === Load TTP Observations ===
def load_mitre_db():
    if not os.path.exists(MITRE_DB_PATH):
        generate_default_mitre_db()
    with open(MITRE_DB_PATH) as f:
        return json.load(f)

# === Generate Kill Chain Map ===
def generate_kill_chain_map(ttps):
    killchain_map = defaultdict(list)
    for ttp in ttps:
        phase = ttp.get("phase", "Unknown")
        killchain_map[phase].append({
            "id": ttp["id"],
            "name": ttp["name"]
        })
    with open(KILLCHAIN_OUTPUT, "w") as f:
        json.dump(killchain_map, f, indent=4)
    return killchain_map

# === SVG Matrix ===
def generate_svg_matrix(killchain_map, output_path):
    svg = Element('svg', width='900', height='500', xmlns='http://www.w3.org/2000/svg')
    y_offset = 40
    for idx, (phase, ttps) in enumerate(killchain_map.items()):
        SubElement(svg, 'text', x='20', y=str(y_offset), fill='black').text = phase
        for jdx, ttp in enumerate(ttps):
            box_y = y_offset + jdx * 30
            SubElement(svg, 'rect', x='150', y=str(box_y), width='250', height='25', fill='lightgray')
            SubElement(svg, 'text', x='155', y=str(box_y + 18), fill='black').text = f"{ttp['id']} - {ttp['name']}"
        y_offset += max(len(ttps), 1) * 30 + 20
    ElementTree(svg).write(output_path)

# === Webhook Alert ===
def send_webhook_alert(ttps):
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "alert_type": "MITRE_TTP_SPIKE",
        "matched_ttps": ttps
    }
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=3)
    except Exception as e:
        print(f"[!] Webhook failed: {e}")

# === WebSocket Trigger (requires ws dashboard server to listen for file changes) ===
def touch_results_file_for_ws_trigger():
    with open("results/trigger_mitre_event.txt", "w") as f:
        f.write(datetime.utcnow().isoformat())

# === Main ===
def main():
    ttps = load_mitre_db()
    killchain_map = generate_kill_chain_map(ttps)
    generate_svg_matrix(killchain_map, SVG_MATRIX_OUTPUT)
    send_webhook_alert(ttps)
    touch_results_file_for_ws_trigger()
    print(f"[✓] Matrix generated at {SVG_MATRIX_OUTPUT}")
    print(f"[✓] Kill chain map saved to {KILLCHAIN_OUTPUT}")
    print("[✓] Alerts dispatched")

if __name__ == "__main__":
    main()
