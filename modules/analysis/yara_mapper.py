import os
import json
import matplotlib.pyplot as plt
from datetime import datetime

# === Mock YARA Hits for Demo ===
yara_hits = [
    {"packet_index": 10, "rule": "ReverseShell", "tags": [], "meta": {}},
    {"packet_index": 45, "rule": "TelnetCredLeak", "tags": [], "meta": {}},
    {"packet_index": 77, "rule": "ReverseShell", "tags": [], "meta": {}},
]

# === Step 1: Auto-chain to firmware_stix_export compatible JSON ===
auto_chain_output = {
    "alerts": [
        {
            "timestamp": datetime.now().isoformat(),
            "rule": hit["rule"],
            "packet_index": hit["packet_index"],
            "alert_type": "YARA_MATCH"
        } for hit in yara_hits
    ]
}
os.makedirs("results", exist_ok=True)
with open("results/firmware_yara_autochain.json", "w") as f:
    json.dump(auto_chain_output, f, indent=4)

# === Step 2: Graphical Anomaly Timeline (color-coded) ===
packet_indices = list(range(100))
values = [0] * 100
for hit in yara_hits:
    values[hit["packet_index"]] = 1 if hit["rule"] == "ReverseShell" else 2

colors = ['green' if v == 0 else 'red' if v == 1 else 'blue' for v in values]
plt.figure(figsize=(12, 2))
plt.bar(packet_indices, [1]*100, color=colors)
plt.title("YARA Match Timeline (Red=ReverseShell, Blue=TelnetCredLeak)")
plt.xlabel("Packet Index")
plt.yticks([])
plt.tight_layout()
plt.savefig("results/yara_timeline.png")
plt.close()

# === Step 3: Dashboard Enrichment Data ===
dashboard_enrichment = {}
for hit in yara_hits:
    dashboard_enrichment[hit["rule"]] = dashboard_enrichment.get(hit["rule"], 0) + 1

with open("results/yara_dashboard_enrichment.json", "w") as f:
    json.dump(dashboard_enrichment, f, indent=4)
