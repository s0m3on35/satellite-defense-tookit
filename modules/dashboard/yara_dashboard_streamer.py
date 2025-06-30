# m

import asyncio
import websockets
import json
import os
from datetime import datetime
import random

DATA_PATH = "results/yara_dashboard_enrichment.json"
WS_URI = "ws://localhost:8765"

# === Create mock enrichment data if it doesn't exist ===
def create_mock_enrichment(path):
    enrichment = {
        "rules_triggered": [
            {"rule": "Backdoor_TCP", "count": random.randint(1, 5), "color": "red"},
            {"rule": "Malware_Generic", "count": random.randint(1, 3), "color": "orange"},
            {"rule": "Custom_Sat_Threat", "count": random.randint(1, 2), "color": "yellow"}
        ],
        "timeline": [
            {"time": datetime.now().isoformat(), "alert": "Backdoor_TCP detected"},
            {"time": datetime.now().isoformat(), "alert": "Custom_Sat_Threat anomaly"},
        ],
        "agent": "satellite-fw-001",
        "summary": "Multiple YARA alerts detected during firmware scan",
        "timestamp": datetime.now().isoformat()
    }
    os.makedirs("results", exist_ok=True)
    with open(path, "w") as f:
        json.dump(enrichment, f, indent=4)
    return enrichment

# === WebSocket broadcast ===
async def broadcast_to_dashboard(data):
    async with websockets.connect(WS_URI) as websocket:
        message = {
            "type": "yara_enrichment_update",
            "timestamp": datetime.now().isoformat(),
            "source": "yara_mapper",
            "payload": data
        }
        await websocket.send(json.dumps(message))
        try:
            ack = await websocket.recv()
            print("Dashboard acknowledged:", ack)
        except:
            print("No response from dashboard.")

# === Main ===
def main():
    if not os.path.exists(DATA_PATH):
        enrichment_data = create_mock_enrichment(DATA_PATH)
    else:
        with open(DATA_PATH) as f:
            enrichment_data = json.load(f)
    asyncio.run(broadcast_to_dashboard(enrichment_data))

if __name__ == "__main__":
    main()
