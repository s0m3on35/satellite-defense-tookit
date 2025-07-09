#!/usr/bin/env python3
# Ruta: modules/dashboard/yara_dashboard_streamer.py
# Descripción: Transmite resultados enriquecidos de YARA al dashboard vía WebSocket

import asyncio
import websockets
import json
import os
from datetime import datetime
import random
import logging

DATA_PATH = "results/yara_dashboard_enrichment.json"
WS_URI = "ws://localhost:8765"

# Logging setup
LOG_PATH = "logs/dashboard/yara_streamer.log"
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format='[%(asctime)s] %(message)s')

def create_mock_enrichment(path):
    """
    Genera datos de ejemplo si no existe archivo de enriquecimiento.
    """
    enrichment = {
        "rules_triggered": [
            {"rule": "Backdoor_TCP", "count": random.randint(1, 5), "severity": "high"},
            {"rule": "Malware_Generic", "count": random.randint(1, 3), "severity": "medium"},
            {"rule": "Custom_Sat_Threat", "count": random.randint(1, 2), "severity": "critical"}
        ],
        "timeline": [
            {"time": datetime.now().isoformat(), "alert": "Backdoor_TCP detected on segment A"},
            {"time": datetime.now().isoformat(), "alert": "Custom_Sat_Threat anomaly flagged"},
        ],
        "agent": "satellite-fw-001",
        "summary": "Multiple YARA rule matches during firmware inspection",
        "timestamp": datetime.now().isoformat(),
        "stix_ref": "results/stix_yara_bundle.json"
    }
    os.makedirs("results", exist_ok=True)
    with open(path, "w") as f:
        json.dump(enrichment, f, indent=4)
    return enrichment

def load_enrichment(path):
    """
    Carga los datos enriquecidos desde disco.
    """
    if not os.path.exists(path):
        return create_mock_enrichment(path)
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load enrichment: {e}")
        return {}

async def broadcast_to_dashboard(data):
    """
    Envía los datos al dashboard vía WebSocket.
    """
    try:
        async with websockets.connect(WS_URI, timeout=5) as websocket:
            payload = {
                "type": "yara_enrichment_update",
                "timestamp": datetime.utcnow().isoformat(),
                "source": "yara_mapper",
                "payload": data
            }
            await websocket.send(json.dumps(payload))
            logging.info(f"Sent enrichment payload to dashboard")

            try:
                ack = await asyncio.wait_for(websocket.recv(), timeout=3)
                logging.info(f"Acknowledged by dashboard: {ack}")
                print(f"[✓] Dashboard ACK: {ack}")
            except asyncio.TimeoutError:
                logging.warning("No ACK received from dashboard")
    except Exception as e:
        logging.error(f"[!] WebSocket error: {e}")
        print(f"[!] Failed to connect to dashboard: {e}")

def main():
    enrichment_data = load_enrichment(DATA_PATH)
    if enrichment_data:
        asyncio.run(broadcast_to_dashboard(enrichment_data))
    else:
        print("[!] No enrichment data available to send.")

if __name__ == "__main__":
    main()
