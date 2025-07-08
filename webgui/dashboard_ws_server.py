# Ruta: webgui/dashboard_ws_server.py
# Descripción: Servidor WebSocket centralizado para la interfaz en tiempo real del dashboard / Satellite Defense Toolkit

import asyncio
import websockets
import json
import os
from datetime import datetime
import logging

LOG_DIR = "logs/dashboard"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "dashboard_stream.log")
STIX_FILE = "results/stix_yara_bundle.json"

connected_clients = set()

# Configura logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
)

async def log_handler(message):
    try:
        data = json.loads(message)
        timestamp = datetime.utcnow().isoformat()
        msg_type = data.get("type", "event")
        log_entry = f"[{timestamp}] {msg_type}: {data.get('message', '')}"
        logging.info(log_entry)
        print(log_entry)
        return data
    except json.JSONDecodeError:
        logging.warning(f"Invalid JSON message received: {message}")
        return None

async def stix_stream_broadcast():
    last_sent = None
    while True:
        try:
            if os.path.exists(STIX_FILE):
                with open(STIX_FILE, "r") as f:
                    stix_data = json.load(f)
                    stix_json = json.dumps({"type": "stix", "data": stix_data})
                    if stix_json != last_sent:
                        await broadcast_to_all(stix_json)
                        last_sent = stix_json
        except Exception as e:
            logging.error(f"[STIX STREAM] Error reading STIX file: {e}")
        await asyncio.sleep(5)

async def broadcast_to_all(message):
    disconnected = set()
    for client in connected_clients:
        try:
            await client.send(message)
        except websockets.exceptions.ConnectionClosed:
            disconnected.add(client)
    connected_clients.difference_update(disconnected)

async def handler(websocket, path):
    connected_clients.add(websocket)
    logging.info(f"[+] New WebSocket client connected: {websocket.remote_address}")
    try:
        async for message in websocket:
            data = await log_handler(message)
            if data:
                msg_out = json.dumps(data)
                await broadcast_to_all(msg_out)
    except websockets.exceptions.ConnectionClosed as e:
        logging.info(f"[-] Client disconnected: {websocket.remote_address}")
    finally:
        connected_clients.discard(websocket)

async def main():
    print("🛰️  [WS Server] Satellite Toolkit Dashboard WebSocket Server running at ws://0.0.0.0:8765")
    server = await websockets.serve(handler, "0.0.0.0", 8765)
    await asyncio.gather(server.wait_closed(), stix_stream_broadcast())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[!] Shutdown signal received. Closing WebSocket server...")
