#!/usr/bin/env python3
# Ruta: webgui/dashboard_ws_server.py

import asyncio
import websockets
import json
import os
from datetime import datetime
import logging
import hashlib

LOG_DIR = "logs/dashboard"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "dashboard_stream.log")
STIX_FILE = "results/stix_yara_bundle.json"
FORENSIC_LOG = "results/forensics_report.json"
TELEMETRY_LOG = "results/telemetry_feed.json"

AUTH_TOKEN = os.environ.get("SATDEF_WS_TOKEN", None)

connected_clients = set()

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
)

def utc_timestamp():
    return datetime.utcnow().isoformat() + "Z"

async def log_handler(message, client=None):
    try:
        data = json.loads(message)
        msg_type = data.get("type", "event")
        content = data.get("message", "")
        event_id = hashlib.sha256((msg_type + content + utc_timestamp()).encode()).hexdigest()[:10]
        log_entry = f"[{utc_timestamp()}] {msg_type} [{event_id}]: {content}"
        logging.info(log_entry)
        print(log_entry)
        data["timestamp"] = utc_timestamp()
        data["id"] = event_id
        return data
    except json.JSONDecodeError:
        logging.warning(f"Invalid JSON received from {client}: {message}")
        return None

async def broadcast_json_from_file(filepath, datatype, interval=5):
    last_sent = None
    while True:
        try:
            if os.path.exists(filepath):
                with open(filepath, "r") as f:
                    data = json.load(f)
                    msg = json.dumps({"type": datatype, "timestamp": utc_timestamp(), "data": data})
                    if msg != last_sent:
                        await broadcast_to_all(msg)
                        last_sent = msg
        except Exception as e:
            logging.error(f"[{datatype.upper()} STREAM] Error: {e}")
        await asyncio.sleep(interval)

async def broadcast_to_all(message):
    disconnected = set()
    for client in connected_clients:
        try:
            await client.send(message)
        except websockets.exceptions.ConnectionClosed:
            disconnected.add(client)
    connected_clients.difference_update(disconnected)

async def handler(websocket, path):
    logging.info(f"[+] Connection attempt from: {websocket.remote_address}")
    if AUTH_TOKEN:
        try:
            auth_msg = await asyncio.wait_for(websocket.recv(), timeout=5)
            auth_data = json.loads(auth_msg)
            if auth_data.get("auth") != AUTH_TOKEN:
                await websocket.send(json.dumps({"error": "unauthorized"}))
                await websocket.close()
                logging.warning(f"[!] Unauthorized client rejected: {websocket.remote_address}")
                return
        except:
            await websocket.close()
            logging.warning(f"[!] Authentication failed for: {websocket.remote_address}")
            return

    connected_clients.add(websocket)
    logging.info(f"[✓] WebSocket client connected: {websocket.remote_address}")
    try:
        async for message in websocket:
            data = await log_handler(message, websocket.remote_address)
            if data:
                await broadcast_to_all(json.dumps(data))
    except websockets.exceptions.ConnectionClosed:
        logging.info(f"[-] Client disconnected: {websocket.remote_address}")
    finally:
        connected_clients.discard(websocket)

async def main():
    print("[WS Server] Satellite Toolkit Dashboard WebSocket Server running at ws://0.0.0.0:8765")
    server = await websockets.serve(handler, "0.0.0.0", 8765)
    await asyncio.gather(
        server.wait_closed(),
        broadcast_json_from_file(STIX_FILE, "stix"),
        broadcast_json_from_file(FORENSIC_LOG, "forensics"),
        broadcast_json_from_file(TELEMETRY_LOG, "telemetry")
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[!] Shutdown signal received. Closing WebSocket server...")
