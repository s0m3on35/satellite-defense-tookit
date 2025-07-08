# WebSocket LServer 

import asyncio
import websockets
import json
import os
from datetime import datetime

LOG_DIR = "logs/dashboard"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "dashboard_stream.log")
STIX_FILE = "results/stix_yara_bundle.json"

connected_clients = set()

async def log_handler(message):
    try:
        data = json.loads(message)
        timestamp = datetime.utcnow().isoformat()
        msg_type = data.get("type", "event")
        log_entry = f"[{timestamp}] {msg_type}: {data.get('message', '')}\n"

        with open(LOG_FILE, "a") as f:
            f.write(log_entry)

        print(log_entry.strip())
        return data
    except json.JSONDecodeError:
        return None

async def stix_stream_broadcast():
    last_sent = None
    while True:
        if os.path.exists(STIX_FILE):
            with open(STIX_FILE, "r") as f:
                try:
                    stix_data = json.load(f)
                    stix_json = json.dumps({"type": "stix", "data": stix_data})
                    if stix_json != last_sent:
                        for client in connected_clients:
                            await client.send(stix_json)
                        last_sent = stix_json
                except json.JSONDecodeError:
                    pass
        await asyncio.sleep(5)

async def handler(websocket):
    connected_clients.add(websocket)
    try:
        async for message in websocket:
            data = await log_handler(message)
            if data:
                for client in connected_clients:
                    if client != websocket:
                        await client.send(json.dumps(data))
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        connected_clients.remove(websocket)

async def main():
    print("Unified Dashboard WebSocket Server started on ws://0.0.0.0:8765")
    server = await websockets.serve(handler, "0.0.0.0", 8765)
    await asyncio.gather(server.wait_closed(), stix_stream_broadcast())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[!] Server shutdown requested.")
