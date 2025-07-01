# WebSocket Log Server for Satellite Defense Toolkit Dashboard

import asyncio
import websockets
import json
import os
from datetime import datetime

LOG_DIR = "logs/dashboard"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "dashboard_stream.log")

connected_clients = set()

async def handler(websocket):
    connected_clients.add(websocket)
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                timestamp = datetime.utcnow().isoformat()
                log_entry = f"[{timestamp}] {data.get('type', 'event')}: {data.get('message', '')}\n"
                with open(LOG_FILE, "a") as f:
                    f.write(log_entry)
                print(log_entry.strip())

                for client in connected_clients:
                    if client != websocket:
                        await client.send(message)

            except json.JSONDecodeError:
                continue
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        connected_clients.remove(websocket)

async def main():
    print("[✓] Dashboard WebSocket Log Server started on ws://0.0.0.0:8765")
    async with websockets.serve(handler, "0.0.0.0", 8765):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[!] Server shutdown requested.")
