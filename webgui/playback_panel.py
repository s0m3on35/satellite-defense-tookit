#!/usr/bin/env python3
# Route: webgui/playback_panel.py
# Description: Enhanced playback of historical events to the Satellite Defense Toolkit dashboard WebSocket

import asyncio
import websockets
import json
import os
import argparse
from datetime import datetime

LOG_FILE = "logs/dashboard/dashboard_stream.log"
DEFAULT_WS_URI = "ws://localhost:8765"

def parse_log_line(line):
    """
    Parses a log line into a structured event dictionary.
    Supports: [timestamp] type [id]: message
    """
    try:
        if not line.strip().startswith("["):
            return None
        timestamp_part = line.split("]")[0].lstrip("[")
        rest = "]".join(line.split("]")[1:]).strip()
        if ": " in rest:
            event_type, message = rest.split(": ", 1)
        else:
            event_type, message = "log", rest
        return {
            "timestamp": timestamp_part,
            "type": event_type.strip().lower(),
            "message": message.strip()
        }
    except Exception as e:
        print(f"[!] Parse error: {e}")
        return None

def filter_events(lines, type_filter=None, keyword=None, since=None):
    """
    Applies optional filters to raw log lines.
    """
    results = []
    for line in lines:
        event = parse_log_line(line)
        if not event:
            continue
        if type_filter and event["type"] != type_filter:
            continue
        if keyword and keyword.lower() not in event["message"].lower():
            continue
        if since:
            try:
                event_dt = datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%S")
                if event_dt < since:
                    continue
            except:
                continue
        results.append(event)
    return results

async def replay_events(ws_uri, events, delay=0.5, dry_run=False):
    """
    Sends events to the specified WebSocket server with delay between each.
    """
    if dry_run:
        print("[*] Dry-run mode: printing events without sending")
        for event in events:
            print(f"[DRY] {event['timestamp']} | {event['type']} | {event['message']}")
            await asyncio.sleep(delay)
        return

    try:
        async with websockets.connect(ws_uri) as ws:
            print(f"[+] Connected to {ws_uri}")
            for event in events:
                await ws.send(json.dumps(event))
                print(f"[→] Sent: {event['type']} - {event['message']}")
                await asyncio.sleep(delay)
    except Exception as e:
        print(f"[!] WebSocket error: {e}")

def parse_args():
    parser = argparse.ArgumentParser(description="Replay historical logs to WebSocket dashboard")
    parser.add_argument("--target", default=DEFAULT_WS_URI, help="WebSocket target URI")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between events (in seconds)")
    parser.add_argument("--limit", type=int, help="Maximum number of events to replay")
    parser.add_argument("--type", help="Filter by event type (e.g., alert, telemetry)")
    parser.add_argument("--keyword", help="Only include events containing this keyword")
    parser.add_argument("--since", help="Only include logs after this timestamp (YYYY-MM-DDTHH:MM:SS)")
    parser.add_argument("--dry", action="store_true", help="Dry-run mode (print events, don't send)")
    return parser.parse_args()

def main():
    args = parse_args()
    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file not found: {LOG_FILE}")
        return

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    since_dt = None
    if args.since:
        try:
            since_dt = datetime.strptime(args.since, "%Y-%m-%dT%H:%M:%S")
        except:
            print("[!] Invalid --since format. Use YYYY-MM-DDTHH:MM:SS")

    events = filter_events(
        lines,
        type_filter=args.type,
        keyword=args.keyword,
        since=since_dt
    )

    if args.limit:
        events = events[:args.limit]

    if not events:
        print("[!] No matching events found.")
        return

    asyncio.run(replay_events(args.target, events, args.delay, dry_run=args.dry))

if __name__ == "__main__":
    main()
