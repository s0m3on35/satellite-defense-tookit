#!/usr/bin/env python3
# File: modules/intel/intel_timeline_builder.py

import os
import json
from glob import glob
from datetime import datetime

LOG_DIRS = ["logs/", "results/intel/"]
OUTPUT_FILE = "results/intel/intelligence_timeline.json"

def parse_timestamp(entry):
    ts = entry.get("timestamp") or entry.get("time") or entry.get("date")
    if isinstance(ts, (int, float)):
        return datetime.utcfromtimestamp(ts).isoformat() + "Z"
    elif isinstance(ts, str):
        return ts
    return "unknown"

def collect_events():
    events = []
    for folder in LOG_DIRS:
        for file_path in glob(os.path.join(folder, "*.json")):
            try:
                with open(file_path) as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        events.append({
                            "source": file_path,
                            "timestamp": parse_timestamp(data),
                            "summary": data.get("summary") or list(data.keys())
                        })
                    elif isinstance(data, list):
                        for item in data:
                            events.append({
                                "source": file_path,
                                "timestamp": parse_timestamp(item),
                                "summary": item.get("summary") or list(item.keys())
                            })
            except Exception as e:
                print(f"[!] Error reading {file_path}: {e}")
    return sorted(events, key=lambda x: x["timestamp"])

def save_timeline(events):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(events, f, indent=2)
    print(f"[+] Timeline saved to {OUTPUT_FILE} with {len(events)} entries.")

if __name__ == "__main__":
    print("[*] Building intelligence timeline...")
    timeline = collect_events()
    save_timeline(timeline)
