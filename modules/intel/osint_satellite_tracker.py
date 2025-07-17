#!/usr/bin/env python3
# File: modules/intel/osint_satellite_tracker.py

import requests
import json
import time
import os

NORAD_IDS = [25544, 39444, 33591]  # Example: ISS, Sentinel, Starlink
OUTPUT_FILE = "results/intel/satellite_tracking.json"
BASE_URL = "https://api.n2yo.com/rest/v1/satellite/positions"
API_KEY = "DEMO_KEY"  # Replace with your real N2YO key

LAT, LON, ALT = 40.4, -3.7, 0  # Example location (Madrid)
SECONDS = 300

def track_satellite(norad_id):
    url = f"{BASE_URL}/{norad_id}/{LAT}/{LON}/{ALT}/{SECONDS}/&apiKey={API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Failed to fetch satellite {norad_id}"}

def save_results(data):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved satellite tracking data to {OUTPUT_FILE}")

if __name__ == "__main__":
    print("[*] Querying satellites via OSINT...")
    results = {"timestamp": time.time(), "results": {}}
    for nid in NORAD_IDS:
        print(f"  ↳ Tracking NORAD ID: {nid}")
        results["results"][str(nid)] = track_satellite(nid)
    save_results(results)
