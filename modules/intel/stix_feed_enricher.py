#!/usr/bin/env python3
# File: modules/intel/stix_feed_enricher.py

import json
import os
import requests
from datetime import datetime
from uuid import uuid4

LOCAL_STIX_FILE = "results/intel/local_stix_bundle.json"
ENRICHED_FILE = "results/intel/enriched_stix_bundle.json"
MISP_FEED_URL = "https://www.circl.lu/doc/misp/feed-osint/full.json"  # Replace with your own or OpenCTI feed

def load_local_stix():
    if not os.path.exists(LOCAL_STIX_FILE):
        raise FileNotFoundError(f"Local STIX bundle not found: {LOCAL_STIX_FILE}")
    with open(LOCAL_STIX_FILE, "r") as f:
        return json.load(f)

def fetch_feed():
    print("[*] Downloading external STIX/OSINT feed...")
    r = requests.get(MISP_FEED_URL, timeout=30)
    r.raise_for_status()
    return r.json()

def enrich_bundle(local_stix, feed_data):
    print("[*] Enriching local bundle with external observables...")
    known_indicators = {i["id"]: i for i in local_stix.get("objects", []) if i["type"] == "indicator"}
    enriched_objects = local_stix["objects"].copy()

    for entry in feed_data.get("objects", []):
        if entry.get("type") == "indicator" and entry.get("pattern") not in [i.get("pattern") for i in known_indicators.values()]:
            entry["id"] = f"indicator--{uuid4()}"
            entry["created_by_ref"] = "identity--toolkit-auto-enricher"
            entry["labels"] = entry.get("labels", []) + ["external-feed"]
            entry["external_references"] = [{"source_name": "MISP Feed", "url": MISP_FEED_URL}]
            entry["created"] = datetime.utcnow().isoformat() + "Z"
            enriched_objects.append(entry)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "objects": enriched_objects
    }

def save_enriched_bundle(bundle):
    os.makedirs(os.path.dirname(ENRICHED_FILE), exist_ok=True)
    with open(ENRICHED_FILE, "w") as f:
        json.dump(bundle, f, indent=2)
    print(f"[+] Enriched STIX bundle saved to: {ENRICHED_FILE}")

if __name__ == "__main__":
    local_bundle = load_local_stix()
    feed_bundle = fetch_feed()
    enriched = enrich_bundle(local_bundle, feed_bundle)
    save_enriched_bundle(enriched)
