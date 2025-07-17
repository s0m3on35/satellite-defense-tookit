#!/usr/bin/env python3
# File: modules/intel/threat_actor_mapper.py

import os
import json
import requests
import re
from datetime import datetime
from collections import defaultdict

MITRE_TTP_DB = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
LOCAL_OBS_FILE = "results/intel/observables.json"
OUTPUT_FILE = "results/intel/threat_actor_matches.json"

def load_mitre_ttp_data():
    print("[*] Downloading MITRE ATT&CK dataset...")
    response = requests.get(MITRE_TTP_DB)
    response.raise_for_status()
    attack_data = response.json()
    techniques = {}
    for obj in attack_data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            techniques[obj["id"]] = {
                "name": obj.get("name"),
                "description": obj.get("description", ""),
                "external_references": obj.get("external_references", []),
                "kill_chain_phases": obj.get("kill_chain_phases", []),
                "x_mitre_detection": obj.get("x_mitre_detection", "")
            }
    return techniques

def load_observables():
    print("[*] Loading local observables...")
    if not os.path.exists(LOCAL_OBS_FILE):
        print(f"[!] Observables file not found: {LOCAL_OBS_FILE}")
        return []
    with open(LOCAL_OBS_FILE, 'r') as f:
        return json.load(f)

def match_techniques(observables, techniques):
    print("[*] Matching observables to MITRE techniques...")
    matches = defaultdict(list)
    for obs in observables:
        obs_str = json.dumps(obs).lower()
        for tech_id, tech in techniques.items():
            combined = (tech["name"] + " " + tech["description"]).lower()
            if any(keyword in obs_str for keyword in [tech["name"].lower()] + re.findall(r"\b\w+\b", tech["description"].lower())):
                matches[tech_id].append({
                    "technique": tech["name"],
                    "matched_observable": obs
                })
    return matches

def export_matches(matches):
    print(f"[*] Exporting results to {OUTPUT_FILE}...")
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "matches": dict(matches)
    }
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    print("[+] Threat actor mapping complete.")

if __name__ == "__main__":
    techniques = load_mitre_ttp_data()
    observables = load_observables()
    matches = match_techniques(observables, techniques)
    export_matches(matches)
