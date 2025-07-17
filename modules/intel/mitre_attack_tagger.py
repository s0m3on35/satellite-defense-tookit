#!/usr/bin/env python3
# File: modules/intel/mitre_attack_tagger.py

import json
import os
import re
from uuid import uuid4
from datetime import datetime

INPUT_FILE = "results/intel/local_stix_bundle.json"
OUTPUT_FILE = "results/intel/mitre_tagged_bundle.json"

MITRE_MAP = {
    "dns exfiltration": "T1048.003",
    "command and control": "T1071",
    "keylogging": "T1056.001",
    "persistence": "T1547",
    "credential access": "T1003",
    "screenshot": "T1113",
    "remote access": "T1021",
    "lateral movement": "T1080",
    "code injection": "T1055",
    "bluetooth": "T1420",
    "firmware": "T1542.002",
    "telemetry": "T1020"
}

def load_stix():
    with open(INPUT_FILE, "r") as f:
        return json.load(f)

def tag_objects(objects):
    for obj in objects:
        text = json.dumps(obj).lower()
        techniques = []
        for k, tid in MITRE_MAP.items():
            if re.search(rf"\b{k}\b", text):
                techniques.append(tid)
        if techniques:
            obj["external_references"] = obj.get("external_references", [])
            for tid in techniques:
                obj["external_references"].append({
                    "source_name": "mitre-attack",
                    "external_id": tid,
                    "url": f"https://attack.mitre.org/techniques/{tid}/"
                })
    return objects

def save_bundle(objs):
    tagged_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "objects": objs,
        "created": datetime.utcnow().isoformat() + "Z"
    }
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(tagged_bundle, f, indent=2)
    print(f"[+] Saved MITRE-tagged STIX bundle to: {OUTPUT_FILE}")

if __name__ == "__main__":
    print("[*] Tagging with MITRE ATT&CK techniques...")
    stix = load_stix()
    objs = tag_objects(stix["objects"])
    save_bundle(objs)
