# modules/threat/stix_threat_matcher.py

import os
import json
from datetime import datetime
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Server

TAXII_SERVER = "https://cti-taxii.mitre.org/taxii/"
COLLECTION_NAME = "enterprise-attack"
OBSERVED_FILE = "observables/observed_tactics.json"
ALERT_FILE = "webgui/alerts.json"
MATCHED_OUTPUT = "threat_feeds/matched_attack_patterns.json"
AGENT_ID = "stix_threat_matcher"

def log(msg):
    print(f"[STIX] {msg}")

def fetch_attack_patterns():
    server = Server(TAXII_SERVER)
    api_root = server.api_roots[0]
    collection = api_root.collections[0]  # Usually enterprise-attack
    source = TAXIICollectionSource(collection)

    patterns = source.query([Filter("type", "=", "attack-pattern")])
    return patterns

def load_observed_tactics():
    if not os.path.exists(OBSERVED_FILE):
        return []
    with open(OBSERVED_FILE) as f:
        return json.load(f)

def match_patterns(patterns, observed):
    matched = []
    for p in patterns:
        tactic = getattr(p, "name", "").lower()
        for obs in observed:
            if obs.lower() in tactic:
                matched.append({
                    "id": getattr(p, "id", ""),
                    "name": tactic,
                    "description": getattr(p, "description", ""),
                    "created": getattr(p, "created", ""),
                    "external_references": getattr(p, "external_references", [])
                })
    return matched

def push_alert(matched):
    alert = {
        "agent": AGENT_ID,
        "alert": f"{len(matched)} STIX TTPs matched",
        "type": "threat-intel",
        "timestamp": datetime.now().timestamp(),
        "details": [m['name'] for m in matched]
    }
    os.makedirs("webgui", exist_ok=True)
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

def main():
    log("Fetching STIX attack patterns...")
    patterns = fetch_attack_patterns()

    log("Loading observed tactics...")
    observed = load_observed_tactics()

    log("Matching patterns...")
    matched = match_patterns(patterns, observed)

    if matched:
        log(f"{len(matched)} patterns matched.")
        os.makedirs("threat_feeds", exist_ok=True)
        with open(MATCHED_OUTPUT, "w") as f:
            json.dump(matched, f, indent=2)
        push_alert(matched)
    else:
        log("No matching STIX patterns found.")

if __name__ == "__main__":
    main()
