import os
import json
import yaml
import time
import logging
import requests
import websocket
import argparse
from datetime import datetime
from stix2 import parse, Bundle

# === Setup ===
def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def setup_logging(log_path):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.getLogger().addHandler(logging.StreamHandler())

def register_agent(agent_id):
    os.makedirs("webgui", exist_ok=True)
    inventory_file = "webgui/agents.json"
    if not os.path.exists(inventory_file):
        with open(inventory_file, "w") as f:
            json.dump([], f)
    with open(inventory_file, "r+") as f:
        agents = json.load(f)
        if agent_id not in [a["agent"] for a in agents]:
            agents.append({"agent": agent_id, "registered": time.time()})
            f.seek(0)
            json.dump(agents, f, indent=2)

# === STIX/TAXII ===
def fetch_stix_feed(url):
    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            return parse(resp.text)
    except Exception as e:
        logging.error(f"Error fetching STIX feed: {e}")
    return None

def match_ttp_patterns(stix_bundle, patterns):
    matches = []
    for obj in stix_bundle.objects:
        for keyword in patterns:
            if keyword.lower() in str(obj).lower():
                matches.append({
                    "id": obj.get("id", "unknown"),
                    "type": obj.get("type", "unknown"),
                    "matched": keyword,
                    "description": str(obj)
                })
    return matches

def enrich_with_mitre(matches):
    enriched = []
    for match in matches:
        if "attack-pattern" in match["type"]:
            ttp_id = match["id"]
            match["mitre_ttp"] = ttp_id
        enriched.append(match)
    return enriched

def push_websocket_alert(matches, ws_url, agent_id):
    try:
        ws = websocket.create_connection(ws_url)
        payload = {
            "agent": agent_id,
            "type": "threat_feed",
            "timestamp": time.time(),
            "matches": matches
        }
        ws.send(json.dumps(payload))
        ws.close()
    except Exception as e:
        logging.error(f"WebSocket push failed: {e}")

def generate_visual_report(matches):
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"results/feed_alert_{timestamp}.json", "w") as f:
        json.dump(matches, f, indent=2)

# === Main ===
def main(args):
    config = load_config(args.config)
    setup_logging(args.log)
    agent_id = "threat_feed_watcher"
    register_agent(agent_id)

    stix_url = config["taxii_feed"]
    patterns = config["match_keywords"]
    ws_url = config.get("websocket_url", "ws://localhost:8765")

    logging.info("Fetching STIX feed...")
    bundle = fetch_stix_feed(stix_url)
    if not bundle:
        logging.error("No STIX data fetched")
        exit(1)

    logging.info("Analyzing feed for threat patterns...")
    matches = match_ttp_patterns(bundle, patterns)
    if matches:
        matches = enrich_with_mitre(matches)
        generate_visual_report(matches)
        push_websocket_alert(matches, ws_url, agent_id)
        logging.info(f"{len(matches)} threat indicators matched and pushed.")
        exit(42)  # Exit code for CI/CD alert trigger
    else:
        logging.info("No threat matches found.")
        exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="STIX/TAXII Threat Feed Watcher")
    parser.add_argument("--config", default="config/feed_config.yaml", help="YAML config path")
    parser.add_argument("--log", default="logs/threat_feed.log", help="Log file path")
    args = parser.parse_args()
    main(args)
