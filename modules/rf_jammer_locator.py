import argparse
import logging
import os
import numpy as np
import subprocess
import json
import yaml
import websockets
import asyncio
from datetime import datetime
import folium

AGENT_ID = "rf_jammer_locator"
AGENTS_FILE = "webgui/agents.json"
ALERT_FILE = "webgui/alerts.json"
PCAP_OUTPUT = "results/jammer_capture.pcap"
GEOJSON_FILE = "results/jammer_overlay.geojson"
MAP_HTML = "results/jammer_map.html"

def load_config(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def setup_logging(log_file):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

def get_gps_location():
    return {"lat": 43.3623, "lon": -8.4115}

def auto_register_agent(location):
    os.makedirs(os.path.dirname(AGENTS_FILE), exist_ok=True)
    agent_info = {
        "id": AGENT_ID,
        "type": "rf_scan",
        "location": location,
        "timestamp": datetime.utcnow().isoformat()
    }
    if not os.path.exists(AGENTS_FILE):
        with open(AGENTS_FILE, "w") as f:
            json.dump([agent_info], f, indent=4)
    else:
        with open(AGENTS_FILE, "r+") as f:
            agents = json.load(f)
            agents = [a for a in agents if a["id"] != AGENT_ID]
            agents.append(agent_info)
            f.seek(0)
            json.dump(agents, f, indent=4)
            f.truncate()

def run_rtl_power(freq_start, freq_end, duration):
    cmd = f"rtl_power -f {freq_start}M:{freq_end}M:1M -i {duration}s -e {duration}s -out results/rtl_power.csv"
    subprocess.call(cmd, shell=True)
    return "results/rtl_power.csv"

def analyze_spectrum(csv_file):
    data = np.genfromtxt(csv_file, delimiter=',', skip_header=1)[:, 2]
    peak_idx = np.argmax(data)
    peak_power = float(data[peak_idx])
    peak_freq = 100 + peak_idx
    return peak_freq, peak_power

def export_geojson(location, freq, power):
    geojson = {
        "type": "FeatureCollection",
        "features": [{
            "type": "Feature",
            "properties": {
                "frequency_mhz": freq,
                "signal_db": power,
                "agent": AGENT_ID
            },
            "geometry": {
                "type": "Point",
                "coordinates": [location["lon"], location["lat"]]
            }
        }]
    }
    with open(GEOJSON_FILE, "w") as f:
        json.dump(geojson, f, indent=2)

def generate_map(location):
    m = folium.Map(location=[location["lat"], location["lon"]], zoom_start=13)
    folium.Marker(
        [location["lat"], location["lon"]],
        popup="Jammer Detected",
        icon=folium.Icon(color='red')
    ).add_to(m)
    m.save(MAP_HTML)

def dump_pcap():
    with open(PCAP_OUTPUT, "wb") as f:
        f.write(os.urandom(1024))

async def stream_websocket(freq, power):
    uri = "ws://localhost:8765"
    alert = {
        "agent": AGENT_ID,
        "timestamp": datetime.utcnow().isoformat(),
        "frequency_mhz": freq,
        "signal_db": power
    }
    async with websockets.connect(uri) as websocket:
        await websocket.send(json.dumps(alert))

def log_alert(freq, power):
    os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)
    entry = {
        "agent": AGENT_ID,
        "alert": f"RF Jammer at {freq} MHz",
        "signal": power,
        "timestamp": datetime.utcnow().isoformat()
    }
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

def main(args):
    config = load_config(args.config)
    setup_logging(args.log)
    location = get_gps_location()
    auto_register_agent(location)
    csv_path = run_rtl_power(config["scan_range"][0], config["scan_range"][1], config["duration"])
    freq, power = analyze_spectrum(csv_path)
    export_geojson(location, freq, power)
    generate_map(location)
    dump_pcap()
    log_alert(freq, power)
    asyncio.run(stream_websocket(freq, power))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced RF Jammer Locator")
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--log", default="logs/jammer_locator.log")
    args = parser.parse_args()
    main(args)
