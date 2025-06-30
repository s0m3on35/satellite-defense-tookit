#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import yaml
import json
import socket

EXPORT_DIR = "results"
PCAP_TEMPLATE = b'\xd4\xc3\xb2\xa1'  # Stub for pcap export

# === Setup ===
def load_config(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger().addHandler(logging.StreamHandler())

def get_gps():
    try:
        out = subprocess.check_output("gpspipe -w -n 10 | grep TPV | head -1", shell=True).decode()
        js = json.loads(out)
        return js.get("lat"), js.get("lon")
    except:
        return None, None

def push_websocket_alert(agent_id, msg):
    try:
        s = socket.socket()
        s.connect(("127.0.0.1", 8765))
        payload = json.dumps({"agent": agent_id, "alert": msg, "time": datetime.now().isoformat()})
        s.send(payload.encode())
        s.close()
    except:
        pass

def run_rtl_power(freq_low, freq_high, duration):
    out_csv = os.path.join(EXPORT_DIR, "rtl_power_scan.csv")
    subprocess.run([
        "rtl_power",
        "-f", f"{freq_low}:{freq_high}:100k",
        "-i", f"{duration}s",
        "-e", f"{duration+5}s",
        "-c", "50%",
        out_csv
    ])
    return out_csv

def parse_rtl_power_csv(csv_path):
    freqs, signal = [], []
    with open(csv_path) as f:
        for line in f:
            parts = line.strip().split(",")
            try:
                readings = list(map(float, parts[6:]))
                freqs += list(np.linspace(float(parts[2]), float(parts[3]), len(readings)))
                signal += readings
            except:
                continue
    return np.array(freqs), np.array(signal)

def plot_heatmap(freqs, signal, path):
    plt.figure(figsize=(10, 4))
    plt.plot(freqs, signal)
    plt.axvline(freqs[np.argmax(signal)], color='red', linestyle='--', label='Jammer Peak')
    plt.xlabel("Frequency (MHz)")
    plt.ylabel("Signal (dB)")
    plt.title("RF Jammer Scan")
    plt.legend()
    plt.grid()
    plt.savefig(path)
    plt.close()

def save_pcap(path):
    with open(path, 'wb') as f:
        f.write(PCAP_TEMPLATE)

def register_agent(agent_id, gps=None):
    agents_file = "webgui/agents.json"
    os.makedirs(os.path.dirname(agents_file), exist_ok=True)
    if os.path.exists(agents_file):
        with open(agents_file, 'r') as f:
            agents = json.load(f)
    else:
        agents = {}
    agents[agent_id] = {
        "agent_id": agent_id,
        "type": "sdr_sensor",
        "registered_at": datetime.now().isoformat(),
        "location": {"lat": gps[0] if gps else None, "lon": gps[1] if gps else None},
        "description": "Detects RF jammers using rtl_power"
    }
    with open(agents_file, 'w') as f:
        json.dump(agents, f, indent=2)

# === Main ===
def main(args):
    config = load_config(args.config)
    setup_logging(args.log)

    os.makedirs(EXPORT_DIR, exist_ok=True)
    agent_id = "rf_jammer_locator"
    push_websocket_alert(agent_id, "Starting RF jammer scan")

    lat, lon = get_gps()
    register_agent(agent_id, gps=(lat, lon))

    if args.use_hackrf:
        logging.info("Capturing raw RF with HackRF")
        raw_path = os.path.join(EXPORT_DIR, "hackrf_capture.bin")
        subprocess.run([
            "hackrf_transfer", "-f", str(config['scan_range'][0] * 1_000_000),
            "-r", raw_path, "-s", "2000000", "-n", str(2_000_000 * config['duration'])
        ])
    else:
        logging.info("Capturing spectrum with rtl_power")
        csv = run_rtl_power(config['scan_range'][0], config['scan_range'][1], config['duration'])
        freqs, signal = parse_rtl_power_csv(csv)
        peak_freq = freqs[np.argmax(signal)]
        peak_level = float(np.max(signal))

        json_out = {
            "timestamp": datetime.now().isoformat(),
            "peak_frequency_mhz": float(peak_freq),
            "peak_signal_level": peak_level,
            "location": {"lat": lat, "lon": lon}
        }
        with open(os.path.join(EXPORT_DIR, "jammer_detection.json"), 'w') as f:
            json.dump(json_out, f, indent=2)

        plot_heatmap(freqs, signal, os.path.join(EXPORT_DIR, "jammer_plot.png"))
        save_pcap(os.path.join(EXPORT_DIR, "jammer_metadata.pcap"))
        logging.info(f"Jammer peak at {peak_freq:.2f} MHz, saved to results/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RF Jammer Locator with SDR Integration")
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--log", default="logs/jammer.log")
    parser.add_argument("--use_hackrf", action="store_true", help="Use HackRF instead of rtl_power")
    args = parser.parse_args()
    main(args)
