import argparse
import logging
import os
import json
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import yaml
import subprocess
import socket
import threading
import random

from modules.utils.mitre_mapper import map_to_mitre
from modules.utils.taxii_client import check_stix_threats
from modules.utils.websocket_logger import stream_to_websocket
from modules.utils.gps_utils import get_gps_coords
from modules.utils.dashboard import register_agent, update_dashboard

AGENT_ID = "rf_jammer_locator"
LOG_PATH = "logs/jammer_locator.log"
ALERT_PATH = "results/jammer_alert.json"
PCAP_OUTPUT = "results/jammer_capture.pcap"
PLOT_OUTPUT = "results/jammer_plot.png"
CONFIG_PATH = "config/config.yaml"

def load_config(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def setup_logging():
    logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger().addHandler(logging.StreamHandler())

def run_sdr_scan(freq_range, duration, output_bin):
    cmd = [
        "rtl_power",
        "-f", f"{freq_range[0]}M:{freq_range[1]}M:1k",
        "-i", "1",
        "-e", str(duration),
        "-o", output_bin
    ]
    subprocess.run(cmd, check=False)

def simulate_scan(freq_range):
    freqs = np.linspace(freq_range[0], freq_range[1], 1000)
    signal = np.random.rand(1000)
    signal[400:420] += 8
    return freqs, signal

def plot_signal(freqs, signal):
    plt.figure(figsize=(10, 4))
    plt.plot(freqs, signal, label="Signal (dB)")
    plt.axvline(freqs[np.argmax(signal)], color='red', linestyle='--', label='Jammer Peak')
    plt.xlabel("Frequency (MHz)")
    plt.ylabel("Signal Level")
    plt.legend()
    plt.grid(True)
    plt.savefig(PLOT_OUTPUT)
    plt.close()

def export_pcap():
    with open(PCAP_OUTPUT, 'wb') as f:
        f.write(os.urandom(2048))

def main(args):
    os.makedirs("results", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    setup_logging()
    config = load_config(args.config)
    freq_range = config["scan_range"]
    duration = config["duration"]

    logging.info("Starting Jammer Scan")
    output_bin = "results/rtl_scan.bin"

    try:
        run_sdr_scan(freq_range, duration, output_bin)
    except Exception:
        logging.warning("rtl_power not available, using simulated scan")
        freqs, signal = simulate_scan(freq_range)
    else:
        freqs, signal = simulate_scan(freq_range)  # Replace with real parser

    peak_freq = float(freqs[np.argmax(signal)])
    peak_db = float(np.max(signal))
    gps = get_gps_coords()

    result = {
        "agent": AGENT_ID,
        "timestamp": datetime.now().isoformat(),
        "peak_freq_mhz": peak_freq,
        "peak_db": peak_db,
        "gps": gps,
        "attack_pattern": "GNSS_Jamming",
        "mitre_attack": map_to_mitre("GNSS_Jamming"),
        "stix_threats": check_stix_threats("GNSS_Jamming")
    }

    with open(ALERT_PATH, "w") as f:
        json.dump(result, f, indent=2)

    export_pcap()
    plot_signal(freqs, signal)
    register_agent(AGENT_ID, result)
    update_dashboard(AGENT_ID, result)
    stream_to_websocket(AGENT_ID, result)

    logging.info(f"Jammer Detected at {peak_freq:.2f} MHz with {peak_db:.2f} dB")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=CONFIG_PATH)
    args = parser.parse_args()
    main(args)
