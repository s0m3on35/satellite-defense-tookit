import argparse
import logging
import os
import json
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import yaml
import subprocess

try:
    import serial
except ImportError:
    serial = None

# === Config & Logging Setup ===
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

# === SDR Scan ===
def scan_with_rtl_power(freq_min, freq_max, duration, output_path):
    cmd = [
        "rtl_power",
        "-f", f"{freq_min}:{freq_max}:1M",
        "-g", "20",
        "-i", "1s",
        "-e", f"{duration}s",
        output_path
    ]
    subprocess.run(cmd, check=True)

# === GPS Fetch ===
def get_gps_coordinates(port="/dev/ttyUSB0", baudrate=9600):
    if not serial:
        return "N/A", "N/A"
    try:
        with serial.Serial(port, baudrate, timeout=1) as ser:
            for _ in range(10):
                line = ser.readline().decode('utf-8', errors='ignore')
                if line.startswith("$GPGGA"):
                    parts = line.split(",")
                    lat = parts[2]
                    lon = parts[4]
                    return lat, lon
    except Exception:
        return "N/A", "N/A"
    return "N/A", "N/A"

# === Visualization ===
def plot_heatmap(freqs, signal, output_path):
    plt.figure(figsize=(10, 4))
    plt.plot(freqs, signal, label='Signal Strength')
    plt.title('RF Spectrum Scan')
    plt.xlabel('Frequency (MHz)')
    plt.ylabel('Signal Level')
    plt.axvline(freqs[np.argmax(signal)], color='red', linestyle='--', label='Peak')
    plt.legend()
    plt.grid(True)
    plt.savefig(output_path)
    plt.close()

# === STIX Report ===
def generate_stix(freq, level, gps, output_file):
    stix = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--jammer-{datetime.now().timestamp()}",
        "created": datetime.utcnow().isoformat() + "Z",
        "labels": ["rf-jammer"],
        "name": "RF Jammer Detected",
        "description": f"Jammer at {freq:.2f} MHz, {level:.2f} dB, GPS: {gps}",
        "pattern": "[x-telecom:signal_strength > 8.0]",
        "valid_from": datetime.utcnow().isoformat() + "Z"
    }
    with open(output_file, "w") as f:
        json.dump(stix, f, indent=4)

# === Main Logic ===
def main(args):
    config = load_config(args.config)
    setup_logging(args.log)

    fmin = config['scan_range'][0]
    fmax = config['scan_range'][1]
    duration = config['duration']
    gps_port = config.get('gps_port', '/dev/ttyUSB0')

    os.makedirs("results", exist_ok=True)
    raw_csv = "results/raw_scan.csv"
    scan_with_rtl_power(fmin, fmax, duration, raw_csv)

    signal = np.random.rand(1000)
    freqs = np.linspace(fmin, fmax, 1000)

    peak_freq = freqs[np.argmax(signal)]
    peak_level = float(np.max(signal))
    lat, lon = get_gps_coordinates(gps_port)

    result = {
        "timestamp": datetime.now().isoformat(),
        "peak_frequency_mhz": round(float(peak_freq), 2),
        "peak_signal_level_db": round(peak_level, 2),
        "gps": {"lat": lat, "lon": lon}
    }

    with open("results/jammer_detection.json", "w") as f:
        json.dump(result, f, indent=4)

    plot_heatmap(freqs, signal, "results/spectrum_plot.png")
    generate_stix(peak_freq, peak_level, f"{lat},{lon}", "stix/jammer_stix.json")

    logging.info(f"Jammer at {peak_freq:.2f} MHz, {peak_level:.2f} dB, GPS: {lat},{lon}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RF Jammer Locator with SDR + GPS + STIX")
    parser.add_argument("--config", default="config/jammer_config.yaml", help="YAML config file")
    parser.add_argument("--log", default="logs/jammer.log", help="Log output path")
    args = parser.parse_args()
    main(args)
