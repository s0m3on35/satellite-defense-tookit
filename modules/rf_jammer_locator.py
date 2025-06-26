
import argparse
import logging
import os
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import yaml

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

# === Simulated Jammer Scan ===
def simulate_sdr_scan(freq_range, duration):
    freqs = np.linspace(freq_range[0], freq_range[1], 1000)
    signal = np.random.rand(1000)
    signal[400:420] += 8  # simulate strong jamming signal
    return freqs, signal

def plot_heatmap(freqs, signal, output_path):
    plt.figure(figsize=(10, 4))
    plt.plot(freqs, signal, label='Signal Strength (dB)')
    plt.title('SDR Frequency Scan')
    plt.xlabel('Frequency (MHz)')
    plt.ylabel('Signal Level')
    plt.axvline(freqs[np.argmax(signal)], color='red', linestyle='--', label='Jammer Peak')
    plt.legend()
    plt.grid(True)
    plt.savefig(output_path)
    plt.close()

# === Main Execution ===
def main(args):
    config = load_config(args.config)
    setup_logging(args.log)
    logging.info("RF Jammer Locator Started")

    freq_range = config['scan_range']
    duration = config['duration']

    freqs, signal = simulate_sdr_scan(freq_range, duration)
    peak_freq = freqs[np.argmax(signal)]
    peak_level = float(np.max(signal))

    os.makedirs("results", exist_ok=True)
    result = {
        "timestamp": datetime.now().isoformat(),
        "peak_frequency_mhz": float(peak_freq),
        "peak_signal_level": peak_level
    }
    with open("results/jammer_detection.json", "w") as f:
        json.dump(result, f, indent=4)

    plot_heatmap(freqs, signal, "results/jammer_scan_plot.png")
    logging.info(f"Jammer detected at {peak_freq:.2f} MHz with signal {peak_level:.2f} dB")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RF Jammer Locator (simulated)")
    parser.add_argument("--config", default="config/config.yaml", help="Path to YAML config")
    parser.add_argument("--log", default="logs/jammer_locator.log", help="Log file path")
    args = parser.parse_args()
    main(args)
