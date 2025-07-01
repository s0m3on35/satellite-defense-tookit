import os
import json
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime

BLOCK_SIZE = 256
ENTROPY_THRESHOLD = 5.0
OUTPUT_DIR = "results"
DEFAULT_FIRMWARE = "sample_firmware.bin"
ANOMALY_JSON = os.path.join(OUTPUT_DIR, "entropy_anomalies.json")
PLOT_OUTPUT = os.path.join(OUTPUT_DIR, "entropy_map.png")

def calculate_entropy(block):
    if not block:
        return 0
    freq = np.array([block.count(b) for b in set(block)])
    prob = freq / len(block)
    entropy = -np.sum(prob * np.log2(prob))
    return entropy

def ask_for_firmware():
    try:
        from tkinter import Tk, filedialog
        root = Tk()
        root.withdraw()
        fw_path = filedialog.askopenfilename(title="Select Firmware Binary")
        root.destroy()
        return fw_path if fw_path else DEFAULT_FIRMWARE
    except:
        path = input("Enter firmware path (or press Enter for default): ").strip()
        return path if path else DEFAULT_FIRMWARE

def generate_entropy_map(firmware_path):
    entropies = []
    with open(firmware_path, "rb") as f:
        while block := f.read(BLOCK_SIZE):
            ent = calculate_entropy(block)
            entropies.append(ent)
    return entropies

def detect_anomalies(entropies):
    return [{"offset": i * BLOCK_SIZE, "entropy": e}
            for i, e in enumerate(entropies) if e >= ENTROPY_THRESHOLD]

def save_anomalies(anomalies):
    with open(ANOMALY_JSON, "w") as f:
        json.dump(anomalies, f, indent=2)

def plot_entropy(entropies):
    plt.figure(figsize=(12, 5))
    plt.plot(entropies, label="Entropy")
    plt.axhline(y=ENTROPY_THRESHOLD, color='r', linestyle='--', label='Threshold')
    plt.title("Entropy Map")
    plt.xlabel("Block Index")
    plt.ylabel("Entropy")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PLOT_OUTPUT)
    plt.close()

def ensure_directories():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def main():
    ensure_directories()
    firmware_path = ask_for_firmware()
    entropies = generate_entropy_map(firmware_path)
    anomalies = detect_anomalies(entropies)
    save_anomalies(anomalies)
    plot_entropy(entropies)
    print(f"[✓] Analyzed: {firmware_path}")
    print(f"[✓] Entropy blocks: {len(entropies)}")
    print(f"[✓] Anomalies detected: {len(anomalies)}")
    print(f"[✓] Saved to: {ANOMALY_JSON}")
    print(f"[✓] Plot saved to: {PLOT_OUTPUT}")

if __name__ == "__main__":
    main()
