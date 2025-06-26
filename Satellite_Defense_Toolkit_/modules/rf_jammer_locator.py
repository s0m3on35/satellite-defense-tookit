
#!/usr/bin/env python3

# RF Jammer Locator - SDR Based
# Requires: SoX, rtl_power, numpy, matplotlib

import subprocess
import numpy as np
import time
import datetime
import matplotlib.pyplot as plt

FREQ_RANGE = "1570M:1580M:10k"
DURATION = 60  # seconds
GAIN = "40"
OUTPUT = "jammer_power.csv"

print(f"[*] Scanning {FREQ_RANGE} for {DURATION}s...")

# Run rtl_power
cmd = [
    "rtl_power",
    "-f", FREQ_RANGE,
    "-i", "1",
    "-e", str(DURATION),
    "-g", GAIN,
    "-c", "20%",
    "-o", OUTPUT
]
subprocess.run(cmd)

# Process results
print("[*] Processing scan data...")

timestamps = []
powers = []

with open(OUTPUT) as f:
    for line in f:
        parts = line.strip().split(",")
        if len(parts) > 6 and parts[0].isdigit():
            timestamp = datetime.datetime.fromtimestamp(int(parts[0]))
            signal_vals = list(map(float, parts[6:]))
            timestamps.append(timestamp)
            powers.append(signal_vals)

powers = np.array(powers)
avg_power = np.mean(powers, axis=0)

plt.figure(figsize=(12, 6))
plt.title("RF Spectrum Scan – Suspected Jammer Zones")
plt.plot(avg_power, color="red")
plt.xlabel("Frequency Bin (10kHz steps)")
plt.ylabel("Average Power (dB)")
plt.grid(True)
plt.savefig("jammer_heatmap.png")
print("✅ Scan complete – see jammer_heatmap.png")
