
#!/usr/bin/env python3

import torch
import torch.nn as nn
import numpy as np
import time
import os

LOG_PATH = "/var/log/telemetry/satellite.log"
SEQ_LEN = 10
THRESHOLD = 0.05

print("[*] Telemetry LSTM Anomaly Monitor (demo mode)")

# Dummy LSTM for sequence anomaly detection
class LSTMMonitor(nn.Module):
    def __init__(self, input_size=3, hidden_size=20):
        super(LSTMMonitor, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.out = nn.Linear(hidden_size, input_size)

    def forward(self, x):
        x, _ = self.lstm(x)
        return self.out(x)

# Initialize model and load dummy weights
model = LSTMMonitor()
model.eval()

def parse_line(line):
    try:
        parts = line.strip().split()
        temp = float(parts[1].split("=")[1])
        volt = float(parts[2].split("=")[1])
        curr = float(parts[3].split("=")[1])
        return [temp, volt, curr]
    except:
        return None

buffer = []

with open(LOG_PATH, "r") as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        datapoint = parse_line(line)
        if datapoint:
            buffer.append(datapoint)
            if len(buffer) >= SEQ_LEN:
                seq = torch.tensor([buffer[-SEQ_LEN:]], dtype=torch.float32)
                with torch.no_grad():
                    predicted = model(seq).numpy()[0]
                deviation = np.abs(np.array(buffer[-1]) - predicted[-1])
                if np.any(deviation > THRESHOLD):
                    print(f"⚠️ Anomaly Detected! Δ={deviation}")
