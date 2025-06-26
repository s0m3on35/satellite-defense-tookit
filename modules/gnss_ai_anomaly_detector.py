
#!/usr/bin/env python3

import serial
import pynmea2
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import time

PORT = "/dev/ttyUSB0"
BAUD = 9600
MODEL_PATH = "gnss_if_model.pkl"
BUFFER_SIZE = 50

print("[*] GNSS AI Anomaly Detector starting...")

# Load or train model
try:
    clf = joblib.load(MODEL_PATH)
    print("[*] Loaded pre-trained model.")
except:
    print("[!] No model found. Training dummy model...")
    dummy_data = np.random.normal(loc=0, scale=1, size=(100, 3))
    clf = IsolationForest(contamination=0.1).fit(dummy_data)
    joblib.dump(clf, MODEL_PATH)

buffer = []

ser = serial.Serial(PORT, BAUD)

while True:
    try:
        line = ser.readline().decode("utf-8", errors="ignore")
        if line.startswith("$GPRMC"):
            msg = pynmea2.parse(line)
            speed = float(msg.spd_over_grnd or 0)
            lat = float(msg.latitude or 0)
            lon = float(msg.longitude or 0)
            data_point = [lat, lon, speed]
            buffer.append(data_point)
            if len(buffer) >= BUFFER_SIZE:
                X = np.array(buffer)
                preds = clf.predict(X)
                if list(preds).count(-1) > BUFFER_SIZE * 0.3:
                    print("⚠️ Potential GNSS spoofing detected! Abnormal movement patterns.")
                buffer = []
    except Exception:
        continue
