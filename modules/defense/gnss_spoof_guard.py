#!/usr/bin/env python3
# Route: modules/defense/gnss_spoof_guard.py

import time
import math
import subprocess
from datetime import datetime
import random

ALERT_LOG = "/var/log/sdt_gnss_spoof_alerts.log"
CHECK_INTERVAL = 10  # seconds
MAX_DRIFT_METERS = 50  # max allowed movement before alert
MAX_TIME_DRIFT_SEC = 2  # max allowed GPS time deviation
DRIFT_HISTORY = []

def haversine(lat1, lon1, lat2, lon2):
    R = 6371000  # Earth radius in meters
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)

    a = math.sin(dphi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2)**2
    return 2 * R * math.atan2(math.sqrt(a), math.sqrt(1 - a))

def get_gps_data():
    try:
        output = subprocess.check_output("gpspipe -w -n 10 | grep -m 1 TPV", shell=True).decode()
        import json
        data = json.loads(output)
        lat = float(data.get("lat", 0.0))
        lon = float(data.get("lon", 0.0))
        gps_time = data.get("time", "")
        return lat, lon, gps_time
    except:
        return None, None, None

def get_system_time():
    return datetime.utcnow().isoformat()

def log_alert(message, critical=True):
    timestamp = datetime.utcnow().isoformat()
    alert = f"{timestamp} - {message}"
    with open(ALERT_LOG, 'a') as logf:
        logf.write(alert + '\n')
    if critical:
        try:
            subprocess.call(['logger', '-p', 'auth.crit', alert])
        except:
            pass

def spoof_detection_loop():
    prev_lat, prev_lon, _ = get_gps_data()
    while True:
        time.sleep(CHECK_INTERVAL)
        lat, lon, gps_time = get_gps_data()
        if None in (lat, lon, gps_time):
            continue

        dist = haversine(prev_lat, prev_lon, lat, lon)
        DRIFT_HISTORY.append(dist)
        if dist > MAX_DRIFT_METERS:
            log_alert(f"GNSS spoofing suspected: jump of {dist:.2f}m detected.")

        try:
            gps_dt = datetime.fromisoformat(gps_time.replace("Z", ""))
            system_dt = datetime.utcnow()
            time_drift = abs((system_dt - gps_dt).total_seconds())
            if time_drift > MAX_TIME_DRIFT_SEC:
                log_alert(f"GNSS time spoofing suspected: GPS vs system time drift = {time_drift:.2f}s.")
        except:
            pass

        prev_lat, prev_lon = lat, lon

if __name__ == "__main__":
    print("[*] Starting GNSS spoofing detection agent...")
    spoof_detection_loop()
