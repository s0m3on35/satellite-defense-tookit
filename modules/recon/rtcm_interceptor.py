#!/usr/bin/env python3
# File: modules/recon/rtcm_interceptor.py

import os
import json
import time
import serial
import threading
from datetime import datetime
from pathlib import Path

LOG_FILE = "logs/rtcm_interceptor.log"
ALERT_FILE = "webgui/alerts.json"
INTEL_OUTPUT = "intel/rtcm_dumps"
SERIAL_PORT = "/dev/ttyUSB0"
BAUDRATE = 9600

Path(INTEL_OUTPUT).mkdir(parents=True, exist_ok=True)
Path("logs").mkdir(parents=True, exist_ok=True)

RTCM_TYPES = {
    1005: "Stationary RTK Reference Station ARP",
    1077: "GPS MSM7",
    1087: "GLONASS MSM7",
    1097: "Galileo MSM7",
    1127: "BeiDou MSM7"
}

def log_event(msg):
    ts = datetime.utcnow().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {msg}\n")
    print(f"[+] {msg}")

def extract_rtcm_type(byte_stream):
    if len(byte_stream) < 6:
        return None
    msg_type = (byte_stream[3] << 4) | (byte_stream[4] >> 4)
    return msg_type

def parse_rtcm(raw):
    header = raw[:6]
    payload = raw[6:-3]
    crc = raw[-3:]
    return {
        "length": len(raw),
        "crc": crc.hex(),
        "header": header.hex(),
        "payload_sample": payload[:10].hex()
    }

def save_rtcm_data(rtcm_msg, msg_type):
    timestamp = datetime.utcnow().isoformat()
    msg_info = {
        "timestamp": timestamp,
        "type": msg_type,
        "description": RTCM_TYPES.get(msg_type, "Unknown"),
        "parsed": rtcm_msg
    }
    filename = f"{INTEL_OUTPUT}/rtcm_{msg_type}_{int(time.time())}.json"
    with open(filename, "w") as f:
        json.dump(msg_info, f, indent=2)

    alert = {
        "timestamp": timestamp,
        "type": "rtcm_capture",
        "msg_type": msg_type,
        "description": msg_info["description"]
    }
    append_alert(alert)
    log_event(f"Captured RTCM type {msg_type}: {msg_info['description']}")

def append_alert(alert):
    try:
        if os.path.exists(ALERT_FILE):
            with open(ALERT_FILE, "r") as f:
                alerts = json.load(f)
        else:
            alerts = []
        alerts.append(alert)
        with open(ALERT_FILE, "w") as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        log_event(f"[!] Failed to write alert: {e}")

def read_rtcm_stream():
    try:
        with serial.Serial(SERIAL_PORT, BAUDRATE, timeout=1) as ser:
            buffer = bytearray()
            while True:
                byte = ser.read(1)
                if byte:
                    buffer.append(byte[0])
                    if buffer[0] != 0xD3:
                        buffer = bytearray()
                        continue
                    if len(buffer) >= 6:
                        length = ((buffer[1] & 0x03) << 8) | buffer[2]
                        full_len = length + 6  # header + payload + CRC
                        if len(buffer) >= full_len:
                            msg_type = extract_rtcm_type(buffer)
                            if msg_type:
                                parsed = parse_rtcm(buffer[:full_len])
                                save_rtcm_data(parsed, msg_type)
                            buffer = bytearray()
    except serial.SerialException as e:
        log_event(f"[!] Serial error: {e}")
    except KeyboardInterrupt:
        log_event("[*] Interrupted by user.")
    except Exception as e:
        log_event(f"[!] Unexpected error: {e}")

def main():
    log_event("[*] RTCM Interceptor started")
    read_rtcm_stream()

if __name__ == "__main__":
    main()
