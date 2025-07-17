#!/usr/bin/env python3

"""
RTCM Interceptor
Captures RTCM (Radio Technical Commission for Maritime Services) correction streams over TCP, UDP, or serial interfaces.
Extracts GNSS correction data for spoofing detection, anomaly analysis, and forensic capture.
Recon
"""

import socket
import serial
import os
import time
from datetime import datetime

SAVE_DIR = "captures/rtcm"
TCP_HOST = "0.0.0.0"
TCP_PORT = 2101
SERIAL_PORT = "/dev/ttyUSB0"
BAUDRATE = 9600
CAPTURE_MODE = "tcp"  # Options: 'tcp', 'udp', 'serial'

timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
RAW_DUMP_FILE = os.path.join(SAVE_DIR, f"rtcm_raw_{timestamp}.bin")
DECODED_FILE = os.path.join(SAVE_DIR, f"rtcm_decoded_{timestamp}.txt")

os.makedirs(SAVE_DIR, exist_ok=True)

def log_packet(packet):
    with open(RAW_DUMP_FILE, "ab") as f:
        f.write(packet)

def decode_rtcm(packet):
    # Minimal parsing for RTCM Version 3 preamble (0xD3)
    if packet[0] == 0xD3:
        msg_len = ((packet[1] & 0x03) << 8) | packet[2]
        msg_type = ((packet[3] & 0xFC) >> 2)
        return f"RTCM Message Type: {msg_type} | Length: {msg_len}"
    return "Non-RTCM or malformed packet"

def save_decoded(line):
    with open(DECODED_FILE, "a") as f:
        f.write(line + "\n")

def intercept_tcp():
    print(f"[*] Listening for RTCM TCP stream on {TCP_HOST}:{TCP_PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((TCP_HOST, TCP_PORT))
        s.listen(1)
        conn, addr = s.accept()
        print(f"[+] Connection from {addr}")
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                log_packet(data)
                decoded = decode_rtcm(data)
                save_decoded(decoded)
                print(decoded)

def intercept_udp():
    print(f"[*] Listening for RTCM UDP packets on {TCP_HOST}:{TCP_PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((TCP_HOST, TCP_PORT))
        while True:
            data, addr = s.recvfrom(4096)
            log_packet(data)
            decoded = decode_rtcm(data)
            save_decoded(decoded)
            print(f"{addr} → {decoded}")

def intercept_serial():
    print(f"[*] Reading RTCM from serial port {SERIAL_PORT} @ {BAUDRATE}...")
    with serial.Serial(SERIAL_PORT, BAUDRATE, timeout=1) as ser:
        while True:
            packet = ser.read(256)
            if packet:
                log_packet(packet)
                decoded = decode_rtcm(packet)
                save_decoded(decoded)
                print(decoded)

def main():
    print("[*] RTCM Interceptor Started")
    print(f"[+] Saving raw data to {RAW_DUMP_FILE}")
    print(f"[+] Saving decoded output to {DECODED_FILE}")

    try:
        if CAPTURE_MODE == "tcp":
            intercept_tcp()
        elif CAPTURE_MODE == "udp":
            intercept_udp()
        elif CAPTURE_MODE == "serial":
            intercept_serial()
        else:
            print(f"[!] Unknown mode: {CAPTURE_MODE}")
    except KeyboardInterrupt:
        print("\n[!] Interception stopped by user.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
