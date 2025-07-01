
import time
import argparse
import random

NMEA_TEMPLATE = "$GPRMC,{time},A,{lat},N,{lon},E,000.0,000.0,{date},,,A*68"

def generate_nmea(lat, lon):
    t = time.strftime("%H%M%S")
    d = time.strftime("%d%m%y")
    return NMEA_TEMPLATE.format(time=t, lat=lat, lon=lon, date=d)

def spoof_loop(lat, lon, interval, jitter):
    try:
        while True:
            jittered_lat = f"{float(lat) + random.uniform(-jitter, jitter):.5f}"
            jittered_lon = f"{float(lon) + random.uniform(-jitter, jitter):.5f}"
            nmea = generate_nmea(jittered_lat, jittered_lon)
            print(nmea)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[+] GNSS spoof simulation ended.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--lat", required=True, help="Base latitude")
    parser.add_argument("--lon", required=True, help="Base longitude")
    parser.add_argument("--interval", type=int, default=1, help="Seconds between NMEA packets")
    parser.add_argument("--jitter", type=float, default=0.0001, help="Random location shift")
    args = parser.parse_args()

    spoof_loop(args.lat, args.lon, args.interval, args.jitter)
