# modules/forensics/memwatch_agent.py
import argparse
import hashlib
import os
import time

def hash_mem_region(region):
    return hashlib.sha256(region).hexdigest()

def scan_memory_regions(mem_path):
    try:
        with open(mem_path, 'rb') as f:
            data = f.read()
            region_hash = hash_mem_region(data)
            print(f"[+] Memory region hash: {region_hash}")
    except Exception as e:
        print(f"[-] Error reading memory: {e}")

def watch_loop(mem_path, interval):
    baseline = None
    while True:
        try:
            with open(mem_path, 'rb') as f:
                data = f.read()
                current_hash = hash_mem_region(data)
                if baseline and current_hash != baseline:
                    print("[!] Memory anomaly detected!")
                baseline = current_hash
        except Exception as e:
            print(f"[-] Memory access failed: {e}")
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mem-path", required=True, help="Path to memory region file")
    parser.add_argument("--watch", action="store_true", help="Enable live monitoring loop")
    parser.add_argument("--interval", type=int, default=5, help="Watch interval")
    args = parser.parse_args()

    if args.watch:
        watch_loop(args.mem_path, args.interval)
    else:
        scan_memory_regions(args.mem_path)
