# modules/forensics/memwatch_agent.py
import hashlib, time, argparse, os

def hash_mem_region(region): return hashlib.sha256(region).hexdigest()

def scan_memory_regions(mem_path):
    with open(mem_path, 'rb') as f: print(f"[+] Memory region hash: {hash_mem_region(f.read())}")

def watch_loop(mem_path, interval):
    baseline = None
    while True:
        try:
            with open(mem_path, 'rb') as f:
                current_hash = hash_mem_region(f.read())
                if baseline and current_hash != baseline:
                    print("[!] Memory anomaly detected!")
                baseline = current_hash
        except Exception as e:
            print(f"[-] Memory access failed: {e}")
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mem-path", required=True)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args()

    if args.watch: watch_loop(args.mem_path, args.interval)
    else: scan_memory_regions(args.mem_path)
