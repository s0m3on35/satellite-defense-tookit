# core/logging/audit_exporter.py
import json
import argparse
import os
from datetime import datetime

LOG_SOURCE = "logs/dashboard/dashboard_stream.log"

def export_json(output):
    if not os.path.exists(LOG_SOURCE):
        print("[-] Log source missing")
        return
    with open(LOG_SOURCE, "r") as f:
        entries = [{"timestamp": l.split("]")[0][1:], "message": l.split("]: ")[1].strip()} for l in f.readlines()]
    with open(output, "w") as out:
        json.dump(entries, out, indent=2)
    print(f"[✓] Audit exported to {output}")

def export_syslog():
    import syslog
    if not os.path.exists(LOG_SOURCE):
        print("[-] Log source missing")
        return
    with open(LOG_SOURCE, "r") as f:
        for l in f.readlines():
            syslog.syslog(syslog.LOG_INFO, l.strip())
    print("[✓] Audit sent to system syslog")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=["json", "syslog"], required=True)
    parser.add_argument("--out", default="results/audit_log.json")
    args = parser.parse_args()

    if args.format == "json":
        export_json(args.out)
    else:
        export_syslog()
