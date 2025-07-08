#!/usr/bin/env python3
# Route: modules/defense/system_call_anomaly_watcher.py

import subprocess
import re
import threading
import time
from datetime import datetime

TARGET_PROCESSES = ["gpsd", "firmware_updater", "ota_handler", "telemetry_daemon"]
SUSPICIOUS_SYSCALLS = ["execve", "ptrace", "socket", "connect", "mmap", "open", "chmod", "write"]
ALERT_LOG = "/var/log/sdt_syscall_anomalies.log"

def log_alert(pid, syscall, line):
    timestamp = datetime.utcnow().isoformat()
    alert = f"{timestamp} - PID {pid} triggered suspicious syscall: {syscall}\n{line}"
    with open(ALERT_LOG, "a") as f:
        f.write(alert + "\n")
    subprocess.call(["logger", "-p", "auth.crit", alert])

def monitor_process(pid):
    cmd = ["strace", "-ff", "-p", str(pid), "-e", "trace=all"]
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True)
    for line in proc.stderr:
        for syscall in SUSPICIOUS_SYSCALLS:
            if syscall in line:
                log_alert(pid, syscall, line.strip())

def get_pid(process_name):
    try:
        output = subprocess.check_output(["pgrep", "-f", process_name]).decode().split()
        return [int(pid) for pid in output]
    except:
        return []

def main_loop():
    print("[*] Starting system call anomaly watcher...")
    tracked_pids = set()
    while True:
        for pname in TARGET_PROCESSES:
            for pid in get_pid(pname):
                if pid not in tracked_pids:
                    t = threading.Thread(target=monitor_process, args=(pid,), daemon=True)
                    t.start()
                    tracked_pids.add(pid)
        time.sleep(5)

if __name__ == "__main__":
    main_loop()
