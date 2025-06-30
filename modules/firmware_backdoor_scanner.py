import os
import re
import json
import time
import argparse
from datetime import datetime

AGENT_ID = "firmware_backdoor_scanner"
ALERT_FILE = "webgui/alerts.json"
AGENTS_DB = "webgui/agents.json"
RESULTS_DIR = "results"
CHAIN_SCRIPT = "modules/report_builder.py"

PATTERNS = [
    (r"(root:.*:0:0:)", "Suspicious /etc/passwd entry (root)"),
    (r"(?i)(telnetd)", "Telnet service detected"),
    (r"(?i)(backdoor)", "Backdoor keyword"),
    (r"(admin:\w+:)", "Hardcoded admin credentials"),
    (r"(?i)(remote_shell|debug_shell)", "Remote or debug shell"),
    (r"(?i)(dropbear|busybox ash)", "Embedded shell or SSH variant")
]

def log(msg):
    print(f"[BACKDOOR] {msg}")

def push_alert(msg):
    alert = {
        "agent": AGENT_ID,
        "alert": msg,
        "type": "firmware",
        "timestamp": time.time()
    }
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

def register_agent():
    os.makedirs(os.path.dirname(AGENTS_DB), exist_ok=True)
    if not os.path.exists(AGENTS_DB):
        with open(AGENTS_DB, "w") as f:
            json.dump([], f)
    with open(AGENTS_DB, "r") as f:
        agents = json.load(f)
    if AGENT_ID not in [a["id"] for a in agents]:
        agents.append({
            "id": AGENT_ID,
            "type": "firmware",
            "registered": datetime.now().isoformat()
        })
        with open(AGENTS_DB, "w") as f:
            json.dump(agents, f, indent=2)

def scan_firmware(directory):
    findings = []
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "rb") as f:
                    content = f.read().decode(errors="ignore")
                    for pattern, desc in PATTERNS:
                        if re.search(pattern, content):
                            findings.append({
                                "timestamp": datetime.now().isoformat(),
                                "file": full_path,
                                "pattern": pattern,
                                "description": desc
                            })
            except:
                continue
    return findings

def export_results(findings):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, "firmware_backdoor_findings.json")
    with open(path, "w") as f:
        json.dump(findings, f, indent=4)
    return path

def chain_reporter():
    os.system(f"python3 {CHAIN_SCRIPT} --source firmware_backdoor_findings.json")

def main():
    parser = argparse.ArgumentParser(description="Firmware Backdoor Scanner")
    parser.add_argument("--input", required=True, help="Unpacked firmware directory")
    args = parser.parse_args()

    register_agent()
    push_alert("Backdoor scan started")
    log("Scanning for hardcoded credentials and backdoors")

    findings = scan_firmware(args.input)

    if findings:
        push_alert(f"{len(findings)} suspicious pattern(s) found")
        log(f"{len(findings)} potential backdoors detected")
    else:
        log("No suspicious patterns found")
        push_alert("Scan complete: no issues")

    export_results(findings)
    chain_reporter()

if __name__ == "__main__":
    main()
