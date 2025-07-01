import yara
import os
import json
import argparse
import uuid
import datetime
from tkinter import filedialog, Tk
import subprocess

RULES_DIR = "rules"
RESULTS_DIR = "results"
MATCH_FILE = os.path.join(RESULTS_DIR, "yara_matches.json")

def ensure_dirs():
    os.makedirs(RULES_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

def generate_sample_rules():
    sample_rule_path = os.path.join(RULES_DIR, "sample_rule.yar")
    if not os.path.exists(sample_rule_path):
        with open(sample_rule_path, "w") as f:
            f.write('''
rule SampleFirmwarePattern
{
    strings:
        $a = { 6A 40 68 00 30 00 00 6A 14 8D 91 }
    condition:
        $a
}
''')

def load_rules():
    rule_files = [os.path.join(RULES_DIR, f) for f in os.listdir(RULES_DIR) if f.endswith(".yar")]
    if not rule_files:
        raise Exception("No YARA rule files found.")
    return yara.compile(filepaths={str(i): path for i, path in enumerate(rule_files)})

def prompt_firmware_gui():
    root = Tk()
    root.withdraw()
    fw_path = filedialog.askopenfilename(title="Select Firmware Binary")
    root.destroy()
    return fw_path

def scan_firmware(firmware_path, rules):
    matches = []
    with open(firmware_path, "rb") as f:
        data = f.read()
        results = rules.match(data=data)
        for match in results:
            matches.append({
                "rule": match.rule,
                "meta": match.meta,
                "tags": match.tags,
                "strings": match.strings
            })
    return matches

def save_matches(matches):
    with open(MATCH_FILE, "w") as f:
        json.dump(matches, f, indent=2)

def export_stix(firmware_path):
    cmd = [
        "python3", "yara_stix_exporter.py",
        "--firmware", firmware_path
    ]
    subprocess.run(cmd)

def main():
    parser = argparse.ArgumentParser(description="YARA Firmware Scanner with STIX Export")
    parser.add_argument("--firmware", help="Path to firmware binary to scan")
    args = parser.parse_args()

    ensure_dirs()
    generate_sample_rules()

    firmware_path = args.firmware or prompt_firmware_gui()
    if not firmware_path or not os.path.exists(firmware_path):
        print("[!] Firmware file not found or not provided.")
        return

    try:
        rules = load_rules()
        print(f"[✓] Loaded YARA rules from: {RULES_DIR}")
    except Exception as e:
        print(f"[!] Rule load error: {e}")
        return

    print(f"[✓] Scanning firmware: {firmware_path}")
    matches = scan_firmware(firmware_path, rules)
    save_matches(matches)
    print(f"[✓] Saved {len(matches)} YARA match results to: {MATCH_FILE}")

    if matches:
        export_stix(firmware_path)
        print("[✓] STIX export complete.")
    else:
        print("[*] No YARA matches. Skipping STIX export.")

if __name__ == "__main__":
    main()
