import os
import yara
import json
from datetime import datetime
from modules.analysis.yara_stix_exporter import generate_stix_bundle

RULES_DIR = "rules"
FIRMWARE_DIR = "firmware_samples"
RESULTS_DIR = "results"
MATCH_FILE = os.path.join(RESULTS_DIR, "yara_matches.json")
STIX_BUNDLE_OUT = os.path.join(RESULTS_DIR, "stix_yara_bundle.json")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(RULES_DIR, exist_ok=True)
os.makedirs(FIRMWARE_DIR, exist_ok=True)

def load_rules():
    rule_files = [os.path.join(RULES_DIR, f) for f in os.listdir(RULES_DIR) if f.endswith(".yar")]
    if not rule_files:
        with open(os.path.join(RULES_DIR, "sample.yar"), "w") as f:
            f.write('rule SampleRule { condition: uint8(0) == 0x7F }')
        rule_files.append(os.path.join(RULES_DIR, "sample.yar"))
    return yara.compile(filepaths={f"r{i}": rf for i, rf in enumerate(rule_files)})

def scan_firmware(rules):
    matches = []
    firmware_files = [os.path.join(FIRMWARE_DIR, f) for f in os.listdir(FIRMWARE_DIR)]
    for fw_path in firmware_files:
        with open(fw_path, 'rb') as f:
            data = f.read()
            m = rules.match(data=data)
            for rule in m:
                matches.append({
                    "rule": rule.rule,
                    "tags": rule.tags,
                    "meta": rule.meta,
                    "firmware": os.path.basename(fw_path),
                    "timestamp": datetime.utcnow().isoformat()
                })
    return matches

def save_matches(matches):
    with open(MATCH_FILE, "w") as f:
        json.dump(matches, f, indent=2)

def export_stix(matches, firmware_file):
    bundle = generate_stix_bundle(matches, firmware_file)
    with open(STIX_BUNDLE_OUT, "w") as f:
        f.write(str(bundle))

if __name__ == "__main__":
    rules = load_rules()
    print("[+] Loaded rules")
    matches = scan_firmware(rules)
    save_matches(matches)
    if matches:
        firmware_file = matches[0]["firmware"] if matches else "unknown.bin"
        export_stix(matches, os.path.join(FIRMWARE_DIR, firmware_file))
        print("[✓] STIX export completed")
    else:
        print("[!] No YARA matches found")
