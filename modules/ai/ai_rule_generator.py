# modules/ai/

import os
import json
import argparse
from datetime import datetime
import hashlib
import re

def extract_keywords(text):
    words = set(re.findall(r"[a-zA-Z0-9_\-]{5,}", text))
    return sorted(words)

def yara_template(rule_name, keywords):
    conditions = " or ".join([f'str{i}' for i in range(len(keywords))])
    strings = "\n".join([f'        $str{i} = "{kw}" nocase' for i, kw in enumerate(keywords)])
    return f"""
rule {rule_name}
{{
    meta:
        author = "SatelliteDefenseToolkit"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        description = "Auto-generated rule from telemetry"
    strings:
{strings}
    condition:
        {conditions}
}}""".strip()

def sigma_template(entry, mitre=None):
    return {
        "title": "Auto Rule - Suspicious Log Pattern",
        "description": entry[:80],
        "logsource": {"category": "application"},
        "detection": {
            "selection": {"message|contains": entry[:40]},
            "condition": "selection"
        },
        "level": "medium",
        "tags": [f"attack.{mitre}"] if mitre else []
    }

def stix_bundle(alerts):
    bundle = {
        "type": "bundle",
        "id": f"bundle--{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "spec_version": "2.1",
        "objects": []
    }
    for alert in alerts:
        bundle["objects"].append({
            "type": "indicator",
            "id": f"indicator--{hashlib.md5(alert['original'][:40].encode()).hexdigest()}",
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat(),
            "name": "Auto Indicator from Anomaly",
            "pattern": f"[x-telemetry:message = '{alert['original'][:40]}']",
            "pattern_type": "stix",
            "labels": ["auto", "ai", "telemetry"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "collection"}]
        })
    return bundle

def generate_rules(input_file, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    with open(input_file) as f:
        lines = [line.strip() for line in f if line.strip()]

    yara_rules = []
    sigma_rules = []
    stix_objects = []

    for i, line in enumerate(lines):
        rule_name = f"AutoGenRule_{i}"
        keywords = extract_keywords(line)
        yara_rules.append(yara_template(rule_name, keywords))
        sigma_rules.append(sigma_template(line, mitre="T1082"))
        stix_objects.append({"original": line})

    with open(os.path.join(out_dir, "autogen_rules.yara"), "w") as f:
        f.write("\n\n".join(yara_rules))

    with open(os.path.join(out_dir, "autogen_rules.sigma.json"), "w") as f:
        json.dump(sigma_rules, f, indent=2)

    with open(os.path.join(out_dir, "autogen_stix_bundle.json"), "w") as f:
        json.dump(stix_bundle(stix_objects), f, indent=2)

    print(f"[✓] Generated YARA, Sigma, and STIX rules in {out_dir}")

def main():
    parser = argparse.ArgumentParser(description="Auto Rule Generator from Logs/Alerts")
    parser.add_argument("--input", required=True, help="Path to file with alerts/logs")
    parser.add_argument("--out", default="results/ai_rules", help="Output directory")
    args = parser.parse_args()
    generate_rules(args.input, args.out)

if __name__ == "__main__":
    main()
