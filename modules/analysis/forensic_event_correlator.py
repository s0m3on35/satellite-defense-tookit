#!/usr/bin/env python3
# modules/analysis/forensic_event_correlator.py

import argparse
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def load_json(file_path):
    if not file_path or not Path(file_path).is_file():
        return []
    with open(file_path, 'r') as f:
        return json.load(f)

def correlate_events(entropy_data, yara_data, syscall_data, string_data):
    timeline = []
    stix = []

    def ts():
        return datetime.utcnow().isoformat() + "Z"

    for region in entropy_data:
        timeline.append({
            "timestamp": ts(),
            "type": "high_entropy_region",
            "details": region
        })

    for hit in yara_data:
        timeline.append({
            "timestamp": ts(),
            "type": "yara_hit",
            "details": hit
        })
        stix.append({
            "type": "indicator",
            "id": f"indicator--yara-{hit.get('rule', 'unknown')}-{hit.get('offset', 'x')}",
            "pattern": f"[file:hashes.'SHA-256' = '{hit.get('sha256', '')}']",
            "created": ts(),
            "labels": ["yara-match"]
        })

    for sc in syscall_data.get("details", []):
        timeline.append({
            "timestamp": ts(),
            "type": "syscall_detected",
            "details": sc
        })

    for decoded in string_data:
        for dtype, val in decoded.get("decodings", {}).items():
            timeline.append({
                "timestamp": ts(),
                "type": "decoded_string",
                "method": dtype,
                "original": decoded.get("original"),
                "decoded": val
            })

    return timeline, {"type": "bundle", "id": "bundle--correlated-events", "objects": stix}

def save_outputs(timeline, stix_bundle, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(out_dir / "event_timeline.json", "w") as f:
        json.dump(timeline, f, indent=2)

    with open(out_dir / "correlated_bundle.stix.json", "w") as f:
        json.dump(stix_bundle, f, indent=2)

    print(f"[+] Timeline and STIX bundle saved to: {out_dir}")

def main():
    parser = argparse.ArgumentParser(description="Forensic Event Correlator (Military-Grade Timeline Generator)")
    parser.add_argument("--entropy", help="Path to entropy scan JSON report")
    parser.add_argument("--yara", help="Path to YARA scan JSON report")
    parser.add_argument("--syscalls", help="Path to syscall extractor JSON report")
    parser.add_argument("--strings", help="Path to decoded string JSON report")
    parser.add_argument("-o", "--output", required=True, help="Output directory for timeline and STIX bundle")
    args = parser.parse_args()

    entropy_data = load_json(args.entropy)
    yara_data = load_json(args.yara)
    syscall_data = load_json(args.syscalls)
    string_data = load_json(args.strings)

    timeline, stix_bundle = correlate_events(entropy_data, yara_data, syscall_data, string_data)
    save_outputs(timeline, stix_bundle, args.output)

if __name__ == "__main__":
    main()
