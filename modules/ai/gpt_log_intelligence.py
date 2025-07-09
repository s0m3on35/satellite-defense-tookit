# modules/ai/gpt_log_intelligence.py

import argparse
import os
import json
from datetime import datetime
from transformers import pipeline
from pathlib import Path

MITRE_MAPPING = {
    "c2": "Command and Control",
    "anomaly": "Collection",
    "login": "Initial Access",
    "rf": "Reconnaissance",
    "ota": "Execution",
    "firmware": "Persistence",
    "gnss": "Defense Evasion"
}

def classify_mitre(text):
    for key, ttp in MITRE_MAPPING.items():
        if key.lower() in text.lower():
            return ttp
    return "Uncategorized"

def analyze_log_entry(entry, summarizer):
    summary = summarizer(entry, max_length=50, min_length=10, do_sample=False)[0]['summary_text']
    mitre_phase = classify_mitre(entry)
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "original": entry.strip(),
        "summary": summary,
        "mitre": mitre_phase
    }

def process_log_file(file_path, output_dir):
    summarizer = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6")

    with open(file_path, 'r') as f:
        lines = f.readlines()

    results = []
    for line in lines:
        if line.strip():
            result = analyze_log_entry(line.strip(), summarizer)
            results.append(result)

    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, "log_analysis.json"), 'w') as f:
        json.dump(results, f, indent=2)

    with open(os.path.join(output_dir, "log_summary_report.md"), 'w') as f:
        for r in results:
            f.write(f"- **Time**: {r['timestamp']} | **MITRE**: {r['mitre']}\n")
            f.write(f"  - **Summary**: {r['summary']}\n")
            f.write(f"  - **Original**: `{r['original']}`\n\n")

    print(f"[✓] Processed {len(results)} entries — reports saved to {output_dir}/")

def main():
    parser = argparse.ArgumentParser(description="AI-Powered Log Intelligence Analyzer")
    parser.add_argument("--log", required=True, help="Path to log or alert file (JSON or text)")
    parser.add_argument("--out", default="reports/ai_log_analysis", help="Output directory")
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"[!] File not found: {log_path}")
        return

    if log_path.suffix == ".json":
        with open(log_path, "r") as f:
            entries = [json.dumps(e) for e in json.load(f)]
        tmp_txt = "tmp_log_input.txt"
        with open(tmp_txt, "w") as f:
            f.write("\n".join(entries))
        process_log_file(tmp_txt, args.out)
        os.remove(tmp_txt)
    else:
        process_log_file(args.log, args.out)

if __name__ == "__main__":
    main()
