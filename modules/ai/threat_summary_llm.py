# Ruta: modules/ai/threat_summary_llm.py

import os
import json
import argparse
import openai
from datetime import datetime

DEFAULT_PROMPT = """
You are a cybersecurity threat analyst. Summarize the following anomaly or threat detection log into two levels:
1. Executive Summary: Plain language for a non-technical audience.
2. Technical Summary: Include relevant threat details, potential MITRE techniques, affected systems, and indicators of compromise (IOCs) if available.

JSON Event:
""".strip()

def load_events(path):
    with open(path, 'r') as f:
        return json.load(f)

def summarize_event(event, api_key, model="gpt-4"):
    openai.api_key = api_key
    prompt = DEFAULT_PROMPT + "\n" + json.dumps(event, indent=2)

    try:
        response = openai.ChatCompletion.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert in satellite and embedded cybersecurity."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=700
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"[ERROR] {e}"

def export_summary(summary, output_path):
    with open(output_path, 'w') as f:
        f.write(summary)

def main():
    parser = argparse.ArgumentParser(description="Threat Summary Generator using LLMs")
    parser.add_argument("--input", required=True, help="Path to JSON file with telemetry or threat events")
    parser.add_argument("--output", default="reports/llm_summary.txt", help="Output file for summary")
    parser.add_argument("--model", default="gpt-4", help="LLM model to use (default: gpt-4)")
    args = parser.parse_args()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("[ERROR] OPENAI_API_KEY not set in environment")
        return

    os.makedirs("reports", exist_ok=True)
    events = load_events(args.input)

    if not events:
        print("[INFO] No events to summarize.")
        return

    combined_summary = f"# LLM Summary Report\nGenerated: {datetime.utcnow().isoformat()}\n\n"

    for i, event in enumerate(events):
        summary = summarize_event(event, api_key, args.model)
        combined_summary += f"## Event {i + 1}\n\n{summary}\n\n"

    export_summary(combined_summary, args.output)
    print(f"[✓] Summary exported to {args.output}")

if __name__ == "__main__":
    main()
