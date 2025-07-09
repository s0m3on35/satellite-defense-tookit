# modules/ai/gpt_remote_analyzer.py

import os
import json
import argparse
import requests
from datetime import datetime

DEFAULT_SYSTEM_PROMPT = """
You are a cybersecurity analyst AI assistant. Given a security alert or log entry, analyze and return:
- Risk level (Low, Medium, High, Critical)
- Description (What this alert may represent)
- Suggested action (e.g., investigate source IP, isolate device, etc.)
- If possible, map to MITRE ATT&CK technique
Return only JSON.
"""

def call_openai(prompt, apikey, model="gpt-4", system_prompt=DEFAULT_SYSTEM_PROMPT):
    headers = {
        "Authorization": f"Bearer {apikey}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt.strip()},
            {"role": "user", "content": prompt.strip()}
        ],
        "temperature": 0.2
    }
    try:
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        content = result["choices"][0]["message"]["content"]
        return json.loads(content)
    except Exception as e:
        print(f"[!] API request failed: {e}")
        return None

def analyze_file(path, apikey, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    results = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            print(f"[>] Analyzing: {line[:100]}...")
            result = call_openai(line, apikey)
            if result:
                result["timestamp"] = datetime.utcnow().isoformat()
                result["original_entry"] = line
                results.append(result)

    out_path = os.path.join(out_dir, "gpt_analysis_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[✓] {len(results)} entries analyzed. Results saved to {out_path}")

def main():
    parser = argparse.ArgumentParser(description="LLM-based Remote Threat Analyzer")
    parser.add_argument("--log", required=True, help="Path to log file (one alert per line)")
    parser.add_argument("--key", required=True, help="OpenAI API key")
    parser.add_argument("--out", default="results/gpt_analysis", help="Output directory")
    args = parser.parse_args()

    analyze_file(args.log, args.key, args.out)

if __name__ == "__main__":
    main()
