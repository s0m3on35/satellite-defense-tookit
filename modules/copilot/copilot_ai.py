import json
import os
import argparse
import random
import re
import platform
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

KNOWLEDGE_PATHS = [
    "results/telemetry_anomalies.json",
    "reports/firmware_report.md",
    "logs/telemetry_monitor.log",
    "logs/firmware_stix.log",
    "recon/agent_inventory.json"
]

RESPONSE_TEMPLATES = {
    "anomaly": "Based on the anomaly detected at point {point_id}, a z-score of {z_score} suggests {recommendation}.",
    "firmware": "Firmware hash mismatch detected: {hash}. Possible cause: {cause}. Recommend: {action}.",
    "agent": "Agent {id} reported {count} telemetry anomalies. Suggested next step: {action}."
}

ACTIONS = [
    "Initiate firmware integrity re-scan",
    "Trigger live PCAP capture",
    "Export to STIX and notify command",
    "Run hash comparison on new firmware file",
    "Send live alert to dashboard"
]

def random_recommendation():
    return random.choice(ACTIONS)

def extract_anomaly_insight(file_path):
    with open(file_path) as f:
        data = json.load(f)
        if not data:
            return "No telemetry anomalies found."
        latest = data[-1]
        return RESPONSE_TEMPLATES["anomaly"].format(
            point_id=latest["point_id"],
            z_score=round(latest["z_score"], 2),
            recommendation=random_recommendation()
        )

def extract_firmware_insight(file_path):
    with open(file_path) as f:
        for line in f:
            if "hash mismatch" in line.lower():
                return RESPONSE_TEMPLATES["firmware"].format(
                    hash="SHA256 mismatch",
                    cause="tampering or OTA corruption",
                    action="investigate source of update"
                )
    return "No firmware hash alerts found."

def extract_agent_insight(file_path):
    with open(file_path) as f:
        agents = json.load(f)
        responses = []
        for aid, ainfo in agents.items():
            count = len(ainfo.get("telemetry", []))
            if count > 0:
                responses.append(RESPONSE_TEMPLATES["agent"].format(
                    id=aid,
                    count=count,
                    action=random_recommendation()
                ))
        return "\n".join(responses) if responses else "All agents nominal."

def ai_answer(query):
    if "anomaly" in query or "telemetry" in query:
        return extract_anomaly_insight("results/telemetry_anomalies.json")
    elif "firmware" in query:
        return extract_firmware_insight("logs/firmware_stix.log")
    elif "agent" in query:
        return extract_agent_insight("recon/agent_inventory.json")
    elif "recommend" in query or "suggest" in query:
        return f"Suggested action: {random_recommendation()}"
    else:
        return "No relevant data found. Try asking about 'anomalies', 'firmware', or 'agent status'."

def interactive_mode():
    console.print(Panel.fit("Satellite Defense Copilot CLI"))
    while True:
        try:
            query = Prompt.ask("Ask Copilot")
            if query.lower() in ["exit", "quit"]:
                console.print("[*] Copilot session ended.")
                break
            answer = ai_answer(query)
            console.print(Panel.fit(answer, title="Copilot"))
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Copilot AI CLI Assistant")
    parser.add_argument("--query", help="Ask Copilot directly via CLI")
    args = parser.parse_args()

    if args.query:
        result = ai_answer(args.query)
        print(result)
    else:
        interactive_mode()
