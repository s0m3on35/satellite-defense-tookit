import argparse
import json
import os
from datetime import datetime

RULES_OUT = "defense/generated_firewall_rules.txt"
LOG_DIR = "results"
RECON_PATH = "recon/agent_inventory.json"

os.makedirs("defense", exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

def generate_rule(ip, port, protocol, action):
    return f"{action.upper()} {protocol.upper()} FROM ANY TO {ip} PORT {port}"

def save_rules(rules):
    with open(RULES_OUT, "w") as f:
        for rule in rules:
            f.write(rule + "\n")

    log_file = os.path.join(LOG_DIR, f"firewall_gen_{datetime.now().strftime('%Y%m%d%H%M%S')}.log")
    with open(log_file, "w") as log:
        for rule in rules:
            log.write(rule + "\n")

def auto_from_recon():
    if not os.path.exists(RECON_PATH):
        print("[!] No recon data found.")
        return []

    with open(RECON_PATH, "r") as f:
        agents = json.load(f)

    rules = []
    for agent, data in agents.items():
        ip = data.get("ip")
        open_ports = data.get("open_ports", [])
        for port in open_ports:
            rules.append(generate_rule(ip, port, "tcp", "deny"))
    return rules

def main():
    parser = argparse.ArgumentParser(description="Generate basic firewall rules from inputs or recon")
    parser.add_argument("--ip", help="Target IP")
    parser.add_argument("--port", help="Port")
    parser.add_argument("--protocol", default="tcp", help="Protocol")
    parser.add_argument("--action", choices=["allow", "deny"], default="deny", help="Allow or Deny")
    parser.add_argument("--auto", action="store_true", help="Auto-generate rules from recon data")
    args = parser.parse_args()

    rules = []

    if args.auto:
        rules = auto_from_recon()
    else:
        if not args.ip or not args.port:
            print("[!] IP and Port required unless using --auto")
            return
        rules.append(generate_rule(args.ip, args.port, args.protocol, args.action))

    save_rules(rules)
    print(f"[+] {len(rules)} firewall rules generated and saved to {RULES_OUT}")

if __name__ == "__main__":
    main()
