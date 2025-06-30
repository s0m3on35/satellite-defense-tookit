import os
import json
import argparse
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from collections import defaultdict

def load_json_events(paths):
    events = []
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    events.extend(data)
                else:
                    events.append(data)
            except Exception as e:
                print(f"[!] Failed to load {path}: {e}")
    return events

def classify_event(event):
    if "z_score" in event:
        return "Telemetry"
    elif "gnss_offset" in event or "spoof_detected" in event:
        return "GNSS"
    elif "kill_chain" in event:
        return "Firmware"
    return "Unknown"

def generate_timeline(events, output_path="results/event_timeline.png"):
    fig, ax = plt.subplots(figsize=(12, 6))
    categorized = defaultdict(list)

    for event in events:
        time = datetime.fromisoformat(event.get("timestamp") or event.get("time") or datetime.now().isoformat())
        category = classify_event(event)
        categorized[category].append(time)

    for label, times in categorized.items():
        ax.plot(times, [label] * len(times), 'o', label=label)

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.xticks(rotation=45)
    plt.title("Satellite Defense Event Timeline")
    plt.xlabel("Timestamp")
    plt.ylabel("Event Type")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path)
    print(f"[+] Timeline plot saved to {output_path}")

def generate_anomaly_cluster(events, output_path="results/anomaly_cluster_plot.png"):
    fig, ax = plt.subplots(figsize=(10, 5))
    telem = [(e["point_id"], e["z_score"]) for e in events if classify_event(e) == "Telemetry"]

    if not telem:
        print("[!] No telemetry events found for clustering.")
        return

    ids, scores = zip(*telem)
    ax.scatter(ids, scores, c='red', label="Z-Score Anomalies")
    plt.title("Telemetry Anomaly Cluster")
    plt.xlabel("Point ID")
    plt.ylabel("Z-Score")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path)
    print(f"[+] Cluster plot saved to {output_path}")

def generate_ttp_matrix(events, output_path="results/ttp_matrix.png"):
    matrix = defaultdict(int)
    for e in events:
        if "kill_chain" in e and "mapped_ttp" in e:
            matrix[(e["kill_chain"], e["mapped_ttp"])] += 1

    if not matrix:
        print("[!] No STIX/TTP mappings found.")
        return

    labels = sorted(set(k[1] for k in matrix))
    rows = sorted(set(k[0] for k in matrix))
    data = [[matrix.get((r, c), 0) for c in labels] for r in rows]

    fig, ax = plt.subplots(figsize=(12, 6))
    cax = ax.matshow(data, cmap="Reds")
    plt.colorbar(cax)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(rows)
    plt.title("TTP Kill Chain Matrix")
    plt.tight_layout()
    plt.savefig(output_path)
    print(f"[+] TTP matrix saved to {output_path}")

def main(args):
    os.makedirs("results", exist_ok=True)
    event_paths = [
        "results/telemetry_anomalies.json",
        "results/gnss_spoof_log.json",
        "results/stix_firmware_alert.json",
        "reports/telemetry_anomalies_stix.json"
    ]
    events = load_json_events(event_paths)
    print(f"[+] Loaded {len(events)} events")

    if args.timeline:
        generate_timeline(events)
    if args.cluster:
        generate_anomaly_cluster(events)
    if args.ttp_matrix:
        generate_ttp_matrix(events)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Satellite Defense Event Visualizer")
    parser.add_argument("--timeline", action="store_true", help="Generate timeline of events")
    parser.add_argument("--cluster", action="store_true", help="Generate anomaly cluster plot")
    parser.add_argument("--ttp-matrix", action="store_true", help="Generate STIX TTP matrix")
    args = parser.parse_args()
    main(args)
