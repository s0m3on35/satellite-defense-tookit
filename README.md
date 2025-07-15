# Satellite Defense Toolkit

## Overview

The Satellite Defense Toolkit is a comprehensive suite for securing, analyzing, and emulating threats against satellite and aerospace systems. It supports red teaming, blue teaming, and forensic operations with a modular design, AI-assisted components, and a fully integrated GUI/CLI/WebSocket dashboard system.

---

## Features

- Real-time telemetry analysis
- AI-based threat classification and Copilot integration
- GNSS spoof detection and spoofing emulation
- Firmware implant, OTA injection, and rollback defense
- Forensic memory, OTA, and timeline analysis
- Full WebSocket-based dashboard and agent visibility
- GUI and CLI toolkits with audit and logging support
- STIX/TAXII threat export and interoperability

---

## Directory Structure

```bash
satellite-defense-toolkit/
├── config/                  # Configuration files (agents, targets)
├── core/                    # Core utilities (audit, logging, security)
├── docs/wiki/               # Markdown documentation and guides
├── logs/                    # Execution logs and dashboard logs
├── modules/                 # Categorized modules
│   ├── ai/                  # AI-assisted classification and summaries
│   ├── analysis/            # Telemetry, signal, and traffic analysis
│   ├── attacks/             # Offensive and red team payloads
│   ├── c2/                  # Command-and-control modules
│   ├── copilot/             # Copilot automation and advisory modules
│   ├── dashboard/           # Dashboard internal services
│   ├── defense/             # Hardening and anomaly prevention
│   ├── firmware/            # Firmware validation, implants, rollback
│   ├── forensics/           # OTA, firmware, memory analysis
│   ├── intel/               # Threat intel and enrichment
│   ├── simulation/          # GNSS spoofing, telemetry simulation
│   ├── stats/               # Metrics, timelines, heatmaps
│   └── visualization/       # Graphs, maps, visual exports
├── results/                 # Generated results, STIX, summaries
├── webgui/                  # GUI and dashboard WebSocket interface
├── satellite_defense_toolkit_gui.py   # Main GUI launcher
├── satellite_defense_toolkit_cli.py   # Command-line interface
├── run_toolkit.sh           # Main launcher script
├── setup.py                 # Install and entrypoint definition
└── README.md                # This file
```

---

## Usage

### GUI Mode

```bash
python3 satellite_defense_toolkit_gui.py
```

- Launches a full GUI with tabbed module browsing, execution logs, agent selector, and audit trail.

### CLI Mode

```bash
python3 satellite_defense_toolkit_cli.py
```

- Interactive CLI menu to run or chain modules, view logs, and select agents.

### Web Dashboard

```bash
python3 webgui/dashboard_ws_server.py
```

- Starts the WebSocket server to receive events from GUI/CLI and display real-time module execution, agent metrics, logs, and visual alerts.

---

## Installation

```bash
pip install -r requirements.txt
```

Or using the included setup script:

```bash
python3 setup.py install
```

---

## Requirements

- Python 3.8+
- Linux (preferred), macOS (partial support)
- Dependencies listed in `setup.py`, including:
  - `stix2`, `websocket-client`, `flask`, `flask-socketio`
  - `tensorflow`, `torch`, `transformers`, `psutil`
  - `opencv-python`, `matplotlib`, `scapy`, `yara-python`
  - `aioblescan`, `blesuite`, `vosk`, `pyttsx3`

---

## Logging and Audit

- Logs: Stored in `logs/`
- Audit trail JSONL: All module executions logged with timestamp, path, and agent
- CLI logs: `logs/cli_audit_log.jsonl`
- GUI logs: `logs/audit_trail.jsonl`

---

## STIX/TAXII Integration

- Outputs from several modules include STIX bundles (`results/stix_bundle.json`)
- Can be exported to external TAXII servers for threat sharing

---

## Agent Management

- All agents are listed in `config/agent_inventory.json`
- Agents can be selected from the GUI or CLI when executing modules
- Dashboard receives events with agent context for mapping

---

/`

---

## License

MIT License – See `LICENSE.md`

---

## Author

Maintained by the Satellite Offensive Research Division lead by someone (D)

GitHub: [https://github.com/s0m3on35/satellite-defense-toolkit](https://github.com/s0m3on35/satellite-defense-toolkit)
