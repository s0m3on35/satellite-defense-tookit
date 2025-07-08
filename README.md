# Satellite Defense Toolkit

![Banner](docs/wiki/banner.jpg)

> A modular, military-grade framework to monitor and defend GNSS, SATCOM, and space-connected infrastructure against spoofing, jamming, firmware tampering, OTA hijacking, telemetry anomalies, and advanced persistent threats.

---

## Key Features

- Live GNSS anomaly detection (spoofing, jamming, entropy shifts)
- OTA firmware stream integrity and implant monitoring
- Full telemetry validation (LSTM, schema, HMAC)
- AI-assisted threat classification and visual dashboards
- C2 spoofing, firmware implants, satellite dish aim override
- Web-based dashboard, STIX/TAXII support, Copilot integration

---

## Launch the Toolkit

```bash
./run_toolkit.sh
```

Or launch the dashboard WebSocket server manually:

```bash
python3 webgui/dashboard_ws_server.py
```

---

## Module Categories

### AI & Threat Intelligence

| Module | Description |
|--------|-------------|
| `gnss_ai_anomaly_detector.py` | Detects GNSS spoofing using Isolation Forest |
| `threat_classifier.py` | AI classification of anomalies from logs or signals |
| `stix_threat_matcher.py` | Maps detected indicators to STIX threat intelligence |
| `mitre_mapper.py` | Tags module findings to MITRE ATT&CK matrix |
| `copilot_ai.py` | GPT-based AI assistant for investigations |

---

### GNSS, RF & Telemetry Defense

| Module | Description |
|--------|-------------|
| `gnss_spoof_guard.py` | Validates GNSS signal consistency and source |
| `rf_injection_barrier.py` | Blocks unauthorized RF interference attempts |
| `telemetry_guardian.py` | Enforces telemetry schema and HMAC signature verification |
| `telemetry_lstm_monitor.py` | Detects telemetry anomalies using LSTM models |
| `rf_jammer_locator.py` | Maps jammers using SDR scans and heatmaps |
| `satcom_c2_spoof_detector.py` | Detects spoofed SATCOM command-and-control streams |

---

### Firmware Security & Hardening

| Module | Description |
|--------|-------------|
| `firmware_watcher_agent.py` | Monitors firmware binaries for unauthorized changes |
| `firmware_integrity_watcher.py` | Tracks cryptographic integrity of deployed firmware |
| `firmware_signature_validator.py` | Validates firmware signature metadata |
| `firmware_rollback_protector.py` | Detects and prevents firmware version downgrades |
| `firmware_memory_shield.py` | Guards runtime memory from firmware abuse |
| `firmware_crypto_auditor.py` | Detects weak or outdated cryptography in binaries |
| `firmware_pcap_export.py` | Exports firmware interactions as PCAP |
| `firmware_stix_export.py` | Converts firmware findings to STIX format |
| `firmware_unpacker.py` | Extracts and analyzes embedded firmware contents |
| `firmware_backdoor_scanner.py` | Scans binaries for static backdoor patterns |

---

### OTA Monitoring & Protection

| Module | Description |
|--------|-------------|
| `ota_guard.py` | Enforces OTA update origin and integrity |
| `ota_stream_guard.py` | Detects anomalies in OTA firmware streams |
| `secure_update_guard.py` | Confirms authenticity of update chain-of-trust |
| `ota_stream_monitor.py` | Logs and analyzes live OTA firmware sessions |
| `ota_firmware_injector.py` | Red-team module to simulate OTA firmware injection |

---

### Active Defense & Hardening

| Module | Description |
|--------|-------------|
| `firewall_rule_generator.py` | Auto-generates defensive iptables rules |
| `binary_integrity_watcher.py` | Detects tampering of critical system binaries |
| `live_integrity_watcher.py` | Real-time file integrity monitor |
| `system_call_anomaly_watcher.py` | Watches for syscall-based tampering or rootkits |
| `interface_integrity_monitor.py` | Guards interfaces from silent misconfig or spoofing |
| `kernel_module_guard.py` | Detects unauthorized kernel module insertions |
| `airgap_mode.py` | Enforces offline isolation during sensitive operations |

---

### Offensive/Red Team Modules

| Module | Description |
|--------|-------------|
| `firmware_persistent_implant.py` | Deploys a simulated persistent implant in firmware |
| `gnss_spoofer.py` | Simulates GNSS spoofing payloads |
| `rf_jammer_dos.py` | Launches DoS against GNSS bands |
| `satcom_c2_hijacker.py` | Intercepts and alters satellite C2 messages |
| `satellite_dish_aim_override.py` | Alters satellite dish angle via override interface |
| `telemetry_data_spoofer.py` | Injects falsified telemetry packets |
| `payload_launcher.py` | Executes chained red team payloads |

---

### Forensics & Investigation

| Module | Description |
|--------|-------------|
| `firmware_timeline_builder.py` | Generates timeline of firmware events and anomalies |
| `memwatch_agent.py` | Extracts volatile memory regions for inspection |
| `ota_packet_analyzer.py` | Analyzes OTA packets and streams |
| `entropy_analyzer.py` | Calculates firmware entropy for hidden payload detection |
| `entropy_stix_chain.py` | Chains entropy findings to STIX |
| `yara_firmware_scanner.py` | Runs YARA rules against firmware |
| `yara_mapper.py` | Links YARA hits to malware family or tags |
| `yara_stix_exporter.py` | Converts YARA hits into STIX for threat intel feeds |

---

### Visualization, Dashboard, and Logs

| Module | Description |
|--------|-------------|
| `event_visualizer.py` | Graphs signals and event correlations |
| `mapview_dashboard.py` | Global map of active agents and alerts |
| `ws_live_dashboard.py` | Live dashboard via WebSocket streams |
| `dashboard_ws_server.py` | WebSocket server backend for dashboard |
| `dashboard_log_viewer.html` | Log viewer HTML for browser UI |
| `firmware_gui_trigger.py` | GUI button for firmware action injection |
| `playback_panel.py` | Replay mode panel for simulated sessions |
| `login_server.py` | Authentication backend for dashboard |
| `satellite_defense_toolkit_gui.py` | Full interactive GUI launcher |

---

### C2, Simulation, Stats, Others

| Module | Description |
|--------|-------------|
| `agent_commander.py` | Issues commands to active agents |
| `agent_fingerprint_logger.py` | Tracks unique agent metadata |
| `gnss_spoofer_sim.py` | GNSS spoofing simulator module |
| `attack_frequency_heatmap.py` | Heatmap of attack attempts or signals |
| `zero_day_mapper.py` | Correlates findings with possible 0-days |
| `threat_feed_watcher.py` | Live watcher for external threat intelligence feeds |

---

## Directory Structure

```
satellite-defense-toolkit/
âââ config/                  # Configuration files
âââ core/                   # Core utilities (audit, logging, security)
âââ docs/wiki/              # Markdown documentation and guides
âââ logs/                   # Live logs (dashboard, modules)
âââ modules/                # Categorized defensive/offensive modules
âââ results/                # Scan results, STIX bundles, YARA hits
âââ webgui/                 # Dashboard, login, visual frontend
âââ run_toolkit.sh          # Primary launcher script
âââ setup.py                # Install dependencies (optional)
âââ README.md               # This file
```

---

## GitHub Pages & Documentation

Documentation and diagrams:

**https://github.com/s0m3on35/satellite-defense-tookit**

---

## License

This project is licensed under the MIT License.

---

## Usage Notice

This repository is strictly prohibited from public redistribution, forking, or derivative use without explicit permission. All rights reserved by the author.
