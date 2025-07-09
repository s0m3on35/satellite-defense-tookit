# Satellite Defense Toolkit

A modular real-time defense and forensics suite for GNSS, SATCOM, and aerospace-critical infrastructure. Detects spoofing, jamming, firmware manipulation, and telemetry anomalies. Includes threat analysis, C2 controls, integrity monitors, STIX integration, and a full operational dashboard.

---

## Key Modules (Selected)

| Category         | Module                                | Description |
|------------------|----------------------------------------|-------------|
| GNSS Defense     | `gnss_ai_anomaly_detector.py`         | Detects GNSS spoofing using Isolation Forest |
| RF Defense       | `rf_jammer_locator.py`                | SDR heatmap jammer localization |
| Firmware         | `firmware_watcher_agent.py`           | HMAC-based firmware integrity monitoring |
| Telemetry        | `telemetry_lstm_monitor.py`           | Detects anomalies via LSTM neural network |
| Dashboard        | `satellite_defense_toolkit_gui.py`    | Central command dashboard (WebSocket, GUI) |
| Advanced Analysis| `binary_diff_engine.py`               | Binary differential engine for firmware forensics |

---

## How to Use

Documentation is available in:

```
docs/wiki/
|- Overview.md
|- Anomaly_Detection.md
|- Firmware_Security.md
|- Configuration.md
|- index.html
```

---

## Full Module Categories

### Defense Modules

- `binary_integrity_watcher.py`
- `firewall_rule_generator.py`
- `firmware_integrity_watcher.py`
- `firmware_memory_shield.py`
- `firmware_rollback_protector.py`
- `firmware_signature_validator.py`
- `gnss_spoof_guard.py`
- `interface_integrity_monitor.py`
- `kernel_module_guard.py`
- `live_integrity_watcher.py`
- `ota_guard.py`
- `ota_stream_guard.py`
- `rf_injection_barrier.py`
- `secure_update_guard.py`
- `system_call_anomaly_watcher.py`
- `telemetry_guardian.py`

### Forensics Modules

- `firmware_timeline_builder.py`
- `memwatch_agent.py`
- `ota_packet_analyzer.py`

### Advanced Analysis

- `binary_diff_engine.py`
- `elf_section_analyzer.py`
- `firmware_cfg_exporter.py`
- `firmware_obfuscation_classifier.py`
- `firmware_recovery_toolkit.py`
- `heap_stack_pattern_scanner.py`
- `syscall_extractor.py`
- `dynamic_string_decoder.py`
- `forensic_event_correlator.py`

### Firmware Analysis

- `firmware_crypto_auditor.py`
- `firmware_pcap_export.py`
- `firmware_stix_export.py`
- `firmware_unpacker.py`
- `firmware_backdoor_scanner.py`

### GNSS/SATCOM Threat Simulation & Attacks

- `gnss_spoofer.py`
- `rf_jammer_dos.py`
- `satcom_c2_hijacker.py`
- `satellite_dish_aim_override.py`
- `telemetry_data_spoofer.py`
- `firmware_persistent_implant.py`
- `ota_firmware_injector.py`

### Intelligence / Threat Detection

- `stix_threat_matcher.py`
- `threat_feed_watcher.py`
- `firmware_cve_mapper.py`
- `zero_day_mapper.py`
- `mitre_mapper.py`

### AI / Anomaly Detection

- `entropy_analyzer.py`
- `entropy_stix_chain.py`
- `yara_firmware_scanner.py`
- `yara_mapper.py`
- `yara_stix_exporter.py`
- `telemetry_lstm_monitor.py`
- `gnss_ai_anomaly_detector.py`

### Copilot / C2 Control

- `copilot_ai.py`
- `agent_commander.py`
- `agent_fingerprint_logger.py`

### Dashboard / GUI

- `dashboard_ws_server.py`
- `ws_live_dashboard.py`
- `mapview_dashboard.py`
- `dashboard_log_viewer.html`
- `playback_panel.py`
- `firmware_gui_trigger.py`
- `login_server.py`
- `mitre_tracker.py`

### Visualization / Statistics

- `attack_frequency_heatmap.py`
- `event_visualizer.py`

---

## Documentation

Detailed usage and configuration available in:

```
docs/wiki/
|- Overview.md
|- Anomaly_Detection.md
|- Firmware_Security.md
|- Configuration.md
|- index.html
```

---

## GitHub Repository

Main repository and documentation:

https://github.com/s0m3on35/satellite-defense-tookit

---

## Usage Notice

This repository is NOT authorized for redistribution, commercial use, or forking without express written permission. All rights reserved.
