
# Satellite Defense Toolkit: Lab Setup Guide

This guide provides step-by-step instructions to build and operate a full testing lab for the Satellite Defense Toolkit. It supports modules for firmware analysis, AI threat classification, OTA replay detection, GNSS spoofing simulation, live dashboards, and memory forensics.

## 1. Requirements

### Host Workstation (Analyst Node)
- Operating System: Ubuntu or Debian Linux
- Minimum RAM: 16 GB
- Required Tools: Python 3, Docker, QEMU, RTL-SDR or HackRF (optional for RF/GNSS testing)

### Target Devices (for testing embedded and OTA modules)
- Raspberry Pi (Zero W or 4)
- ESP32 or STM32 microcontroller dev board
- UART-to-USB or JTAG debugger for memory access
- RTL-SDR USB dongle or HackRF One for SDR modules

## 2. Wiring Summary

### UART Connection from Raspberry Pi to Host
| Pi GPIO | Wire Color | USB-UART Pin |
|---------|------------|---------------|
| GPIO 6  | Black      | GND           |
| GPIO 8  | Green      | TX            |
| GPIO 10 | White      | RX            |

Connect USB end to the analyst workstation. Use this to simulate live memory access for `memwatch_agent.py`.

## 3. Installation Steps

### Step 1: Clone the Toolkit
```bash
git clone https://github.com/your-org/satellite-defense-toolkit.git
cd satellite-defense-toolkit
```

### Step 2: Run Lab Setup Script
```bash
chmod +x lab_setup.sh
./lab_setup.sh
```

This script installs dependencies, creates necessary directories, and generates test data including:
- Sample logs
- OTA stream binaries
- Memory simulation files
- MITRE map example

## 4. Resulting Folder Structure
```
satellite-defense-toolkit/
|-- lab_setup.sh
|-- run_toolkit.sh
|-- modules/
|-- webgui/
|-- copilot/
|-- results/
|   |-- mitre_map.json
|   |-- stix_ota_alert.json
|-- logs/
|   |-- dashboard/
|   |   |-- dashboard_stream.log
|   |-- ota_streams/
|       |-- ota_stream.bin
|-- sandbox/
```

## 5. Module Testing Reference

| Module | Command | Input |
|--------|---------|-------|
| `memwatch_agent.py` | `python3 memwatch_agent.py --mem-path /tmp/mem.bin --watch` | Simulated memory |
| `firmware_crypto_auditor.py` | `python3 firmware_crypto_auditor.py --firmware firmware.bin` | Binary firmware |
| `payload_emulator.py` | `python3 payload_emulator.py --bin firmware.elf --mode qemu` | ELF binary |
| `gnss_spoofer_sim.py` | `python3 gnss_spoofer_sim.py --lat 37.77 --lon -122.41` | Fake NMEA GNSS stream |
| `ota_stream_monitor.py` | `python3 ota_stream_monitor.py --stream logs/ota_streams/ota_stream.bin` | OTA replay stream |
| `threat_classifier.py` | `python3 threat_classifier.py --log logs/sample.log` | Log file |
| `dashboard_ws_server.py` | `python3 dashboard_ws_server.py` | Starts WebSocket server |
| `login_server.py` | `python3 login_server.py` then visit `http://localhost:8080` | Web login panel |
| `mitre_tracker.py` | `python3 mitre_tracker.py` then visit `http://localhost:8090` | MITRE tactic viewer |
| `playback_panel.py` | `python3 playback_panel.py --target ws://localhost:8765` | Replay alerts |
| `copilot_chat.py` | `python3 copilot_chat.py --q "What is T1059?"` | GPT Copilot query |

## 6. Example: OTA Replay Detection

1. Generate simulated OTA stream:
```bash
dd if=/dev/urandom of=logs/ota_streams/ota_stream.bin bs=4K count=10
```

2. Start monitoring:
```bash
python3 modules/firmware/ota_stream_monitor.py --stream logs/ota_streams/ota_stream.bin
```

3. Simulate a replayed chunk:
```bash
cat logs/ota_streams/ota_stream.bin >> logs/ota_streams/ota_stream.bin
```

4. Check `results/stix_ota_alert.json` for auto-generated alert.

## 7. Dashboard Access

- WebSocket live stream: `ws://localhost:8765`
- Login interface: `http://localhost:8080`
- MITRE ATT&CK tracker: `http://localhost:8090`

## 8. Recommended Practices

- Use `tmux` or `screen` to run multiple modules in parallel
- Export logs using `audit_exporter.py`
- Monitor `logs/dashboard/dashboard_stream.log` for live data

## 9. Troubleshooting

- Ensure all `logs/` and `results/` directories exist
- Use `--help` with any module for argument options
- For Copilot module, ensure your OpenAI key is configured in environment or script
