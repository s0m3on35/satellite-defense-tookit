#  Satellite Defense Toolkit

!(docs/wiki/banner.jpg)

> A modular toolkit to monitor and defend GNSS, SATCOM, and space-connected infrastructure against spoofing, jamming, firmware tampering, and telemetry anomalies.

---

## Key Modules

| Module | Description |
|--------|-------------|
| `gnss_ai_anomaly_detector.py` | Detects spoofing using Isolation Forest on live GNSS/NMEA streams |
| `rf_jammer_locator.py` | Locates active GNSS-band jammers using SDR heatmaps |
| `firmware_watcher_agent.py` | Monitors firmware integrity using HMAC hashing |
| `telemetry_lstm_monitor.py` | Identifies anomalies in satellite telemetry with LSTM models |
| `satellite_defense_toolkit_launcher.py` | Main interactive menu and logging dashboard |


---

##  How to Use

```bash
python3 satellite_defense_toolkit_launcher.py
```

Use the launcher to interactively configure modules, analyze logs, and export results.

---

## Folder Structure

```
satellite-defense-toolkit/
├── config/                  # YAML-based config files
├── modules/                 # All core Python scripts
├── logs/                    # Execution logs
├── results/                 # Scan/output results
├── docs/wiki/               # Documentation + Diagrams
```

---

##  License

This project is licensed under the MIT License.

---

##  GitHub Pages

This repository includes diagrams and documentation hosted at:

**(([https://github.com/s0m3on35/satellite-defense-tookit](https://github.com/s0m3on35/satellite-defense-tookit)))**

---
## Usage Notice
This repository is NOT authorized for public redistribution, forking, or reuse. Contact the author for permissions.

