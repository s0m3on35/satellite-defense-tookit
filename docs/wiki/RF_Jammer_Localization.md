# RF Jammer Localization

This module detects and localizes radio frequency (RF) jamming attempts by scanning the spectrum and identifying high-entropy interference sources.

---

## 1. Overview

This component uses Software Defined Radio (SDR) hardware and statistical analysis to detect active RF jammers in the environment. It supports automated triangulation and anomaly classification.

---

## 2. Core Features

- **SDR Compatibility:** Works with RTL-SDR, HackRF, and BladeRF
- **Spectrum Scanning:** Detects wideband and narrowband interference
- **Entropy Analysis:** Measures spectral noise patterns over time
- **Heatmap Generation:** Produces signal strength maps for localization
- **WebSocket Alerts:** Triggers real-time notifications to the dashboard

---

## 3. Detection Workflow

1. **SDR Initialization**
   - Configure frequency sweep range (e.g., 850–950 MHz)
   - Set gain, sample rate, and dwell time

2. **Signal Capture**
   - Collect raw spectrum data using `rtl_power` or similar tools

3. **Entropy Calculation**
   - Measure deviation from baseline noise floor
   - Use z-score, Isolation Forest, or rolling average methods

4. **Localization**
   - Correlate multiple scans with GPS data
   - Output KML/heatmap or signal intensity histogram

5. **Alerting**
   - If threshold is crossed:
     - Log timestamp, frequency, entropy level
     - Send alert via WebSocket or webhook

---

## 4. Configuration Parameters

- `--range`: Frequency range (MHz)
- `--threshold`: Entropy anomaly threshold
- `--output`: Path to save results or heatmaps
- `--gps`: Enable GPS tagging
- `--realtime`: Stream alerts to dashboard

---

## 5. Use Cases

- Detect RF-based denial-of-service attacks
- Identify rogue transmitters in GNSS bands
- Monitor field environments for spectrum hygiene
- Validate SDR countermeasures in satellite testbeds

---

## 6. Integration Points

- Dashboard module for displaying real-time alerts
- STIX export module for reporting detected jamming patterns
- GNSS telemetry correlation engine for spoof/jam hybrid detection

---

> This module is mission-critical for defending against jamming attacks targeting GNSS, telemetry uplinks, and OTA channels.
