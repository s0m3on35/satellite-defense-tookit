# GNSS Spoof Detection

This module identifies potential spoofing attempts against GNSS (Global Navigation Satellite System) receivers by analyzing signal characteristics and applying anomaly detection techniques.

---

## 1. Overview

GNSS spoofing attacks attempt to deceive receivers with false satellite signals. This module is designed to detect such behavior in real time and provide actionable intelligence for mitigation.

---

## 2. Detection Techniques

- **Signal Strength Deviation**
  - Detects unusually strong signals inconsistent with expected satellite power levels.

- **Satellite ID Anomalies**
  - Flags duplicated or unknown satellite IDs not matching almanac data.

- **Time/Location Drift**
  - Compares GNSS-reported location/time to ground truth or expected paths.

- **Phase and Doppler Shift Monitoring**
  - Detects irregularities in satellite movement patterns.

- **Machine Learning Integration**
  - Isolation Forest and custom models applied over telemetry and GNSS vectors.

---

## 3. Output and Logging

- Logs anomalies to `logs/gnss_spoof/`
- Generates alert JSON payloads for dashboard and Copilot modules
- Supports STIX 2.1 export for external correlation

---

## 4. Configuration Parameters

Available via `config/config.yaml`:

```yaml
gnss_poll_interval: 5            # Seconds between GNSS snapshots
spoof_detection_threshold: 0.8   # Anomaly score threshold (0â1 scale)
use_isolation_forest: true
expected_location:
  lat: 43.3615
  lon: -8.4115
  radius: 200                    # Meters
```

---

## 5. Integration Points

- Live map overlay on dashboard
- Cross-reference with RF jammer signals
- Auto-chain to telemetry anomaly detection or mitigation scripts

---

## 6. Future Roadmap

- Kalman filter integration for smoother drift detection
- Differential GNSS comparison with trusted base stations
- GNSS-to-RTK comparison module
- Export STIX TTPs for known spoofing kits
