 Telemetry Monitoring

This module provides real-time monitoring of satellite and ground system telemetry data. It detects deviations from normal operational ranges and flags abnormal behavior for further investigation.

---

## 1. Overview

Telemetry data is a vital stream of operational information, including temperature, voltage, current, and subsystem statuses. This module continuously monitors these values and identifies suspicious fluctuations using statistical and ML-based methods.

---

## 2. Features

- **Signal Health Checks**: Detects silent sensors, missing fields, or dropout patterns.
- **Rolling Mean Z-Score**: Real-time anomaly detection based on configurable standard deviation thresholds.
- **Live Dashboard Updates**: Sends alerts to the GUI dashboard with agent tag and metric details.
- **Sensor Profile Learning**: Learns baseline values over time to adjust dynamically.

---

## 3. Supported Inputs

- JSON streams over MQTT or HTTP
- CSV-formatted telemetry logs
- Direct input from local sensors or serial interfaces

---

## 4. Anomaly Detection Methods

- **Rolling Mean & Standard Deviation**: Detects outliers based on learned average behavior.
- **Gradient Drift**: Detects slow deviations (e.g., rising temperature over time).
- **AI-Based Classification (Optional)**: Uses LSTM or SVM models for classifying anomalies with context.

---

## 5. Configuration

This module uses shared config values from `config/config.yaml`:

```yaml
threshold: 3.0
duration: 15
agent_id: sat-ground-001
alert_webhook: http://localhost:8080/alert
```

CLI arguments (optional):
- `--input`: Path to telemetry file or stream URI
- `--threshold`: Override default anomaly threshold
- `--log`: Enable local JSONL logging of anomalies

---

## 6. Output

- Alert log: `logs/anomalies/telemetry_alerts.jsonl`
- Optional visual graphs: `results/telemetry_plots/`
- WebSocket alert sent if dashboard active

---

## 7. Use Cases

- Onboard health monitoring for LEO/GEO satellites
- Ground system power and RF station metrics
- Long-duration test monitoring for hardware simulations

---

## 8. Future Enhancements

- AI model training from real-world labeled datasets
- Integration with satellite digital twins
- STIX enrichment for anomaly correlation
