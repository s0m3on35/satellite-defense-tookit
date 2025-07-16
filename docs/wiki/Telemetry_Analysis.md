# Telemetry Analysis

This module enables the real-time and historical analysis of telemetry data from satellite systems, including onboard sensors and environmental indicators.

---

## 1. Overview

Telemetry analysis is critical for detecting hardware malfunctions, unexpected behavior, or possible tampering. This module supports local file parsing, live stream ingestion, and alert generation based on custom thresholds or ML models.

---

## 2. Supported Inputs

- CSV logs from onboard sensors
- Live telemetry over serial or IP (UDP/TCP)
- Simulated streams from test environments
- JSON-formatted telemetry packets

---

## 3. Analysis Features

### • Baseline Deviation Detection
Detects values that deviate from established norms using:
- Rolling mean and standard deviation
- Z-score and peak detection logic

### • Machine Learning Models
Supports models for pattern recognition and anomaly prediction:
- LSTM-based time series models
- Isolation Forest or Autoencoder approaches

### • Multi-Metric Monitoring
Simultaneous evaluation of:
- Voltage
- Temperature
- Radiation levels
- Uptime and CPU load

---

## 4. Visualization

- Real-time line plots with `matplotlib`
- Event-based spike highlighting
- Exportable PDF or PNG plots for each metric

---

## 5. Configuration Options

Defined in `config/config.yaml`, including:
- `telemetry_port`: e.g. `/dev/ttyUSB0` or `udp://0.0.0.0:9000`
- `metrics`: list of monitored telemetry fields
- `alert_threshold`: numeric threshold for triggering anomalies

---

## 6. Integration Points

- Feeds into the anomaly detector for deeper correlation
- Sends alerts to the dashboard via WebSocket
- Logs analysis results to `logs/telemetry/`

---

## 7. Roadmap

- Integration with real satellite ground station data feeds
- STIX-based threat enrichment based on correlated anomalies
- Dashboard widget for live multi-agent telemetry comparison
