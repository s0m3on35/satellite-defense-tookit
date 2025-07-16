# GNSS Spoofing Detection

This module is designed to identify and mitigate spoofing attempts targeting Global Navigation Satellite Systems (GNSS). It monitors signal characteristics, timing, and behavior patterns to detect spoofed or manipulated GNSS data.

---

## 1. Detection Techniques

### • Signal Strength & Noise Anomalies
- Detects sudden jumps in SNR (Signal-to-Noise Ratio)
- Identifies inconsistencies across satellite channels

### • Position Drift Monitoring
- Flags rapid or unrealistic location shifts
- Validates satellite geometry (DOP) against expected norms

### • Timestamp Integrity
- Checks for backward time jumps or time discontinuities
- Uses reference timing from internal clocks or external NTP sources

### • Doppler Shift Verification
- Compares observed signal Doppler shift with expected satellite motion

---

## 2. Modes of Operation

- **Passive Mode**: Observes existing GNSS signals and evaluates anomalies
- **Active Mitigation**: Optionally disables location-dependent logic if spoof detected

---

## 3. Configuration Parameters

- `snr_threshold`: Minimum acceptable SNR deviation to raise alert
- `doppler_tolerance`: Allowed deviation from predicted Doppler shift
- `drift_limit`: Max allowed position drift per second (meters)
- `ntp_sync`: Enable/disable NTP-based time validation

---

## 4. Output

- Logs detailed spoof detection events to `logs/gnss_alerts/`
- Can emit real-time alerts to WebSocket dashboard
- Optionally generates STIX indicators upon confirmed spoof attempts

---

## 5. Integration & Usage

- Integrated with `dashboard_ws_server.py` for live visualization
- Can auto-trigger forensic capture or defensive fallback modules
- Compatible with SDRs and hardware GPS receivers

---

## 6. Future Enhancements

- Cross-correlation with RF signal databases
- GNSS fingerprinting for satellite consistency validation
- Integration with GNSS simulators for red team scenarios
