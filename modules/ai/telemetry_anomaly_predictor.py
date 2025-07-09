# modules/ai/telemetry_anomaly_predictor.py

import argparse
import os
import json
import numpy as np
import joblib
from keras.models import load_model, Sequential
from keras.layers import LSTM, Dense
from sklearn.preprocessing import MinMaxScaler
from datetime import datetime
import matplotlib.pyplot as plt

def simulate_future_telemetry(n_points=200):
    normal = np.random.normal(0, 1, (n_points, 1))
    spike = np.random.normal(6, 0.4, (5, 1))
    data = np.vstack([normal, spike])
    return data.flatten()

def prepare_data(data, look_back):
    scaler = MinMaxScaler()
    data_scaled = scaler.fit_transform(data.reshape(-1, 1))
    X = []
    for i in range(len(data_scaled) - look_back):
        X.append(data_scaled[i:i+look_back])
    return np.array(X), scaler

def train_model(data, look_back):
    X, scaler = prepare_data(data, look_back)
    y = data[look_back:]

    model = Sequential()
    model.add(LSTM(32, input_shape=(look_back, 1)))
    model.add(Dense(1))
    model.compile(loss='mse', optimizer='adam')
    model.fit(X, y, epochs=15, batch_size=1, verbose=0)

    return model, scaler

def predict_future_anomalies(model, scaler, data, look_back, threshold=3.0):
    data_scaled = scaler.transform(data.reshape(-1, 1))
    X = []
    for i in range(len(data_scaled) - look_back):
        X.append(data_scaled[i:i+look_back])
    X = np.array(X)
    preds = model.predict(X, verbose=0).reshape(-1)
    actual = data[look_back:]
    errors = np.square(actual - preds)
    mse = np.mean(errors)
    anomaly_flags = errors > threshold * mse
    return preds, anomaly_flags, errors

def export_alerts(preds, anomalies, errors, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    alerts = []
    for i, is_anom in enumerate(anomalies):
        if is_anom:
            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "predicted_value": float(preds[i]),
                "error_score": float(errors[i]),
                "point_id": i,
                "type": "PREDICTED_ANOMALY"
            }
            alerts.append(alert)

    with open(os.path.join(output_dir, "predicted_anomalies.json"), "w") as f:
        json.dump(alerts, f, indent=2)

    with open(os.path.join(output_dir, "predicted_report.md"), "w") as f:
        for a in alerts:
            f.write(f"- **Time**: {a['timestamp']} | **Point**: {a['point_id']} | **Prediction**: {a['predicted_value']:.2f} | **Error**: {a['error_score']:.2f}\n")

    return alerts

def plot_predictions(data, preds, anomalies, out_path):
    plt.figure(figsize=(10, 4))
    plt.plot(data, label="Original")
    offset = len(data) - len(preds)
    plt.plot(range(offset, len(data)), preds, label="Predicted")
    plt.scatter(
        [i + offset for i, x in enumerate(anomalies) if x],
        data[offset:][anomalies],
        c='red', label='Predicted Anomalies'
    )
    plt.legend()
    plt.title("Future Telemetry Prediction and Anomalies")
    plt.savefig(out_path)
    plt.close()

def main():
    parser = argparse.ArgumentParser(description="Telemetry Predictor (LSTM-Based)")
    parser.add_argument("--look_back", type=int, default=10, help="Number of steps to look back")
    parser.add_argument("--threshold", type=float, default=3.0, help="Error multiplier for anomaly detection")
    parser.add_argument("--model", default="models/lstm_predictor.h5", help="Path to LSTM model")
    parser.add_argument("--scaler", default="models/predictor_scaler.pkl", help="Path to scaler")
    parser.add_argument("--out", default="results", help="Output folder for alerts")
    args = parser.parse_args()

    data = simulate_future_telemetry()

    if os.path.exists(args.model) and os.path.exists(args.scaler):
        model = load_model(args.model)
        scaler = joblib.load(args.scaler)
        print("[✓] Loaded existing model and scaler")
    else:
        print("[!] No model found. Training a new one...")
        model, scaler = train_model(data, args.look_back)
        os.makedirs("models", exist_ok=True)
        model.save(args.model)
        joblib.dump(scaler, args.scaler)

    preds, anomalies, errors = predict_future_anomalies(
        model, scaler, data, args.look_back, threshold=args.threshold
    )

    alerts = export_alerts(preds, anomalies, errors, args.out)
    plot_predictions(data, preds, anomalies, os.path.join(args.out, "prediction_plot.png"))
    print(f"[✓] {len(alerts)} predicted anomalies written to {args.out}/")

if __name__ == "__main__":
    main()
