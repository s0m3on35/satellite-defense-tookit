#!/usr/bin/env python3
# File: models/train_lstm_model.py

import numpy as np
import pandas as pd
import os
import yaml
import joblib
import logging
from keras.models import Sequential
from keras.layers import LSTM, Dense, Dropout
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import mean_squared_error
from datetime import datetime
from pathlib import Path

CONFIG_PATH = "config/config.yaml"
MODEL_DIR = Path("models")
MODEL_FILE = MODEL_DIR / "lstm_model.h5"
SCALER_FILE = MODEL_DIR / "lstm_scaler.pkl"
LOG_FILE = "logs/lstm_training.log"
ALERT_THRESHOLD = 0.02  # Default; overridden by config

# Setup logging
os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s [LSTM] %(levelname)s: %(message)s")

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return yaml.safe_load(f)
    return {}

def load_telemetry_data(file_path, column='value'):
    df = pd.read_csv(file_path)
    if column not in df.columns:
        raise ValueError(f"Telemetry column '{column}' not found in CSV.")
    return df[column].values

def prepare_data(data, look_back=10):
    scaler = MinMaxScaler()
    data_scaled = scaler.fit_transform(data.reshape(-1, 1))
    X, y = [], []
    for i in range(len(data_scaled) - look_back):
        X.append(data_scaled[i:i+look_back])
        y.append(data_scaled[i+look_back])
    return np.array(X), np.array(y), scaler

def build_model(input_shape):
    model = Sequential()
    model.add(LSTM(64, input_shape=input_shape, return_sequences=True))
    model.add(Dropout(0.2))
    model.add(LSTM(32))
    model.add(Dense(1))
    model.compile(loss='mean_squared_error', optimizer='adam')
    return model

def train_model(X, y, model_path, scaler_path):
    model = build_model((X.shape[1], 1))
    model.fit(X, y, epochs=30, batch_size=16, verbose=1)
    model.save(model_path)
    joblib.dump(scaler, scaler_path)
    logging.info(f"Model saved: {model_path}")
    logging.info(f"Scaler saved: {scaler_path}")
    print(f"[✓] Model and scaler saved")

def evaluate_model(model, X, y, threshold):
    predictions = model.predict(X)
    mse = mean_squared_error(y, predictions)
    logging.info(f"Evaluation MSE: {mse:.6f}")
    print(f"[INFO] Evaluation MSE: {mse:.6f}")
    if mse > threshold:
        logging.warning(f"Anomaly threshold exceeded (MSE: {mse:.6f})")
        print("[!] Anomaly alert triggered")
        # Placeholder: send alert to dashboard or webhook
        # e.g., websocket_alert({"event": "lstm_anomaly", "mse": mse})
    return mse

def main():
    config = load_config()
    telemetry_file = config.get("telemetry_csv", "data/telemetry_stream.csv")
    look_back = config.get("look_back", 10)
    alert_threshold = config.get("threshold", ALERT_THRESHOLD)

    if not os.path.exists(telemetry_file):
        raise FileNotFoundError(f"Telemetry file not found: {telemetry_file}")

    data = load_telemetry_data(telemetry_file)
    X, y, scaler = prepare_data(data, look_back)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model = build_model((X.shape[1], 1))
    model.fit(X, y, epochs=30, batch_size=16, verbose=1)
    model.save(MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)

    logging.info("Model training completed")
    print("[✓] Model trained and saved")

    evaluate_model(model, X, y, alert_threshold)

if __name__ == "__main__":
    main()
