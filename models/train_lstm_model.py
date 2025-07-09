# Ruta: models/train_lstm_model.py

import numpy as np
import os
import joblib
from keras.models import Sequential
from keras.layers import LSTM, Dense
from sklearn.preprocessing import MinMaxScaler

def simulate_telemetry_stream(n_points=150):
    normal = np.random.normal(0, 1, (n_points, 1))
    anomaly = np.random.normal(5, 0.5, (10, 1))
    data = np.vstack([normal, anomaly])
    return data.flatten()

def prepare_lstm_data(data, look_back=10):
    scaler = MinMaxScaler()
    data_scaled = scaler.fit_transform(data.reshape(-1, 1))
    X, y = [], []
    for i in range(len(data_scaled) - look_back):
        X.append(data_scaled[i:i+look_back])
        y.append(data_scaled[i+look_back])
    return np.array(X), np.array(y), scaler

def train_and_save_model(data, look_back, model_path, scaler_path):
    X, y, scaler = prepare_lstm_data(data, look_back)
    model = Sequential()
    model.add(LSTM(20, input_shape=(X.shape[1], 1)))
    model.add(Dense(1))
    model.compile(loss='mean_squared_error', optimizer='adam')
    model.fit(X, y, epochs=10, batch_size=1, verbose=0)
    model.save(model_path)
    joblib.dump(scaler, scaler_path)
    print(f"[✓] Model saved to {model_path}")
    print(f"[✓] Scaler saved to {scaler_path}")

def main():
    look_back = 10
    model_path = "models/lstm_model.h5"
    scaler_path = "models/lstm_scaler.pkl"
    os.makedirs("models", exist_ok=True)

    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print("[*] Training model (fallback)...")
        data = simulate_telemetry_stream()
        train_and_save_model(data, look_back, model_path, scaler_path)
    else:
        print("[✓] Model and scaler already exist. Skipping training.")

if __name__ == "__main__":
    main()
