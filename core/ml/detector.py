# core/ml/detector.py

import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pickle
import torch
import torch.nn as nn
import pandas as pd
from collections import deque
from xgboost import XGBClassifier

MODELS    = "data/models/"
PROCESSED = "data/processed/"
SEQ_LEN   = 10

# ─── Autoencoder ─────────────────────────────────────────────────────────────
class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64), nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Linear(64, 32),        nn.ReLU(),
            nn.BatchNorm1d(32),
            nn.Linear(32, 16),        nn.ReLU(),
            nn.Linear(16, 8),         nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),         nn.ReLU(),
            nn.Linear(16, 32),        nn.ReLU(),
            nn.Linear(32, 64),        nn.ReLU(),
            nn.Linear(64, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


# ─── LSTM ─────────────────────────────────────────────────────────────────────
class LSTMDetector(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2):
        super().__init__()
        self.lstm = nn.LSTM(
            input_dim, hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.classifier(out[:, -1, :]).squeeze()


# ─── Main Detector ────────────────────────────────────────────────────────────
class MLDetector:
    def __init__(self):
        print("[ML] Loading all models...")

        # Scaler
        with open(PROCESSED + "scaler.pkl", "rb") as f:
            self.scaler = pickle.load(f)

        # Random Forest
        with open(MODELS + "random_forest.pkl", "rb") as f:
            self.rf = pickle.load(f)
        self.rf.n_jobs = 1
        self.rf.verbose = 0
        print("[ML] Random Forest loaded")

        # XGBoost
        self.xgb = XGBClassifier()
        self.xgb.load_model(MODELS + "xgboost.json")
        print("[ML] XGBoost loaded")

        # Isolation Forest
        with open(MODELS + "isolation_forest.pkl", "rb") as f:
            self.iso = pickle.load(f)
        self.iso.n_jobs = 1
        self.iso.verbose = 0
        print("[ML] Isolation Forest loaded")

        # Autoencoder
        with open(MODELS + "ae_input_dim.pkl", "rb") as f:
            ae_dim = pickle.load(f)
        with open(MODELS + "ae_threshold.pkl", "rb") as f:
            self.ae_threshold = pickle.load(f)

        # LSTM
        with open(MODELS + "lstm_input_dim.pkl", "rb") as f:
            lstm_dim = pickle.load(f)

        # CPU only
        self.device = torch.device("cpu")

        self.ae = Autoencoder(ae_dim).to(self.device)
        self.ae.load_state_dict(torch.load(
            MODELS + "autoencoder.pt", map_location=self.device))
        self.ae.eval()
        print("[ML] Autoencoder loaded")

        self.lstm = LSTMDetector(lstm_dim).to(self.device)
        self.lstm.load_state_dict(torch.load(
            MODELS + "lstm.pt", map_location=self.device))
        self.lstm.eval()
        print("[ML] LSTM loaded")

        self.seq_buffer = deque(maxlen=SEQ_LEN)
        print(f"[ML] All models ready. Device: {self.device}\n")

    def features_to_df(self, features):
        row = {
            'Flow Duration':               features.get("duration", 0),
            'Total Fwd Packets':           features.get("packets_per_sec", 0),
            'Total Backward Packets':      0,
            'Total Length of Fwd Packets': features.get("bytes_per_sec", 0),
            'Total Length of Bwd Packets': 0,
            'Fwd Packet Length Max':       features.get("size", 0),
            'Fwd Packet Length Min':       features.get("size", 0),
            'Fwd Packet Length Mean':      features.get("size", 0),
            'Flow Bytes/s':                features.get("bytes_per_sec", 0),
            'Flow Packets/s':              features.get("packets_per_sec", 0),
            'Flow IAT Mean':               features.get("duration", 0),
            'Flow IAT Std':                0,
            'SYN Flag Count':              features.get("flag_syn", 0),
            'ACK Flag Count':              features.get("flag_ack", 0),
            'RST Flag Count':              features.get("flag_rst", 0),
            'FIN Flag Count':              features.get("flag_fin", 0),
            'PSH Flag Count':              0,
            'Destination Port':            features.get("dst_port", 0),
        }
        return pd.DataFrame([row])

    def predict(self, features):
        df     = self.features_to_df(features)
        scaled = self.scaler.transform(df)

        # ── Random Forest ──
        rf_prob = self.rf.predict_proba(scaled)[0][1]
        rf_pred = int(rf_prob > 0.5)

        # ── XGBoost ──
        xgb_prob = self.xgb.predict_proba(scaled)[0][1]
        xgb_pred = int(xgb_prob > 0.5)

        # ── Isolation Forest ──
        iso_raw  = self.iso.predict(scaled)[0]
        iso_pred = 1 if iso_raw == -1 else 0

        # ── Autoencoder ──
        tensor = torch.tensor(scaled, dtype=torch.float32).to(self.device)
        with torch.no_grad():
            recon = self.ae(tensor).cpu().numpy()
        ae_error = float(np.mean((scaled - recon) ** 2))
        ae_pred  = 1 if ae_error > self.ae_threshold else 0

        # ── LSTM ──
        self.seq_buffer.append(scaled[0])
        lstm_pred = 0
        lstm_prob = 0.0
        if len(self.seq_buffer) == SEQ_LEN:
            seq   = np.array(list(self.seq_buffer), dtype=np.float32)
            seq_t = torch.tensor(seq).unsqueeze(0).to(self.device)
            with torch.no_grad():
                lstm_prob = float(self.lstm(seq_t).cpu().numpy())
            lstm_pred = int(lstm_prob > 0.5)

        # ── Weighted Voting ──
        score = (rf_pred * 3) + (xgb_pred * 3) + \
                (lstm_pred * 2) + (iso_pred * 1) + (ae_pred * 1)

        verdict    = "ATTACK" if score >= 4 else "BENIGN"
        avg_prob   = (rf_prob + xgb_prob) / 2
        confidence = min(round(avg_prob * 100, 1), 99.9)

        return {
            "verdict":    verdict,
            "confidence": confidence,
            "score":      f"{score}/10",
            "rf":         rf_pred,
            "xgb":        xgb_pred,
            "lstm":       lstm_pred,
            "iso":        iso_pred,
            "ae":         ae_pred,
            "rf_prob":    round(rf_prob, 4),
            "xgb_prob":   round(xgb_prob, 4),
            "lstm_prob":  round(lstm_prob, 4),
            "ae_error":   round(ae_error, 6),
        }
