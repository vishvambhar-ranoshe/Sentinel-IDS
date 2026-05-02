# core/ml/train_lstm.py

import numpy as np
import pickle
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import time

PROCESSED = "data/processed/"
MODELS    = "data/models/"
SEQ_LEN   = 10  # look at 10 packets at a time

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
        # Take last timestep
        out = out[:, -1, :]
        return self.classifier(out).squeeze()

def make_sequences(X, y, seq_len):
    Xs, ys = [], []
    for i in range(len(X) - seq_len):
        Xs.append(X[i:i+seq_len])
        ys.append(y[i+seq_len-1])
    return np.array(Xs, dtype=np.float32), np.array(ys, dtype=np.float32)

def train():
    print("[*] Loading data...")
    X_train = np.load(PROCESSED + "X_train.npy").astype(np.float32)
    X_test  = np.load(PROCESSED + "X_test.npy").astype(np.float32)
    y_train = np.load(PROCESSED + "y_train.npy").astype(np.float32)
    y_test  = np.load(PROCESSED + "y_test.npy").astype(np.float32)

    # Sample 100k for speed
    idx = np.random.choice(len(X_train), 100000, replace=False)
    X_train = X_train[idx]
    y_train = y_train[idx]

    print("[*] Building sequences...")
    X_seq, y_seq = make_sequences(X_train, y_train, SEQ_LEN)
    X_test_seq, y_test_seq = make_sequences(X_test[:50000],
                                             y_test[:50000], SEQ_LEN)

    print(f"[*] Train sequences: {X_seq.shape}")
    print(f"[*] Test  sequences: {X_test_seq.shape}")

    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"[*] Device: {device}")

    loader = DataLoader(
        TensorDataset(torch.tensor(X_seq), torch.tensor(y_seq)),
        batch_size=512, shuffle=True
    )

    input_dim = X_seq.shape[2]
    model     = LSTMDetector(input_dim).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn   = nn.BCELoss()

    print("[*] Training 15 epochs...")
    start = time.time()

    for epoch in range(15):
        model.train()
        total_loss = 0
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            pred = model(xb)
            loss = loss_fn(pred, yb)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"    Epoch {epoch+1:02d}/15 — Loss: {total_loss/len(loader):.4f}")

    print(f"[*] Done in {round(time.time()-start, 2)}s")

    # Evaluate
    print("[*] Evaluating...")
    model.eval()
    with torch.no_grad():
        X_t = torch.tensor(X_test_seq).to(device)
        probs = model(X_t).cpu().numpy()

    y_pred = (probs > 0.5).astype(int)

    print("\n--- LSTM Report ---")
    print(classification_report(y_test_seq, y_pred,
          target_names=["BENIGN", "ATTACK"]))
    print("--- Confusion Matrix ---")
    print(confusion_matrix(y_test_seq, y_pred))
    print(f"--- ROC-AUC: {roc_auc_score(y_test_seq, probs):.4f} ---")

    torch.save(model.state_dict(), MODELS + "lstm.pt")
    with open(MODELS + "lstm_input_dim.pkl", "wb") as f:
        pickle.dump(input_dim, f)
    print("\n[DONE] Saved to data/models/lstm.pt")

if __name__ == "__main__":
    train()
