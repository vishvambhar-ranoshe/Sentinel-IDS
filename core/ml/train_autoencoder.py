# core/ml/train_autoencoder.py

import numpy as np
import pickle
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
import time

PROCESSED = "data/processed/"
MODELS    = "data/models/"

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

def train():
    print("[*] Loading data...")
    X_normal = np.load(PROCESSED + "X_normal.npy").astype(np.float32)
    X_test   = np.load(PROCESSED + "X_test.npy").astype(np.float32)
    y_test   = np.load(PROCESSED + "y_test.npy")

    idx = np.random.choice(len(X_normal), 200000, replace=False)
    X_train = X_normal[idx]

    print(f"[*] Training on {len(X_train)} normal samples")

    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"[*] Using device: {device}")

    tensor = torch.tensor(X_train).to(device)
    loader = DataLoader(TensorDataset(tensor, tensor),
                        batch_size=512, shuffle=True)

    input_dim = X_train.shape[1]
    model = Autoencoder(input_dim).to(device)

    # Lower learning rate for stable training
    optimizer = torch.optim.Adam(model.parameters(), lr=3e-4)

    # Reduce LR if loss plateaus
    loss_fn = nn.MSELoss()
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
    optimizer, patience=3, factor=0.5
    )
    print("[*] Training 30 epochs...")
    start = time.time()

    for epoch in range(30):
        model.train()
        total_loss = 0
        for xb, yb in loader:
            pred = model(xb)
            loss = loss_fn(pred, yb)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        avg = total_loss / len(loader)
        scheduler.step(avg)
        print(f"    Epoch {epoch+1:02d}/30 — Loss: {avg:.6f}")

    print(f"[*] Done in {round(time.time()-start, 2)}s")

    # Threshold at 90th percentile — more sensitive
    print("[*] Calculating threshold...")
    model.eval()
    with torch.no_grad():
        sample = torch.tensor(X_normal[:10000]).to(device)
        recon  = model(sample).cpu().numpy()
        errors = np.mean((X_normal[:10000] - recon) ** 2, axis=1)
        threshold = np.percentile(errors, 90)
    print(f"[*] Threshold: {threshold:.6f}")

    # Evaluate
    print("[*] Evaluating...")
    with torch.no_grad():
        X_test_t = torch.tensor(X_test).to(device)
        recon_test = model(X_test_t).cpu().numpy()
    test_errors = np.mean((X_test - recon_test) ** 2, axis=1)
    y_pred = (test_errors > threshold).astype(int)

    print("\n--- Autoencoder Report ---")
    print(classification_report(y_test, y_pred,
          target_names=["BENIGN", "ATTACK"]))
    print("--- Confusion Matrix ---")
    print(confusion_matrix(y_test, y_pred))
    print(f"--- ROC-AUC: {roc_auc_score(y_test, test_errors):.4f} ---")

    torch.save(model.state_dict(), MODELS + "autoencoder.pt")
    with open(MODELS + "ae_input_dim.pkl", "wb") as f:
        pickle.dump(input_dim, f)
    with open(MODELS + "ae_threshold.pkl", "wb") as f:
        pickle.dump(threshold, f)

    print("\n[DONE] Saved to data/models/")

if __name__ == "__main__":
    train()
