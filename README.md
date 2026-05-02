# Sentinel-IDS

![PYTHON](https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python)
![ML](https://img.shields.io/badge/ML_Models-5-4A90D9?style=flat-square)
![LAYERS](https://img.shields.io/badge/Detection_Layers-9-orange?style=flat-square)
![DATASET](https://img.shields.io/badge/Dataset-CICIDS2017-green?style=flat-square)
![STATUS](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![LICENSE](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![NIDS](https://img.shields.io/badge/NIDS-%E2%9C%93-success?style=flat-square)
![HIDS](https://img.shields.io/badge/HIDS-%E2%9C%93-success?style=flat-square)

> A real-time hybrid intrusion detection system combining network surveillance, host monitoring, and a five-model ML ensemble into one unified threat detection platform.

**Author : Vishvambhar Ranoshe**

---

## What is Sentinel-IDS?

Sentinel is not a configuration of existing tools. Every component is built from scratch packet capture, feature extraction, detection pipeline, ML inference, correlation engine, alert logging, REST API, and dashboard.

It captures live packets on all active interfaces simultaneously, runs them through nine detection layers, feeds them into five machine learning models in parallel, correlates network and host events, and displays everything live on a React dashboard with dark and light mode.

---
## Dashboard

<img width="1470" height="956" alt="Screenshot 2026-05-02 at 7 07 03 PM" src="https://github.com/user-attachments/assets/1bca13c2-8a54-4d1d-a950-1e93241a587f" />

---
## ML Model Performance

Trained on **CICIDS2017** - 2,827,876 samples across 15 attack categories.

| Model | Type | Accuracy | ROC-AUC | Train Time |
|---|---|---|---|---|
| Random Forest | Supervised | 99.7% | 0.9998 | 10.45s |
| XGBoost | Supervised | 99.7% | 0.9997 | 0.71s |
| LSTM | Sequential | 95.0% | 0.9801 | 34.29s |
| Autoencoder | Unsupervised | 81.0% | 0.8158 | 49s |
| Isolation Forest | Unsupervised | 82.0% | 0.7337 | 0.31s |

**Ensemble Voting**

| Formula | Threshold |
|---|---|
| RF(×3) + XGB(×3) + LSTM(×2) + ISO(×1) + AE(×1) | Alert fires at Score ≥ 4 / 10 |

No single model can trigger a false alarm alone.

**Attack Categories Covered**

| Category | Attacks |
|---|---|
| Denial of Service | DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest |
| Network Scan | PortScan, DDoS |
| Brute Force | FTP-Patator, SSH-Patator |
| Web Attacks | SQL Injection, XSS, Brute Force |
| Advanced | Botnet, Heartbleed, Infiltration |

---

## Detection Layers

| Layer | Name | Detects |
|---|---|---|
| 1 | THRESHOLD | DDoS, flooding, connection storms |
| 2 | SIGNATURE | Port scans, suspicious ports, known patterns |
| 3 | PROTOCOL | TTL anomaly, SYN+FIN, TCP null scan, malformed packets |
| 4 | STATISTICAL | Volume spikes, oversized packets, MTU violations |
| 5 | BEHAVIOUR | Slow stealthy scans, low-rate reconnaissance |
| 6 | FRAGMENTATION | Tiny packet floods, signature evasion via fragmentation |
| 7 | ENTROPY | Payload obfuscation, encoding, C2 communication |
| 8 | DECOY | Spoofed IP scans, nmap decoy detection |
| 9 | SLOW-RATE | hping3 slow scans, long-window attack patterns |

---

## What Sentinel Detects

**Network Level**

| Threat | Method |
|---|---|
| Port scans | nmap SYN, NULL, FIN, XMAS, decoy scans |
| DDoS / DoS | Flooding, slowloris, GoldenEye, Hulk |
| Brute force | SSH, FTP, RDP password attacks |
| Protocol evasion | TTL manipulation, fragmentation, malformed flags |
| Payload obfuscation | Base64, XOR, high-entropy encoded payloads |
| Web attacks | SQL injection, XSS, brute force login |
| Botnet C2 | Anomalous outbound communication patterns |
| Slow rate attacks | hping3, low-and-slow reconnaissance |

**Host Level**

| Threat | Method |
|---|---|
| New process spawn | Unknown processes detected immediately |
| File changes | Modifications in sensitive system paths |
| Auth failures | SSH wrong password, sudo failures |
| Session detection | New SSH sessions, PAM authentication events |

---

## Architecture

| Stage | Component |
|---|---|
| 1 | Packet Capture - Scapy on all interfaces |
| 2 | Feature Extraction - 18-dimensional vector |
| 3 | 9-Layer Detection Pipeline |
| 4 | ML Ensemble - 5 models, weighted voting |
| 5 | Correlation Engine - NIDS + HIDS unified alert |
| 6 | FastAPI Backend + WebSocket |
| 7 | React Dashboard - dark/light mode, live updates |

---

## Comparison With Existing Tools

| Feature | Snort | Wazuh | Sentinel-IDS |
|---|---|---|---|
| Zero-day detection | ✗ | ✗ | ✓ |
| ML-based detection | ✗ | ✗ | ✓ |
| NIDS + HIDS combined | ✗ | ✗ | ✓ |
| Confidence scoring | ✗ | ✗ | ✓ |
| Sequential detection (LSTM) | ✗ | ✗ | ✓ |
| Entropy analysis | ✗ | ✗ | ✓ |
| Explainable alerts | ✗ | ✗ | ✓ |
| Fragmentation detection | ✓ | ✗ | ✓ |
| Live dashboard | ✗ | ✓ | ✓ |

---

## Stack

| Layer | Technology |
|---|---|
| Packet Capture | Scapy |
| Feature Engineering | Pandas, NumPy, Scikit-learn |
| ML Models | Scikit-learn, XGBoost, PyTorch |
| Host Monitoring | Psutil, Watchdog |
| Backend | FastAPI, WebSocket, Uvicorn |
| Frontend | React, Recharts |
| Dataset | CICIDS2017 |

---

## Setup

```bash
git clone https://github.com/vishvambhar-ranoshe/Sentinel-IDS.git
cd Sentinel-IDS
pip install -r requirements.txt
sudo python main.py
```

Open new terminal:

```bash
cd dashboard
npm install
npm start
```

Open `http://localhost:3000`

---

## Lab Setup

| Component | Role |
|---|---|
| Mac | Runs IDS engine, ML models, dashboard |
| Kali Linux | Attacker machine for testing |
| Interfaces | Auto-detected on startup, all active interfaces monitored |

---

*Built by **Vishvambhar Ranoshe***
