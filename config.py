# config.py

# Detection Thresholds
MAX_CONNECTIONS_PER_SEC = 100
MAX_PACKETS_PER_IP      = 500
STAT_DEVIATION_LIMIT    = 3

# ML
AUTOENCODER_THRESHOLD = 0.05
MODEL_PATH = "data/models/"

# Alerts
LOG_PATH = "logs/alerts.log"
ALERT_LEVEL = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Honeypot
HONEYPOT_PORT = 9999
