# core/alerts/logger.py

import json
import os
import numpy as np
from datetime import datetime

LOG_PATH = "logs/alerts.log"

class SentinelEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.float32, np.float64)):
            return float(obj)
        if isinstance(obj, (np.int32, np.int64)):
            return int(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)

def init_logger():
    os.makedirs("logs", exist_ok=True)
    print(f"[ALERTS] Logging to {LOG_PATH}")

def log_alert(alert_type, alert):
    entry = {
        "type":      alert_type,
        "timestamp": datetime.now().isoformat(),
        "alert":     alert
    }
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry, cls=SentinelEncoder) + "\n")
