# main.py

import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

import warnings
warnings.filterwarnings("ignore")

import logging
logging.getLogger("joblib").setLevel(logging.ERROR)

import threading

from core.capture.sniffer import start_capture
from core.features.extractor import extract_features
from core.detection.engine import run_pipeline
from core.ml.detector import MLDetector
from core.hids.monitor import start_hids, set_alert_callback
from core.correlation.engine import correlate
from core.alerts.logger import init_logger, log_alert
from core.api.server import start_api, push_alert, push_packet, push_stats

ml           = MLDetector()
packet_count = 0

def handle_hids_alert(alert):
    print(f"[HIDS ALERT] [{alert['severity']}] "
          f"[{alert['layer']}] {alert['reason']}")
    log_alert("HIDS", alert)
    push_alert("HIDS", alert)

    corr = correlate(hids_alert=alert)
    if corr:
        print(f"[CORRELATED] [{corr['severity']}] {corr['reason']}")
        log_alert("CORRELATED", corr)
        push_alert("CORRELATED", corr)

def handle_packet(packet):
    global packet_count
    packet_count += 1

    features = extract_features(packet)
    if not features:
        return

    src_ip = features.get("src_ip", "unknown")
    push_packet({"src_ip": src_ip,
                 "dst_ip": features.get("dst_ip"),
                 "dst_port": features.get("dst_port"),
                 "size": features.get("size"),
                 "protocol": features.get("protocol")})

    # Rule layers
    rule_alerts = run_pipeline(features)
    for alert in rule_alerts:
        print(f"[RULE ALERT] [{alert['severity']}] "
              f"[{alert['layer']}] {alert['reason']}")
        log_alert("RULE", alert)
        push_alert("RULE", alert)

        corr = correlate(nids_alert=alert, src_ip=src_ip)
        if corr:
            print(f"[CORRELATED] [{corr['severity']}] {corr['reason']}")
            log_alert("CORRELATED", corr)
            push_alert("CORRELATED", corr)

    # ML layer
    ml_result = ml.predict(features)

    if ml_result["verdict"] == "ATTACK":
        ml_alert = {
            "layer":    "ML",
            "severity": "HIGH",
            "reason":   f"ML detected attack from {src_ip} | "
                        f"Score:{ml_result['score']} "
                        f"Confidence:{ml_result['confidence']}%",
            "detail":   ml_result
        }
        print(f"[ML ALERT] Score:{ml_result['score']} | "
              f"Confidence:{ml_result['confidence']}% | "
              f"RF:{ml_result['rf']} XGB:{ml_result['xgb']} "
              f"LSTM:{ml_result['lstm']} ISO:{ml_result['iso']} "
              f"AE:{ml_result['ae']}")
        log_alert("ML", ml_alert)
        push_alert("ML", ml_alert)

        corr = correlate(nids_alert=ml_alert, src_ip=src_ip)
        if corr:
            print(f"[CORRELATED] [{corr['severity']}] {corr['reason']}")
            log_alert("CORRELATED", corr)
            push_alert("CORRELATED", corr)

    elif packet_count % 50 == 0:
        print(f"[OK] {src_ip} → "
              f"{features['dst_ip']}:{features['dst_port']} | "
              f"Score:{ml_result['score']} "
              f"RF:{ml_result['rf_prob']:.4f} "
              f"XGB:{ml_result['xgb_prob']:.4f}")
        push_stats()

if __name__ == "__main__":
    init_logger()
    set_alert_callback(handle_hids_alert)

    # Start API in background thread
    threading.Thread(target=start_api, daemon=True).start()

    start_hids()
    start_capture(handle_packet)
