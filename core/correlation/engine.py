# core/correlation/engine.py

from datetime import datetime
from collections import defaultdict
import time

# Store recent alerts per IP for correlation
recent_nids     = defaultdict(list)
recent_hids     = []
last_correlated = defaultdict(float)
WINDOW          = 60
COOLDOWN        = 30

def correlate(nids_alert=None, hids_alert=None, src_ip=None):
    now = time.time()

    # Store incoming alerts
    if nids_alert and src_ip:
        recent_nids[src_ip] = [
            a for a in recent_nids[src_ip]
            if now - a["time"] < WINDOW
        ]
        recent_nids[src_ip].append({
            "alert": nids_alert,
            "time":  now
        })

    if hids_alert:
        recent_hids[:] = [
            a for a in recent_hids
            if now - a["time"] < WINDOW
        ]
        recent_hids.append({
            "alert": hids_alert,
            "time":  now
        })

    result = None

    if src_ip and nids_alert:
        nids_count  = len(recent_nids[src_ip])
        hids_count  = len(recent_hids)
        nids_layers = list({a["alert"]["layer"] for a in recent_nids[src_ip]})
        now2        = time.time()

        if (now2 - last_correlated[src_ip]) > COOLDOWN:

            # CRITICAL — both NIDS and HIDS active
            if nids_count >= 2 and hids_count >= 2:
                last_correlated[src_ip] = now2
                result = {
                    "severity":  "CRITICAL",
                    "src_ip":    src_ip,
                    "reason":    f"CORRELATED: {nids_count} network alerts + "
                                 f"{hids_count} host alerts within {WINDOW}s",
                    "layers":    nids_layers,
                    "timestamp": datetime.now().isoformat()
                }

            # HIGH — multiple NIDS layers firing
            elif nids_count >= 3 and len(nids_layers) >= 2:
                last_correlated[src_ip] = now2
                result = {
                    "severity":  "HIGH",
                    "src_ip":    src_ip,
                    "reason":    f"CORRELATED: {nids_count} alerts across "
                                 f"{len(nids_layers)} detection layers from {src_ip}",
                    "layers":    nids_layers,
                    "timestamp": datetime.now().isoformat()
                }

    return result
