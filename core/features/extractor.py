# core/features/extractor.py

from collections import defaultdict
import time

ip_tracker = defaultdict(lambda: {
    "count":       0,
    "first_seen":  time.time(),
    "last_seen":   time.time(),
    "total_bytes": 0,
    "ports":       set(),
    "flags":       []
})

def extract_features(packet):
    if not packet:
        return None

    src = packet["src_ip"]
    now = time.time()

    tracker = ip_tracker[src]
    tracker["count"]       += 1
    tracker["last_seen"]    = now
    tracker["total_bytes"] += packet["size"]
    if packet["dst_port"]:
        tracker["ports"].add(packet["dst_port"])
    if packet["flags"]:
        tracker["flags"].append(packet["flags"])

    duration = max(now - tracker["first_seen"], 0.001)

    features = {
        "src_ip":          packet["src_ip"],
        "dst_ip":          packet["dst_ip"],
        "protocol":        packet["protocol"],
        "size":            packet["size"],
        "ttl":             packet["ttl"],
        "src_port":        packet["src_port"] or 0,
        "dst_port":        packet["dst_port"] or 0,
        "packets_per_sec": round(tracker["count"] / duration, 4),
        "bytes_per_sec":   round(tracker["total_bytes"] / duration, 4),
        "unique_ports":    len(tracker["ports"]),
        "duration":        round(duration, 4),
        "flag_syn":        1 if packet["flags"] and "S" in packet["flags"] else 0,
        "flag_ack":        1 if packet["flags"] and "A" in packet["flags"] else 0,
        "flag_fin":        1 if packet["flags"] and "F" in packet["flags"] else 0,
        "flag_rst":        1 if packet["flags"] and "R" in packet["flags"] else 0,
        "payload":         packet.get("payload", b""),
        "timestamp":       packet["timestamp"]
    }

    return features
