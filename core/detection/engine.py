# core/detection/engine.py

import config
from collections import defaultdict
import time
import math

# ─── State Tracking ───────────────────────────────────────────────────────────
connection_tracker = defaultdict(list)
port_tracker       = defaultdict(set)
frag_tracker       = defaultdict(list)
decoy_tracker      = defaultdict(set)
slow_tracker       = defaultdict(list)
ttl_baseline       = {}
entropy_cooldown   = defaultdict(float)
threshold_cooldown = defaultdict(float)

SLOW_WINDOW        = 300
FRAG_WINDOW        = 10
ENTROPY_THRESH     = 7.0
ENTROPY_COOLDOWN   = 30
THRESHOLD_COOLDOWN = 10


# ─── Layer 1: Threshold ───────────────────────────────────────────────────────
def check_threshold(features):
    src = features["src_ip"]
    now = time.time()

    connection_tracker[src] = [
        t for t in connection_tracker[src] if now - t < 1.0
    ]
    connection_tracker[src].append(now)
    count = len(connection_tracker[src])

    if count > config.MAX_CONNECTIONS_PER_SEC:
        if now - threshold_cooldown[src] > THRESHOLD_COOLDOWN:
            threshold_cooldown[src] = now
            return {
                "triggered": True,
                "layer":    "THRESHOLD",
                "reason":   f"Too many connections: {count}/sec from {src}",
                "severity": "HIGH"
            }

    return {"triggered": False}


# ─── Layer 2: Signature ───────────────────────────────────────────────────────
def check_signature(features):
    src      = features["src_ip"]
    dst_port = features["dst_port"]

    port_tracker[src].add(dst_port)
    unique = len(port_tracker[src])

    if unique > 20 and unique % 20 == 1:
        return {
            "triggered": True,
            "layer":    "SIGNATURE",
            "reason":   f"Port scan detected: {unique} unique ports from {src}",
            "severity": "HIGH"
        }

    suspicious_ports = [22, 23, 3389, 4444, 5900]
    if dst_port in suspicious_ports:
        return {
            "triggered": True,
            "layer":    "SIGNATURE",
            "reason":   f"Connection to suspicious port {dst_port} from {src}",
            "severity": "MEDIUM"
        }

    return {"triggered": False}


# ─── Layer 3: Protocol Analysis ───────────────────────────────────────────────
def check_protocol(features):
    src = features["src_ip"]
    ttl = features.get("ttl", 64)

    if src not in ttl_baseline:
        ttl_baseline[src] = ttl
    else:
        diff = abs(ttl - ttl_baseline[src])
        if diff > 20:
            return {
                "triggered": True,
                "layer":    "PROTOCOL",
                "reason":   f"TTL anomaly from {src}: expected ~{ttl_baseline[src]}, got {ttl} (diff={diff}) — possible evasion",
                "severity": "MEDIUM"
            }

    if ttl < 10:
        return {
            "triggered": True,
            "layer":    "PROTOCOL",
            "reason":   f"Suspiciously low TTL: {ttl} from {src}",
            "severity": "MEDIUM"
        }

    if features["flag_syn"] and features["flag_fin"]:
        return {
            "triggered": True,
            "layer":    "PROTOCOL",
            "reason":   "Malformed packet: SYN+FIN flags — possible evasion attempt",
            "severity": "HIGH"
        }

    if features["protocol"] == 6:
        if not any([features["flag_syn"], features["flag_ack"],
                    features["flag_fin"], features["flag_rst"]]):
            return {
                "triggered": True,
                "layer":    "PROTOCOL",
                "reason":   f"TCP null scan from {src} — all flags zero",
                "severity": "HIGH"
            }

    return {"triggered": False}


# ─── Layer 4: Statistical ─────────────────────────────────────────────────────
def check_statistical(features):
    if features["bytes_per_sec"] > 1_000_000:
        return {
            "triggered": True,
            "layer":    "STATISTICAL",
            "reason":   f"Abnormal traffic volume: {features['bytes_per_sec']:.0f} bytes/sec",
            "severity": "HIGH"
        }

    if features["size"] > 1500:
        return {
            "triggered": True,
            "layer":    "STATISTICAL",
            "reason":   f"Oversized packet: {features['size']} bytes",
            "severity": "LOW"
        }

    return {"triggered": False}


# ─── Layer 5: Behaviour ───────────────────────────────────────────────────────
def check_behaviour(features):
    src          = features["src_ip"]
    unique_ports = features["unique_ports"]

    if unique_ports > 30 and features["packets_per_sec"] < 5:
        return {
            "triggered": True,
            "layer":    "BEHAVIOUR",
            "reason":   f"Slow stealthy scan: {unique_ports} ports at low rate from {src}",
            "severity": "MEDIUM"
        }

    return {"triggered": False}


# ─── Layer 6: Fragmentation Detection ────────────────────────────────────────
def check_fragmentation(features):
    src = features["src_ip"]
    now = time.time()

    if features["size"] < 28 and features["protocol"] == 6:
        frag_tracker[src] = [
            t for t in frag_tracker[src] if now - t < FRAG_WINDOW
        ]
        frag_tracker[src].append(now)
        count = len(frag_tracker[src])

        if count >= 5:
            return {
                "triggered": True,
                "layer":    "FRAGMENTATION",
                "reason":   f"Fragmentation attack: {count} tiny packets from {src} in {FRAG_WINDOW}s — possible signature evasion",
                "severity": "HIGH"
            }

    return {"triggered": False}


# ─── Layer 7: Payload Entropy ─────────────────────────────────────────────────
def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    length  = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def check_entropy(features):
    payload  = features.get("payload", b"")
    dst_port = features.get("dst_port", 0)
    src_ip   = features.get("src_ip", "")
    now      = time.time()

    # Skip encrypted ports
    if dst_port in [443, 8443, 993, 995, 465, 853]:
        return {"triggered": False}

    if not payload or len(payload) < 16:
        return {"triggered": False}

    # Cooldown per src+port
    key = f"{src_ip}:{dst_port}"
    if now - entropy_cooldown[key] < ENTROPY_COOLDOWN:
        return {"triggered": False}

    entropy = compute_entropy(payload)

    if entropy > ENTROPY_THRESH:
        entropy_cooldown[key] = now
        return {
            "triggered": True,
            "layer":    "ENTROPY",
            "reason":   f"High payload entropy ({entropy:.2f} bits) from {src_ip} port {dst_port} — possible encoding/obfuscation",
            "severity": "MEDIUM"
        }

    return {"triggered": False}


# ─── Layer 8: Decoy / Spoofed IP Detection ───────────────────────────────────
def check_decoy(features):
    src      = features["src_ip"]
    dst_port = features["dst_port"]

    if not dst_port:
        return {"triggered": False}

    decoy_tracker[dst_port].add(src)
    unique_sources = len(decoy_tracker[dst_port])

    if unique_sources > 50:
        decoy_tracker[dst_port] = {src}

    if unique_sources > 15:
        return {
            "triggered": True,
            "layer":    "DECOY",
            "reason":   f"Decoy scan: {unique_sources} different IPs targeting port {dst_port} — possible IP spoofing",
            "severity": "HIGH"
        }

    return {"triggered": False}


# ─── Layer 9: Slow Rate (hping) Detection ────────────────────────────────────
def check_slow_rate(features):
    src = features["src_ip"]
    now = time.time()

    slow_tracker[src] = [
        t for t in slow_tracker[src] if now - t < SLOW_WINDOW
    ]
    slow_tracker[src].append(now)

    count        = len(slow_tracker[src])
    unique_ports = features["unique_ports"]

    if count > 50 and unique_ports > 15 and features["packets_per_sec"] < 2:
        return {
            "triggered": True,
            "layer":    "SLOW-RATE",
            "reason":   f"Slow rate attack from {src}: {count} packets over {SLOW_WINDOW}s, {unique_ports} ports — hping pattern",
            "severity": "HIGH"
        }

    return {"triggered": False}


# ─── Full Pipeline ────────────────────────────────────────────────────────────
def run_pipeline(features):
    results = []

    for check in [
        check_threshold,
        check_signature,
        check_protocol,
        check_statistical,
        check_behaviour,
        check_fragmentation,
        check_entropy,
        check_decoy,
        check_slow_rate,
    ]:
        result = check(features)
        if result.get("triggered"):
            results.append(result)

    return results
