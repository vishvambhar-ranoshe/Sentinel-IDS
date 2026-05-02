# core/capture/sniffer.py

from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list
from datetime import datetime
import threading

def get_active_interfaces():
    all_interfaces = get_if_list()
    # Skip loopback and inactive interfaces
    skip = ['lo0', 'lo', 'gif0', 'stf0', 'utun0',
            'utun1', 'utun2', 'utun3', 'utun4']
    active = [i for i in all_interfaces if i not in skip]
    print(f"[SENTINEL] Detected interfaces: {active}")
    return active

def process_packet(packet):
    if not packet.haslayer(IP):
        return None

    data = {
        "timestamp": datetime.now().isoformat(),
        "src_ip":    packet[IP].src,
        "dst_ip":    packet[IP].dst,
        "protocol":  packet[IP].proto,
        "size":      len(packet),
        "ttl":       packet[IP].ttl,
        "src_port":  None,
        "dst_port":  None,
        "flags":     None,
        "payload":   b"",
    }

    if packet.haslayer(TCP):
        data["src_port"] = packet[TCP].sport
        data["dst_port"] = packet[TCP].dport
        data["flags"]    = str(packet[TCP].flags)

    elif packet.haslayer(UDP):
        data["src_port"] = packet[UDP].sport
        data["dst_port"] = packet[UDP].dport

    if packet.haslayer(Raw):
        data["payload"] = bytes(packet[Raw].load)

    return data

def start_capture_on(iface, callback):
    try:
        print(f"[SENTINEL] Starting capture on {iface}")
        sniff(
            iface=iface,
            prn=lambda pkt: callback(process_packet(pkt)),
            store=False,
            count=0
        )
    except Exception as e:
        print(f"[SENTINEL] Could not capture on {iface}: {e}")

def start_capture(callback):
    interfaces = get_active_interfaces()

    if not interfaces:
        print("[SENTINEL] No active interfaces found")
        return

    # Start a thread for each interface
    threads = []
    for iface in interfaces:
        t = threading.Thread(
            target=start_capture_on,
            args=(iface, callback),
            daemon=True
        )
        t.start()
        threads.append(t)
        print(f"[SENTINEL] Thread started for {iface}")

    print(f"[SENTINEL] Monitoring {len(interfaces)} interfaces simultaneously")

    # Keep main thread alive
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[SENTINEL] Stopping capture...")
