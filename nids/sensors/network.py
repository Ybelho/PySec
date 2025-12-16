from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time

WINDOW = 10
PORT_SCAN_THRESHOLD = 10

activity = defaultdict(list)

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        now = time.time()

        activity[src_ip].append((now, dst_port))
        activity[src_ip] = [(t, p) for t, p in activity[src_ip] if now - t <= WINDOW]

        ports = {p for _, p in activity[src_ip]}
        if len(ports) >= PORT_SCAN_THRESHOLD:
            return {
                "type": "PORT_SCAN",
                "severity": "MEDIUM",
                "src_ip": src_ip,
                "ports": list(ports),
                "description": "Scan de ports détecté par analyse réseau"
            }
    return None

def start_sniff(callback):
    sniff(prn=lambda p: callback(process_packet(p)), store=False)

