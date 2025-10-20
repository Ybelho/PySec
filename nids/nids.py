#!/usr/bin/env python3
from scapy.all import sniff, TCP, IP, Raw
from collections import defaultdict, deque
import time, logging, json, os

os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename='logs/nids.log', level=logging.INFO, format='%(asctime)s %(message)s')
ALERT_FILE = "logs/alerts.jsonl"

RATE_WINDOW = 10
PKT_RATE_THRESHOLD = 120   # ajuster

recent = defaultdict(lambda: deque())

def write_alert(obj):
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(obj) + "\n")

def sig_detect(pkt):
    if TCP in pkt:
        flags = pkt[TCP].flags
        # SYN only
        if flags == 0x02 or flags == "S":
            return {"type":"SYN","src":pkt[IP].src,"summary":pkt.summary()}
    if Raw in pkt:
        p = bytes(pkt[Raw].load)
        if b"wget" in p or b"curl" in p or b"/bin/sh" in p:
            return {"type":"SHELL_PAYLOAD","src":pkt[IP].src,"payload":p[:200].decode('latin-1',errors='replace')}
    return None

def anomaly_detect(pkt):
    if IP in pkt:
        src = pkt[IP].src
        now = time.time()
        recent[src].append(now)
        while recent[src] and now - recent[src][0] > RATE_WINDOW:
            recent[src].popleft()
        if len(recent[src]) > PKT_RATE_THRESHOLD:
            return {"type":"HIGH_RATE","src":src,"count":len(recent[src])}
    return None

def alert(a):
    a["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    logging.warning(f"ALERT {a}")
    write_alert(a)
    print("ALERT:", a)

def handle(pkt):
    try:
        s = sig_detect(pkt)
        if s:
            alert(s)
        a = anomaly_detect(pkt)
        if a:
            alert(a)
    except Exception as e:
        logging.exception("Erreur handle")

if __name__ == "__main__":
    print("NIDS: sniffing... (CTRL+C pour stop)")
    # interface=None => sniff on host when network_mode: host
    sniff(prn=handle, store=False)
