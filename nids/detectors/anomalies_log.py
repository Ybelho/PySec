from collections import defaultdict
from datetime import datetime, timedelta

FAILED_THRESHOLD = 5
WINDOW = timedelta(seconds=60)

failed_logins = defaultdict(list)

def detect_bruteforce(event):
    if event.get("eventid") != "cowrie.login.failed":
        return None

    src_ip = event.get("src_ip")
    now = datetime.now()

    failed_logins[src_ip].append(now)
    failed_logins[src_ip] = [
        t for t in failed_logins[src_ip] if now - t <= WINDOW
    ]

    if len(failed_logins[src_ip]) >= FAILED_THRESHOLD:
        return {
            "type": "BRUTE_FORCE",
            "severity": "HIGH",
            "src_ip": src_ip,
            "attempts": len(failed_logins[src_ip]),
            "description": "Brute force SSH détecté"
        }
    return None

