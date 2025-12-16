import json
import os
from datetime import datetime

ALERTS_FILE = "/app/logs/alerts.jsonl"

def enrich_mitre(alert):
    if alert.get("mitre"):
        return alert

    t = alert.get("type", "").upper()

    if t == "PRIV_ESC":
        alert["mitre"] = {
            "tactic": "Privilege Escalation",
            "technique": "Sudo Abuse",
            "id": "T1548"
        }
    elif t == "BRUTE_FORCE":
        alert["mitre"] = {
            "tactic": "Credential Access",
            "technique": "Brute Force",
            "id": "T1110"
        }

    return alert


def load_alerts():
    alerts = []
    if not os.path.exists(ALERTS_FILE):
        return alerts

    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                a = json.loads(line)

                # ================= MITRE AUTO-MAPPING =================
                if not a.get("mitre"):
                    alert_type = a.get("type", "").upper()
                    cmd = (a.get("command") or "").lower()

                    if alert_type == "PRIV_ESC" or "sudo" in cmd or "su " in cmd:
                        a["mitre"] = {
                            "tactic": "Privilege Escalation",
                            "id": "T1548",
                            "technique": "Abuse Elevation Control Mechanism"
                        }

                alerts.append(a)

            except Exception:
                continue

    return alerts

def latest_alerts(since_iso=None, limit=30):
    alerts = load_alerts()

    if since_iso:
        try:
            since = datetime.fromisoformat(since_iso)
            alerts = [
                a for a in alerts
                if "timestamp" in a
                and datetime.fromisoformat(a["timestamp"]) > since
            ]
        except Exception:
            pass

    return alerts[-limit:]
