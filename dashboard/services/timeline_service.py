from collections import defaultdict
from services.alerts_service import load_alerts

def mitre_killchain():
    alerts = load_alerts()
    timeline = defaultdict(list)

    for a in alerts:
        mitre = a.get("mitre")
        if not mitre:
            continue

        timeline[a.get("src_ip", "unknown")].append({
            "timestamp": a.get("timestamp"),
            "severity": a.get("severity"),
            "tactic": mitre.get("tactic"),
            "technique": mitre.get("technique"),
            "id": mitre.get("id")
        })

    for ip in timeline:
        timeline[ip].sort(key=lambda e: e["timestamp"] or "")

    return dict(timeline)
