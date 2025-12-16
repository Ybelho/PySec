# nids/mitre/aggregator.py

import json
import os
from collections import defaultdict

ALERTS_FILE = os.getenv("ALERTS_FILE", "/app/logs/alerts.jsonl")


def aggregate_mitre_alerts(alerts_file: str = ALERTS_FILE) -> dict:
    """
    Agrège les alertes par tactique / technique MITRE ATT&CK.
    """
    summary = defaultdict(lambda: defaultdict(lambda: {
        "technique": "",
        "count": 0,
        "severity": set()
    }))

    if not os.path.exists(alerts_file):
        return {}

    with open(alerts_file, "r") as f:
        for line in f:
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            mitre = alert.get("mitre")
            if not mitre:
                continue

            tactic = mitre.get("tactic", "Unknown")
            technique_id = mitre.get("id", "N/A")
            technique_name = mitre.get("technique", "Unknown")

            entry = summary[tactic][technique_id]
            entry["technique"] = technique_name
            entry["count"] += 1

            severity = alert.get("severity")
            if severity:
                entry["severity"].add(severity)

    # Convert set → string lisible
    for tactic in summary:
        for tid in summary[tactic]:
            sev = summary[tactic][tid]["severity"]
            summary[tactic][tid]["severity"] = ", ".join(sorted(sev))

    return summary

