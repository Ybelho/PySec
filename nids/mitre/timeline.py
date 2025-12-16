# nids/mitre/timeline.py

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ALERTS_FILE = "/app/logs/alerts.jsonl"
TIMELINE_TXT = "/app/logs/mitre_timeline.txt"
TIMELINE_JSON = "/app/logs/mitre_timeline.json"


def parse_ts(ts: str) -> str:
    """
    Normalise le timestamp pour affichage lisible.
    """
    try:
        return datetime.fromisoformat(ts.replace("Z", "")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


def generate_mitre_timeline():
    """
    Génère une timeline MITRE par session à partir des alertes.
    """
    if not Path(ALERTS_FILE).exists():
        return None

    sessions = defaultdict(list)

    with open(ALERTS_FILE, "r") as f:
        for line in f:
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            session = alert.get("session", "unknown")
            sessions[session].append(alert)

    timeline = {}

    for session, alerts in sessions.items():
        alerts.sort(key=lambda a: a.get("timestamp", ""))

        timeline[session] = []
        for a in alerts:
            mitre = a.get("mitre", {})
            timeline[session].append({
                "timestamp": parse_ts(a.get("timestamp", "")),
                "src_ip": a.get("src_ip"),
                "tactic": mitre.get("tactic"),
                "technique": mitre.get("technique"),
                "id": mitre.get("id"),
                "type": a.get("type"),
                "command": a.get("command"),
            })

    # --- Écriture JSON ---
    with open(TIMELINE_JSON, "w") as jf:
        json.dump(timeline, jf, indent=2, ensure_ascii=False)

    # --- Écriture TXT lisible humain ---
    with open(TIMELINE_TXT, "w") as tf:
        for session, events in timeline.items():
            tf.write(f"\n=== Session {session} ===\n")
            for e in events:
                tf.write(
                    f"[{e['timestamp']}] "
                    f"{e['tactic']} ({e['id']}) | "
                    f"{e['type']} | "
                    f"{e.get('command','')}\n"
                )

    return TIMELINE_TXT, TIMELINE_JSON

