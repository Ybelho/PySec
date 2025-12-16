# nids/mitre/reporter.py

import json
import os
from datetime import datetime
from mitre.aggregator import aggregate_mitre_alerts

LOG_DIR = "/app/logs"


def generate_mitre_report() -> tuple[str, str] | None:
    """
    Génère un rapport MITRE ATT&CK :
    - mitre_summary.json
    - mitre_summary.txt
    """
    summary = aggregate_mitre_alerts()

    if not summary:
        return None

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    json_path = os.path.join(LOG_DIR, "mitre_summary.json")
    txt_path = os.path.join(LOG_DIR, "mitre_summary.txt")

    # JSON
    with open(json_path, "w") as jf:
        json.dump(summary, jf, indent=2, ensure_ascii=False)

    # TXT (humain)
    with open(txt_path, "w") as tf:
        tf.write("=== MITRE ATT&CK SUMMARY ===\n")
        tf.write(f"Generated: {ts}\n\n")

        for tactic, techniques in summary.items():
            tf.write(f"[TACTIC] {tactic}\n")
            for tid, data in techniques.items():
                tf.write(
                    f"  - {tid} | {data['technique']} | "
                    f"Count: {data['count']} | Severity: {data['severity']}\n"
                )
            tf.write("\n")

    return json_path, txt_path

