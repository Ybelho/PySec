# nids/reporter/report.py

import json
import os
from datetime import datetime
from cryptography.fernet import Fernet

from mitre.reporter import generate_mitre_report
from mitre.timeline import generate_mitre_timeline

ALERTS_FILE = os.getenv("ALERTS_FILE", "/app/logs/alerts.jsonl")
LOG_DIR = "/app/logs"


def generate_report() -> tuple[str, str] | None:
    """
    Génère :
    - report.txt
    - report.enc (chiffré)
    - mitre_summary.txt
    - mitre_summary.json
    """
    if not os.path.exists(ALERTS_FILE):
        return None

    with open(ALERTS_FILE, "r") as f:
        alerts = [json.loads(line) for line in f if line.strip()]

    if not alerts:
        return None

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = os.path.join(LOG_DIR, "report.txt")

    # ======================
    # 1) RAPPORT PRINCIPAL
    # ======================
    with open(report_path, "w") as rf:
        rf.write("=== NIDS SECURITY REPORT ===\n")
        rf.write(f"Generated: {ts}\n")
        rf.write(f"Total alerts: {len(alerts)}\n\n")

        for a in alerts[-50:]:  # dernier batch
            rf.write(
                f"[{a.get('timestamp')}] "
                f"{a.get('type')} | "
                f"Severity: {a.get('severity')} | "
                f"Src: {a.get('src_ip')}\n"
            )

    # ======================
    # 2) CHIFFREMENT
    # ======================
    key = Fernet.generate_key()
    fernet = Fernet(key)

    with open(report_path, "rb") as rf:
        encrypted = fernet.encrypt(rf.read())

    enc_path = os.path.join(LOG_DIR, "report.enc")
    key_path = os.path.join(LOG_DIR, "report.key")

    with open(enc_path, "wb") as ef:
        ef.write(encrypted)

    with open(key_path, "wb") as kf:
        kf.write(key)

    # ======================
    # 3) RAPPORT MITRE ATT&CK
    # ======================
    mitre_out = generate_mitre_report()

    if mitre_out:
        mitre_json, mitre_txt = mitre_out
        print(f"[MITRE] Rapport généré: {mitre_txt}")
    generate_mitre_timeline()

    return report_path, enc_path
