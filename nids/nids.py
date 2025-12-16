#!/usr/bin/env python3
"""
NIDS (Network Intrusion Detection System)

Version "propre + complète" :
- Capte et analyse :
  1) les logs Cowrie en temps réel (détection signatures + anomalies log)
  2) le trafic réseau en temps réel via Scapy (détection anomalies réseau)
- Écrit les alertes en JSONL
- Génère un rapport + chiffrement (Fernet/AES-like) périodiquement (optionnel)

Dépend des fichiers ajoutés :
- sensors/cowrie_log.py
- sensors/network.py
- detectors/signatures.py
- detectors/anomalies_log.py
- detectors/anomalies_net.py
- reporter/report.py
"""

import os
import json
import time
import logging
import threading
from datetime import datetime

# --- Paths / Config ---
COWRIE_LOG = os.getenv("COWRIE_LOG", "/cowrie_logs/cowrie.json")
ALERTS_FILE = os.getenv("ALERTS_FILE", "/app/logs/alerts.jsonl")

# Rapports (optionnel)
ENABLE_REPORT = os.getenv("ENABLE_REPORT", "1") == "1"
REPORT_EVERY_SECONDS = int(os.getenv("REPORT_EVERY_SECONDS", "120"))  # 2 minutes par défaut

# Logging
os.makedirs("/app/logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/app/logs/nids.log"),
        logging.StreamHandler(),
    ],
)

# --- Imports modules ajoutés ---
from sensors.cowrie_log import tail_cowrie_log
from sensors.network import start_sniff
from detectors.signatures import detect_command_signatures
from detectors.anomalies_log import detect_bruteforce
from detectors.anomalies_net import detect_port_scan
from reporter.report import generate_report
from mitre.mapping import enrich_with_mitre


# --- Anti-doublons (Cowrie) ---
processed_events = set()
processed_lock = threading.Lock()


def write_alert(alert: dict) -> None:
    """
    Écrit une alerte dans ALERTS_FILE en JSONL.
    Ajoute des champs standard si manquants.
    """
    alert.setdefault("timestamp", datetime.now().isoformat())
    try:
        with open(ALERTS_FILE, "a") as f:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")
        logging.info(f"ALERT: {alert.get('type')} [{alert.get('severity','?')}] {alert.get('description','')}")
    except Exception as e:
        logging.error(f"Erreur écriture alerte: {e}")


def normalize_cowrie_event(event: dict) -> dict:
    """
    Normalise un event Cowrie et construit un event_id stable pour éviter doublons.
    """
    ts = event.get("timestamp") or event.get("time") or ""
    eid = event.get("eventid") or ""
    sess = event.get("session") or ""
    src = event.get("src_ip") or "unknown"
    event_id = f"{ts}:{eid}:{sess}:{src}"
    return event_id


def handle_cowrie_event(event: dict) -> None:
    """
    Callback appelé pour chaque event Cowrie (JSON).
    Déclenche signature + anomalies log.
    """
    try:
        event_id = normalize_cowrie_event(event)

        with processed_lock:
            if event_id in processed_events:
                return
            processed_events.add(event_id)
            # éviter une fuite mémoire infinie sur long run
            if len(processed_events) > 200000:
                processed_events.clear()

        src_ip = event.get("src_ip", "unknown")

        # 1) Signatures (commandes)
        sig = detect_command_signatures(event)
        if sig:
            alert = {
                "src_ip": src_ip,
                "session": event.get("session"),
                **sig,
                "raw_event": event,
            }

            alert = enrich_with_mitre(alert)
            write_alert(alert)
        # 2) Anomalies log (bruteforce via cowrie.login.failed)
        bf = detect_bruteforce(event)
        if bf:
            # detect_bruteforce renvoie déjà src_ip, attempts, etc.
            alert = {
                **bf,
                "raw_event": event,
            }

            alert = enrich_with_mitre(alert)
            write_alert(alert)
    except Exception as e:
        logging.error(f"Erreur handle_cowrie_event: {e}")


def handle_network_alert(net_alert: dict | None) -> None:
    """
    Callback réseau : net_alert est soit None soit un dict.
    On le passe dans le détecteur anomalies réseau.
    """
    try:
        if not net_alert:
            return
        alert = detect_port_scan(net_alert)
        if alert:
            alert = enrich_with_mitre(alert)
            write_alert(alert)
    except Exception as e:
        logging.error(f"Erreur handle_network_alert: {e}")


def thread_cowrie() -> None:
    logging.info(f"[Cowrie] Tail logs: {COWRIE_LOG}")
    tail_cowrie_log(COWRIE_LOG, callback=handle_cowrie_event, interval=2)


def thread_network() -> None:
    logging.info("[Network] Sniff Scapy (TCP/IP) en temps réel")
    # start_sniff appelle callback(process_packet(...))
    # où process_packet retourne None ou un dict event
    start_sniff(callback=handle_network_alert)


def thread_reporter() -> None:
    """
    Génère régulièrement un rapport (report.txt) + chiffré (report.enc) + clé (report.key).
    Utile pour démontrer l'exigence "rapport chiffré".
    """
    if not ENABLE_REPORT:
        logging.info("[Reporter] Désactivé (ENABLE_REPORT=0)")
        return

    logging.info(f"[Reporter] Génération rapport toutes les {REPORT_EVERY_SECONDS}s")
    while True:
        try:
            out = generate_report()
            if out:
                report_file, enc_file = out
                logging.info(f"[Reporter] Rapport généré: {report_file} | chiffré: {enc_file}")
            else:
                logging.info("[Reporter] Pas d'alertes -> pas de rapport")
        except Exception as e:
            logging.error(f"[Reporter] Erreur génération rapport: {e}")
        time.sleep(REPORT_EVERY_SECONDS)


def main():
    logging.info("=== Démarrage du NIDS (complet) ===")
    logging.info(f"COWRIE_LOG={COWRIE_LOG}")
    logging.info(f"ALERTS_FILE={ALERTS_FILE}")
    logging.info(f"ENABLE_REPORT={int(ENABLE_REPORT)} REPORT_EVERY_SECONDS={REPORT_EVERY_SECONDS}")

    # S'assure que le fichier alertes existe
    try:
        os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
        if not os.path.exists(ALERTS_FILE):
            open(ALERTS_FILE, "a").close()
    except Exception as e:
        logging.error(f"Impossible d'initialiser {ALERTS_FILE}: {e}")

    threads = []

    t1 = threading.Thread(target=thread_cowrie, name="cowrie-tail", daemon=True)
    t2 = threading.Thread(target=thread_network, name="net-sniff", daemon=True)
    threads.extend([t1, t2])

    t3 = threading.Thread(target=thread_reporter, name="reporter", daemon=True)
    threads.append(t3)

    for t in threads:
        t.start()

    # Boucle principale : garde le process vivant
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Arrêt demandé (CTRL+C).")
    except Exception as e:
        logging.error(f"Erreur fatale main: {e}")
        raise


if __name__ == "__main__":
    main()
