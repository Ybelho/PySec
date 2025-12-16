# sensors/cowrie_log.py
import time
import json
import logging
import os
from pathlib import Path


def tail_cowrie_log(path: str, callback, interval: int = 2) -> None:
    """
    Suit un fichier Cowrie JSON en temps réel (mode tail -f).
    Appelle callback(event_dict) pour chaque event valide.
    """

    logging.info(f"[CowrieSensor] Attente du fichier: {path}")

    # Attendre que le fichier existe ET contienne quelque chose
    while True:
        try:
            if Path(path).exists() and os.path.getsize(path) > 0:
                break
        except Exception:
            pass
        time.sleep(2)

    logging.info(f"[CowrieSensor] Fichier trouvé, début du tail")

    with open(path, "r") as f:
        # Aller à la fin du fichier (comportement tail -f)
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(interval)
                continue

            try:
                event = json.loads(line.strip())
                callback(event)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                logging.error(f"[CowrieSensor] Erreur traitement ligne: {e}")
