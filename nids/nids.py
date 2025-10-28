#!/usr/bin/env python3
"""
NIDS (Network Intrusion Detection System)
Détecte les attaques à partir des logs Cowrie et du trafic réseau
"""
import json
import time
import logging
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter

# Configuration
COWRIE_LOG = "/cowrie_logs/cowrie.json"
ALERTS_FILE = "/app/logs/alerts.jsonl"
CHECK_INTERVAL = 2  # secondes

# Configurer logging
os.makedirs("/app/logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/nids.log'),
        logging.StreamHandler()
    ]
)

# Compteurs pour détection d'anomalies
ip_activity = defaultdict(lambda: {
    'login_attempts': 0,
    'failed_logins': 0,
    'commands': 0,
    'last_seen': None
})

# État pour éviter les doublons
processed_events = set()


class SignatureDetector:
    """Détection basée sur signatures"""
    
    @staticmethod
    def detect_payload_download(event):
        """Détecte les tentatives de téléchargement de payload"""
        if event.get('eventid') != 'cowrie.command.input':
            return None
        
        cmd = event.get('input', '').lower()
        dangerous_patterns = [
            'wget', 'curl', 'fetch', 'powershell',
            'invoke-webrequest', 'certutil', 'bitsadmin'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in cmd:
                return {
                    'type': 'PAYLOAD_DOWNLOAD',
                    'severity': 'HIGH',
                    'pattern': pattern.upper(),
                    'command': event.get('input'),
                    'description': f"Tentative de téléchargement détectée avec {pattern}"
                }
        return None
    
    @staticmethod
    def detect_privilege_escalation(event):
        """Détecte les tentatives d'élévation de privilèges"""
        if event.get('eventid') != 'cowrie.command.input':
            return None
        
        cmd = event.get('input', '').lower()
        priv_esc_patterns = ['sudo', 'su ', 'chmod +s', 'pkexec']
        
        for pattern in priv_esc_patterns:
            if pattern in cmd:
                return {
                    'type': 'PRIVILEGE_ESCALATION',
                    'severity': 'HIGH',
                    'pattern': pattern.upper(),
                    'command': event.get('input')
                }
        return None
    
    @staticmethod
    def detect_reconnaissance(event):
        """Détecte les commandes de reconnaissance"""
        if event.get('eventid') != 'cowrie.command.input':
            return None
        
        cmd = event.get('input', '').lower()
        recon_patterns = [
            'nmap', 'netstat', 'ifconfig', 'ip addr',
            'whoami', 'id', 'uname', 'cat /etc/passwd'
        ]
        
        for pattern in recon_patterns:
            if pattern in cmd:
                return {
                    'type': 'RECONNAISSANCE',
                    'severity': 'MEDIUM',
                    'pattern': pattern.upper(),
                    'command': event.get('input')
                }
        return None


class AnomalyDetector:
    """Détection basée sur anomalies"""
    
    BRUTE_FORCE_THRESHOLD = 5  # tentatives en 60 secondes
    COMMAND_FLOOD_THRESHOLD = 20  # commandes en 60 secondes
    
    @staticmethod
    def detect_brute_force(src_ip):
        """Détecte les attaques par force brute"""
        ip_data = ip_activity[src_ip]
        
        if ip_data['failed_logins'] >= AnomalyDetector.BRUTE_FORCE_THRESHOLD:
            return {
                'type': 'BRUTE_FORCE',
                'severity': 'HIGH',
                'failed_attempts': ip_data['failed_logins'],
                'description': f"Attaque par force brute détectée: {ip_data['failed_logins']} tentatives échouées"
            }
        return None
    
    @staticmethod
    def detect_command_flood(src_ip):
        """Détecte une activité suspecte (trop de commandes)"""
        ip_data = ip_activity[src_ip]
        
        if ip_data['commands'] >= AnomalyDetector.COMMAND_FLOOD_THRESHOLD:
            return {
                'type': 'COMMAND_FLOOD',
                'severity': 'MEDIUM',
                'command_count': ip_data['commands'],
                'description': f"Activité anormale: {ip_data['commands']} commandes exécutées"
            }
        return None


def write_alert(alert_data):
    """Écrit une alerte dans le fichier JSONL"""
    try:
        with open(ALERTS_FILE, 'a') as f:
            f.write(json.dumps(alert_data) + '\n')
        logging.info(f"ALERT: {alert_data['type']} - {alert_data.get('description', '')}")
    except Exception as e:
        logging.error(f"Erreur écriture alerte: {e}")


def process_event(event):
    """Traite un événement Cowrie et génère des alertes"""
    try:
        # Éviter les doublons
        event_id = f"{event.get('timestamp')}:{event.get('eventid')}:{event.get('session')}"
        if event_id in processed_events:
            return
        processed_events.add(event_id)
        
        src_ip = event.get('src_ip', 'unknown')
        eventid = event.get('eventid', '')
        
        # Mise à jour des statistiques IP
        ip_activity[src_ip]['last_seen'] = datetime.now()
        
        # Détection basée sur signatures
        detectors = [
            SignatureDetector.detect_payload_download,
            SignatureDetector.detect_privilege_escalation,
            SignatureDetector.detect_reconnaissance
        ]
        
        for detector in detectors:
            result = detector(event)
            if result:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'session': event.get('session'),
                    **result,
                    'raw_event': event
                }
                write_alert(alert)
        
        # Mise à jour compteurs pour anomalies
        if eventid == 'cowrie.login.failed':
            ip_activity[src_ip]['failed_logins'] += 1
            
            # Vérifier brute force
            result = AnomalyDetector.detect_brute_force(src_ip)
            if result:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    **result
                }
                write_alert(alert)
        
        elif eventid == 'cowrie.login.success':
            ip_activity[src_ip]['login_attempts'] += 1
            logging.info(f"Login réussi depuis {src_ip}")
        
        elif eventid == 'cowrie.command.input':
            ip_activity[src_ip]['commands'] += 1
            
            # Vérifier command flood
            result = AnomalyDetector.detect_command_flood(src_ip)
            if result:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    **result
                }
                write_alert(alert)
    
    except Exception as e:
        logging.error(f"Erreur traitement événement: {e}")


def tail_cowrie_logs():
    """Suit les logs Cowrie en temps réel"""
    logging.info(f"Surveillance des logs: {COWRIE_LOG}")
    
    # Attendre que le fichier existe
    while not Path(COWRIE_LOG).exists():
        logging.warning(f"En attente du fichier {COWRIE_LOG}...")
        time.sleep(5)
    
    # Position de lecture
    with open(COWRIE_LOG, 'r') as f:
        # Aller à la fin du fichier
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if line:
                try:
                    event = json.loads(line.strip())
                    process_event(event)
                except json.JSONDecodeError:
                    continue
            else:
                time.sleep(CHECK_INTERVAL)


def periodic_cleanup():
    """Nettoie les anciennes données (optionnel)"""
    # Réinitialiser les compteurs toutes les 5 minutes
    # pour éviter les faux positifs
    pass


def main():
    logging.info("=== Démarrage du NIDS ===")
    logging.info(f"Fichier de logs Cowrie: {COWRIE_LOG}")
    logging.info(f"Fichier d'alertes: {ALERTS_FILE}")
    
    try:
        tail_cowrie_logs()
    except KeyboardInterrupt:
        logging.info("Arrêt du NIDS")
    except Exception as e:
        logging.error(f"Erreur fatale: {e}")
        raise


if __name__ == "__main__":
    main()