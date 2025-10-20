# Projet EPITA — Honeypot & Pentest automatisé (livrable intermédiaire)

## Équipe
- Membre A : Belhocine YANNI — Infra & Honeypot  
- Membre B : ZHANG Christophe — Attaques / Attacker  
- Membre C : ABUR Busra — NIDS & Détection  
(ajouter si 4e membre)

## Choix technologique
- Honeypot : **Cowrie** (SSH/Telnet honeypot)
- NIDS : **Python + Scapy** (détection signatures & anomalies)
- Attaquant automatisé : Python + outils (nmap, sshpass, curl, hping3)

## Attaques planifiées (MVP)
1. Scan SYN (nmap) → détection SYN_SCAN
2. Brute-force SSH (sshpass) → détection BRUTE_FORCE
3. Commande post-auth « wget » simulée → détection SHELL_PAYLOAD

## Architecture (schéma)
- 3 services Docker : cowrie, nids, attacker
- NIDS en `network_mode: host` pour sniffing dans le labo, logs locaux

## Planning (jusqu'au 27/11)
- Semaine 1 : infra Docker, cowrie ok, attacker minimal — tests basiques  
- Semaine 2 : NIDS minimal (signatures) + corrélation logs — tests automatisés  
- Semaine 3 : Documentation, PDF intermédiaire, préparation demo

## Méthodologie de test
- Exécuter `docker compose up --build -d`  
- Lancer `docker exec -it attacker python auto_pentest.py`  
- Lancer `docker exec -it nids python nids.py` (si non lancé via compose)  
- Récupérer `cowrie/var/log/cowrie/cowrie.json` et `nids/logs/alerts.jsonl`

## Risques & mitigations
- Ne pas exposer la machine sur Internet (réseau isolé)  
- Limiter durée et intensité des DoS tests  
- Anonymiser IP si partage externe

## Livrables intermédiaires
- Dockerfiles + scripts (attacker, nids)  
- Logs sample (cowrie + nids)  
- Ce document (PDF)

---
