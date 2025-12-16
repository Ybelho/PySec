# PySec – Honeypot, NIDS & SOC Dashboard

## 1. Objectif du projet

PySec est un projet de cybersécurité pédagogique visant à concevoir une chaîne complète de détection d’intrusion :

- Honeypot SSH (Cowrie)
- NIDS Python avec détection par signatures et anomalies
- Enrichissement MITRE ATT&CK
- Dashboard SOC temps réel (Flask)
- Génération de rapports PDF
- Simulation d’attaques automatisées

Le projet est conçu pour être démontrable, reproductible et lisible dans un cadre académique.

---

## 2. Architecture globale

Flux logique :

Attacker (Docker)
→ Cowrie Honeypot (SSH)
→ Logs JSON
→ NIDS Python
→ Alertes enrichies MITRE
→ Dashboard SOC Flask
→ Export PDF

---

## 3. Structure du dépôt

```text
PySec/
├── attacker/               # Attaques automatisées (nmap, brute-force, payload)
├── cowrie/                 # Honeypot SSH Cowrie
├── nids/                   # Détection intrusion Python
├── dashboard/              # Dashboard SOC Flask
├── analyze/                # Scripts d’analyse offline
├── logs/                   # Logs partagés (volumes Docker)
├── docker-compose.yml      # Orchestration complète
├── setup_and_run.sh        # Gestion Cowrie + Docker
├── setup_venvs.sh          # Génération des environnements Python
├── test_nids.sh            # Tests rapides NIDS
├── .env / .env.example     # Variables d’environnement
└── README.md
```
---

## 4. Prérequis

- Linux (Ubuntu recommandé)
- Python 3.10+
- Docker et Docker Compose
- Accès réseau local (lab uniquement)

---

## 5. Gestion des environnements Python

Les environnements virtuels ne sont pas versionnés.

Script dédié :

setup_venvs.sh

Fonction :
- Crée tous les .venv nécessaires (dashboard, nids, analyse)
- Installe les dépendances depuis requirements.txt
- Aucun .env n’est lu ni généré

Exécution :

chmod +x setup_venvs.sh
./setup_venvs.sh

---

## 6. Lancement du projet

### Étape 1 – Démarrage Cowrie + Docker

`git clone https://github.com/cowrie/cowrie.git`

Script principal :

`./setup_and_run.sh install`

`./setup_and_run.sh start`

Fonctions :
- Active le venv Cowrie
- Démarre Cowrie en local (port 2222)
- Lance tous les containers Docker

### Étape 2 – Vérification

docker ps
curl http://localhost:5000/api/stats

---

## 7. Accès au dashboard SOC

URL :

http://localhost:5000

Pages disponibles :
- Overview
- Alerts (live polling)
- Stats (risk score par IP)
- MITRE ATT&CK (heatmap + drill-down)
- Kill Chain Timeline
- Export PDF

---

## 8. MITRE ATT&CK & Kill Chain

Chaque alerte est enrichie avec :
- Tactique MITRE
- Technique
- ID (ex: T1059)

Les privilèges élevés sont correctement mappés (Privilege Escalation).

La timeline affiche :
- Date complète
- Ordre chronologique
- Sévérité

---

## 9. Simulation d’attaques

Container attacker :
- Scan SYN (nmap)
- Brute-force SSH
- Commandes détectables (wget, sudo, whoami)

Lancement :

docker compose up attacker

---

## 10. Export PDF

Route :

/export/pdf

Contenu :
- KPI globaux
- Répartition par sévérité
- Timeline
- Top MITRE
- Heatmap

---

## 11. Arrêt et nettoyage

Arrêt propre :

./setup_and_run.sh stop

Suppression des containers :

docker compose down -v

---

## 12. Sécurité et cadre

Ce projet est strictement destiné à :
- Un environnement de laboratoire
- Une démonstration académique

Ne jamais exposer Cowrie ou le dashboard sur Internet.

---

## 13. Conclusion

PySec est un projet complet et cohérent illustrant :
- La détection d’attaques réelles
- L’enrichissement MITRE ATT&CK
- La visualisation SOC moderne
- Une chaîne sécurité de bout en bout

Idéal pour une soutenance, un TP avancé ou un portfolio cybersécurité.
