#!/usr/bin/env bash
set -euo pipefail

# ---------- CONFIG ----------
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COWRIE_DIR="${PROJECT_ROOT}/cowrie"
VENV_DIR="${COWRIE_DIR}/cowrie-env"
COWRIE_BIN="${COWRIE_DIR}/bin/cowrie"
COWRIE_CFG_DIR="${COWRIE_DIR}/etc"
COWRIE_CFG="${COWRIE_CFG_DIR}/cowrie.cfg"
DOCKER_COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
TZ_DEFAULT="Europe/Paris"

# ---------- HELP ----------
usage() {
  cat <<EOF
Usage: $0 <command>

Commands:
  install        Installe dépendances système (Debian/Ubuntu si possible), crée venv et installe Cowrie
  start          Démarre Cowrie (venv locale) puis 'docker compose up -d' (si docker-compose.yml présent)
  stop           Arrête Cowrie et 'docker compose down'
  restart        stop puis start
  status         Affiche l'état basique (process Cowrie + containers)
  logs           Affiche les logs Cowrie (cowrie.log si présent)
  redirect22     (Optionnel) Ajoute iptables PREROUTING 22 -> 2222 (nécessite sudo)
  enable-telnet  (Optionnel) Active Telnet dans ${COWRIE_CFG}
  update         Met à jour Cowrie (git pull + pip install -e .) dans le venv
  help           Affiche cette aide

Notes:
- Ce script suppose l'arborescence:
    ${PROJECT_ROOT}/cowrie
    ${PROJECT_ROOT}/docker-compose.yml  (optionnel)
- Teste uniquement sur un environnement de labo contrôlé.
EOF
}

# ---------- UTILS ----------
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || return 1
}

apt_install_if_available() {
  if need_cmd apt-get; then
    echo "[*] Installation via apt-get: $*"
    sudo apt-get update -y
    sudo apt-get install -y --no-install-recommends "$@"
  else
    echo "[!] apt-get non disponible. Installe manuellement: $*"
  fi
}

ensure_cowrie_tree() {
  if [[ ! -d "${COWRIE_DIR}" ]]; then
    echo "[!] Dossier 'cowrie' introuvable à ${COWRIE_DIR}"
    echo "    Clone attendu à la racine du projet. Abandon."
    exit 1
  fi
}

ensure_venv() {
  if [[ ! -d "${VENV_DIR}" ]]; then
    echo "[*] Création du virtualenv Cowrie..."
    python3 -m venv "${VENV_DIR}"
  fi
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  python -m pip install --upgrade pip
}

ensure_cowrie_installed() {
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  pushd "${COWRIE_DIR}" >/dev/null
  echo "[*] Installation Cowrie en mode editable..."
  python -m pip install -e .
  popd >/dev/null
}

ensure_cfg() {
  mkdir -p "${COWRIE_CFG_DIR}"
  if [[ ! -f "${COWRIE_CFG}" ]]; then
    echo "[*] Création ${COWRIE_CFG} par défaut..."
    cat > "${COWRIE_CFG}" <<EOF
[output_jsonlog]
enabled = true

[honeypot]
hostname = files

[ssh]
# Cowrie écoute en 2222 par défaut, NE PAS activer 22 ici sans redirection/authbind
listen_endpoints = tcp:2222:interface=0.0.0.0

[device]
# Fuseaux horaires pour les timestamps
timezone = ${TZ_DEFAULT}
EOF
  fi
}

cowrie_start() {
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  pushd "${COWRIE_DIR}" >/dev/null
  echo "[*] Démarrage Cowrie..."
  "${COWRIE_BIN}" start
  popd >/dev/null
}

cowrie_stop() {
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  pushd "${COWRIE_DIR}" >/dev/null
  echo "[*] Arrêt Cowrie..."
  if ! "${COWRIE_BIN}" stop; then
    echo "[i] Cowrie n'était peut-être pas démarré."
  fi
  popd >/dev/null
}

docker_up() {
  if [[ -f "${DOCKER_COMPOSE_FILE}" ]]; then
    if ! need_cmd docker; then
      echo "[!] Docker non trouvé, skip docker compose."
      return 0
    fi
    echo "[*] Démarrage docker compose..."
    docker compose -f "${DOCKER_COMPOSE_FILE}" up -d --build
  else
    echo "[i] docker-compose.yml non trouvé, skip docker compose."
  fi
}

docker_down() {
  if [[ -f "${DOCKER_COMPOSE_FILE}" ]] && need_cmd docker; then
    echo "[*] Arrêt docker compose..."
    docker compose -f "${DOCKER_COMPOSE_FILE}" down
  fi
}

show_status() {
  echo "---- STATUS ----"
  if pgrep -f "twistd.*cowrie" >/dev/null 2>&1; then
    echo "Cowrie: RUNNING"
  else
    echo "Cowrie: STOPPED"
  fi
  if need_cmd docker; then
    echo "Containers (docker):"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  fi
}

show_logs() {
  LOGFILE_GLOB="${COWRIE_DIR}/var/log/cowrie/cowrie.log"
  JSON_GLOB="${COWRIE_DIR}/var/log/cowrie/cowrie.json*"
  if ls ${LOGFILE_GLOB} >/dev/null 2>&1; then
    tail -n 100 -F ${LOGFILE_GLOB}
  elif ls ${JSON_GLOB} >/dev/null 2>&1; then
    tail -n 50 -F ${JSON_GLOB}
  else
    echo "[i] Logs introuvables pour l'instant. Vérifie que Cowrie a démarré et créé var/log/cowrie/"
  fi
}

redirect_22() {
  echo "[*] Ajout règle iptables PREROUTING: 22 -> 2222 (nécessite sudo)"
  sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
  echo "[i] Teste depuis UNE AUTRE machine. Sur la machine locale, la redirection ne s'applique pas à loopback."
}

enable_telnet() {
  ensure_cfg
  if ! grep -q "^\[telnet\]" "${COWRIE_CFG}"; then
    cat >> "${COWRIE_CFG}" <<'EOF'

[telnet]
enabled = true
# écoute par défaut 2223 si activé
EOF
    echo "[*] Telnet activé dans ${COWRIE_CFG}. Redémarre Cowrie pour appliquer."
  else
    echo "[i] Telnet semble déjà présent dans ${COWRIE_CFG}."
  fi
}

do_install() {
  ensure_cowrie_tree
  echo "[*] Installation des dépendances système (si Debian/Ubuntu détecté) ..."
  apt_install_if_available git python3-pip python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind
  echo "[*] Préparation venv + installation Cowrie ..."
  ensure_venv
  ensure_cowrie_installed
  ensure_cfg
  echo "[✓] Installation terminée."
}

do_update() {
  ensure_cowrie_tree
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate" || true
  if [[ -d "${COWRIE_DIR}/.git" ]]; then
    pushd "${COWRIE_DIR}" >/dev/null
    echo "[*] git pull ..."
    git pull --ff-only || true
    echo "[*] pip upgrade ..."
    python -m pip install --upgrade -e .
    popd >/dev/null
    echo "[✓] Cowrie mis à jour."
  else
    echo "[!] Le dossier cowrie n'est pas un repo git (pas de .git)."
  fi
}

# ---------- MAIN ----------
cmd="${1:-help}"
case "${cmd}" in
  install)
    do_install
    ;;
  start)
    ensure_cowrie_tree
    ensure_venv
    ensure_cfg
    cowrie_start
    docker_up
    show_status
    ;;
  stop)
    cowrie_stop || true
    docker_down || true
    show_status
    ;;
  restart)
    "$0" stop
    "$0" start
    ;;
  status)
    show_status
    ;;
  logs)
    show_logs
    ;;
  redirect22)
    redirect_22
    ;;
  enable-telnet)
    enable_telnet
    ;;
  update)
    do_update
    ;;
  help|*)
    usage
    ;;
esac

