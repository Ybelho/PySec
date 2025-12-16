#!/usr/bin/env bash
set -e

echo "🐍 PySec – Python venv bootstrap"
echo "================================"

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

create_venv () {
  NAME="$1"
  DIR="$2"

  if [ ! -d "$DIR" ]; then
    echo "📦 Creating venv for $NAME → $DIR"
    python3 -m venv "$DIR"
  else
    echo "✅ venv for $NAME already exists"
  fi

  # activate
  source "$DIR/bin/activate"
  pip install --upgrade pip

  if [ -f "$3" ]; then
    echo "📜 Installing requirements for $NAME"
    pip install -r "$3"
  else
    echo "⚠️ No requirements.txt for $NAME"
  fi

  deactivate
}

# ---------- Dashboard ----------
create_venv \
  "dashboard" \
  "$PROJECT_ROOT/.venv_dashboard" \
  "$PROJECT_ROOT/dashboard/requirements.txt"

# ---------- NIDS ----------
create_venv \
  "nids" \
  "$PROJECT_ROOT/.venv_nids" \
  "$PROJECT_ROOT/nids/requirements.txt"

# ---------- Attacker ----------
if [ -f "$PROJECT_ROOT/attacker/auto_pentest.py" ]; then
  create_venv \
    "attacker" \
    "$PROJECT_ROOT/.venv_attacker" \
    "$PROJECT_ROOT/attacker/requirements.txt"
fi

# ---------- Analyze ----------
create_venv \
  "analyze" \
  "$PROJECT_ROOT/.venv_analyze" \
  "$PROJECT_ROOT/analyze/requirements.txt"

echo ""
echo "✅ All Python environments are ready"
echo "👉 Venvs created:"
echo "   - .venv_dashboard"
echo "   - .venv_nids"
echo "   - .venv_attacker (if requirements.txt exists)"
echo "   - .venv_analyze"

