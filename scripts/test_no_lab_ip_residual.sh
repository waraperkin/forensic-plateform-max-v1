#!/usr/bin/env bash
# Échoue si l'IP lab 192.0.2.9 reste dans les configs runtime critiques.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail=0
LAB_IP='10\.78\.0\.9'

check_file() {
  local label="$1" file="$2"
  if [ -f "$file" ] && grep -qE "$LAB_IP" "$file" 2>/dev/null; then
    echo "FAIL: $label contient 192.0.2.9 ($file)" >&2
    fail=1
  else
    echo "PASS: $label"
  fi
}

check_file "velociraptor server.config" "$ROOT/velociraptor/config/server.config.yaml"
check_file "docker-compose.yml" "$ROOT/docker-compose.yml"
check_file "forensic.conf" "$ROOT/config/nginx/conf.d/forensic.conf"
check_file "grafana.ini" "$ROOT/config/grafana/grafana.ini"
check_file "portal-cert config" "$ROOT/portal-cert/public/config.json"
check_file "portal-it config" "$ROOT/portal-it/public/config.json"

if [ -f "$ROOT/.env" ] && grep -qE "^PUBLIC_HOST=${LAB_IP}" "$ROOT/.env" 2>/dev/null; then
  echo "WARN: .env local PUBLIC_HOST = 192.0.2.9 (fichier non versionné — lancer ./forensic.sh align-host)" >&2
else
  echo "PASS: .env PUBLIC_HOST"
fi

[ "$fail" -eq 0 ] && echo "Aucune IP lab résiduelle dans les configs critiques" || exit 1
