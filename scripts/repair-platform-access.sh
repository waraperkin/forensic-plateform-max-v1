#!/usr/bin/env bash
# Répare les accès Logstash / MISP / Velociraptor / docs sans relancer tout le full-start.
# Usage : ./scripts/repair-platform-access.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
  fp_align_env_public_ip 2>/dev/null || true
fi

HOST=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "127.0.0.1")
HOST=$(fp_normalize_host "$HOST" 2>/dev/null || echo "$HOST")
export PUBLIC_HOST="$HOST"
BASE="https://${HOST}"

log() { echo "[repair-access] $*"; }

log "Hôte public : $HOST"

# 1 — Nginx : snippet VR + reload
if [ -x "$ROOT/scripts/render-velociraptor-nginx-snippet.sh" ]; then
  bash "$ROOT/scripts/render-velociraptor-nginx-snippet.sh" || true
fi
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-nginx$'; then
  docker network connect velociraptor_net forensic-nginx 2>/dev/null || true
  docker exec forensic-nginx nginx -t 2>/dev/null && docker exec forensic-nginx nginx -s reload 2>/dev/null \
    && log "Nginx rechargé" \
    || log "WARN reload nginx"
fi

# 2 — MISP baseurl + bootstrap App.base (/misp/)
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-misp$'; then
  log "MISP — bootstrap + baseurl"
  export MISP_PUBLIC_BASE_URL="$(fp_misp_public_base_url 2>/dev/null || echo "${BASE}/misp")"
  docker compose up -d misp 2>/dev/null || true
  n=0
  until docker exec forensic-misp curl -sf --max-time 5 http://127.0.0.1/users/login >/dev/null 2>&1; do
    n=$((n + 1))
    [ "$n" -ge 36 ] && { log "WARN MISP timeout"; break; }
    sleep 5
  done
  if [ "$n" -lt 36 ]; then
    MSYS_NO_PATHCONV=1 docker exec forensic-misp bash /scripts/misp-apply-bootstrap-fix.sh 2>/dev/null || true
    bash "$ROOT/scripts/misp-configure-host.sh" 2>/dev/null || log "WARN misp-configure-host"
  fi
else
  log "WARN forensic-misp absent"
fi

# 3 — Velociraptor sidecar + nginx
if [ -x "$ROOT/scripts/repair-velociraptor-access.sh" ]; then
  bash "$ROOT/scripts/repair-velociraptor-access.sh" || log "WARN repair-velociraptor-access"
fi

# 4 — Portail CERT (docs statiques + auth)
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^cert-portal$'; then
  log "Portail CERT — rebuild si docs absents dans le conteneur"
  if ! docker exec cert-portal test -f /app/public/docs/fr/platform-inventory.json 2>/dev/null; then
    log "Docs manquants dans cert-portal — rebuild image"
    docker compose up -d --build cert-portal 2>/dev/null || true
    sleep 8
  fi
fi

# 5 — Vérification
if [ -x "$ROOT/scripts/verify-platform-ready.sh" ]; then
  BASE_URL="$BASE" bash "$ROOT/scripts/verify-platform-ready.sh"
else
  for path in /logstash/ /misp/users/login /velociraptor/app/index.html /docs/fr/platform-inventory.json; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 "${BASE}${path}" 2>/dev/null || echo "000")
    log "${path} → HTTP ${code}"
  done
fi

log "Réparation terminée — ${BASE}/"
