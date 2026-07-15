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

# 1 — Nginx : snippet VR + recreate (volume docs)
if [ -x "$ROOT/scripts/render-velociraptor-nginx-snippet.sh" ]; then
  bash "$ROOT/scripts/render-velociraptor-nginx-snippet.sh" || true
fi
docker compose up -d --force-recreate nginx 2>/dev/null || true
sleep 3
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-nginx$'; then
  docker network connect velociraptor_net forensic-nginx 2>/dev/null || true
  docker exec forensic-nginx nginx -t 2>/dev/null && docker exec forensic-nginx nginx -s reload 2>/dev/null \
    && log "Nginx rechargé" \
    || log "WARN reload nginx"
fi

# 2 — MISP CSRF + baseurl
if [ -x "$ROOT/scripts/misp-repair-csrf.sh" ]; then
  bash "$ROOT/scripts/misp-repair-csrf.sh" || log "WARN misp-repair-csrf"
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-misp$'; then
  log "MISP — bootstrap + baseurl"
  export MISP_PUBLIC_BASE_URL="$(fp_misp_public_base_url 2>/dev/null || echo "${BASE}/misp")"
  docker compose up -d misp 2>/dev/null || true
  MSYS_NO_PATHCONV=1 docker exec forensic-misp bash /scripts/misp-apply-bootstrap-fix.sh 2>/dev/null || true
  bash "$ROOT/scripts/misp-configure-host.sh" 2>/dev/null || log "WARN misp-configure-host"
else
  log "WARN forensic-misp absent"
fi

# 3 — Velociraptor sidecar + nginx
if [ -x "$ROOT/scripts/repair-velociraptor-access.sh" ]; then
  bash "$ROOT/scripts/repair-velociraptor-access.sh" || log "WARN repair-velociraptor-access"
fi

# 4 — Portail CERT (docs + JS)
log "Portail CERT — rebuild sans cache layer shared"
docker compose build --no-cache cert-portal 2>/dev/null || docker compose build cert-portal 2>/dev/null || true
docker compose up -d --force-recreate cert-portal 2>/dev/null || true
sleep 8

# 5 — Vérification
if [ -x "$ROOT/scripts/verify-platform-ready.sh" ]; then
  FP_SKIP_HELK_PATTERNS=1 BASE_URL="$BASE" bash "$ROOT/scripts/verify-platform-ready.sh"
else
  for path in /logstash/ /misp/users/login /velociraptor/app/index.html /docs/fr/platform-inventory.json; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 "${BASE}${path}" 2>/dev/null || echo "000")
    log "${path} → HTTP ${code}"
  done
fi

log "Réparation terminée — ${BASE}/"
