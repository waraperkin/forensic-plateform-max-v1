#!/usr/bin/env bash
# Garantit que l'admin portail CERT correspond à CERT_PORTAL_SECRET (.env).
# Appelé automatiquement par post-start-align (full-start) — pas de lancement manuel requis.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

log() { echo "[ensure-portal-admin] $*"; }

fp_env_val() {
  local key="$1" def="${2:-}"
  if [ ! -f "$ROOT/.env" ]; then
    echo "$def"
    return
  fi
  local v
  v=$(grep -E "^${key}=" "$ROOT/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true)
  if [ -n "$v" ]; then
    echo "$v"
  else
    echo "$def"
  fi
}

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
fi

USER=$(fp_env_val "PORTAL_ADMIN_USER" "admin")
PASS=$(fp_env_val "PORTAL_ADMIN_PASSWORD" "")
if [ -z "$PASS" ]; then
  # P-04 : pas de mot de passe labo codé en dur — repli sur CERT_PORTAL_SECRET
  PASS=$(fp_env_val "CERT_PORTAL_SECRET" "")
fi
if [ -z "$PASS" ]; then
  echo "[ensure-portal-admin] ERREUR: ni PORTAL_ADMIN_PASSWORD ni CERT_PORTAL_SECRET définis (.env)" >&2
  exit 1
fi
HOST=$(fp_url_identity 2>/dev/null | head -n1 || fp_detect_public_ip 2>/dev/null | head -n1 || fp_env_val "PUBLIC_HOST" "127.0.0.1")
HOST=$(fp_normalize_host "$HOST" 2>/dev/null || echo "$HOST")
CONTAINER="${FP_CERT_PORTAL_CONTAINER:-forensic-cert-portal}"
CERT_PORT="${FP_CERT_PORTAL_PORT:-3000}"

portal_login_ok() {
  local base="$1" code
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 12 \
    -X POST "${base}/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${USER}\",\"password\":\"${PASS}\"}" 2>/dev/null || echo "000")
  [ "$code" = "200" ]
}

if portal_login_ok "http://127.0.0.1:${CERT_PORT}"; then
  log "Connexion portail OK (localhost:${CERT_PORT})"
  exit 0
fi

if portal_login_ok "https://${HOST}"; then
  log "Connexion portail OK (https://${HOST})"
  exit 0
fi

log "Identifiants portail incohérents — réinitialisation admin (users.json)…"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
  docker compose up -d cert-portal 2>/dev/null || true
  sleep 4
fi

docker exec "$CONTAINER" sh -c 'rm -f /shared-uploads/.portal-auth/users.json 2>/dev/null' 2>/dev/null || true
docker compose up -d --force-recreate cert-portal 2>/dev/null || docker compose restart cert-portal 2>/dev/null || true
sleep 5

if portal_login_ok "http://127.0.0.1:${CERT_PORT}"; then
  log "Admin portail resynchronisé — ${USER} / (CERT_PORTAL_SECRET dans .env)"
  exit 0
fi

log "ERREUR: connexion portail toujours impossible après reset"
log "  → ./scripts/repair-env-file.sh --reset-portal"
log "  → grep CERT_PORTAL_SECRET .env"
exit 1
