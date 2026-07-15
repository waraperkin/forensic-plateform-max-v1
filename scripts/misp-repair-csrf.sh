#!/usr/bin/env bash
# Répare MISP CSRF / baseurl derrière nginx /misp/ (AWS IP publique).
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
export MISP_PUBLIC_BASE_URL="$(fp_misp_public_base_url 2>/dev/null || echo "${BASE}/misp")"

log() { echo "[misp-repair] $*"; }

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-misp$'; then
  log "ERREUR: conteneur forensic-misp absent"
  exit 1
fi

log "Hôte public : $HOST"

# Force require du correctif App.base (même si ancien patch inline)
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-misp$'; then
  docker exec forensic-misp bash -c \
    'grep -q "misp-bootstrap-localhost-fix.php" /var/www/MISP/app/Config/bootstrap.php 2>/dev/null || echo "require \"/scripts/misp-bootstrap-localhost-fix.php\";" >> /var/www/MISP/app/Config/bootstrap.php' \
    2>/dev/null || true
fi
log "MISP_PUBLIC_BASE_URL=${MISP_PUBLIC_BASE_URL}"

# Persiste l'URL publique dans .env (sans source .env complet)
if [ -f "$ROOT/.env" ]; then
  if grep -q '^MISP_PUBLIC_BASE_URL=' "$ROOT/.env"; then
    sed -i "s|^MISP_PUBLIC_BASE_URL=.*|MISP_PUBLIC_BASE_URL=${MISP_PUBLIC_BASE_URL}|" "$ROOT/.env"
  else
    echo "MISP_PUBLIC_BASE_URL=${MISP_PUBLIC_BASE_URL}" >> "$ROOT/.env"
  fi
fi

docker compose up -d misp 2>/dev/null || true

n=0
until docker exec forensic-misp curl -sf --max-time 5 http://127.0.0.1/users/login >/dev/null 2>&1; do
  n=$((n + 1))
  [ "$n" -ge 36 ] && { log "ERREUR: MISP timeout"; exit 1; }
  sleep 5
done

bash "$ROOT/scripts/misp-configure-host.sh"

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-nginx$'; then
  docker exec forensic-nginx nginx -t 2>/dev/null && docker exec forensic-nginx nginx -s reload 2>/dev/null \
    && log "Nginx rechargé" || log "WARN reload nginx"
fi

code=$(docker exec forensic-nginx wget -q -O /dev/null --no-check-certificate -S \
  "${MISP_PUBLIC_BASE_URL}/users/login" 2>&1 | awk '/HTTP\//{print $2}' | tail -1 || echo "000")
if echo "$code" | grep -qE '^(200|302)$'; then
  log "MISP login → HTTP ${code}"
else
  log "WARN: MISP login → HTTP ${code} (attendu 200|302)"
fi

log "MISP réparé — ${MISP_PUBLIC_BASE_URL}/users/login"
