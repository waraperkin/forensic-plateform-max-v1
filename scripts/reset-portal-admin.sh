#!/usr/bin/env bash
# Réinitialise l'admin portail CERT pour correspondre à CERT_PORTAL_SECRET dans .env
# Usage : ./scripts/reset-portal-admin.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

log() { echo "[reset-portal] $*"; }

if [ -f "$ROOT/.env" ]; then
  USER=$(grep -E '^PORTAL_ADMIN_USER=' "$ROOT/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || echo "admin")
  PASS=$(grep -E '^PORTAL_ADMIN_PASSWORD=' "$ROOT/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || true)
  if [ -z "$PASS" ]; then
    PASS=$(grep -E '^CERT_PORTAL_SECRET=' "$ROOT/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || true)
  fi
fi
USER="${USER:-admin}"
PASS="${PASS:-F0r3ns1c_Portal_2024!}"
CONTAINER="${FP_CERT_PORTAL_CONTAINER:-forensic-cert-portal}"
AUTH_DIR="/shared-uploads/.portal-auth"
USERS_FILE="${AUTH_DIR}/users.json"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
  log "Démarrage cert-portal…"
  docker compose up -d cert-portal
  sleep 3
fi

log "Suppression users.json (recréation admin au prochain démarrage)…"
docker exec "$CONTAINER" sh -c "rm -f '${USERS_FILE}' '${AUTH_DIR}/users.json.bak' 2>/dev/null; ls -la '${AUTH_DIR}' 2>/dev/null || true"

log "Redémarrage cert-portal (ensureBootstrapAdmin)…"
docker compose restart cert-portal
sleep 4

if docker exec "$CONTAINER" test -f "$USERS_FILE" 2>/dev/null; then
  log "OK — users.json recréé"
else
  log "WARN — users.json absent (vérifiez les logs cert-portal)"
fi

echo ""
echo "  Connexion : ${USER} / ${PASS}"
echo "  (valeurs depuis .env CERT_PORTAL_SECRET / PORTAL_ADMIN_PASSWORD)"
