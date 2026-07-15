#!/usr/bin/env bash
# Répare un .env corrompu (clés traduites, secrets vides) et affiche les identifiants portail.
# Usage : ./scripts/repair-env-file.sh [--reset-portal]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export DIR="$ROOT"
RESET_PORTAL=0
for arg in "$@"; do
  case "$arg" in
    --reset-portal) RESET_PORTAL=1 ;;
    -h|--help)
      echo "Usage: $0 [--reset-portal]"
      echo "  Régénère .env depuis .env.example si clés non canoniques, complète les secrets labo,"
      echo "  recrée cert-portal. --reset-portal : efface users.json (admin = CERT_PORTAL_SECRET)."
      exit 0
      ;;
  esac
done

log() { echo "[repair-env] $*"; }

if [ ! -f "$ROOT/.env.example" ]; then
  log "ERREUR: .env.example absent — git pull depuis v2/main"
  exit 1
fi

if ! grep -qE '^POSTGRES_PASSWORD=' "$ROOT/.env.example"; then
  log "ERREUR: .env.example invalide (POSTGRES_PASSWORD absent) — git pull"
  exit 1
fi

# shellcheck source=/dev/null
. "$ROOT/scripts/lib/installer.sh"

log "Bootstrap / complétion .env…"
_fp_bootstrap_env_file || { log "Échec bootstrap .env"; exit 1; }

PORTAL_PASS=$(grep -E '^CERT_PORTAL_SECRET=' "$ROOT/.env" | tail -1 | cut -d= -f2- || true)
PORTAL_USER=$(grep -E '^PORTAL_ADMIN_USER=' "$ROOT/.env" | tail -1 | cut -d= -f2- || echo "admin")
PUBLIC=$(grep -E '^PUBLIC_HOST=' "$ROOT/.env" | tail -1 | cut -d= -f2- || echo "127.0.0.1")

log "Recréation cert-portal (charge le nouveau .env)…"
docker compose up -d --force-recreate cert-portal 2>&1 | tail -5 || true

if [ "$RESET_PORTAL" -eq 1 ] && [ -x "$ROOT/scripts/reset-portal-admin.sh" ]; then
  bash "$ROOT/scripts/reset-portal-admin.sh"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  .env réparé — identifiants portail CERT"
echo "  URL      : https://${PUBLIC}/"
echo "  Login    : ${PORTAL_USER:-admin}"
echo "  Password : ${PORTAL_PASS:-F0r3ns1c_Portal_2024!}"
echo ""
echo "  Si connexion impossible : ./scripts/reset-portal-admin.sh"
echo "  Puis relancer : docker compose up -d --force-recreate cert-portal"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
