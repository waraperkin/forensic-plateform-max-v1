#!/usr/bin/env bash
# Configure MISP.baseurl depuis l'hôte (après démarrage du conteneur).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTAINER="${MISP_CONTAINER:-forensic-misp}"

if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck source=/dev/null
  source "$ROOT/.env"
  set +a
fi
if [ -f "$ROOT/config/local-ports.env" ]; then
  set -a
  # shellcheck source=/dev/null
  source "$ROOT/config/local-ports.env"
  set +a
fi

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
fi

HOST="$(fp_url_identity 2>/dev/null || fp_resolve_public_host 2>/dev/null || echo "localhost")"
HOST=$(fp_normalize_host "$HOST" 2>/dev/null || echo "$HOST")
_computed="$(fp_misp_public_base_url 2>/dev/null || echo "https://${HOST}/misp")"
# Réaligne si .env sans port alors que FP_HTTPS_PORT ≠ 443 (dev local Docker Desktop)
if [ -z "${MISP_PUBLIC_BASE_URL:-}" ] || echo "${MISP_PUBLIC_BASE_URL}" | grep -qE '^https?://[^:/]+/misp/?$'; then
  export MISP_PUBLIC_BASE_URL="$_computed"
else
  export MISP_PUBLIC_BASE_URL="${MISP_PUBLIC_BASE_URL}"
fi
# Normalise : une seule fois https://, pas de slash final
MISP_PUBLIC_BASE_URL="${MISP_PUBLIC_BASE_URL#https://}"
MISP_PUBLIC_BASE_URL="${MISP_PUBLIC_BASE_URL#http://}"
MISP_PUBLIC_BASE_URL="https://${MISP_PUBLIC_BASE_URL%/}"
export MISP_PUBLIC_BASE_URL

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
  echo "[misp-configure-host] Container $CONTAINER absent"
  exit 1
fi

echo "[misp-configure-host] MISP_PUBLIC_BASE_URL=${MISP_PUBLIC_BASE_URL}"
MSYS_NO_PATHCONV=1 docker exec -e "MISP_PUBLIC_BASE_URL=${MISP_PUBLIC_BASE_URL}" "$CONTAINER" \
  bash /scripts/misp-configure-public-url.sh
echo "[misp-configure-host] Terminé"
