#!/usr/bin/env bash
# Configure MISP.baseurl depuis l'hôte (après démarrage du conteneur).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTAINER="${MISP_CONTAINER:-forensic-misp}"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
  fp_align_env_public_ip 2>/dev/null || true
fi
if [ -f "$ROOT/.env" ]; then
  while IFS= read -r _line || [ -n "$_line" ]; do
    case "$_line" in "#"*|"") continue ;; esac
    case "$_line" in
      MISP_PUBLIC_BASE_URL=*)
        _v="${_line#MISP_PUBLIC_BASE_URL=}"
        _v="${_v%\"}"; _v="${_v#\"}"; _v="${_v%\'}"; _v="${_v#\'}"
        [ -n "$_v" ] && export MISP_PUBLIC_BASE_URL="$_v"
        ;;
    esac
  done < "$ROOT/.env"
fi
if [ -f "$ROOT/config/local-ports.env" ]; then
  while IFS= read -r _line || [ -n "$_line" ]; do
    case "$_line" in "#"*|"") continue ;; esac
    case "$_line" in
      MISP_PUBLIC_BASE_URL=*)
        _v="${_line#MISP_PUBLIC_BASE_URL=}"
        _v="${_v%\"}"; _v="${_v#\"}"; _v="${_v%\'}"; _v="${_v#\'}"
        [ -n "$_v" ] && export MISP_PUBLIC_BASE_URL="$_v"
        ;;
    esac
  done < "$ROOT/config/local-ports.env"
fi

HOST="$(fp_url_identity 2>/dev/null || fp_resolve_public_host 2>/dev/null || echo "localhost")"
HOST=$(fp_normalize_host "$HOST" 2>/dev/null || echo "$HOST")
_computed="$(fp_misp_public_base_url 2>/dev/null || echo "https://${HOST}/misp")"
if [ -z "${MISP_PUBLIC_BASE_URL:-}" ] || echo "${MISP_PUBLIC_BASE_URL}" | grep -qE '^https?://[^:/]+/misp/?$'; then
  export MISP_PUBLIC_BASE_URL="$_computed"
else
  export MISP_PUBLIC_BASE_URL="${MISP_PUBLIC_BASE_URL}"
fi
MISP_PUBLIC_BASE_URL="${MISP_PUBLIC_BASE_URL#https://}"
MISP_PUBLIC_BASE_URL="${MISP_PUBLIC_BASE_URL#http://}"
MISP_PUBLIC_BASE_URL="https://${MISP_PUBLIC_BASE_URL%/}"
export MISP_PUBLIC_BASE_URL

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
  echo "[misp-configure-host] Container $CONTAINER absent"
  exit 1
fi

echo "[misp-configure-host] MISP_PUBLIC_BASE_URL=${MISP_PUBLIC_BASE_URL}"

_run_in_misp() {
  MSYS_NO_PATHCONV=1 docker exec -e "MISP_PUBLIC_BASE_URL=${MISP_PUBLIC_BASE_URL}" "$CONTAINER" "$@"
}

for attempt in 1 2 3 4 5; do
  if _run_in_misp bash /scripts/misp-apply-bootstrap-fix.sh 2>/dev/null \
    && _run_in_misp bash /scripts/misp-configure-public-url.sh; then
    _run_in_misp bash -c 'rm -rf /var/www/MISP/app/tmp/cache/models/* /var/www/MISP/app/tmp/cache/persistent/* 2>/dev/null || true'
    echo "[misp-configure-host] Terminé"
    exit 0
  fi
  echo "[misp-configure-host] tentative ${attempt}/5 — attente MISP…" >&2
  sleep 10
done

echo "[misp-configure-host] ERREUR après 5 tentatives" >&2
exit 1
