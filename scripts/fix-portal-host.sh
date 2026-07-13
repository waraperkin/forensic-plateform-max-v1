#!/usr/bin/env bash
# Aligne config.json portails + rebuild cert/it après correction PUBLIC_HOST.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
. "$ROOT/scripts/lib/host-ip.sh"
fp_load_env_public_host 2>/dev/null || true
IP=$(fp_detect_public_host 2>/dev/null || fp_resolve_public_host 2>/dev/null || echo "127.0.0.1")
IP=$(fp_normalize_host "$IP")
BASE_URL="$(fp_public_https_origin 2>/dev/null || echo "https://${IP}")"
echo "[fix-portal-host] soc_base_url=$BASE_URL"
for cfg in portal-cert/public/config.json portal-it/public/config.json; do
  jq --arg url "$BASE_URL" '.soc_base_url = $url' "$cfg" > "${cfg}.tmp" && mv -f "${cfg}.tmp" "$cfg"
  echo "[fix-portal-host] OK $cfg"
done
bash "$ROOT/scripts/render-velociraptor-nginx-snippet.sh" 2>/dev/null || true
if grep -q '^PUBLIC_HOST=' .env; then
  sed -i "s/^PUBLIC_HOST=.*/PUBLIC_HOST=${IP}/" .env
fi
docker compose up -d --build cert-portal it-portal
docker compose up -d nginx
echo "[fix-portal-host] terminé — https://${IP}/"
