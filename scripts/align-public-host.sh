#!/usr/bin/env bash
# Aligne toutes les configs runtime sur l'IP hôte détectée (portable — clone frais / nouvelle VM).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export DIR="$ROOT"

# shellcheck source=/dev/null
. "$ROOT/scripts/lib/host-ip.sh"
# shellcheck source=/dev/null
. "$ROOT/scripts/lib/platform-host.sh"
# shellcheck source=/dev/null
. "$ROOT/scripts/lib/installer.sh"

HOST=$(fp_url_identity 2>/dev/null || fp_detect_public_host 2>/dev/null || echo "127.0.0.1")
HOST=$(fp_normalize_host "$HOST")
echo "[align-host] IP hôte : $HOST"

_fp_bootstrap_env_complete || true
fp_prepare_platform_host || true
_fp_ensure_runtime_host_config || true

if [ -x "$ROOT/scripts/generate-grafana-ini.sh" ]; then
  bash "$ROOT/scripts/generate-grafana-ini.sh"
fi
if [ -x "$ROOT/scripts/render-velociraptor-nginx-snippet.sh" ]; then
  bash "$ROOT/scripts/render-velociraptor-nginx-snippet.sh"
fi

docker compose up -d --build cert-portal it-portal nginx 2>/dev/null || true
docker compose exec -T nginx nginx -s reload 2>/dev/null || true

echo "[align-host] Terminé — https://${HOST}/"
