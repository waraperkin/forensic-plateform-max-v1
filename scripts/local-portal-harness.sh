#!/usr/bin/env bash
# Harness local — portails CERT/IT sans stack complète (tests Playwright UI).
# N'interfère pas avec d'autres projets Docker : uniquement redis éphémère si besoin.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export FP_DEV_MODE=1
export FP_ALLOW_DEV_DEFAULTS=1
export CERT_PORTAL_URL="${CERT_PORTAL_URL:-http://127.0.0.1:3000}"
export PUBLIC_HOST="${PUBLIC_HOST:-127.0.0.1}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
export OPENSEARCH_URL="${OPENSEARCH_URL:-http://127.0.0.1:9200}"
export PORTAL_AUTH_DATA_DIR="${PORTAL_AUTH_DATA_DIR:-/tmp/fp-portal-auth}"
mkdir -p "$PORTAL_AUTH_DATA_DIR"

REDIS_CID=""
CERT_PID=""
IT_PID=""

kill_port() {
  local p="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -ti ":$p" | xargs -r kill -9 2>/dev/null || true
  elif command -v fuser >/dev/null 2>&1; then
    fuser -k "${p}/tcp" 2>/dev/null || true
  fi
}

cleanup() {
  [ -n "$CERT_PID" ] && kill "$CERT_PID" 2>/dev/null || true
  [ -n "$IT_PID" ] && kill "$IT_PID" 2>/dev/null || true
  kill_port 3000
  kill_port 3001
  [ -n "$REDIS_CID" ] && sudo docker rm -f "$REDIS_CID" 2>/dev/null || true
}
trap cleanup EXIT

start_redis() {
  if command -v redis-cli >/dev/null 2>&1 && redis-cli ping 2>/dev/null | grep -q PONG; then
    echo "Redis local déjà actif"
    return 0
  fi
  if command -v docker >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    REDIS_CID="fp-harness-redis-$$"
    sudo docker run -d --name "$REDIS_CID" -p 6379:6379 redis:7-alpine 2>/dev/null || true
    sleep 2
    echo "Redis Docker : $REDIS_CID"
  else
    echo "WARN: Redis indisponible — portails démarreront en mode dégradé"
  fi
}

link_shared_assets() {
  for portal in portal-cert portal-it; do
    local target="$ROOT/$portal/public/shared"
    rm -rf "$target"
    ln -sfn "$ROOT/portal-shared" "$target"
    echo "portal-shared → $portal/public/shared"
  done
}

install_portal_deps() {
  for d in portal-cert portal-it; do
    if [ ! -d "$ROOT/$d/node_modules" ]; then
      echo "npm install $d..."
      (cd "$ROOT/$d" && npm install --no-fund --no-audit 2>/dev/null)
    fi
  done
  link_shared_assets
  mkdir -p "$ROOT/portal-cert/lib" "$ROOT/portal-cert/routes" "$ROOT/portal-it/lib" "$ROOT/portal-it/routes"
  for f in ingest-queue.js helk-connector.js velociraptor-connector.js global-health.js service-registry.js \
    cors-policy.js platform-secrets.js bridge-response.js upload-limits.js ui-error-log.js; do
    [ -f "$ROOT/lib/$f" ] && cp -f "$ROOT/lib/$f" "$ROOT/portal-cert/lib/$f"
    [ -f "$ROOT/lib/$f" ] && cp -f "$ROOT/lib/$f" "$ROOT/portal-it/lib/$f"
  done
  for f in master-intakes.js master-ingest-errors.js; do
    [ -f "$ROOT/portal-cert/routes/$f" ] && cp -f "$ROOT/portal-cert/routes/$f" "$ROOT/portal-it/routes/$f"
  done
}

patch_portal_configs() {
  local base="http://127.0.0.1:3000"
  for cfg in portal-cert/public/config.json portal-it/public/config.json; do
    if [ -f "$ROOT/$cfg" ]; then
      jq --arg url "$base" '.soc_base_url = $url' "$cfg" > "${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"
    fi
  done
}

start_portals() {
  kill_port 3000
  kill_port 3001
  sleep 1
  echo "Démarrage portail CERT :3000..."
  (cd "$ROOT/portal-cert" && PORTAL_AUTH_DATA_DIR="$PORTAL_AUTH_DATA_DIR" node server.js) &
  CERT_PID=$!
  echo "Démarrage portail IT :3001..."
  (cd "$ROOT/portal-it" && \
    PORTAL_AUTH_DATA_DIR="$PORTAL_AUTH_DATA_DIR" \
    CERT_PORTAL_URL="http://127.0.0.1:3000" \
    node server.js) &
  IT_PID=$!
  sleep 4
  for i in 1 2 3 4 5 6 7 8 9 10; do
    curl -sf http://127.0.0.1:3000/api/health >/dev/null && break
    sleep 1
  done
  curl -sf http://127.0.0.1:3000/api/health >/dev/null && echo "CERT OK" || echo "CERT FAIL"
  curl -sf http://127.0.0.1:3001/api/health >/dev/null && echo "IT OK" || echo "IT FAIL"
}

case "${1:-start}" in
  start)
    start_redis
    install_portal_deps
    patch_portal_configs
    start_portals
    echo ""
    echo "Harness actif — CERT http://127.0.0.1:3000  IT http://127.0.0.1:3001"
    echo "Tests : BASE_URL=http://127.0.0.1:3000 cd tests && npx playwright test ui-renovation-cert-it"
    wait
    ;;
  test)
    start_redis
    install_portal_deps
    patch_portal_configs
    start_portals
    cd "$ROOT/tests"
    npm install --no-fund --no-audit 2>/dev/null || true
    npx playwright install chromium 2>/dev/null || true
    BASE_URL=http://127.0.0.1:3000 PORTAL_AUTH_DATA_DIR="$PORTAL_AUTH_DATA_DIR" FP_DEV_MODE=1 FP_HARNESS_MODE=1 \
      npx playwright test --project=ui-integration ui-renovation-cert-it --reporter=list --timeout=60000
    ;;
  *)
    echo "Usage: $0 [start|test]"
    exit 1
    ;;
esac
