#!/usr/bin/env bash
# Réparation accès Velociraptor (502 / sidecar absent) sans relancer tout le full-start.
# Usage : ./scripts/repair-velociraptor-access.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export FP_ROOT="$ROOT"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
  fp_align_env_public_ip 2>/dev/null || true
fi
if [ -f "$ROOT/scripts/lib/vr-gui-check.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/vr-gui-check.sh"
fi

HOST=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "127.0.0.1")
HOST=$(fp_normalize_host "$HOST" 2>/dev/null || echo "$HOST")
export PUBLIC_HOST="$HOST"
export FP_VR_NGINX_ONLY=1

VR_GUI_PORT=$(fp_vr_gui_port)
VR_HOST_URL=$(fp_vr_host_gui_url)

log() { echo "[repair-vr] $*"; }

log "Hôte public : $HOST"
log "Port GUI hôte : $VR_GUI_PORT"

bash "$ROOT/scripts/render-velociraptor-nginx-snippet.sh" 2>/dev/null || true

# Corrige ancienne config nginx (HTTPS → sidecar HTTP plain = 502 garanti)
CONF="$ROOT/config/nginx/conf.d/forensic.conf"
if grep -qE 'proxy_pass https://\$velociraptor_upstream' "$CONF" 2>/dev/null; then
  log "PATCH: forensic.conf utilisait proxy_pass https:// vers VR (→ http://)"
  sed -i 's|proxy_pass https://\$velociraptor_upstream/velociraptor/;|proxy_pass http://$velociraptor_upstream/velociraptor/;|g' "$CONF"
  sed -i '/proxy_ssl_verify off;/d' "$CONF"
fi
if ! grep -q 'set \$velociraptor_upstream' "$CONF" 2>/dev/null; then
  log "ATTENTION: set \$velociraptor_upstream absent — mettre à jour forensic.conf (upstream dynamique)"
fi

if [ ! -x "$ROOT/scripts/ensure-velociraptor-sidecar.sh" ]; then
  log "ERREUR: ensure-velociraptor-sidecar.sh absent"
  exit 1
fi

log "1/5 — Sidecar GUI + régénération config"
bash "$ROOT/scripts/ensure-velociraptor-sidecar.sh"

VR_CFG="$ROOT/velociraptor/config/server.config.yaml"
if [ -f "$VR_CFG" ] && grep -qE 'public_url:.*localhost|public_url:.*127\.0\.0\.1' "$VR_CFG" 2>/dev/null; then
  log "ERREUR: server.config.yaml public_url encore localhost — régénération forcée"
  FP_VR_NGINX_ONLY=1 PUBLIC_HOST="$HOST" bash "$ROOT/velociraptor/scripts/generate-config.sh" || true
  cd "$ROOT/velociraptor" && docker compose -f docker-compose.velociraptor.yml up -d --force-recreate velociraptor-server 2>/dev/null || true
  cd "$ROOT"
fi
if [ -f "$VR_CFG" ] && ! grep -q "$HOST" "$VR_CFG" 2>/dev/null; then
  log "WARN: public_url ne contient pas $HOST — vérifier velociraptor/config/server.config.yaml"
fi

log "1b/5 — Test direct hôte :${VR_GUI_PORT}"
if ! fp_vr_test_host_gui 10; then
  log "ERREUR: velociraptor-server injoignable sur $VR_HOST_URL"
  log "  → docker logs velociraptor-server --tail 40"
  docker logs velociraptor-server --tail 40 2>&1 || true
  exit 1
fi
log "GUI OK sur localhost:${VR_GUI_PORT}"

log "2/5 — api.config.yaml + bridge"
VR_ADMIN="${VELOCIRAPTOR_ADMIN_USER:-admin}"
VR_PASS="${VELOCIRAPTOR_ADMIN_PASSWORD:-F0r3ns1c_VR_2024!}"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^velociraptor-server$'; then
  docker exec velociraptor-server test -f /data/.admin_bootstrapped 2>/dev/null \
    || docker exec velociraptor-server velociraptor --config /config/server.config.yaml \
      user add --role administrator "$VR_ADMIN" "$VR_PASS" 2>/dev/null || true
  if docker exec velociraptor-server velociraptor --config /config/server.config.yaml config api_client \
    --name forensic-bridge --role administrator /tmp/api.config.yaml 2>/dev/null \
    && docker cp velociraptor-server:/tmp/api.config.yaml "$ROOT/velociraptor/config/api.config.yaml" 2>/dev/null; then
    log "api.config.yaml régénéré"
  else
    log "WARN: api.config.yaml non régénéré (bridge utilisera server.config.yaml)"
  fi
fi

log "3/5 — Réseau nginx + recréation nginx/bridge"
docker network connect velociraptor_net forensic-nginx 2>/dev/null || true
docker compose up -d --force-recreate velociraptor-bridge nginx 2>/dev/null || true
sleep 3
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-nginx$'; then
  if fp_vr_test_nginx_to_server forensic-nginx /velociraptor/; then
    log "nginx → velociraptor-server:8000 OK"
  else
    log "ERREUR: nginx ne joint pas velociraptor-server:8000 (vérifier velociraptor_net)"
    docker exec forensic-nginx wget -S -O /dev/null -T 10 http://velociraptor-server:8000/velociraptor/ 2>&1 | tail -10 || true
    exit 1
  fi
fi

log "4/5 — Vérification HTTPS"
if [ -x "$ROOT/scripts/verify-platform-ready.sh" ]; then
  BASE_URL="https://${HOST}" bash "$ROOT/scripts/verify-platform-ready.sh"
else
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 "https://${HOST}/velociraptor/" || echo "000")
  if fp_vr_http_code_ok "$code"; then
    log "Velociraptor GUI → HTTP $code"
  else
    log "ERREUR: Velociraptor GUI → HTTP $code"
    exit 1
  fi
fi

log "Velociraptor réparé — https://${HOST}/velociraptor/ (admin / ${VR_PASS})"
