#!/usr/bin/env bash
# Démarre velociraptor-server et bloque jusqu'à ce que la GUI réponde en HTTP.
# Requis avant reload nginx — sinon 502 Bad Gateway sur /velociraptor/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VR_DIR="$ROOT/velociraptor"
VR_COMPOSE=(docker compose -f docker-compose.velociraptor.yml -f docker-compose.external-net.yml)
CONTAINER="${FP_VR_CONTAINER:-velociraptor-server}"
MAX_WAIT="${FP_VR_WAIT_SEC:-180}"
export FP_ROOT="$ROOT"

log() { echo "[ensure-vr] $*"; }

# Journal : ne jamais faire échouer le script si logs/ non accessible
_fp_vr_log() {
  local f="${FP_LOG_START:-$ROOT/logs/forensic_start.log}"
  mkdir -p "$(dirname "$f")" 2>/dev/null || true
  if touch "$f" 2>/dev/null; then
    echo "$f"
  else
    echo "/tmp/fp-velociraptor-sidecar.log"
  fi
}
FP_VR_LOG="$(_fp_vr_log)"
export FP_LOG_START="$FP_VR_LOG"

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
export FP_VR_NGINX_ONLY="${FP_VR_NGINX_ONLY:-1}"

VR_GUI_PORT=$(fp_vr_gui_port)
VR_HOST_URL=$(fp_vr_host_gui_url)

ensure_network() {
  local name=$1 cidr=$2
  if ! docker network inspect "$name" >/dev/null 2>&1; then
    docker network create --driver bridge --subnet "$cidr" "$name" \
      && log "Réseau $name créé ($cidr)" \
      || { log "ERREUR création réseau $name"; return 1; }
  fi
}

log "Hôte public : $HOST"
log "Port GUI hôte : $VR_GUI_PORT"
ensure_network velociraptor_net 172.31.0.0/24

if [ ! -x "$VR_DIR/scripts/generate-config.sh" ]; then
  log "ERREUR: $VR_DIR/scripts/generate-config.sh absent"
  exit 1
fi

log "Régénération server.config.yaml (use_plain_http + public_url IP)"
if ! FP_VR_NGINX_ONLY=1 PUBLIC_HOST="$HOST" bash "$VR_DIR/scripts/generate-config.sh" \
  >> "$FP_VR_LOG" 2>&1; then
  if [ -s "$VR_DIR/config/server.config.yaml" ]; then
    log "generate-config partiel — conservation de server.config.yaml existant"
  else
    log "ERREUR: generate-config échoué et pas de config"
    exit 1
  fi
fi

log "Démarrage conteneur $CONTAINER"
cd "$VR_DIR"
"${VR_COMPOSE[@]}" up -d --build --force-recreate velociraptor-server \
  >> "$FP_VR_LOG" 2>&1

log "Attente GUI Velociraptor sur $VR_HOST_URL (max ${MAX_WAIT}s)…"
deadline=$((SECONDS + MAX_WAIT))
ready=0
while [ "$SECONDS" -lt "$deadline" ]; do
  if fp_vr_test_host_gui 5; then
    ready=1
    break
  fi
  if docker inspect --format='{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null | grep -q healthy; then
    if fp_vr_test_host_gui 5; then
      ready=1
      break
    fi
  fi
  sleep 3
done

if [ "$ready" -ne 1 ]; then
  log "ERREUR: Velociraptor GUI injoignable sur $VR_HOST_URL"
  docker ps -a --filter "name=$CONTAINER" --format 'status={{.Status}}' 2>/dev/null || true
  docker logs "$CONTAINER" --tail 50 2>&1 || true
  exit 1
fi

log "GUI OK sur localhost:${VR_GUI_PORT}"

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-nginx$'; then
  if fp_vr_test_nginx_to_server forensic-nginx /velociraptor/; then
    log "Nginx → velociraptor-server:8000 OK"
  else
    log "ERREUR: forensic-nginx ne joint pas velociraptor-server:8000"
    docker exec forensic-nginx wget -S -O /dev/null -T 10 \
      http://velociraptor-server:8000/velociraptor/ 2>&1 | tail -15 || true
    exit 1
  fi
fi

log "Velociraptor sidecar prêt — https://${HOST}/velociraptor/"
