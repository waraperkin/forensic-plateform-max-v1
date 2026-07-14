#!/usr/bin/env bash
# Alignement post-démarrage — appelé automatiquement par ./forensic.sh -full-start (ne pas lancer manuellement).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
  fp_align_env_public_ip 2>/dev/null || true
fi

HOST=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "localhost")
HOST=$(fp_normalize_host "$HOST" 2>/dev/null || echo "$HOST")
export PUBLIC_HOST="${PUBLIC_HOST:-$HOST}"
FP_ORIGIN="$(fp_public_https_origin 2>/dev/null || echo "https://${HOST}")"
export HELK_KIBANA_PUBLIC_URL="${HELK_KIBANA_PUBLIC_URL:-${FP_ORIGIN}/helk/kibana}"
export MISP_PUBLIC_BASE_URL="$(fp_misp_public_base_url 2>/dev/null || echo "${FP_ORIGIN}/misp")"

log() { echo "[post-start] $*"; }

log "Mode accès IP — hôte : $HOST"

if command -v node >/dev/null 2>&1 && [ -f "$ROOT/scripts/align-subpath-public-urls.mjs" ]; then
  BASE_URL="${BASE_URL:-$FP_ORIGIN}" node "$ROOT/scripts/align-subpath-public-urls.mjs" \
    >> "${FP_LOG_START:-$ROOT/logs/forensic_start.log}" 2>&1 \
    && log "URLs sous-chemin alignées (Cortex/TheHive/MinIO/portails)" \
    || log "WARN align-subpath-public-urls"
fi
fp_patch_portal_soc_base_urls "$HOST" 2>/dev/null || true

if [ "${FP_SKIP_PREPARE:-0}" != "1" ]; then
  bash "$ROOT/scripts/setup-site-identity.sh" 2>/dev/null && log "Identité site OK" || log "WARN setup-site-identity"
  bash "$ROOT/scripts/generate-nginx-access-snippet.sh" 2>/dev/null && log "Redirect DNS EC2 → IP OK" || log "WARN generate-nginx-access-snippet"
fi

# MISP — attendre HTTP puis aligner baseurl + credentials
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-misp$'; then
  log "Attente MISP..."
  n=0
  until docker exec forensic-misp curl -sf --max-time 5 http://127.0.0.1/users/login >/dev/null 2>&1; do
    n=$((n + 1))
    [ "$n" -ge 72 ] && { log "WARN MISP timeout"; break; }
    sleep 5
  done
  if [ "$n" -lt 72 ]; then
    bash "$ROOT/scripts/misp-configure-host.sh" >> "${FP_LOG_START:-$ROOT/logs/misp-init.log}" 2>&1 \
      && log "MISP.baseurl aligné (IP)" \
      || log "WARN misp-configure-host"
    docker compose up -d --force-recreate misp 2>/dev/null || true
    sleep 15
    bash "$ROOT/scripts/misp-init.sh" >> "${FP_LOG_START:-$ROOT/logs/misp-init.log}" 2>&1 \
      && log "MISP admin OK" \
      || log "WARN misp-init partiel"
  fi
else
  log "WARN forensic-misp absent"
fi

# Velociraptor — conteneur GUI obligatoire (sinon nginx 502 sur /velociraptor/)
if [ -x "$ROOT/scripts/ensure-velociraptor-sidecar.sh" ]; then
  bash "$ROOT/scripts/ensure-velociraptor-sidecar.sh" >> "${FP_LOG_START:-$ROOT/logs/forensic_start.log}" 2>&1 \
    && log "Velociraptor GUI prête" \
    || { log "ERREUR ensure-velociraptor-sidecar"; exit 1; }
elif [ "${FP_SKIP_SIDECARS:-0}" != "1" ] && [ -x "$ROOT/scripts/setup-sidecars.sh" ]; then
  bash "$ROOT/scripts/setup-sidecars.sh" >> "${FP_LOG_START:-$ROOT/logs/forensic_start.log}" 2>&1 \
    && log "Sidecars HELK/VR OK" \
    || { log "ERREUR setup-sidecars"; exit 1; }
fi

# Régénère api.config.yaml Velociraptor (bridge)
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^velociraptor-server$'; then
  VR_ADMIN="${VELOCIRAPTOR_ADMIN_USER:-admin}"
  VR_PASS="${VELOCIRAPTOR_ADMIN_PASSWORD:-F0r3ns1c_VR_2024!}"
  if [ -f "$ROOT/.env" ]; then
    _vr_pass=$(grep -E '^VELOCIRAPTOR_ADMIN_PASSWORD=' "$ROOT/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || true)
    [ -n "$_vr_pass" ] && VR_PASS="$_vr_pass"
  fi
  docker exec velociraptor-server test -f /data/.admin_bootstrapped 2>/dev/null \
    || docker exec velociraptor-server velociraptor --config /config/server.config.yaml \
      user add --role administrator "$VR_ADMIN" "$VR_PASS" 2>/dev/null || true
  if docker exec velociraptor-server velociraptor --config /config/server.config.yaml config api_client \
    --name forensic-bridge --role administrator /tmp/api.config.yaml 2>/dev/null \
    && docker cp velociraptor-server:/tmp/api.config.yaml "$ROOT/velociraptor/config/api.config.yaml" 2>/dev/null; then
    log "Velociraptor api.config.yaml régénéré"
    docker compose up -d --force-recreate velociraptor-bridge 2>/dev/null || true
  else
    log "WARN api.config.yaml — bridge utilisera server.config.yaml"
  fi
fi

docker compose up -d helk-bridge velociraptor-bridge nginx 2>/dev/null \
  || docker compose up -d helk-bridge velociraptor-bridge nginx 2>/dev/null \
  || true

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^helk-kibana$'; then
  if [ -x "$ROOT/scripts/ensure-helk-kibana-objects.sh" ]; then
    bash "$ROOT/scripts/ensure-helk-kibana-objects.sh" >> "${FP_LOG_START:-$ROOT/logs/forensic_start.log}" 2>&1 \
      && log "HELK Kibana index-patterns + dashboards OK" \
      || log "WARN ensure-helk-kibana-objects"
  fi
fi

if [ -x "$ROOT/scripts/render-velociraptor-nginx-snippet.sh" ]; then
  bash "$ROOT/scripts/render-velociraptor-nginx-snippet.sh" >> "${FP_LOG_START:-$ROOT/logs/forensic_start.log}" 2>&1 || true
fi
docker exec forensic-nginx nginx -s reload 2>/dev/null && log "Nginx rechargé" || log "WARN reload nginx"

# Portail CERT — admin aligné sur CERT_PORTAL_SECRET (.env)
if [ -x "$ROOT/scripts/ensure-portal-admin.sh" ]; then
  bash "$ROOT/scripts/ensure-portal-admin.sh" >> "${FP_LOG_START:-$ROOT/logs/forensic_start.log}" 2>&1 \
    && log "Portail CERT — admin synchronisé (.env)" \
    || { log "ERREUR ensure-portal-admin"; exit 1; }
fi

# Validation finale HTTPS (échec = full-start incomplet)
if [ -x "$ROOT/scripts/verify-platform-ready.sh" ]; then
  BASE_URL="${BASE_URL:-$FP_ORIGIN}" bash "$ROOT/scripts/verify-platform-ready.sh" \
    >> "${FP_LOG_START:-$ROOT/logs/forensic_start.log}" 2>&1 \
    && log "verify-platform-ready OK" \
    || { log "ERREUR verify-platform-ready (Velociraptor/HELK/MISP)"; exit 1; }
fi

log "Finalisation terminée — https://${HOST}/"
