#!/usr/bin/env bash
# Configuration complète HELK + Velociraptor — sidecars, bridges, ingestion lab, intégration plateforme
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELK_ROOT="$ROOT/helk"
if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
fi
export FP_ROOT="$ROOT"
if [ -f "$ROOT/scripts/lib/vr-gui-check.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/vr-gui-check.sh"
fi
PUBLIC_HOST="${PUBLIC_HOST:-$(fp_url_identity 2>/dev/null || fp_detect_public_host 2>/dev/null || true)}"
VR_ADMIN="${VELOCIRAPTOR_ADMIN_USER:-admin}"
VR_PASS="${VELOCIRAPTOR_ADMIN_PASSWORD:-F0r3ns1c_VR_2024!}"

step() { echo -e "\n\033[0;34m━━━ $* ━━━\033[0m"; }
ok() { echo -e "\033[0;32m[ OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }

ensure_network() {
  local name=$1 cidr=$2
  if ! docker network inspect "$name" >/dev/null 2>&1; then
    docker network create --driver bridge --subnet "$cidr" "$name"
    ok "Réseau $name ($cidr)"
  else
    ok "Réseau $name déjà présent"
  fi
}

step "Réseaux sidecar HELK / Velociraptor"
ensure_network helk_net 172.30.0.0/24
ensure_network velociraptor_net 172.31.0.0/24

step "Configuration Velociraptor (server + client)"
cd "$ROOT/velociraptor"
PUBLIC_HOST="$PUBLIC_HOST" bash scripts/generate-config.sh

step "Stack HELK sidecar (ES + Kibana + Logstash + Kafka/ZK)"
cd "$HELK_ROOT"
docker compose -f docker-compose.helk.yml -f docker-compose.external-net.yml up -d \
  || warn "HELK sidecar partiel (Kafka/port — ES/Kibana peuvent suffire)"
for i in $(seq 1 60); do
  curl -sf http://127.0.0.1:19200/_cluster/health >/dev/null 2>&1 && break
  sleep 3
done
curl -sf http://127.0.0.1:19200/_cluster/health >/dev/null || { warn "HELK ES pas prêt"; exit 1; }
ok "HELK Elasticsearch"

step "Stack Velociraptor sidecar"
cd "$ROOT/velociraptor"
docker compose -f docker-compose.velociraptor.yml -f docker-compose.external-net.yml up -d --build
for i in $(seq 1 40); do
  fp_vr_test_host_gui 5 && break
  sleep 3
done
fp_vr_test_host_gui 5 || { warn "Velociraptor GUI pas prêt sur $(fp_vr_host_gui_url)"; exit 1; }
ok "Velociraptor server"

step "API client Velociraptor (forensic-bridge)"
sleep 5
if docker exec velociraptor-server test -f /data/.admin_bootstrapped 2>/dev/null; then
  :
else
  docker exec velociraptor-server velociraptor --config /config/server.config.yaml \
    user add --role administrator "$VR_ADMIN" "$VR_PASS" 2>/dev/null || true
fi
docker exec velociraptor-server velociraptor --config /config/server.config.yaml config api_client \
  --name forensic-bridge --role administrator /tmp/api.config.yaml 2>/dev/null \
  && docker cp velociraptor-server:/tmp/api.config.yaml "$ROOT/velociraptor/config/api.config.yaml" \
  || warn "api.config.yaml — regénérer après premier login GUI"
if [[ -s "$ROOT/velociraptor/config/api.config.yaml" ]]; then
  ok "api.config.yaml ($(wc -c < "$ROOT/velociraptor/config/api.config.yaml") octets)"
else
  warn "api.config.yaml vide — bridge utilisera server.config.yaml"
fi

step "Ingestion lab HELK + Sigma"
bash "$HELK_ROOT/scripts/setup-helk-full.sh" sigma 2>/dev/null || true
bash "$HELK_ROOT/scripts/setup-helk-full.sh" ingest 2>/dev/null || warn "ingestion lab partielle"
bash "$HELK_ROOT/scripts/setup-helk-full.sh" kibana 2>/dev/null || true

step "Bridges + portails + sigma-runner + nginx"
cd "$ROOT"
docker compose up -d --build helk-bridge velociraptor-bridge helk-sigma-runner cert-portal it-portal 2>&1 | tail -5
docker compose up -d --force-recreate nginx 2>&1 | tail -3
sleep 8

step "Sync OpenSearch ↔ HELK (bridge)"
docker exec forensic-helk-bridge curl -sf -X POST http://127.0.0.1:8095/sync \
  -H "Content-Type: application/json" -d '{}' >/dev/null 2>&1 \
  && ok "HELK bridge sync" || warn "sync HELK — bridge pas encore prêt"

step "Export lab Velociraptor → plateforme"
curl -sf -X POST "https://${PUBLIC_HOST}/velociraptor/api/export/full" \
  -H "Content-Type: application/json" \
  -d '{"events":[{"@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","message":"HELK-VR setup validation","host":"lab-host","source":"velociraptor","tags":["setup","lab"]}]}' \
  >/dev/null 2>&1 || warn "export VR lab — vérifier nginx/auth"

ok "Configuration HELK + Velociraptor terminée"
echo "  HELK Kibana : https://${PUBLIC_HOST}/helk/kibana/"
echo "  Velociraptor: https://${PUBLIC_HOST}/velociraptor/"
echo "  CERT HELK   : https://${PUBLIC_HOST}/?tab=helk-hunting"
echo "  CERT VR     : https://${PUBLIC_HOST}/?tab=velociraptor-dfir"
echo "  Verify      : python3 $ROOT/scripts/helk_velociraptor_master_verify.py"
