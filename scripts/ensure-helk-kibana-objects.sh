#!/usr/bin/env bash
# Import index-patterns + dashboards HELK Kibana + ingestion lab si indices vides.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
fi

HOST=$(fp_url_identity 2>/dev/null || echo "localhost")
export PUBLIC_HOST="${PUBLIC_HOST:-$HOST}"
export HELK_KIBANA_PUBLIC_URL="$(fp_public_https_origin 2>/dev/null || echo "https://${HOST}")/helk/kibana"
export BASE_URL="${BASE_URL:-$(fp_public_https_origin 2>/dev/null || echo "https://${HOST}")}"

log() { echo "[ensure-helk-kibana] $*"; }

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^helk-kibana$'; then
  log "WARN helk-kibana absent — skip"
  exit 0
fi

log "HELK_KIBANA_PUBLIC_URL=$HELK_KIBANA_PUBLIC_URL"

# Aligner SERVER_PUBLICBASEURL (évite redirect loop / mauvais chemins SPA)
cd "$ROOT/helk"
HELK_KIBANA_PUBLIC_URL="$HELK_KIBANA_PUBLIC_URL" \
  docker compose -f docker-compose.helk.yml -f docker-compose.external-net.yml up -d helk-kibana 2>/dev/null || true
cd "$ROOT"

for i in $(seq 1 30); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${BASE_URL}/helk/kibana/api/status" 2>/dev/null || echo "000")
  if echo "$code" | grep -qE '^200$'; then break; fi
  sleep 3
done

if command -v node >/dev/null 2>&1 && [ -f "$ROOT/scripts/helk-kibana-import.mjs" ]; then
  BASE_URL="$BASE_URL" node "$ROOT/scripts/helk-kibana-import.mjs" || {
    log "WARN import Node échoué — repli bash"
    bash "$ROOT/helk/scripts/kibana-import-full.sh" 2>/dev/null || true
  }
else
  KIBANA_URL="${BASE_URL}/helk/kibana" bash "$ROOT/helk/scripts/kibana-import-full.sh" 2>/dev/null || true
fi

# Ingestion lab si peu de documents événements
sysmon_count=$(curl -sf "http://127.0.0.1:${FP_HELK_ES_PORT:-19200}/helk-sysmon-*/_count" 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)
if [ "${sysmon_count:-0}" -lt 10 ]; then
  log "Ingestion lab (sysmon=${sysmon_count})"
  bash "$ROOT/helk/scripts/setup-helk-full.sh" ingest 2>/dev/null || true
fi

patterns=$(curl -sk "${BASE_URL}/helk/kibana/api/saved_objects/_find?type=index-pattern&per_page=20" \
  -H 'kbn-xsrf: true' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
log "Index patterns Kibana: ${patterns}"
[ "${patterns:-0}" -gt 0 ] || exit 1
