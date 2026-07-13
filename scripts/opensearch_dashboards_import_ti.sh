#!/usr/bin/env bash
# Import dashboards SIEM TI dans OpenSearch Dashboards
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OSD="${OSD_URL:-http://localhost:5601/dashboards}"
OSD_NGINX="${OSD_NGINX_URL:-https://localhost/dashboards}"
COMBINED="${ROOT}/dashboards/opensearch/fp_siem_ti_saved_objects.ndjson"
LOG="${ROOT}/logs/opensearch_dashboards_ti_import.log"

G='\033[0;32m'
C='\033[0;36m'
NC='\033[0m'

mkdir -p "$(dirname "$LOG")"
: >"$LOG"

echo -e "${C}[os-ti-osd]${NC} Génération dashboards TI..."
python3 "$ROOT/scripts/build_opensearch_siem_ti_dashboards.py" >>"$LOG" 2>&1

for base in "$OSD" "$OSD_NGINX"; do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' "${base}/api/status" 2>/dev/null || echo "000")
  if [ "$CODE" = "200" ]; then
    IMPORT_BASE="$base"
    break
  fi
done
[ -n "${IMPORT_BASE:-}" ] || { echo "OSD inaccessible"; exit 1; }

curl -sk -X POST "${IMPORT_BASE}/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" \
  -H "securitytenant: global" \
  --form file=@"$COMBINED" >>"$LOG" 2>&1

python3 "$ROOT/scripts/opensearch_refresh_index_pattern.py" fp-ti >>"$LOG" 2>&1 || true

echo -e "${G}══ Dashboards TI importés ══${NC}"
echo -e "${C}TI Overview : ${IMPORT_BASE}/app/dashboards#/view/fp-ti-overview${NC}"
echo -e "${C}IOC Matches : ${IMPORT_BASE}/app/dashboards#/view/fp-ioc-matches${NC}"
echo -e "${C}Threat Map  : ${IMPORT_BASE}/app/dashboards#/view/fp-ioc-threat-map${NC}"
echo -e "${C}Case View   : ${IMPORT_BASE}/app/dashboards#/view/fp-case-ioc-view${NC}"
