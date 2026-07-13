#!/usr/bin/env bash
# Import / mise à jour dashboards Grafana Timesketch (idempotent)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

GF_URL="${GRAFANA_URL:-https://localhost/grafana}"
GF_USER="${GRAFANA_USER:-admin}"
GF_PASS="${GRAFANA_ADMIN_PASSWORD:-F0r3ns1c_GF_2024!}"
FOLDER="${GRAFANA_TS_FOLDER:-Timesketch}"
DASH_DIR="${ROOT}/dashboards/timesketch"
LOG="${TS_GF_IMPORT_LOG:-$ROOT/logs/grafana_timesketch_import.log}"

G='\033[0;32m'
R='\033[0;31m'
C='\033[0;36m'
NC='\033[0m'
PASS_N=0
FAIL_N=0

mkdir -p "$(dirname "$LOG")"
: >"$LOG"

log() { echo -e "${C}[grafana-ts]${NC} $*" | tee -a "$LOG"; }
ok()  { echo -e "  ${G}✓${NC} $*" | tee -a "$LOG"; PASS_N=$((PASS_N + 1)); }
bad() { echo -e "  ${R}✗${NC} $*" | tee -a "$LOG"; FAIL_N=$((FAIL_N + 1)); }

log "Journal : $LOG"

log "1/5 — Santé Grafana..."
CODE=$(curl -sk -o /dev/null -w '%{http_code}' "${GF_URL}/api/health" 2>/dev/null || echo "000")
if [ "$CODE" = "200" ]; then
  ok "Grafana health HTTP 200"
else
  bad "Grafana inaccessible HTTP $CODE"
  exit 1
fi

log "2/5 — Génération dashboards JSON (format OpenSearch corrigé)..."
if python3 "$ROOT/scripts/build_timesketch_grafana_dashboards.py" >>"$LOG" 2>&1; then
  ok "build_timesketch_grafana_dashboards.py"
else
  bad "build_timesketch_grafana_dashboards.py"
fi

log "3/5 — Export métriques Timesketch → OpenSearch..."
export TS_METRICS_MAX_SKETCHES="${TS_METRICS_MAX_SKETCHES:-20}"
export TS_METRICS_FETCH_DETAIL="${TS_METRICS_FETCH_DETAIL:-1}"
if python3 "$ROOT/scripts/timesketch_export_grafana_metrics.py" >>"$LOG" 2>&1; then
  ok "timesketch_export_grafana_metrics.py"
else
  bad "timesketch_export_grafana_metrics.py"
fi

if [ "${GRAFANA_RESTART:-1}" = "1" ]; then
  docker restart forensic-grafana 2>/dev/null && sleep 12 && ok "Grafana redémarré (provisioning)" || true
fi

log "4/5 — Datasources Timesketch..."
for uid in forensic-timesketch forensic-timesketch-metrics forensic-all forensic-main; do
  HC=$(curl -sk -o /dev/null -w '%{http_code}' -u "${GF_USER}:${GF_PASS}" \
    "${GF_URL}/api/datasources/uid/${uid}/health" 2>/dev/null || echo "000")
  if [ "$HC" = "200" ]; then
    ok "datasource ${uid} health"
  else
    bad "datasource ${uid} health HTTP ${HC}"
  fi
done

log "5/5 — Import dashboards JSON..."
FOLDER_UID=""
FR=$(curl -sk -u "${GF_USER}:${GF_PASS}" "${GF_URL}/api/folders" 2>/dev/null || echo "[]")
FOLDER_UID=$(echo "$FR" | python3 -c "
import json,sys,os
name=os.environ.get('FOLDER','Timesketch')
for f in json.load(sys.stdin):
    if f.get('title')==name:
        print(f.get('uid',''))
        break
" 2>/dev/null || true)
if [ -z "$FOLDER_UID" ]; then
  CR=$(curl -sk -u "${GF_USER}:${GF_PASS}" -X POST "${GF_URL}/api/folders" \
    -H "Content-Type: application/json" \
    -d "{\"title\":\"${FOLDER}\"}" 2>/dev/null)
  FOLDER_UID=$(echo "$CR" | python3 -c "import json,sys; print(json.load(sys.stdin).get('uid',''))" 2>/dev/null || true)
  [ -n "$FOLDER_UID" ] && ok "dossier Grafana « ${FOLDER} » créé" || bad "création dossier Grafana"
fi

for dash in "$DASH_DIR"/*.json; do
  [ -f "$dash" ] || continue
  name=$(basename "$dash")
  payload=$(FOLDER_UID="$FOLDER_UID" python3 -c "
import json,sys,os
folder_uid=os.environ.get('FOLDER_UID','')
with open(sys.argv[1]) as f:
    d=json.load(f)
body={'dashboard':d,'overwrite':True,'message':'forensic.sh grafana-timesketch'}
if folder_uid:
    body['folderUid']=folder_uid
print(json.dumps(body))
" "$dash")
  RESP=$(curl -sk -u "${GF_USER}:${GF_PASS}" -X POST "${GF_URL}/api/dashboards/db" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null)
  STATUS=$(echo "$RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
  if [ "$STATUS" = "success" ]; then
    URL=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('url',''))" 2>/dev/null || true)
    LINK="${GF_URL%/}${URL}"
    LINK="${LINK//\/grafana\/grafana\//\/grafana/}"
    ok "import ${name} → ${LINK}"
  else
    bad "import ${name}: ${RESP:0:200}"
  fi
done

echo "" | tee -a "$LOG"
if [ "$FAIL_N" -eq 0 ]; then
  echo -e "${G}══ Grafana Timesketch : OK ($PASS_N checks) ══${NC}" | tee -a "$LOG"
  FUID=$(curl -sk -u "${GF_USER}:${GF_PASS}" "${GF_URL}/api/folders" 2>/dev/null | python3 -c "
import json,sys
for f in json.load(sys.stdin):
    if f.get('title')=='Timesketch':
        print(f.get('uid',''))
        break
" 2>/dev/null || true)
  if [ -n "$FUID" ]; then
    echo -e "${C}Dossier Timesketch : ${GF_URL}/dashboards/f/${FUID}/${NC}" | tee -a "$LOG"
  fi
  echo -e "${C}Overview : ${GF_URL}/d/timesketch-overview${NC}" | tee -a "$LOG"
  exit 0
fi
echo -e "${R}══ Grafana Timesketch : KO ($FAIL_N échec(s)) ══${NC}" | tee -a "$LOG"
exit 1
