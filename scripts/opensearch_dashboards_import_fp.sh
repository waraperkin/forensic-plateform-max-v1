#!/usr/bin/env bash
# Import dashboards / data views FP dans OpenSearch Dashboards (idempotent)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OSD="${OSD_URL:-http://localhost:5601/dashboards}"
OSD_NGINX="${OSD_NGINX_URL:-https://localhost/dashboards}"
NDJSON="${ROOT}/dashboards/opensearch/fp_siem_saved_objects.ndjson"
LOG="${OS_FP_OSD_IMPORT_LOG:-$ROOT/logs/opensearch_dashboards_import.log}"

G='\033[0;32m'
R='\033[0;31m'
C='\033[0;36m'
NC='\033[0m'

mkdir -p "$(dirname "$LOG")"
: >"$LOG"

log() { echo -e "${C}[os-fp-osd]${NC} $*" | tee -a "$LOG"; }
ok()  { echo -e "  ${G}✓${NC} $*" | tee -a "$LOG"; }
bad() { echo -e "  ${R}✗${NC} $*" | tee -a "$LOG"; }

log "Journal : $LOG"
log "1/4 — Génération NDJSON..."
python3 "$ROOT/scripts/build_opensearch_dashboards.py" >>"$LOG" 2>&1
ok "build_opensearch_dashboards.py"

log "2/4 — Santé OpenSearch Dashboards..."
for base in "$OSD" "$OSD_NGINX"; do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' "${base}/api/status" 2>/dev/null || echo "000")
  if [ "$CODE" = "200" ]; then
    ok "OSD ${base} HTTP 200"
    IMPORT_BASE="$base"
    break
  fi
done
if [ -z "${IMPORT_BASE:-}" ]; then
  bad "OpenSearch Dashboards inaccessible"
  exit 1
fi

log "2b/4 — Index-patterns requis (ensure avant import)..."
python3 "$ROOT/scripts/opensearch_refresh_index_pattern.py" --ensure \
  fp-events fp-logs fp-ti fp-ti-opencti fp-ti-misp fp-timesketch \
  fp-obs-logs fp-mitre fp-fusion >>"$LOG" 2>&1 || true
ok "index-patterns ensure"

log "3/4 — Import saved objects (overwrite, retry jusqu'à 0 erreur)..."
# Nombre total d'objets attendus dans le NDJSON (lignes contenant un "type").
TOTAL=$(grep -c '"type"' "$NDJSON" 2>/dev/null || echo 0)
# Import idempotent avec retry : au 1er passage certaines références
# (index-patterns) peuvent ne pas être encore résolues → des objets échouent.
# overwrite=true rend l'opération ré-exécutable ; on boucle jusqu'à 0 erreur.
ATTEMPTS="${OS_FP_OSD_IMPORT_RETRIES:-6}"
NC=0
ERR=0
for i in $(seq 1 "$ATTEMPTS"); do
  RESP=$(curl -sk -X POST "${IMPORT_BASE}/api/saved_objects/_import?overwrite=true" \
    -H "osd-xsrf: true" \
    -H "securitytenant: global" \
    --form file=@"$NDJSON" 2>/dev/null)
  read -r NC ERR < <(echo "$RESP" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    print('0 999'); sys.exit(0)
errs=d.get('errors',[]) or []
print(d.get('successCount',0), len(errs))
for e in errs[:30]:
    sys.stderr.write(f\"  import KO {e.get('type')}/{e.get('id')} -> {e.get('error',{})}\n\")
" 2>>"$LOG")
  echo "[os-fp-osd] tentative $i/$ATTEMPTS : successCount=$NC errors=$ERR (total=$TOTAL)" >>"$LOG"
  if [ "${ERR:-1}" = "0" ] && [ "${NC:-0}" -ge "${TOTAL:-0}" ]; then
    break
  fi
  sleep 4
done
if [ "${NC:-0}" -gt 0 ] && [ "${ERR:-1}" = "0" ]; then
  ok "import $NC/$TOTAL objet(s) — 0 erreur"
elif [ "${NC:-0}" -gt 0 ]; then
  bad "import incomplet: $NC/$TOTAL ($ERR erreur(s) persistantes) — voir $LOG"
  exit 1
else
  bad "import échoué: ${RESP:0:300}"
  exit 1
fi

log "3b/4 — Rafraîchissement index-patterns (field_caps)..."
python3 "$ROOT/scripts/opensearch_refresh_index_pattern.py" \
  fp-events fp-logs fp-ti fp-ti-opencti fp-ti-misp fp-timesketch \
  fp-obs-logs fp-mitre fp-fusion fp-ti-enriched >>"$LOG" 2>&1 || true
ok "index-patterns rafraîchis"

log "4/4 — Vérification dashboards..."
for uid in fp-opensearch-overview fp-opensearch-security; do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' "${IMPORT_BASE}/api/saved_objects/dashboard/${uid}" 2>/dev/null)
  if [ "$CODE" = "200" ]; then
    ok "dashboard $uid"
  else
    bad "dashboard $uid HTTP $CODE"
  fi
done

echo ""
echo -e "${G}══ OpenSearch Dashboards FP : OK ══${NC}"
echo -e "${C}Overview  : ${IMPORT_BASE}/app/dashboards#/view/fp-opensearch-overview${NC}"
echo -e "${C}Security  : ${IMPORT_BASE}/app/dashboards#/view/fp-opensearch-security${NC}"
echo -e "${C}Discover  : ${IMPORT_BASE}/app/discover#/?_a=(index:'fp-events')${NC}"
