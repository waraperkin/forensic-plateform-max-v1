#!/usr/bin/env bash
# Deep test Grafana : health, datasources OpenSearch, dashboard, queries, provisioning
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

GF_C="${GRAFANA_CONTAINER:-forensic-grafana}"
GF_URL="${GRAFANA_URL:-https://localhost/grafana}"
LOG="${GF_DEEP_LOG:-$ROOT/logs/grafana_deep_test.log}"

mkdir -p "$(dirname "$LOG")"
: >"$LOG"

G='\033[0;32m'
R='\033[0;31m'
Y='\033[1;33m'
C='\033[0;36m'
NC='\033[0m'
PASS_N=0
FAIL_N=0

log()  { echo -e "${C}[gf-deep]${NC} $*" | tee -a "$LOG"; }
ok()   { echo -e "  ${G}✓${NC} $*" | tee -a "$LOG"; PASS_N=$((PASS_N + 1)); }
bad()  { echo -e "  ${R}✗${NC} $*" | tee -a "$LOG"; FAIL_N=$((FAIL_N + 1)); }
warn() { echo -e "  ${Y}⚠${NC} $*" | tee -a "$LOG"; }

log "Journal : $LOG"

log "1/4 — Conteneur Grafana + provisioning..."
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$GF_C"; then
  ok "container $GF_C running"
else
  bad "container $GF_C absent"
fi
for f in config/grafana/provisioning/datasources/opensearch.yml \
         config/grafana/provisioning/dashboards/forensic.yml \
         dashboards/forensic-overview.json; do
  [ -f "$ROOT/$f" ] && ok "$f" || bad "$f manquant"
done
if docker exec "$GF_C" test -f /etc/grafana/provisioning/datasources/opensearch.yml 2>/dev/null; then
  ok "provisioning datasources monté"
else
  bad "provisioning datasources non monté dans $GF_C"
fi
if docker exec "$GF_C" test -f /var/lib/grafana/dashboards/forensic-overview.json 2>/dev/null; then
  ok "dashboard forensic-overview monté"
else
  bad "dashboard forensic-overview non monté"
fi
PLUGIN=$(docker exec "$GF_C" grafana cli plugins ls 2>/dev/null | grep -c opensearch || true)
if [ "${PLUGIN:-0}" -ge 1 ]; then
  ok "plugin grafana-opensearch-datasource installé"
else
  warn "plugin opensearch non listé (peut être en cours d'install)"
fi

log "2/4 — Nginx /grafana/ (sans origin not allowed)..."
CODE=$(curl -skL -o /dev/null -w '%{http_code}' "${GF_URL}/api/health" 2>/dev/null || echo "000")
if [ "$CODE" = "200" ]; then
  ok "Nginx ${GF_URL}/api/health HTTP 200"
else
  bad "Nginx Grafana health HTTP $CODE"
fi
BODY=$(curl -sk "${GF_URL}/login" 2>/dev/null || true)
if echo "$BODY" | grep -qi "origin not allowed"; then
  bad "Grafana UI: origin not allowed (vérifier GF_LIVE_ALLOWED_ORIGINS / CORS)"
else
  ok "login HTML sans origin not allowed"
fi

log "3/4 — Tests API Python (datasources, dashboard, query)..."
export GRAFANA_URL="$GF_URL" GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-F0r3ns1c_GF_2024!}"
if python3 "$ROOT/scripts/grafana_deep_test_verify.py" >>"$LOG" 2>&1; then
  ok "grafana_deep_test_verify.py"
else
  bad "grafana_deep_test_verify.py"
fi

log "4/5 — Simulation UI (login, dashboard, CORS, headless)..."
if [ "${GF_DEEP_SKIP_UI:-0}" != "1" ]; then
  export GRAFANA_URL="$GF_URL" GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-F0r3ns1c_GF_2024!}" OBS_UI_SCOPE=gf
  if python3 "$ROOT/scripts/observability_ui_verify.py" >>"$LOG" 2>&1; then
    ok "observability_ui_verify.py (Grafana)"
  else
    bad "observability_ui_verify.py"
  fi
else
  warn "GF_DEEP_SKIP_UI=1"
fi

log "5/5 — Logs Grafana (erreurs récentes)..."
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$GF_C"; then
  ERR=$(docker logs "$GF_C" --tail 80 2>&1 | grep -ciE 'origin not allowed|failed to|plugin.*error|datasource.*error' || true)
  if [ "${ERR:-0}" -eq 0 ]; then
    ok "pas d'erreur datasource/origin récente"
  else
    warn "$ERR ligne(s) erreur dans logs Grafana"
  fi
fi

echo "" | tee -a "$LOG"
if [ "$FAIL_N" -eq 0 ]; then
  echo -e "${G}══ Grafana deep test : OK ($PASS_N checks) ══${NC}" | tee -a "$LOG"
  exit 0
fi
echo -e "${R}══ Grafana deep test : KO ($FAIL_N échec(s), $PASS_N OK) ══${NC}" | tee -a "$LOG"
exit 1
