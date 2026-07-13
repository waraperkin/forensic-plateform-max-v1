#!/usr/bin/env bash
# Deep test Timesketch UI/API : Sigma config, règles, Threat Intelligence (indicateurs), explore, analyzers
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

TS="${TIMESKETCH_URL:-http://localhost:5000}"
USER="${TIMESKETCH_USER:-admin}"
PASS="${TIMESKETCH_PASSWORD:-F0r3ns1c_TS_2024!}"
WEB="${TIMESKETCH_WEB_CONTAINER:-forensic-timesketch-web}"
LOG="${TS_DEEP_LOG:-$ROOT/logs/timesketch_deep_test.log}"
SKETCH_ID="${TS_DEEP_SKETCH_ID:-}"

mkdir -p "$(dirname "$LOG")"
: >"$LOG"

G='\033[0;32m'
R='\033[0;31m'
Y='\033[1;33m'
C='\033[0;36m'
NC='\033[0m'
PASS_N=0
FAIL_N=0

log()  { echo -e "${C}[ts-deep]${NC} $*" | tee -a "$LOG"; }
ok()   { echo -e "  ${G}✓${NC} $*" | tee -a "$LOG"; PASS_N=$((PASS_N + 1)); }
bad()  { echo -e "  ${R}✗${NC} $*" | tee -a "$LOG"; FAIL_N=$((FAIL_N + 1)); }
warn() { echo -e "  ${Y}⚠${NC} $*" | tee -a "$LOG"; }

log "Journal : $LOG"

log "1/6 — Fichiers de config montés dans le conteneur..."
for f in sigma_config.yaml ontology.yaml intelligence_tag_metadata.yaml context_links.yaml data_finder.yaml; do
  if docker exec "$WEB" test -f "/etc/timesketch/$f" 2>/dev/null; then
    ok "/etc/timesketch/$f"
  else
    bad "/etc/timesketch/$f manquant — regénérer conf + redémarrer timesketch-web"
  fi
done
if docker exec "$WEB" grep -q 'SIGMA_CONFIG = "/etc/timesketch/sigma_config.yaml"' /etc/timesketch/timesketch.conf 2>/dev/null; then
  ok "timesketch.conf SIGMA_CONFIG"
else
  bad "SIGMA_CONFIG absent de timesketch.conf — bash scripts/generate-timesketch-conf.sh"
fi

log "2/6 — Import règles Sigma (tsctl, fichier par fichier)..."
IMP_OK=0
for sf in example_sigma.yml fp-e2e-4625-stable.yml forensic-detection-rules.yml; do
  if docker exec "$WEB" test -f "/opt/timesketch/sigma_rules/$sf" 2>/dev/null; then
    if docker exec "$WEB" bash -c ". /opt/venv/bin/activate && tsctl import-sigma-rules /opt/timesketch/sigma_rules/$sf" >>"$LOG" 2>&1; then
      ok "import $sf"
      IMP_OK=$((IMP_OK + 1))
    else
      warn "import $sf échoué"
    fi
  fi
done
[ "$IMP_OK" -ge 1 ] || bad "aucun fichier Sigma importé"

log "3/6 — Tests API Python (login, Sigma POST, TI attribute, explore)..."
export TIMESKETCH_URL="$TS" TIMESKETCH_USER="$USER" TIMESKETCH_PASSWORD="$PASS" TS_DEEP_SKETCH_ID="$SKETCH_ID"
if python3 "$ROOT/scripts/timesketch_deep_test_verify.py" >>"$LOG" 2>&1; then
  ok "timesketch_deep_test_verify.py"
else
  bad "timesketch_deep_test_verify.py"
fi

log "4/6 — E2E avancé (ingest + analyzers)..."
if [ "${TS_DEEP_SKIP_E2E:-0}" != "1" ]; then
  if TS_E2E_SKIP_ACTIVATE=1 bash "$ROOT/scripts/timesketch_advanced_e2e.sh" >>"$LOG" 2>&1; then
    ok "timesketch_advanced_e2e.sh"
  else
    bad "timesketch_advanced_e2e.sh"
  fi
else
  warn "TS_DEEP_SKIP_E2E=1"
fi

log "5/6 — Vérification tous les sketches (explore + analyzer GET)..."
if python3 "$ROOT/scripts/timesketch_verify_all_sketches.py" >>"$LOG" 2>&1; then
  ok "timesketch_verify_all_sketches.py"
else
  bad "timesketch_verify_all_sketches.py (voir $ROOT/logs/ts_verify_all.log)"
fi

log "6/6 — Logs web (erreurs récentes)..."
ERR=$(docker logs "$WEB" --tail 80 2>&1 | grep -ciE 'sigma_config|ontology|Value needs to be a string|Problem reading the Sigma' || true)
if [ "${ERR:-0}" -eq 0 ]; then
  ok "pas d'erreur Sigma/TI récente dans logs web"
else
  warn "$ERR ligne(s) Sigma/TI dans logs — peut être historique"
fi

echo "" | tee -a "$LOG"
if [ "$FAIL_N" -eq 0 ]; then
  echo -e "${G}══ Timesketch deep test : OK ($PASS_N checks) ══${NC}" | tee -a "$LOG"
  exit 0
fi
echo -e "${R}══ Timesketch deep test : KO ($FAIL_N échec(s), $PASS_N OK) ══${NC}" | tee -a "$LOG"
exit 1
