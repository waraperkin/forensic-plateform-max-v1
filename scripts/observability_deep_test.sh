#!/usr/bin/env bash
# Deep test unifié OpenSearch + Grafana (même technique que timesketch_deep_test.sh)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

G='\033[0;32m'
R='\033[0;31m'
C='\033[0;36m'
NC='\033[0m'

echo -e "${C}══ Observability deep test (OpenSearch + Grafana + UI) ══${NC}"
FAIL=0
export OS_DEEP_SKIP_UI=1 GF_DEEP_SKIP_UI=1

if bash "$ROOT/scripts/opensearch_deep_test.sh"; then
  echo -e "${G}OpenSearch : OK${NC}"
else
  echo -e "${R}OpenSearch : KO${NC}"
  FAIL=$((FAIL + 1))
fi

echo ""
if bash "$ROOT/scripts/grafana_deep_test.sh"; then
  echo -e "${G}Grafana : OK${NC}"
else
  echo -e "${R}Grafana : KO${NC}"
  FAIL=$((FAIL + 1))
fi

echo ""
UI_LOG="${OBS_UI_LOG:-$ROOT/logs/observability_ui_verify.log}"
if [ "${OBS_DEEP_SKIP_UI:-0}" != "1" ] && [ -f "$ROOT/scripts/observability_ui_verify.py" ]; then
  echo -e "${C}── Simulation UI (navigateur + headless Chrome) ──${NC}"
  mkdir -p "$(dirname "$UI_LOG")"
  # shellcheck source=/dev/null
  [ -f "$ROOT/.env" ] && set -a && source "$ROOT/.env" && set +a
  export OBS_UI_SCOPE=all
  if python3 "$ROOT/scripts/observability_ui_verify.py" | tee "$UI_LOG"; then
    echo -e "${G}UI simulation : OK${NC}"
  else
    echo -e "${R}UI simulation : KO — voir $UI_LOG${NC}"
    FAIL=$((FAIL + 1))
  fi
fi

if [ "$FAIL" -eq 0 ]; then
  echo -e "${G}══ Observability deep test : OK ══${NC}"
  echo "Logs : logs/opensearch_deep_test.log logs/grafana_deep_test.log logs/observability_ui_verify.log"
  exit 0
fi
echo -e "${R}══ Observability deep test : KO ($FAIL composant(s)) ══${NC}"
exit 1
