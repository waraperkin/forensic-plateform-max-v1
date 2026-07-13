#!/usr/bin/env bash
# Uploads de test via API portail CERT pour alimenter OpenSearch + Timesketch
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="${ROOT}/tests/fixtures"
CASE_ID="${FP_CASE_ID:-GF-GRAFANA-$(date +%s)}"
CERT_URL="${CERT_PORTAL_URL:-https://localhost}"

G='\033[0;32m'
C='\033[0;36m'
NC='\033[0m'

upload_one() {
  local file="$1"
  local case="${2:-$CASE_ID}"
  local analyst="${3:-grafana-test}"
  echo -e "${C}[upload]${NC} $file → case $case"
  curl -sk -X POST "${CERT_URL}/api/upload" \
    -F "caseId=${case}" \
    -F "analyst=${analyst}" \
    -F "priority=high" \
    -F "osType=windows" \
    -F "files=@${file}" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(' ', d)" 2>/dev/null || echo "  (réponse non-JSON)"
}

echo -e "${C}══ Uploads test plateforme (CASE_ID=${CASE_ID}) ══${NC}"

for f in \
  "${FIX}/timesketch-advanced-e2e.csv" \
  "${FIX}/windows-security-sample.csv" \
  "${FIX}/wara-linux-auth.log" \
  "${FIX}/wara-nginx-access.log"; do
  [ -f "$f" ] && upload_one "$f" "$CASE_ID" "grafana-deep" || true
done

echo ""
echo -e "${C}Attente ingestion (90s)...${NC}"
sleep 90

OS="${OS_URL:-http://localhost:9200}"
CNT=$(curl -sk "${OS}/forensic-uploads*/_count?q=case_id:${CASE_ID}" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "?")
echo -e "${G}Uploads indexés (forensic-uploads): ${CNT}${NC}"
echo "CASE_ID=${CASE_ID}"
