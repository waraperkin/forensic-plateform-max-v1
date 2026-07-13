#!/usr/bin/env bash
# Upload fixtures avec IOC connus (alignés seed TI / MISP E2E) pour valider ti_match
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] && set -a && source .env && set +a

CERT_URL="${CERT_URL:-https://localhost}"
CASE_ID="${TI_TEST_CASE:-GF-TI-$(date +%s)}"
FIXTURES="$ROOT/tests/fixtures"

upload() {
  local f="$1"
  [ -f "$f" ] || return 0
  echo "[upload-ti] $f → case $CASE_ID"
  curl -sk -X POST "${CERT_URL}/api/upload" \
    -F "caseId=${CASE_ID}" \
    -F "analyst=ti-test" \
    -F "osType=linux" \
    -F "files=@${f}" | python3 -c "import sys,json; print(json.load(sys.stdin))" 2>/dev/null || true
}

# Log synthétique avec IP/domaine IOC seed
TMP_LOG=$(mktemp)
cat >"$TMP_LOG" <<'LOGEOF'
May 20 10:00:01 testhost sshd[1234]: Failed password for invalid user admin from 203.0.113.50 port 22
May 20 10:00:02 testhost nginx: evil-wara-test.example GET /malware HTTP/1.1
May 20 10:00:03 testhost kernel: connection from 10.10.10.10 dropped
LOGEOF

upload "$FIXTURES/wara-linux-auth.log"
upload "$FIXTURES/wara-nginx-access.log"
upload "$TMP_LOG"
rm -f "$TMP_LOG"

echo ""
echo "Attente ingestion (90s)..."
sleep 90

OS="${OS_URL:-http://localhost:9200}"
MATCHES=$(curl -sf "$OS/forensic-*/_search" -H 'Content-Type: application/json' -d '{
  "size":0,"track_total_hits":true,
  "query":{"bool":{"filter":[{"term":{"ti_match":true}}]}}
}' | python3 -c "import sys,json; t=json.load(sys.stdin)['hits']['total']; print(t.get('value',t))" 2>/dev/null || echo "0")

echo "CASE_ID=$CASE_ID"
echo "ti_match events (forensic-*): $MATCHES"
