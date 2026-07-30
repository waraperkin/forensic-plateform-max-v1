#!/usr/bin/env bash
# Upload fixtures avec IOC connus (alignés seed TI / MISP E2E) pour valider ti_match
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] && set -a && source .env && set +a

CERT_URL="${CERT_URL:-https://localhost}"
CASE_ID="${TI_TEST_CASE:-GF-TI-$(date +%s)}"
FIXTURES="$ROOT/tests/fixtures"
UPLOAD_FAIL=0

# P15 — auth service-à-service : le gate API exige une session (401 sinon).
# Le token interne (.env) évite une session navigateur ; repli login cookie.
AUTH_ARGS=()
COOKIE_JAR=""
if [ -n "${INTERNAL_API_TOKEN:-}" ]; then
  AUTH_ARGS=(-H "X-Internal-Token: ${INTERNAL_API_TOKEN}")
else
  COOKIE_JAR=$(mktemp)
  login_rc=$(curl -sk -o /dev/null -w '%{http_code}' -c "$COOKIE_JAR" -X POST \
    "${CERT_URL}/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"${PORTAL_ADMIN_USER:-admin}\",\"password\":\"${PORTAL_ADMIN_PASSWORD:-}\"}")
  if [ "$login_rc" != "200" ]; then
    echo "[upload-ti] KO login portail (HTTP $login_rc) — uploads impossibles" >&2
    rm -f "$COOKIE_JAR"
    exit 1
  fi
  AUTH_ARGS=(-b "$COOKIE_JAR")
fi

upload() {
  local f="$1"
  [ -f "$f" ] || return 0
  echo "[upload-ti] $f → case $CASE_ID"
  local resp
  resp=$(curl -sk -X POST "${CERT_URL}/api/upload" \
    "${AUTH_ARGS[@]}" \
    -F "caseId=${CASE_ID}" \
    -F "analyst=ti-test" \
    -F "osType=linux" \
    -F "files=@${f}")
  echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin))" 2>/dev/null || echo "$resp"
  # P15 — une erreur JSON (ex: 401 Authentification requise) doit faire ÉCHOUER
  # l'étape au lieu d'être marquée OK silencieusement.
  if echo "$resp" | grep -q '"error"'; then
    echo "[upload-ti] KO upload $f — erreur API (voir ci-dessus)" >&2
    UPLOAD_FAIL=$((UPLOAD_FAIL+1))
  fi
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
[ -n "$COOKIE_JAR" ] && rm -f "$COOKIE_JAR"

if [ "$UPLOAD_FAIL" -gt 0 ]; then
  echo "[upload-ti] KO $UPLOAD_FAIL upload(s) en échec — étape en erreur" >&2
  exit 1
fi

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
# P15 — 0 correspondance TI = échec réel du test E2E, pas un OK.
if [ "$MATCHES" = "0" ]; then
  echo "[upload-ti] KO aucun événement ti_match après ingestion" >&2
  exit 1
fi
echo "[upload-ti] OK $MATCHES événement(s) ti_match"
