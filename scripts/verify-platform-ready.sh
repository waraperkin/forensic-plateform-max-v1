#!/usr/bin/env bash
# Vérification complète portail + outils (HTTPS via nginx). Code sortie 0 = prêt production lab.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
fi

BASE="${BASE_URL:-${FP_BASE_URL:-${FP_ORCH_BASE_URL:-}}}"
if [ -z "$BASE" ]; then
  HOST=$(fp_cert_identity 2>/dev/null || fp_resolve_public_host 2>/dev/null || echo "127.0.0.1")
  BASE="https://${HOST}"
fi
BASE="${BASE%/}"

check() {
  local name="$1" path="$2" expect="${3:-200}"
  local code
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 25 "${BASE}${path}" 2>/dev/null || echo "000")
  if echo "$code" | grep -qE "$expect"; then
    echo "PASS: $name"
    return 0
  fi
  echo "FAIL: $name (${BASE}${path}) → HTTP $code (attendu $expect)" >&2
  return 1
}

fail=0

echo "=== Vérification plateforme — $BASE ==="
echo ""

echo "--- Portail ---"
check "Nginx health" "/nginx-health" "200" || fail=1
check "Portail CERT" "/" "200|302" || fail=1
check "Portail CERT /api/health" "/api/health" "200" || fail=1
check "Portail CERT /api/health/global" "/api/health/global" "200" || fail=1
check "Portail IT /it/api/health" "/it/api/health" "200" || fail=1

echo ""
echo "--- SOC / SIEM / Observabilité ---"
check "OpenSearch Dashboards" "/dashboards/" "200|302" || fail=1
check "Grafana" "/grafana/api/health" "200" || fail=1
check "Timesketch" "/timesketch/" "200|302" || fail=1
check "Logstash monitoring" "/logstash/" "200" || fail=1

echo ""
echo "--- Documentation portail ---"
check "Docs HTML (fr)" "/docs/fr/platform-overview.html" "200" || fail=1
check "Docs inventaire (fr)" "/docs/fr/platform-inventory.json" "200" || fail=1

echo ""
echo "--- Threat Intel / IR ---"
check "OpenCTI" "/cti/" "200|302" || fail=1
check "MISP login" "/misp/users/login" "200|302" || fail=1
check "TheHive" "/thehive/" "200|302" || fail=1
check "Cortex" "/cortex/" "200|302|303" || fail=1

echo ""
echo "--- DFIR / Hunting ---"
check "HELK Kibana" "/helk/kibana/" "200|302" || fail=1
check "HELK API" "/helk/api/" "200" || fail=1
helk_patterns=$(curl -sk --max-time 15 "${BASE}/helk/kibana/api/saved_objects/_find?type=index-pattern&per_page=20" \
  -H 'kbn-xsrf: true' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
if [ "${helk_patterns:-0}" -gt 0 ]; then
  echo "PASS: HELK index patterns (${helk_patterns})"
else
  echo "FAIL: HELK index patterns absents (Discover vide)" >&2
  fail=1
fi
check "Cortex" "/cortex/" "200|302|303" || fail=1
cortex_loc=$(curl -sk -I --max-time 15 "${BASE}/cortex/" 2>/dev/null | awk -F': ' 'tolower($1)=="location"{print $2}' | tr -d '\r' | head -1)
if [ -n "$cortex_loc" ] && echo "$cortex_loc" | grep -qE '^https?://[^/]+/cortex/' && ! echo "$cortex_loc" | grep -qE '^https?://[^:/]+/cortex/'; then
  echo "PASS: Cortex redirect avec port ($cortex_loc)"
elif [ -n "$cortex_loc" ] && echo "$cortex_loc" | grep -q ':8443'; then
  echo "PASS: Cortex redirect ($cortex_loc)"
elif [ -z "$cortex_loc" ]; then
  echo "PASS: Cortex (pas de redirect)"
else
  echo "FAIL: Cortex redirect sans port HTTPS ($cortex_loc)" >&2
  fail=1
fi
check "Velociraptor GUI" "/velociraptor/" "200|302|307|401" || fail=1
check "Velociraptor app" "/velociraptor/app/index.html" "200|302|307|401" || fail=1
check "Velociraptor API" "/velociraptor/api/health" "200" || fail=1

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^velociraptor-server$'; then
  echo "PASS: conteneur velociraptor-server actif"
else
  echo "FAIL: conteneur velociraptor-server absent (nginx → 502)" >&2
  fail=1
fi

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-nginx$'; then
  if docker exec forensic-nginx wget -q -O /dev/null -T 15 \
    http://velociraptor-server:8000/velociraptor/app/index.html 2>/dev/null; then
    echo "PASS: nginx → velociraptor-server:8000"
  else
    code=$((docker exec forensic-nginx wget -S -O /dev/null -T 10 \
      http://velociraptor-server:8000/velociraptor/app/index.html 2>&1 || true) | awk '/^[[:space:]]*HTTP\//{print $2}' | tail -1)
    if echo "$code" | grep -qE '^(200|301|302|307|308|401)$'; then
      echo "PASS: nginx → velociraptor-server:8000 (HTTP $code)"
    else
      echo "FAIL: nginx ne joint pas velociraptor-server:8000" >&2
      fail=1
    fi
  fi
fi

echo ""
echo "--- Stockage ---"
check "MinIO console" "/minio/" "200|302" || fail=1

echo ""
echo "--- Interconnexion TI (OpenCTI/MISP <-> OS/HELK/TS) ---"
if command -v python3 >/dev/null 2>&1; then
  export PYTHONPATH="${ROOT}/scripts:${PYTHONPATH:-}"
  if python3 "$ROOT/scripts/ti_platform_interconnect_verify.py"; then
    echo "PASS: TI interconnect verify"
  else
    echo "FAIL: TI interconnect — lancer: python3 scripts/ti_platform_interconnect.py" >&2
    fail=1
  fi
else
  echo "WARN: python3 absent — skip TI interconnect verify"
fi

echo ""
if [ "$fail" -eq 0 ]; then
  echo "✅ Plateforme prête — portail + 11 services accessibles via $BASE"
  exit 0
fi

echo "❌ Échecs détectés — relancer ./forensic.sh -full-start (voir logs/forensic_start.log)" >&2
exit 1
