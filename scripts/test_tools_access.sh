#!/usr/bin/env bash
# Vérifie l'accès HTTPS aux outils critiques (depuis l'hôte ou BASE_URL).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
fi

BASE="${BASE_URL:-${FP_BASE_URL:-}}"
if [ -z "$BASE" ]; then
  HOST=$(fp_cert_identity 2>/dev/null || fp_resolve_public_host 2>/dev/null || echo "127.0.0.1")
  BASE="https://${HOST}"
fi
BASE="${BASE%/}"

check() {
  local name="$1" path="$2" expect="${3:-200}"
  local code attempt
  for attempt in 1 2 3; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 20 "${BASE}${path}" || echo "000")
    if [ "$code" = "429" ] && [ "$attempt" -lt 3 ]; then
      sleep 3
      continue
    fi
    break
  done
  if echo "$code" | grep -qE "$expect"; then
    echo "PASS: $name ($path) → HTTP $code"
  else
    echo "FAIL: $name ($path) → HTTP $code (attendu $expect)" >&2
    return 1
  fi
}

fail=0
check "Nginx" "/nginx-health" "200" || fail=1
check "Portail CERT" "/" "200|302" || fail=1
check "MISP login" "/misp/users/login" "200|302" || fail=1
check "HELK Kibana" "/helk/kibana/" "200|302" || fail=1
check "Velociraptor GUI" "/velociraptor/" "200|302|307|401" || fail=1
check "Velociraptor API" "/velociraptor/api/health" "200" || fail=1
check "Santé globale" "/api/health/global" "200" || fail=1

echo ""
[ "$fail" -eq 0 ] && echo "Accès outils OK — $BASE" || { echo "Échecs détectés — $BASE"; exit 1; }
