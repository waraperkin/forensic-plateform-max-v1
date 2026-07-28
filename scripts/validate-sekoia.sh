#!/usr/bin/env bash
# validate-sekoia.sh — smoke test de la couche Sekoia sur une VM fraîche.
#
# Vérifie, dans l'ordre :
#   1. santé des 3 services (control-plane 8901, s1-controlplane 8902, monitor 8903)
#   2. refus 401 sans token sur un endpoint protégé
#   3. liste des intakes avec token interne
#   4. présence des indices sekoia-* dans OpenSearch
#
# Usage :
#   ./scripts/validate-sekoia.sh                     # défauts compose (réseau interne)
#   BASE_CP=http://localhost:8901 ./scripts/validate-sekoia.sh
#
# Prérequis : curl, INTERNAL_API_TOKEN renseigné dans l'environnement ou .env.
set -u

BASE_CP="${BASE_CP:-http://sekoia-controlplane:8901}"
BASE_S1="${BASE_S1:-http://s1-controlplane:8902}"
BASE_MON="${BASE_MON:-http://sekoia-monitor:8903}"
BASE_OS="${BASE_OS:-http://opensearch-node1:9200}"
TOKEN="${INTERNAL_API_TOKEN:-}"
OS_USER="${OPENSEARCH_USER:-admin}"
OS_PASSWORD="${OPENSEARCH_PASSWORD:-}"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✅ $1"; }
ko()   { FAIL=$((FAIL+1)); echo "  ❌ $1"; }
check() { # check <label> <cmd...>
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$label"; else ko "$label"; fi
}

echo "══ 1. Santé des services ══"
check "control-plane /health ($BASE_CP)" curl -fsS --max-time 5 "$BASE_CP/health"
check "s1-controlplane /health ($BASE_S1)" curl -fsS --max-time 5 "$BASE_S1/health"
check "monitor /health ($BASE_MON)" curl -fsS --max-time 5 "$BASE_MON/health"

echo "══ 2. Sécurité : endpoints protégés ══"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BASE_CP/control/sekoia/config")"
if [ "$code" = "401" ] || [ "$code" = "403" ]; then
  ok "GET /control/sekoia/config sans token → $code (refusé)"
else
  ko "GET /control/sekoia/config sans token → $code (attendu 401/403)"
fi

echo "══ 3. API interne authentifiée ══"
if [ -z "$TOKEN" ]; then
  ko "INTERNAL_API_TOKEN absent — tests authentifiés impossibles"
else
  check "GET /control/sekoia/intakes (token)" \
    curl -fsS --max-time 10 -H "X-Internal-Token: $TOKEN" "$BASE_CP/control/sekoia/intakes"
  check "GET /control/sekoia/rules (token)" \
    curl -fsS --max-time 10 -H "X-Internal-Token: $TOKEN" "$BASE_CP/control/sekoia/rules"
  check "GET /control/sekoia/coverage (token)" \
    curl -fsS --max-time 10 -H "X-Internal-Token: $TOKEN" "$BASE_CP/control/sekoia/coverage"
fi

echo "══ 4. Indices OpenSearch sekoia-* ══"
auth=(); [ -n "$OS_PASSWORD" ] && auth=(-u "$OS_USER:$OS_PASSWORD")
indices="$(curl -fsS --max-time 10 "${auth[@]}" "$BASE_OS/_cat/indices/sekoia-*?format=json" 2>/dev/null || echo '[]')"
if echo "$indices" | grep -q 'sekoia-'; then
  ok "indices sekoia-* présents :"
  echo "$indices" | grep -o '"index":"[^"]*"' | sed 's/"index":"/     - /;s/"$//' | sort -u
else
  ko "aucun indice sekoia-* (le monitor a-t-il tourné au moins un cycle ?)"
fi

echo "════════════════════════════════"
echo "Résultat : $PASS OK / $FAIL KO"
[ "$FAIL" -eq 0 ]
