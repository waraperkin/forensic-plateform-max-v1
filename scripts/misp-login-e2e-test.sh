#!/usr/bin/env bash
# Test E2E login MISP via nginx (CSRF réel) + API — code sortie 0 = OK.
# Usage : ./scripts/misp-login-e2e-test.sh [base_url]   (défaut https://127.0.0.1)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

BASE="${1:-https://127.0.0.1}"
BASE="${BASE%/}"

EMAIL="" ; PASS="" ; APIKEY=""
if [ -f "$ROOT/.env" ]; then
  EMAIL=$(grep -E '^MISP_ADMIN_EMAIL=' "$ROOT/.env" | tail -1 | cut -d= -f2- | tr -d '"' || true)
  PASS=$(grep -E '^MISP_ADMIN_PASSWORD=' "$ROOT/.env" | tail -1 | cut -d= -f2- | tr -d '"' || true)
  APIKEY=$(grep -E '^MISP_ADMIN_API_KEY=' "$ROOT/.env" | tail -1 | cut -d= -f2- | tr -d '"' || true)
fi
EMAIL="${EMAIL:-admin@forensic.local}"

fail=0
jar=$(mktemp) ; page=$(mktemp) ; post=$(mktemp)
trap 'rm -f "$jar" "$page" "$post"' EXIT

# 1 — GET page de login : 200, formulaire préfixé /misp/, jeton CSRF présent
code=$(curl -sk -c "$jar" -b "$jar" -o "$page" -w '%{http_code}' --max-time 30 "$BASE/misp/users/login" || echo 000)
if [ "$code" = "200" ]; then echo "PASS: GET /misp/users/login → 200"; else echo "FAIL: GET login → $code"; fail=1; fi
grep -q 'action="/misp/users/login"' "$page" \
  && echo "PASS: form action=/misp/users/login (App.base OK)" \
  || { echo "FAIL: form action sans préfixe /misp"; fail=1; }
TOKEN=$(grep -oP 'name="data\[_Token\]\[key\]"[^>]*value="\K[^"]+' "$page" | head -1 || true)
FIELDS=$(grep -oP 'name="data\[_Token\]\[fields\]"[^>]*value="\K[^"]*' "$page" | head -1 || true)
if [ -n "$TOKEN" ]; then echo "PASS: jeton CSRF présent"; else echo "FAIL: jeton CSRF absent"; fail=1; fi

# 2 — POST login : 302 attendu (jamais 400 CSRF ni redirect /misp/misp)
if [ -n "$PASS" ] && [ -n "$TOKEN" ]; then
  code=$(curl -sk -c "$jar" -b "$jar" -o "$post" -w '%{http_code}' --max-time 30 \
    -H "Referer: $BASE/misp/users/login" \
    -X POST "$BASE/misp/users/login" \
    --data-urlencode "_method=POST" \
    --data-urlencode "data[_Token][key]=$TOKEN" \
    --data-urlencode "data[_Token][fields]=$FIELDS" \
    --data-urlencode "data[_Token][unlocked]=" \
    --data-urlencode "data[User][email]=$EMAIL" \
    --data-urlencode "data[User][password]=$PASS")
  loc=$(curl -sk -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' --max-time 30 \
    -H "Referer: $BASE/misp/users/login" "$BASE/misp/users/login" || true)
  if [ "$code" = "302" ]; then
    echo "PASS: POST login → 302 (CSRF OK)"
  else
    echo "FAIL: POST login → $code (attendu 302 — CSRF/credentials)"; fail=1
    grep -qiE 'cross-site|csrf|blackhole' "$post" && echo "       ↳ page d'erreur CSRF détectée"
  fi
  if echo "$loc" | grep -q '/misp/misp'; then echo "FAIL: redirect double préfixe /misp/misp"; fail=1; fi
  # 3 — Session authentifiée : /misp/events/index → 200
  code=$(curl -sk -b "$jar" -o /dev/null -w '%{http_code}' --max-time 30 "$BASE/misp/events/index" || echo 000)
  if [ "$code" = "200" ]; then echo "PASS: /misp/events/index authentifié → 200"; else echo "FAIL: events/index → $code"; fail=1; fi
else
  echo "SKIP: POST login (MISP_ADMIN_PASSWORD ou jeton indisponible)"
fi

# 4 — API : version + search
if [ -n "$APIKEY" ]; then
  ver=$(curl -sk --max-time 30 -H "Authorization: $APIKEY" -H "Accept: application/json" \
    "$BASE/misp/servers/getVersion" || true)
  echo "$ver" | grep -q '"version"' \
    && echo "PASS: API getVersion ($(echo "$ver" | grep -oP '"version":\s*"\K[^"]+' | head -1))" \
    || { echo "FAIL: API getVersion → $ver"; fail=1; }
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 30 -H "Authorization: $APIKEY" \
    -H "Accept: application/json" -H "Content-Type: application/json" \
    -X POST "$BASE/misp/attributes/restSearch" -d '{"limit":1}' || echo 000)
  if [ "$code" = "200" ]; then echo "PASS: API restSearch → 200"; else echo "FAIL: API restSearch → $code"; fail=1; fi
else
  echo "SKIP: API (MISP_ADMIN_API_KEY absent de .env)"
fi

[ "$fail" -eq 0 ] && echo "=== MISP E2E OK ===" || echo "=== MISP E2E ÉCHEC ===" >&2
exit "$fail"
