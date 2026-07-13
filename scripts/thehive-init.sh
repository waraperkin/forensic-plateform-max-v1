#!/bin/sh
# TheHive + Cortex : attente des API puis enregistrement du connecteur Cortex.
# Authentification : identifiants .env (THEHIVE_*) puis valeurs officielles StrangeBee par défaut.
set -eu

THEHIVE_URL="${THEHIVE_URL:-http://thehive:9000/thehive}"
CORTEX_URL="${CORTEX_URL:-http://cortex:9001}"
TH_DEFAULT_LOGIN="${TH_DEFAULT_LOGIN:-admin@thehive.local}"
TH_DEFAULT_PASS="${TH_DEFAULT_PASS:-secret}"
MAX="${MAX_WAIT_ROUNDS:-60}"

wait_http() {
  _label="$1"
  _url="$2"
  _n=0
  echo "[INIT] Attente ${_label}..."
  until curl -sf --max-time 15 "$_url" >/dev/null 2>&1; do
    _n=$((_n + 1))
    if [ "$_n" -ge "$MAX" ]; then
      echo "[INIT] ${_label} : timeout" >&2
      exit 1
    fi
    sleep 5
  done
}

wait_http "TheHive" "$THEHIVE_URL/api/status"
wait_http "Cortex" "$CORTEX_URL/api/status"
echo "[INIT] TheHive et Cortex répondent"

AUTH_CUSTOM="${THEHIVE_ADMIN_LOGIN:-}:${THEHIVE_ADMIN_PASSWORD:-}"
AUTH_DEFAULT="${TH_DEFAULT_LOGIN}:${TH_DEFAULT_PASS}"

BRAND_CODE=$(curl -sS -o /tmp/th_branding.json -w '%{http_code}' -u "$AUTH_DEFAULT" -X POST "$THEHIVE_URL/api/v1/branding" \
  -F "title=Forensic Minimal" || printf '%s' "000")
case "$BRAND_CODE" in
  200|201|204|409) echo "[INIT] TheHive branding : HTTP $BRAND_CODE" ;;
  *) echo "[INIT] WARN TheHive branding HTTP $BRAND_CODE" >&2 ;;
esac

BODY="{\"type\":\"cortex\",\"name\":\"Cortex-Forensic\",\"url\":\"${CORTEX_URL}\",\"auth\":{\"type\":\"bearer\",\"key\":\"${CORTEX_API_KEY}\"},\"includedTheHiveOrganisations\":[\"*\"],\"statusCheckInterval\":60}"

CODE="000"
for cand in "$AUTH_CUSTOM" "$AUTH_DEFAULT"; do
  for attempt in 1 2 3 4 5; do
    CODE=$(curl -sS -o /tmp/th_cortex_reg.json -w '%{http_code}' -X POST "$THEHIVE_URL/api/v1/connector" \
      -H "Content-Type: application/json" \
      -u "$cand" \
      -d "$BODY" || printf '%s' "000")
    case "$CODE" in
      200|201|204|409)
        echo "[INIT] Connecteur Cortex : HTTP $CODE (auth ${cand%%:*}, tentative $attempt)"
        echo "[INIT] TheHive init terminé"
        exit 0
        ;;
    esac
    echo "[INIT] Essai auth ${cand%%:*} tentative $attempt → HTTP $CODE (pause 10s)"
    sleep 10
  done
  echo "[INIT] Essai auth ${cand%%:*} : dernier HTTP $CODE"
done

# Utilisateur analyste E2E (création case)
ORG_ID=$(curl -sS -u "$AUTH_DEFAULT" -H "Content-Type: application/json" \
  -d '{"query":[{"_name":"listOrganisation"}]}' "$THEHIVE_URL/api/v1/query" 2>/dev/null \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['_id'] if d else '~20584')" 2>/dev/null || echo "~20584")
E2E_LOGIN="${THEHIVE_ANALYST_LOGIN:-cert-analyst@forensic.local}"
E2E_PASS="${THEHIVE_ANALYST_PASSWORD:-F0r3ns1c_TH_Analyst!}"
curl -sS -o /dev/null -w '%{http_code}' -X POST "$THEHIVE_URL/api/v1/user" \
  -H "Content-Type: application/json" -u "$AUTH_DEFAULT" \
  -d "{\"login\":\"$E2E_LOGIN\",\"name\":\"CERT Analyst\",\"profile\":\"org-admin\",\"password\":\"$E2E_PASS\",\"organisations\":[{\"organisation\":\"$ORG_ID\",\"profile\":\"org-admin\"}]}" \
  | grep -qE '200|201|409' && echo "[INIT] Utilisateur E2E $E2E_LOGIN prêt" || true

echo "[INIT] WARN: connecteur Cortex non enregistré (dernier HTTP $CODE). Vérifier logs TheHive." >&2
if [ -f /tmp/th_cortex_reg.json ]; then
  head -c 500 /tmp/th_cortex_reg.json >&2 || true
  echo >&2
fi
exit 0
