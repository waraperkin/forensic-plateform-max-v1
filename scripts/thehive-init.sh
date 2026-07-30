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

# TheHive 5.3 exige un login email ("expected valid email address"). Un
# THEHIVE_ADMIN_LOGIN hérité sans '@' (ex. "admin") rendait le provisionnement
# impossible (create 400 / reset 404) et le login .env KO (audit V02) →
# normalisation systématique avant toute utilisation.
TH_ENV_LOGIN="${THEHIVE_ADMIN_LOGIN:-}"
case "$TH_ENV_LOGIN" in
  ""|*@*) : ;;
  *) TH_ENV_LOGIN="${TH_ENV_LOGIN}@forensic.local"
     echo "[INIT] THEHIVE_ADMIN_LOGIN non-email → normalisé en ${TH_ENV_LOGIN}" ;;
esac
AUTH_CUSTOM="${TH_ENV_LOGIN}:${THEHIVE_ADMIN_PASSWORD:-}"
AUTH_DEFAULT="${TH_DEFAULT_LOGIN}:${TH_DEFAULT_PASS}"

# ── Provisionnement de l'admin .env dans TheHive ─────────────────────────────
# Le .env annonce THEHIVE_ADMIN_LOGIN/THEHIVE_ADMIN_PASSWORD, mais TheHive ne
# crée au boot que son admin par défaut (admin@thehive.local/secret) : sans
# provisionnement, le login .env échoue (401 AuthenticationError — audit P01).
# On crée le compte .env (ou on réaligne son mot de passe) via l'admin par
# défaut, puis TOUT le script utilise les identifiants .env.
th_code() { # method path user:pass [json-body] [field]
  curl -sS -o "${5:-/dev/null}" -w '%{http_code}' -X "$1" "$THEHIVE_URL$2" \
    -H "Content-Type: application/json" -u "$3" ${4:+-d "$4"} 2>/dev/null || printf '000'
}

ensure_env_admin() {
  _login="$TH_ENV_LOGIN"
  _pass="${THEHIVE_ADMIN_PASSWORD:-}"
  if [ -z "$_login" ] || [ -z "$_pass" ]; then
    echo "[INIT] WARN THEHIVE_ADMIN_LOGIN/PASSWORD absents du .env — admin par défaut conservé" >&2
    return 1
  fi
  # 1) Déjà aligné ?
  if [ "$(th_code GET /api/v1/user/current "$_login:$_pass")" = "200" ]; then
    echo "[INIT] Admin .env ($_login) déjà fonctionnel"
    return 0
  fi
  # 2) Création (profil plateforme admin, mot de passe inclus dans le body)
  #    via l'admin par défaut — pattern confirmé TheHive 4/5.
  code=$(th_code POST /api/v1/user "$AUTH_DEFAULT" \
    "{\"login\":\"$_login\",\"name\":\"Platform Admin\",\"profile\":\"admin\",\"password\":\"$_pass\"}" /tmp/th_user_create.json)
  case "$code" in
    200|201) echo "[INIT] Admin .env $_login créé dans TheHive" ; return 0 ;;
  esac
  echo "[INIT] création admin .env ($_login) → HTTP $code: $(head -c 300 /tmp/th_user_create.json 2>/dev/null)" >&2
  # 3) Existe déjà (ou = admin par défaut) → réalignement du mot de passe
  code=$(th_code PUT "/api/v1/user/$_login/password" "$AUTH_DEFAULT" "{\"password\":\"$_pass\"}" /tmp/th_user_reset.json)
  case "$code" in
    200|204)
      echo "[INIT] Mot de passe TheHive de $_login réaligné sur .env"
      return 0 ;;
  esac
  echo "[INIT] WARN provisionnement admin .env ($_login) impossible (reset HTTP $code): $(head -c 300 /tmp/th_user_reset.json 2>/dev/null)" >&2
  return 1
}

if ensure_env_admin; then
  AUTH_EFFECTIVE="$AUTH_CUSTOM"
else
  AUTH_EFFECTIVE="$AUTH_DEFAULT"
fi

BRAND_CODE=$(curl -sS -o /tmp/th_branding.json -w '%{http_code}' -u "$AUTH_EFFECTIVE" -X POST "$THEHIVE_URL/api/v1/branding" \
  -F "title=Forensic Minimal" || printf '%s' "000")
case "$BRAND_CODE" in
  200|201|204|409) echo "[INIT] TheHive branding : HTTP $BRAND_CODE" ;;
  *) echo "[INIT] WARN TheHive branding HTTP $BRAND_CODE" >&2 ;;
esac

BODY="{\"type\":\"cortex\",\"name\":\"Cortex-Forensic\",\"url\":\"${CORTEX_URL}\",\"auth\":{\"type\":\"bearer\",\"key\":\"${CORTEX_API_KEY}\"},\"includedTheHiveOrganisations\":[\"*\"],\"statusCheckInterval\":60}"

CODE="000"
for cand in "$AUTH_EFFECTIVE" "$AUTH_DEFAULT"; do
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
ORG_ID=$(curl -sS -u "$AUTH_EFFECTIVE" -H "Content-Type: application/json" \
  -d '{"query":[{"_name":"listOrganisation"}]}' "$THEHIVE_URL/api/v1/query" 2>/dev/null \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['_id'] if d else '~20584')" 2>/dev/null || echo "~20584")
E2E_LOGIN="${THEHIVE_ANALYST_LOGIN:-cert-analyst@forensic.local}"
E2E_PASS="${THEHIVE_ANALYST_PASSWORD:-F0r3ns1c_TH_Analyst!}"
curl -sS -o /dev/null -w '%{http_code}' -X POST "$THEHIVE_URL/api/v1/user" \
  -H "Content-Type: application/json" -u "$AUTH_EFFECTIVE" \
  -d "{\"login\":\"$E2E_LOGIN\",\"name\":\"CERT Analyst\",\"profile\":\"org-admin\",\"password\":\"$E2E_PASS\",\"organisations\":[{\"organisation\":\"$ORG_ID\",\"profile\":\"org-admin\"}]}" \
  | grep -qE '200|201|409' && echo "[INIT] Utilisateur E2E $E2E_LOGIN prêt" || true

echo "[INIT] WARN: connecteur Cortex non enregistré (dernier HTTP $CODE). Vérifier logs TheHive." >&2
if [ -f /tmp/th_cortex_reg.json ]; then
  head -c 500 /tmp/th_cortex_reg.json >&2 || true
  echo >&2
fi
exit 0
