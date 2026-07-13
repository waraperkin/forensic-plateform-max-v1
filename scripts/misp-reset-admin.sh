#!/usr/bin/env bash
# Reset idempotent du compte admin MISP (email + mot de passe + clé API)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
[ -f "$ROOT/.env" ] && set -a && source "$ROOT/.env" && set +a

CONTAINER="${MISP_CONTAINER:-forensic-misp}"
DB_CONTAINER="${MISP_DB_CONTAINER:-forensic-misp-db}"
EMAIL="${MISP_ADMIN_EMAIL:-admin@forensic.local}"
PASS="${MISP_ADMIN_PASSWORD:-F0r3ns1c_MISP_2024!}"
API_KEY="${MISP_ADMIN_API_KEY:-a1b2c3d4e5f6789012345678901234567890abcd}"
MYSQL_PASS="${MYSQL_PASSWORD:-F0r3ns1c_MISP_DB!}"
MISP_URL="${MISP_URL:-http://localhost:8090}"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
  echo "[misp-reset] Container $CONTAINER absent — démarrer la stack puis relancer."
  exit 1
fi

echo "[misp-reset] Attente HTTP MISP..."
n=0
until docker exec "$CONTAINER" curl -sf --max-time 5 http://127.0.0.1/users/login >/dev/null 2>&1; do
  n=$((n + 1))
  [ "$n" -ge 60 ] && { echo "[misp-reset] timeout"; exit 1; }
  sleep 5
done

cake() {
  docker exec -u www-data "$CONTAINER" /var/www/MISP/app/Console/cake "$@"
}

fix_misp_tmp_perms() {
  docker exec "$CONTAINER" chown -R www-data:www-data /var/www/MISP/app/tmp 2>/dev/null || true
  docker exec "$CONTAINER" chmod -R 775 /var/www/MISP/app/tmp 2>/dev/null || true
}

mysql_misp() {
  docker exec "$CONTAINER" mysql --skip-ssl -h misp-db -u misp -p"${MYSQL_PASS}" misp -N -e "$1" 2>/dev/null
}

echo "[misp-reset] Désactivation e-mails (évite échec login si SMTP absent)..."
cake Admin setSetting MISP.disable_emailing true --force 2>/dev/null || true
cake Admin setSetting Security.alert_on_suspicious_logins false --force 2>/dev/null || true

echo "[misp-reset] Mot de passe + email utilisateur id=1..."
cake user change_pw "admin@admin.test" "$PASS" --no_password_change 2>/dev/null || true
mysql_misp "UPDATE users SET email='${EMAIL}', change_pw=0, termsaccepted=1 WHERE id=1;"
cake user change_pw "$EMAIL" "$PASS" --no_password_change 2>/dev/null || true
cake user change_authkey 1 "$API_KEY" 2>/dev/null || true
mysql_misp "DELETE FROM bruteforces WHERE username IN ('${EMAIL}','admin@admin.test');" || true
fix_misp_tmp_perms

echo "[misp-reset] Vérification API..."
me_email=""
if curl -sf -H "Authorization: $API_KEY" -H "Accept: application/json" \
  "${MISP_URL}/users/view/me.json" | grep -q '"email"'; then
  me_email=$(curl -sf -H "Authorization: $API_KEY" -H "Accept: application/json" \
    "${MISP_URL}/users/view/me.json" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['User']['email'])" 2>/dev/null || true)
  echo "[misp-reset] API OK — email=$me_email"
else
  echo "[misp-reset] WARN — clé API non vérifiée sur ${MISP_URL}"
fi

echo "[misp-reset] Vérification login UI (${EMAIL})..."
export MISP_URL MISP_ADMIN_EMAIL="$EMAIL" MISP_ADMIN_PASSWORD="$PASS"
if MISP_ADMIN_EMAIL="$EMAIL" MISP_ADMIN_PASSWORD="$PASS" MISP_URL="$MISP_URL" \
  python3 -c "
import os, re, sys, requests
base = os.environ['MISP_URL'].rstrip('/')
email = os.environ['MISP_ADMIN_EMAIL']
password = os.environ['MISP_ADMIN_PASSWORD']
s = requests.Session()
r = s.get(f'{base}/users/login', timeout=25)
if r.status_code != 200 or 'password' not in r.text:
    sys.exit(1)
key = re.search(r'name=\"data\[_Token\]\[key\]\"[^>]*value=\"([^\"]+)\"', r.text)
fields = re.search(r'name=\"data\[_Token\]\[fields\]\"[^>]*value=\"([^\"]*)\"', r.text)
if not key:
    sys.exit(1)
data = {
    '_method': 'POST',
    'data[_Token][key]': key.group(1),
    'data[_Token][fields]': fields.group(1) if fields else '',
    'data[_Token][unlocked]': '',
    'data[User][email]': email,
    'data[User][password]': password,
}
r2 = s.post(f'{base}/users/login', data=data, allow_redirects=False, timeout=30)
if r2.status_code not in (302, 303):
    sys.exit(1)
r3 = s.get(f'{base}/events/index', allow_redirects=True, timeout=30)
if r3.status_code != 200 or 'login' in r3.url:
    sys.exit(1)
print('OK')
"; then
  echo "[misp-reset] Login UI OK — $EMAIL"
else
  echo "[misp-reset] ERREUR — login UI échoué pour $EMAIL" >&2
  exit 1
fi

[ "$me_email" = "$EMAIL" ] || echo "[misp-reset] WARN — email API ($me_email) != attendu ($EMAIL)"

echo "[misp-reset] URL publique MISP (proxy nginx)..."
if docker exec "$CONTAINER" test -f /scripts/misp-configure-public-url.sh 2>/dev/null; then
  if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
    # shellcheck source=/dev/null
    . "$ROOT/scripts/lib/host-ip.sh"
    fp_load_env_public_host 2>/dev/null || true
  fi
  _host="$(fp_url_identity 2>/dev/null || fp_resolve_public_host 2>/dev/null || echo "localhost")"
  _host=$(fp_normalize_host "$_host" 2>/dev/null || echo "$_host")
  export MISP_PUBLIC_BASE_URL="${MISP_PUBLIC_BASE_URL:-https://${_host}/misp}"
  MISP_PUBLIC_BASE_URL="${MISP_PUBLIC_BASE_URL#https://}"
  MISP_PUBLIC_BASE_URL="${MISP_PUBLIC_BASE_URL#http://}"
  MISP_PUBLIC_BASE_URL="https://${MISP_PUBLIC_BASE_URL%/}"
  export MISP_PUBLIC_BASE_URL
  docker exec -e "MISP_PUBLIC_BASE_URL=${MISP_PUBLIC_BASE_URL}" "$CONTAINER" \
    /scripts/misp-configure-public-url.sh 2>/dev/null \
    && echo "[misp-reset] MISP.baseurl → ${MISP_PUBLIC_BASE_URL}" \
    || echo "[misp-reset] WARN — configure-public-url partiel"
fi

echo "[misp-reset] Terminé — $EMAIL / (MISP_ADMIN_PASSWORD dans .env)"
