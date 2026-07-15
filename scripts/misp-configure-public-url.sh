#!/bin/sh
# Aligne MISP.baseurl sur l'URL publique HTTPS (proxy Nginx /misp/).
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
fi
if [ -f "$ROOT/.env" ]; then
  while IFS= read -r _line || [ -n "$_line" ]; do
    case "$_line" in "#"*|"") continue ;; esac
    if echo "$_line" | grep -q '^MISP_PUBLIC_BASE_URL='; then
      _v="${_line#MISP_PUBLIC_BASE_URL=}"
      _v="${_v%\"}"; _v="${_v#\"}"; _v="${_v%\'}"; _v="${_v#\'}"
      [ -n "$_v" ] && export MISP_PUBLIC_BASE_URL="$_v"
    fi
  done < "$ROOT/.env"
fi

PUBLIC_BASE="${MISP_PUBLIC_BASE_URL:-${BASE_URL:-}}"
if [ -z "$PUBLIC_BASE" ] || echo "$PUBLIC_BASE" | grep -q '10\.78\.0\.9'; then
  _host=$(fp_url_identity 2>/dev/null || fp_resolve_public_host 2>/dev/null || echo "localhost")
  _host=$(fp_normalize_host "$_host" 2>/dev/null || echo "$_host")
  PUBLIC_BASE="https://${_host}/misp"
fi
# Normalise (évite https://https://…)
PUBLIC_BASE="${PUBLIC_BASE#https://}"
PUBLIC_BASE="${PUBLIC_BASE#http://}"
PUBLIC_BASE="https://${PUBLIC_BASE%/}"

CAKE="/var/www/MISP/app/Console/cake"
if [ ! -x "$CAKE" ] && [ -f "$CAKE" ]; then
  chmod +x "$CAKE" 2>/dev/null || true
fi

echo "[misp-configure-public-url] MISP.baseurl → ${PUBLIC_BASE}"
sudo -u www-data "$CAKE" Admin setSetting "MISP.baseurl" "${PUBLIC_BASE}" 2>/dev/null \
  || "$CAKE" Admin setSetting "MISP.baseurl" "${PUBLIC_BASE}"

sudo -u www-data "$CAKE" Admin setSetting "MISP.external_baseurl" "${PUBLIC_BASE}" 2>/dev/null \
  || "$CAKE" Admin setSetting "MISP.external_baseurl" "${PUBLIC_BASE}"

# Proxy TLS : évite redirections http:// derrière Nginx
sudo -u www-data "$CAKE" Admin setSetting "Security.force_https" true --force 2>/dev/null \
  || "$CAKE" Admin setSetting "Security.force_https" true --force

# Coercion désactivée : App.fullBaseUrl doit rester scheme://host (sans /misp).
# Avec App.base=/misp (bootstrap IP-fix), la coercion MISP remettait
# fullBaseUrl=https://host/misp → FormHelper hashe /misp/misp/… → CSRF 400.
sudo -u www-data "$CAKE" Admin setSetting "MISP.disable_baseurl_coercion" true --force 2>/dev/null \
  || "$CAKE" Admin setSetting "MISP.disable_baseurl_coercion" true --force

if [ -x /scripts/misp-apply-bootstrap-fix.sh ]; then
  /scripts/misp-apply-bootstrap-fix.sh || true
fi

# cake Admin setSetting peut laisser config.php en root:600 → CSRF/salt illisibles
chown www-data:www-data /var/www/MISP/app/Config/config.php 2>/dev/null || true
chmod 640 /var/www/MISP/app/Config/config.php 2>/dev/null || true

sudo -u www-data "$CAKE" Admin getSetting "MISP.baseurl" 2>/dev/null \
  || "$CAKE" Admin getSetting "MISP.baseurl"

echo "[misp-configure-public-url] Terminé"
