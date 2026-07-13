#!/bin/sh
# Désactive les redirections HTTPS forcées (Apache ou Nginx selon image MISP).
set -eu
echo "[misp-disable-ssl] Début"

APACHE_CONF="/etc/apache2/sites-enabled/000-default.conf"
if [ -f "$APACHE_CONF" ]; then
  echo "[misp-disable-ssl] Apache: $APACHE_CONF"
  sed -i '/RewriteCond %{HTTPS} off/,+2d' "$APACHE_CONF" 2>/dev/null || true
  sed -i 's/UseCanonicalName On/UseCanonicalName Off/g' "$APACHE_CONF" 2>/dev/null || true
  if command -v apache2ctl >/dev/null 2>&1; then
    apache2ctl graceful 2>/dev/null || service apache2 reload 2>/dev/null || true
  fi
fi

for d in /etc/nginx/http.d /etc/nginx/sites-enabled /etc/nginx/conf.d; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    if grep -qE 'return\s+301\s+https|rewrite.*https' "$f" 2>/dev/null; then
      echo "[misp-disable-ssl] Nginx (commentaire manuel requis): $f"
    fi
  done
done

if [ -x /scripts/misp-configure-public-url.sh ]; then
  MISP_PUBLIC_BASE_URL="${MISP_PUBLIC_BASE_URL:-}" \
    /scripts/misp-configure-public-url.sh || true
fi

echo "[misp-disable-ssl] Terminé"
