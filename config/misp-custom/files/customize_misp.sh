#!/bin/bash
# Exécuté automatiquement par l'entrypoint misp-core à CHAQUE démarrage du
# conteneur (après /configure_misp.sh qui applique BASE_URL).
# Rend la configuration sous-chemin /misp auto-réparatrice : le patch
# App.base + les réglages anti-CSRF survivent aux recréations du conteneur
# (config.php et bootstrap.php vivent dans le FS du conteneur, pas un volume).
set -u

CAKE=/var/www/MISP/app/Console/cake
CONFIG=/var/www/MISP/app/Config/config.php

log() { echo "[customize-misp] $*"; }

set_setting() {
  sudo -u www-data "$CAKE" Admin setSetting "$1" "$2" --force >/dev/null 2>&1 \
    || "$CAKE" Admin setSetting "$1" "$2" --force >/dev/null 2>&1 \
    || log "WARN setSetting $1"
}

# 1 — bootstrap.php : nettoie tout patch corrompu puis réapplique App.base
#     (dérivé de MISP.baseurl — les IP ne matchent pas la regex CakePHP).
if [ -x /scripts/misp-sanitize-bootstrap.sh ]; then
  bash /scripts/misp-sanitize-bootstrap.sh || log "WARN sanitize-bootstrap"
fi
if [ -f /scripts/misp-apply-bootstrap-fix.sh ]; then
  sh /scripts/misp-apply-bootstrap-fix.sh || log "WARN apply-bootstrap-fix"
fi

# 2 — Réglages proxy /misp (idempotents, appliqués à chaque boot)
if [ -n "${BASE_URL:-}" ]; then
  set_setting MISP.external_baseurl "${BASE_URL}"
fi
set_setting Security.force_https true
# App.fullBaseUrl doit rester scheme://host (sans /misp) — la coercion MISP
# remettrait fullBaseUrl=baseurl (avec /misp) → FormHelper hashe /misp/misp/…
# → CSRF 400 au login.
set_setting MISP.disable_baseurl_coercion true

# 3 — cake Admin setSetting peut laisser config.php en root:600
#     → salt/CSRF illisibles par php-fpm (www-data)
chown www-data:www-data "$CONFIG" 2>/dev/null || true
chmod 640 "$CONFIG" 2>/dev/null || true

# 4 — Purge des caches modèles (une baseurl périmée peut y rester figée)
rm -rf /var/www/MISP/app/tmp/cache/models/* \
       /var/www/MISP/app/tmp/cache/persistent/* 2>/dev/null || true

log "OK — baseurl=$("$CAKE" Admin getSetting MISP.baseurl 2>/dev/null | tail -1 || echo '?')"
exit 0
