#!/usr/bin/env bash
# Vérifie que le bootstrap prépare IP + fichiers nginx sans Docker.
#
# SÉCURITÉ DONNÉES : fp_prepare_platform_host réécrit de VRAIS fichiers du
# repo (.env, statics nginx, grafana.ini, timesketch.conf, snippets VR).
# Tous sont sauvegardés dans $WORKDIR et restaurés par trap EXIT — même en
# cas d'échec du test (set -e). Le .env de production ne doit JAMAIS être
# perdu par un preflight (bug constaté : le backup précédent sauvegardait
# l'.env SIMULÉ au lieu du réel).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export DIR="$ROOT"
export FP_LOG_INSTALL="$ROOT/logs/test-prepare-host.log"
mkdir -p "$ROOT/logs"

# shellcheck source=/dev/null
. "$ROOT/scripts/lib/host-ip.sh"
# shellcheck source=/dev/null
. "$ROOT/scripts/lib/platform-host.sh"

WORKDIR=$(mktemp -d)

# Fichiers réels réécrits par le test (ou par fp_prepare_platform_host)
STATE_FILES=(
  .env
  config/nginx/static/robots.txt
  config/nginx/static/site-info.html
  config/nginx/static/.well-known/security.txt
  config/nginx/generated/ec2-dns-redirect.conf
  config/grafana/grafana.ini
  config/timesketch/timesketch.conf
  config/nginx/snippets/velociraptor-proxy.conf
)

cleanup() {
  # Restaure chaque fichier réel depuis le backup (ou le supprime s'il
  # n'existait pas avant le test), puis nettoie le répertoire temporaire.
  local f
  for f in "${STATE_FILES[@]}"; do
    if [ -f "$WORKDIR/backup/$f" ]; then
      mkdir -p "$ROOT/$(dirname "$f")"
      cp -f "$WORKDIR/backup/$f" "$ROOT/$f"
    else
      rm -f "$ROOT/$f"
    fi
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for f in "${STATE_FILES[@]}"; do
  if [ -f "$ROOT/$f" ]; then
    mkdir -p "$WORKDIR/backup/$(dirname "$f")"
    cp "$ROOT/$f" "$WORKDIR/backup/$f"
  fi
done

cp "$ROOT/.env.example" "$WORKDIR/.env"
# Simule bootstrap .env avec IP test (hors plages RFC 5737 — celles-ci sont
# traitées comme placeholders auto-réparés par la lib host-ip)
TEST_IP="192.168.2.199"
sed -i "s/^PUBLIC_HOST=.*/PUBLIC_HOST=${TEST_IP}/" "$WORKDIR/.env" 2>/dev/null || echo "PUBLIC_HOST=${TEST_IP}" >> "$WORKDIR/.env"
cp "$WORKDIR/.env" "$ROOT/.env"

FP_SKIP_ENV_ALIGN=1 PUBLIC_HOST="$TEST_IP" fp_prepare_platform_host

fail=0
for f in config/nginx/static/robots.txt config/nginx/static/site-info.html config/nginx/static/.well-known/security.txt; do
  if [ -f "$ROOT/$f" ]; then
    echo "PASS: $f existe"
  else
    echo "FAIL: $f absent" >&2
    fail=1
  fi
done

# Vérifie l'IP injectée (TEST_IP) ou l'identité résolue sur EC2 si align actif
IDENTITY="${TEST_IP}"
if grep -q "$IDENTITY" "$ROOT/config/nginx/static/site-info.html" 2>/dev/null; then
  echo "PASS: site-info.html contient IP ($IDENTITY)"
elif grep -qE 'https://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$ROOT/config/nginx/static/site-info.html" 2>/dev/null; then
  RESOLVED=$(grep -oE 'https://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$ROOT/config/nginx/static/site-info.html" | head -1 | sed 's|https://||')
  echo "PASS: site-info.html contient IP publique ($RESOLVED)"
else
  echo "FAIL: site-info.html sans URL IP" >&2
  fail=1
fi

[ "$fail" -eq 0 ] && echo "Bootstrap prepare host OK" || exit 1
