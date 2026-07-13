#!/usr/bin/env bash
# Configure l'accès public via nom de domaine (évite blocage proxy « Uncategorized » sur IP nue).
# Usage : PUBLIC_HOSTNAME=forensic-lab.example.com ./scripts/setup-public-access.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
fi

DOMAIN="${PUBLIC_HOSTNAME:-${1:-}}"
if [ -z "$DOMAIN" ]; then
  echo "Usage: PUBLIC_HOSTNAME=forensic-lab.entreprise.com $0"
  echo "       ou: $0 forensic-lab.entreprise.com"
  exit 1
fi

echo "[public-access] Domaine : $DOMAIN"
echo "[public-access] 1) Créer un enregistrement DNS A → IP publique AWS"
echo "[public-access] 2) Mise à jour .env et TLS..."

if [ -f "$ROOT/.env" ]; then
  if grep -q '^PUBLIC_HOSTNAME=' "$ROOT/.env"; then
    sed -i "s/^PUBLIC_HOSTNAME=.*/PUBLIC_HOSTNAME=${DOMAIN}/" "$ROOT/.env"
  else
    echo "PUBLIC_HOSTNAME=${DOMAIN}" >> "$ROOT/.env"
  fi
  if grep -q '^PUBLIC_HOST=' "$ROOT/.env"; then
    sed -i "s/^PUBLIC_HOST=.*/PUBLIC_HOST=${DOMAIN}/" "$ROOT/.env"
  fi
fi
export PUBLIC_HOSTNAME="$DOMAIN"
export PUBLIC_HOST="$DOMAIN"

./forensic.sh tls || true
bash "$ROOT/scripts/setup-sidecars.sh" 2>/dev/null || true
bash "$ROOT/scripts/misp-configure-host.sh" 2>/dev/null || true

echo ""
echo "[public-access] Accès recommandé : https://${DOMAIN}/"
echo "[public-access] Demander à IT l'allowlist du domaine (plus simple qu'une IP nue)."
echo "[public-access] Certificat Let's Encrypt (optionnel) :"
echo "  certbot certonly --standalone -d ${DOMAIN}"
echo "  puis pointer nginx vers /etc/letsencrypt/live/${DOMAIN}/"
