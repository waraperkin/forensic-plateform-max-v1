#!/bin/bash
# Déploiement TLS CYBERCORP full-auto (CA + cert serveur + confiance + nginx)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== 1/6 Génération certificats ==="
bash scripts/generate_tls_all.sh

echo "=== 2/6 Installation CA système (sudo) ==="
if [[ "$(id -u)" -eq 0 ]]; then
  bash scripts/install_ca_system.sh
else
  if [[ -n "${SUDO_PASSWORD:-}" ]]; then
    echo "$SUDO_PASSWORD" | sudo -S bash scripts/install_ca_system.sh
  else
    sudo bash scripts/install_ca_system.sh
  fi
fi

echo "=== 3/6 Confiance NSS Chromium / Cursor ==="
bash scripts/trust_ca_chromium.sh

# Certificat serveur en confiance directe (partition navigateur intégré)
if [[ -x /tmp/nss-tools/usr/bin/certutil ]] || command -v certutil >/dev/null 2>&1; then
  CERTUTIL="${CERTUTIL:-/tmp/nss-tools/usr/bin/certutil}"
  if ! [[ -x "$CERTUTIL" ]]; then
    apt-get download -o Dir::Cache=/tmp libnss3-tools >/dev/null 2>&1 || true
    dpkg-deb -x /tmp/libnss3-tools*.deb /tmp/nss-tools 2>/dev/null || true
    CERTUTIL="/tmp/nss-tools/usr/bin/certutil"
  fi
  DB="$HOME/.config/Cursor/Partitions/cursor-browser"
  mkdir -p "$DB"
  "$CERTUTIL" -d "sql:$DB" -A -t "P,," -n "CyberCorp-Server-192.0.2.9" \
    -i "$ROOT/nginx/certs/server/server.crt" 2>/dev/null || true
fi

echo "=== 4/6 Redémarrage nginx + portails ==="
docker compose up -d --build nginx cert-portal it-portal

echo "=== 5/6 Rechargement réseau Cursor (navigateur intégré) ==="
pkill -f "utility-sub-type=network.mojom.NetworkService.*user-data-dir=$HOME/.config/Cursor" 2>/dev/null || true
sleep 2

echo "=== 6/6 Validation TLS ==="
curl -sf https://192.0.2.9/login.html >/dev/null
echo "curl https://192.0.2.9/login.html → SSL certificate verify ok"

if docker ps --format '{{.Names}}' | grep -q '^forensic-misp$'; then
  echo "=== MISP baseurl publique ==="
  docker exec forensic-misp sudo -u www-data /var/www/MISP/app/Console/cake Admin setSetting \
    "MISP.baseurl" "${MISP_PUBLIC_BASE_URL:-https://192.0.2.9/misp}" 2>/dev/null || true
fi

for path in dashboards/ timesketch/ cti/ thehive/ misp/ cortex/ minio/ grafana/ it/; do
  if [[ "$path" == "misp/" ]]; then
    loc=$(curl -sI "https://192.0.2.9/$path" | awk -F': ' '/^Location:/ {print $2}' | tr -d '\r')
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://192.0.2.9/$path")
    echo "  /$path → HTTP $code Location=${loc:-—}"
  else
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://192.0.2.9/$path")
    echo "  /$path → HTTP $code"
  fi
done

echo ""
echo "TLS CYBERCORP déployé. Ouvrez https://192.0.2.9/ dans le navigateur intégré."
