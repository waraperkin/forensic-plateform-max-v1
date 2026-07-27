#!/bin/bash
# Déploiement TLS CYBERCORP full-auto (CA + cert serveur + confiance + nginx)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# P-15 : hôte résolu dynamiquement — plus aucune IP codée en dur.
# shellcheck source=lib/host-ip.sh
source "$ROOT/scripts/lib/host-ip.sh"
HOST="$(fp_url_identity 2>/dev/null | head -n1 || echo 127.0.0.1)"
BASE="https://${HOST}"
echo "Hôte détecté : ${HOST}"

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

echo "=== 3/6 Confiance NSS Chromium / navigateurs intégrés ==="
bash scripts/trust_ca_chromium.sh

# Certificat serveur en confiance directe (partitions navigateurs Electron)
if [[ -x /tmp/nss-tools/usr/bin/certutil ]] || command -v certutil >/dev/null 2>&1; then
  CERTUTIL="${CERTUTIL:-/tmp/nss-tools/usr/bin/certutil}"
  if ! [[ -x "$CERTUTIL" ]]; then
    apt-get download -o Dir::Cache=/tmp libnss3-tools >/dev/null 2>&1 || true
    dpkg-deb -x /tmp/libnss3-tools*.deb /tmp/nss-tools 2>/dev/null || true
    CERTUTIL="/tmp/nss-tools/usr/bin/certutil"
  fi
  for DB in "$HOME"/.config/*/Partitions/*; do
    [[ -d "$DB" ]] || continue
    "$CERTUTIL" -d "sql:$DB" -A -t "P,," -n "CyberCorp-Server-${HOST}" \
      -i "$ROOT/nginx/certs/server/server.crt" 2>/dev/null || true
  done
fi

echo "=== 4/6 Redémarrage nginx + portails ==="
docker compose up -d --build nginx cert-portal it-portal

echo "=== 5/6 Rechargement réseau navigateurs intégrés (Electron) ==="
pkill -f "utility-sub-type=network.mojom.NetworkService.*user-data-dir=$HOME/.config/" 2>/dev/null || true
sleep 2

echo "=== 6/6 Validation TLS ==="
curl -sf "${BASE}/login.html" >/dev/null
echo "curl ${BASE}/login.html → SSL certificate verify ok"

if docker ps --format '{{.Names}}' | grep -q '^forensic-misp$'; then
  echo "=== MISP baseurl publique ==="
  docker exec forensic-misp sudo -u www-data /var/www/MISP/app/Console/cake Admin setSetting \
    "MISP.baseurl" "${MISP_PUBLIC_BASE_URL:-$(fp_misp_public_base_url)}" 2>/dev/null || true
fi

for path in dashboards/ timesketch/ cti/ thehive/ misp/ cortex/ minio/ grafana/ it/; do
  if [[ "$path" == "misp/" ]]; then
    loc=$(curl -sI "${BASE}/$path" | awk -F': ' '/^Location:/ {print $2}' | tr -d '\r')
    code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/$path")
    echo "  /$path → HTTP $code Location=${loc:-—}"
  else
    code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/$path")
    echo "  /$path → HTTP $code"
  fi
done

echo ""
echo "TLS CYBERCORP déployé. Ouvrez ${BASE}/ dans le navigateur intégré."
