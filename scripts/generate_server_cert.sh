#!/bin/bash
# Certificat serveur Nginx — modèle fp-final2 : CN=forensic-platform + IP publique en SAN.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
fi

IP="${1:-}"
if [ -z "$IP" ]; then
  IP=$(fp_detect_public_ip 2>/dev/null || fp_url_identity 2>/dev/null || fp_detect_public_host 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
fi
IP=$(fp_normalize_host "$IP" 2>/dev/null || echo "$IP")

bash "$ROOT/scripts/generate-ssl-cert.sh" "$IP"

mkdir -p "$ROOT/nginx/certs/server"
cp -f "$ROOT/config/nginx/ssl/forensic.crt" "$ROOT/nginx/certs/server/server.crt"
cp -f "$ROOT/config/nginx/ssl/forensic.key" "$ROOT/nginx/certs/server/server.key"

echo "Certificat serveur synchronisé (CN=forensic-platform, SAN IP=${IP})"
