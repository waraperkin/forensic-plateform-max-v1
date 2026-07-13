#!/bin/bash
# Génère la CA + certificat serveur CYBERCORP (IP 192.0.2.9)
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
if [ -z "$IP" ]; then
  echo "Erreur: impossible de détecter l'IP (hostname -I)" >&2
  exit 1
fi
bash scripts/generate_ca.sh
bash scripts/generate_server_cert.sh "$IP"
echo "TLS prêt. Ensuite :"
echo "  sudo bash scripts/install_ca_system.sh   # confiance système"
echo "  bash scripts/trust_ca_chromium.sh        # NSS utilisateur"
echo "  docker compose up -d --build nginx cert-portal it-portal"
