#!/bin/bash
# Génère la CA + certificat serveur CYBERCORP (IP hôte détectée dynamiquement)
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# P-15 : résolution via le helper commun (PUBLIC_HOST > AWS > routable > local)
. "$ROOT/scripts/lib/host-ip.sh" 2>/dev/null || true
IP=$(fp_detect_public_ip 2>/dev/null | head -n1 || hostname -I 2>/dev/null | awk '{print $1}' || true)
if [ -z "$IP" ]; then
  echo "Erreur: impossible de détecter l'IP (hostname -I)" >&2
  exit 1
fi
echo "Certificat serveur pour IP : $IP"
bash scripts/generate_ca.sh
bash scripts/generate_server_cert.sh "$IP"
echo "TLS prêt. Ensuite :"
echo "  sudo bash scripts/install_ca_system.sh   # confiance système"
echo "  bash scripts/trust_ca_chromium.sh        # NSS utilisateur"
echo "  docker compose up -d --build nginx cert-portal it-portal"
