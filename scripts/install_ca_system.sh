#!/bin/bash
# Installe la CA CyberCorp dans le magasin de confiance système (Linux).
# Requis pour curl sans --cacert et pour le navigateur intégré Chromium.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CA_SRC="$ROOT/nginx/certs/ca/ca.crt"

if [[ ! -f "$CA_SRC" ]]; then
  echo "Erreur: $CA_SRC introuvable. Exécutez d'abord scripts/generate_ca.sh"
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Ce script doit être exécuté en root : sudo bash scripts/install_ca_system.sh"
  exit 1
fi

cp "$CA_SRC" /usr/local/share/ca-certificates/cybercorp-ca.crt
update-ca-certificates

# NSS (Chromium / navigateur intégré) — utilisateur courant si SUDO_USER défini
TARGET_USER="${SUDO_USER:-$USER}"
if command -v certutil >/dev/null 2>&1 && [[ -n "$TARGET_USER" && "$TARGET_USER" != root ]]; then
  NSSDB="/home/$TARGET_USER/.pki/nssdb"
  mkdir -p "$NSSDB"
  chown -R "$TARGET_USER:$TARGET_USER" "/home/$TARGET_USER/.pki"
  sudo -u "$TARGET_USER" certutil -d "sql:$NSSDB" -A -t "C,," -n "CyberCorp-Root-CA" -i "$CA_SRC" 2>/dev/null || true
fi

# Politique Chromium : importer les racines système (navigateur intégré / Electron)
mkdir -p /etc/chromium/policies/managed /etc/opt/chrome/policies/managed 2>/dev/null || true
echo '{"ImportEnterpriseRoots": true}' > /etc/chromium/policies/managed/cybercorp.json
cp /etc/chromium/policies/managed/cybercorp.json /etc/opt/chrome/policies/managed/cybercorp.json 2>/dev/null || true

echo "CA CyberCorp installée. Redémarrez Cursor si le navigateur intégré était ouvert avant l'installation."
