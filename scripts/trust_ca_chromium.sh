#!/bin/bash
# Importe la CA CyberCorp dans les bases NSS utilisateur (Chromium / navigateur intégré).
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CA="$ROOT/nginx/certs/ca/ca.crt"

if [[ ! -f "$CA" ]]; then
  echo "Erreur: exécutez scripts/generate_ca.sh d'abord."
  exit 1
fi

CERTUTIL=""
for c in certutil /tmp/nss-tools/usr/bin/certutil; do
  if command -v "$c" >/dev/null 2>&1; then
    CERTUTIL="$c"
    break
  fi
done
if [[ -z "$CERTUTIL" ]]; then
  apt-get download -o Dir::Cache=/tmp libnss3-tools >/dev/null 2>&1 || true
  dpkg-deb -x /tmp/libnss3-tools*.deb /tmp/nss-tools 2>/dev/null || true
  CERTUTIL="/tmp/nss-tools/usr/bin/certutil"
fi
if [[ ! -x "$CERTUTIL" ]]; then
  echo "certutil introuvable — installez libnss3-tools ou exécutez install_ca_system.sh avec sudo."
  exit 1
fi

import_ca() {
  local db="$1"
  mkdir -p "$(dirname "$db")"
  "$CERTUTIL" -d "sql:$db" -A -t "C,," -n "CyberCorp-Root-CA" -i "$CA" 2>/dev/null || \
  "$CERTUTIL" -d "sql:$db" -A -t "CP,CP,CP" -n "CyberCorp-Root-CA" -i "$CA" 2>/dev/null || true
  echo "  → $db"
}

echo "Import CA dans NSS utilisateur..."
import_ca "$HOME/.pki/nssdb"
import_ca "$HOME/.config/chromium"
import_ca "$HOME/.config/google-chrome"
import_ca "$HOME/.config/Cursor/Crashpad"
import_ca "$HOME/.config/Cursor/Partitions/cursor-browser"
import_ca "$HOME/.config/Cursor"

echo "Terminé. Redémarrez Cursor pour le navigateur intégré."
echo "Si l'erreur persiste : sudo bash scripts/install_ca_system.sh"
