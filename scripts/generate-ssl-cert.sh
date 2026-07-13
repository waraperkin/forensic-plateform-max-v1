#!/bin/bash
# Génère un certificat SSL auto-signé robuste (RSA 4096, SHA-256)
# pour chiffrer les uploads du Portail IT sur internet

DIR="$(cd "$(dirname "$0")/.." && pwd)"
SSL_DIR="$DIR/config/nginx/ssl"
CERT="$SSL_DIR/forensic.crt"
KEY="$SSL_DIR/forensic.key"
FINGERPRINT_FILE="$SSL_DIR/fingerprint.txt"

mkdir -p "$SSL_DIR"

# IP publique (argument, PUBLIC_HOST, ou détection AWS / locale)
LOCAL_IP="${1:-}"
if [ -z "$LOCAL_IP" ] && [ -f "$DIR/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$DIR/scripts/lib/host-ip.sh"
  LOCAL_IP=$(fp_detect_public_host 2>/dev/null || true)
fi
LOCAL_IP="${LOCAL_IP:-$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")}"

_cert_san_has_ip() {
  [ -f "$CERT" ] || return 1
  openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -Fq "$LOCAL_IP"
}

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  # Vérifier si le cert est encore valide (> 30 jours) ET SAN correct
  if openssl x509 -checkend 2592000 -noout -in "$CERT" 2>/dev/null && _cert_san_has_ip; then
    echo "[ssl] Certificat existant valide (SAN=$LOCAL_IP) — conservation"
    exit 0
  fi
  echo "[ssl] Certificat expiré ou SAN ≠ $LOCAL_IP — régénération"
fi

echo "[ssl] Génération certificat SSL RSA-4096..."

# Configuration SAN (Subject Alternative Names)
cat > /tmp/ssl-ext.cnf << EXTCONF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C  = FR
ST = IDF
L  = Paris
O  = Forensic Platform CERT
OU = Digital Forensics
CN = forensic-platform

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = forensic-platform
IP.1  = 127.0.0.1
IP.2  = ${LOCAL_IP}
EXTCONF

openssl req -x509 \
  -newkey rsa:4096 \
  -keyout "$KEY" \
  -out "$CERT" \
  -days 365 \
  -nodes \
  -config /tmp/ssl-ext.cnf \
  2>/dev/null

# Calculer le fingerprint SHA-256
FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in "$CERT" 2>/dev/null | sed 's/SHA256 Fingerprint=//')
echo "$FINGERPRINT" > "$FINGERPRINT_FILE"
echo "[ssl] Certificat généré"
echo "[ssl] IP: ${LOCAL_IP}"
echo "[ssl] Fingerprint SHA-256: $FINGERPRINT"
echo "[ssl] Valide 365 jours"
echo "[ssl] Fichiers: $CERT / $KEY"
