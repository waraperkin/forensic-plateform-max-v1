#!/usr/bin/env bash
# Vérifie le modèle TLS fp-final2 : CN=forensic-platform + IP publique en SAN.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# shellcheck source=/dev/null
. "$ROOT/scripts/lib/host-ip.sh"

TEST_IP="${TEST_IP:-203.0.113.88}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

export DIR="$ROOT"
bash "$ROOT/scripts/generate_server_cert.sh" "$TEST_IP" >/dev/null

CERT="$ROOT/config/nginx/ssl/forensic.crt"
fail=0

subj=$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null || true)
if echo "$subj" | grep -q 'CN.*forensic-platform'; then
  echo "PASS: CN=forensic-platform"
else
  echo "FAIL: CN attendu forensic-platform ($subj)" >&2
  fail=1
fi

if openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -Fq "$TEST_IP"; then
  echo "PASS: SAN contient IP test $TEST_IP"
else
  echo "FAIL: SAN sans IP $TEST_IP" >&2
  fail=1
fi

if openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -Fq 'forensic-platform'; then
  echo "PASS: SAN contient DNS forensic-platform"
else
  echo "FAIL: SAN sans DNS forensic-platform" >&2
  fail=1
fi

if [ -f "$ROOT/nginx/certs/server/server.crt" ] \
  && cmp -s "$CERT" "$ROOT/nginx/certs/server/server.crt" 2>/dev/null; then
  echo "PASS: server.crt synchronisé avec forensic.crt"
else
  echo "FAIL: server.crt non synchronisé" >&2
  fail=1
fi

grep -q '/etc/nginx/ssl/forensic.crt' "$ROOT/config/nginx/conf.d/forensic.conf" \
  && echo "PASS: nginx.conf pointe vers forensic.crt" \
  || { echo "FAIL: nginx n'utilise pas forensic.crt" >&2; fail=1; }

[ "$fail" -eq 0 ] && echo "Modèle TLS fp-final2 OK" || exit 1
