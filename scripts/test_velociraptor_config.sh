#!/usr/bin/env bash
# Valide server.config.yaml Velociraptor (plain HTTP derrière nginx, public_url IP).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GEN="$ROOT/velociraptor/scripts/generate-config.sh"
CFG="$ROOT/velociraptor/config/server.config.yaml"
TEST_IP="${TEST_IP:-203.0.113.10}"
fail=0

FP_VR_NGINX_ONLY=1 PUBLIC_HOST="$TEST_IP" FP_HTTPS_PORT=443 bash "$GEN" >/dev/null

if grep -q 'use_plain_http: true' "$CFG"; then
  echo "PASS: GUI use_plain_http"
else
  echo "FAIL: GUI use_plain_http absent" >&2
  fail=1
fi

if grep -q "public_url: https://${TEST_IP}/velociraptor/" "$CFG"; then
  echo "PASS: public_url avec base_path VR"
elif grep -q "public_url: https://${TEST_IP}/velociraptor/app/index.html" "$CFG"; then
  echo "PASS: public_url VR 0.76+ (app/index.html)"
else
  echo "FAIL: public_url incorrect ($(grep public_url "$CFG" || true))" >&2
  fail=1
fi

if grep -q '/velociraptor/app/index.html' "$CFG"; then
  echo "PASS: public_url VR 0.76 conforme"
else
  echo "FAIL: public_url sans chemin VR requis" >&2
  fail=1
fi

if grep -q "$TEST_IP" "$CFG"; then
  echo "PASS: IP test dans config"
else
  echo "FAIL: IP $TEST_IP absente" >&2
  fail=1
fi

[ "$fail" -eq 0 ] && echo "Config Velociraptor OK" || exit 1
