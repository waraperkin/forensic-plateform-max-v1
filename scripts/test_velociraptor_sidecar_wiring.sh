#!/usr/bin/env bash
# Vérifie que ensure-velociraptor-sidecar.sh existe et que les tests couvrent le 502.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail=0

for f in \
  "$ROOT/scripts/ensure-velociraptor-sidecar.sh" \
  "$ROOT/scripts/setup-sidecars.sh" \
  "$ROOT/scripts/post-start-align.sh"; do
  if [ -f "$f" ]; then
    echo "PASS: $(basename "$f") existe"
  else
    echo "FAIL: $f absent" >&2
    fail=1
  fi
done

if grep -q 'ensure-velociraptor-sidecar' "$ROOT/scripts/post-start-align.sh"; then
  echo "PASS: post-start-align appelle ensure-vr"
else
  echo "FAIL: post-start-align sans ensure-vr" >&2
  fail=1
fi

if grep -q 'velociraptor-server' "$ROOT/scripts/verify-platform-ready.sh"; then
  echo "PASS: verify-platform-ready contrôle velociraptor-server"
else
  echo "FAIL: verify sans check conteneur VR" >&2
  fail=1
fi

if grep -q 'localhost:8000/velociraptor' "$ROOT/scripts/lib/installer.sh"; then
  echo "PASS: fp_start_tests inclut VR direct"
else
  echo "FAIL: fp_start_tests sans VR" >&2
  fail=1
fi

CONF="$ROOT/config/nginx/conf.d/forensic.conf"
if grep -qE 'proxy_pass https://\$velociraptor_upstream' "$CONF"; then
  echo "FAIL: nginx proxy VR en HTTPS (doit être http:// — sinon 502)" >&2
  fail=1
else
  echo "PASS: nginx proxy VR en HTTP plain"
fi

[ "$fail" -eq 0 ] && echo "Velociraptor sidecar wiring OK" || exit 1
