#!/usr/bin/env bash
# Pré-vol statique avant ./forensic.sh -full-start (~2 h).
# Usage : ./scripts/preflight-full-start.sh
# Code sortie 0 = prêt pour clone + full-start sur VM AWS fraîche.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -x "$ROOT/scripts/ensure-scripts-executable.sh" ]; then
  bash "$ROOT/scripts/ensure-scripts-executable.sh"
elif [ -f "$ROOT/scripts/ensure-scripts-executable.sh" ]; then
  chmod +x "$ROOT/scripts/ensure-scripts-executable.sh" 2>/dev/null || true
  bash "$ROOT/scripts/ensure-scripts-executable.sh"
fi

STATIC_TESTS=(
  test_host_ip.sh
  test_tls_forensic_platform.sh
  test_velociraptor_config.sh
  test_velociraptor_sidecar_wiring.sh
  test_proxy_subpath_config.sh
  test_portal_dockerfile_deps.sh
  test_bootstrap_fresh_install.sh
  test_bootstrap_prepare_host.sh
  test_bootstrap_env_corrupt.sh
  test_env_canonical.sh
  test_no_lab_ip_residual.sh
  test_nginx_config.sh
  test_full_start_gates.sh
)

fail=0
passed=0

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  PREFLIGHT — forensic-minimal (avant ./forensic.sh -full-start) ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

for name in "${STATIC_TESTS[@]}"; do
  script="$ROOT/scripts/$name"
  if [ ! -f "$script" ]; then
    echo "FAIL: $name absent" >&2
    fail=1
    continue
  fi
  if [ ! -x "$script" ]; then
    echo "WARN: $name non exécutable — lancement via bash (chmod +x recommandé)" >&2
  fi
  echo "── $name ──"
  if bash "$script"; then
    passed=$((passed + 1))
  else
    echo "FAIL: $name" >&2
    fail=1
  fi
  echo ""
done

# Vérifications structurelles supplémentaires
echo "── checks structurels ──"
for req in \
  "scripts/ensure-velociraptor-sidecar.sh" \
  "scripts/ensure-portal-admin.sh" \
  "scripts/repair-env-file.sh" \
  "scripts/setup-sidecars.sh" \
  "scripts/post-start-align.sh" \
  "scripts/verify-platform-ready.sh" \
  "velociraptor/config/server.config.yaml" \
  "config/nginx/conf.d/forensic.conf"; do
  if [ -f "$ROOT/$req" ]; then
    echo "PASS: $req"
  else
    echo "FAIL: $req manquant" >&2
    fail=1
  fi
done

if [ -f "$ROOT/velociraptor/config/server.config.yaml" ]; then
  size=$(wc -c < "$ROOT/velociraptor/config/server.config.yaml" | tr -d ' ')
  if [ "$size" -lt 500 ]; then
    echo "FAIL: server.config.yaml vide ou trop court ($size octets)" >&2
    fail=1
  else
    echo "PASS: server.config.yaml non vide ($size octets)"
  fi
  if grep -q 'use_plain_http: true' "$ROOT/velociraptor/config/server.config.yaml"; then
    echo "PASS: use_plain_http dans server.config.yaml"
  else
    echo "FAIL: use_plain_http absent (redirect loops / 502 possibles)" >&2
    fail=1
  fi
  if grep -q '/velociraptor/app/index.html' "$ROOT/velociraptor/config/server.config.yaml"; then
    echo "PASS: public_url VR 0.76+ conforme"
  else
    echo "FAIL: public_url VR non conforme (base_path requis)" >&2
    fail=1
  fi
fi

echo ""
if [ "$fail" -eq 0 ]; then
  echo "✅ PREFLIGHT OK — $passed tests statiques passés"
  echo ""
  echo "Procédure zero-touch (VM AWS EC2 — Security Group : TCP 80 + 443) :"
  echo "  sudo mkdir -p /opt"
  echo "  sudo git clone https://github.com/waraperkin/forensic-minimal-v2.git /opt/forensic-minimal-v2"
  echo "  cd /opt/forensic-minimal-v2"
  echo "  ./scripts/preflight-full-start.sh"
  echo "  ./forensic.sh -full-start"
  echo ""
  echo "Portail CERT : https://<IP>/  (admin / F0r3ns1c_Portal_2024!)"
  echo "Velociraptor : https://<IP>/velociraptor/  (admin / F0r3ns1c_VR_2024!)"
  exit 0
fi

echo "❌ PREFLIGHT ÉCHOUÉ — corriger avant de lancer -full-start (~2 h)" >&2
exit 1
