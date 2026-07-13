#!/usr/bin/env bash
# Configuration Velociraptor DFIR complète (offline lab).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FM_ROOT="$(cd "$ROOT/.." && pwd)"

echo "=== Velociraptor full config (offline lab) ==="

chmod +x "$ROOT/scripts/import-official-artifacts.sh" "$ROOT/scripts/lab_collect.py" 2>/dev/null || true

if [ "${SKIP_OFFICIAL_IMPORT:-0}" != "1" ]; then
  if command -v git >/dev/null 2>&1; then
    "$ROOT/scripts/import-official-artifacts.sh" || echo "[setup] Import officiel ignoré (réseau ou structure upstream)."
  else
    echo "[setup] git absent — skip import officiel."
  fi
else
  echo "[setup] SKIP_OFFICIAL_IMPORT=1"
fi

mkdir -p "$ROOT/lab-collections"

echo "[setup] Smoke test simulateur local…"
python3 "$ROOT/scripts/lab_collect.py" --local-only --playbook windows-triage-full --case-id SETUP-SMOKE --no-export

echo "[setup] Terminé."
echo "  Docs: $FM_ROOT/docs/VELOCIRAPTOR-FULL-CONFIG.md"
echo "  Verify: python3 $FM_ROOT/scripts/velociraptor_full_config_verify.py"
echo "  Rebuild: cd $FM_ROOT && docker compose build velociraptor-bridge && docker compose up -d velociraptor-bridge"
