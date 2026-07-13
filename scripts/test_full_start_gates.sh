#!/usr/bin/env bash
# Vérifie que forensic.sh propage les échecs sidecar/finalize/tests (pas de || warn silencieux).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FS="$ROOT/forensic.sh"
fail=0

check_absent() {
  local label="$1" pattern="$2"
  if grep -qE "$pattern" "$FS"; then
    echo "FAIL: $label — motif interdit trouvé" >&2
    grep -nE "$pattern" "$FS" | head -3 >&2 || true
    fail=1
  else
    echo "PASS: $label"
  fi
}

check_present() {
  local label="$1" pattern="$2"
  if grep -qE "$pattern" "$FS"; then
    echo "PASS: $label"
  else
    echo "FAIL: $label — motif attendu absent" >&2
    fail=1
  fi
}

check_absent "setup-sidecars sans warn silencieux" \
  'setup-sidecars\.sh.*\|\| warn'

check_absent "helk_velociraptor_master sans warn silencieux" \
  'helk_velociraptor_master_setup\.sh.*\|\| warn'

check_absent "fp_finalize sans warn silencieux" \
  'fp_finalize_platform_access.*\|\| warn'

check_absent "post-start-align sans warn silencieux" \
  'post-start-align\.sh.*\|\| warn'

check_absent "fp_start_tests sans || true" \
  'fp_start_tests \|\| true'

check_present "START_FAIL sidecars" \
  'START_FAIL\+=\("Sidecars HELK/Velociraptor"\)'

check_present "START_FAIL finalize" \
  'START_FAIL\+=\("Finalisation accès IP'

check_present "START_FAIL tests" \
  'START_FAIL\+=\("Tests automatiques post-démarrage"\)'

check_present "orchestrateur verify-platform-ready" \
  'verify-platform-ready\.sh'

if grep -q 'fs_rc=1' "$FS"; then
  echo "PASS: orchestrateur fs_rc=1 sur verify KO"
else
  echo "FAIL: orchestrateur ne force pas fs_rc=1" >&2
  fail=1
fi

[ "$fail" -eq 0 ] && echo "Gates full-start OK" || exit 1
