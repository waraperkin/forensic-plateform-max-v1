#!/usr/bin/env bash
# Garantit +x sur forensic.sh et scripts/*.sh après git clone (Windows → Linux).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$ROOT/forensic.sh" ] && chmod +x "$ROOT/forensic.sh" 2>/dev/null || true
find "$ROOT/scripts" -type f -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
