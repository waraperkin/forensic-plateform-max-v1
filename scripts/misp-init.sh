#!/usr/bin/env bash
# Initialisation MISP après démarrage — aligné sur MISP_ADMIN_EMAIL (.env)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "$ROOT/scripts/misp-reset-admin.sh"
