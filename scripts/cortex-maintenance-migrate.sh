#!/usr/bin/env bash
# Migration DB Cortex (sortir de « Update Database » / erreurs user init).
# Essaie plusieurs couples Basic auth (TheHive admin .env, variantes courantes).
set -uo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
__env() { grep -E "^${1}=" "$DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2- || true; }
BASE="${CORTEX_URL:-http://localhost:9003}"
TH_USER="$(__env THEHIVE_ADMIN_LOGIN)"; TH_USER="${TH_USER:-admin@thehive.local}"
TH_PASS="$(__env THEHIVE_ADMIN_PASSWORD)"; TH_PASS="${TH_PASS:-secret}"

AUTH_CANDIDATES=(
  "${CORTEX_MIGRATE_USER:-}:${CORTEX_MIGRATE_PASSWORD:-}"
  "${TH_USER}:${TH_PASS}"
  "admin:${TH_PASS}"
  "admin@thehive.local:${TH_PASS}"
)
# Retire entrées vides « : »
CLEAN=()
for a in "${AUTH_CANDIDATES[@]}"; do
  [ -n "${a%%:*}" ] && [ -n "${a#*:}" ] && CLEAN+=("$a")
done

for path in /api/maintenance/migrate /api/v1/maintenance/migrate; do
  for auth in "${CLEAN[@]}"; do
    user="${auth%%:*}"
    pass="${auth#*:}"
    code=$(curl -sS -u "${user}:${pass}" -o /tmp/cortex_migrate_body.txt -w '%{http_code}' \
      -X POST "${BASE}${path}" --max-time 60 2>/dev/null) || code="000"
    echo "[cortex-migrate] POST ${path} user=${user} → HTTP ${code}"
    head -c 400 /tmp/cortex_migrate_body.txt 2>/dev/null || true
    echo
    case "$code" in 200|201|204|302) exit 0 ;; esac
  done
done
exit 0
