#!/usr/bin/env bash
# Helpers validation — MinIO / Docker (sans dépendre exclusivement de docker exec)
set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
# shellcheck source=/dev/null
[ -f "$ROOT/.env" ] && set -a && source "$ROOT/.env" && set +a

docker_ok() {
  docker ps >/dev/null 2>&1
}

count_minio_buckets() {
  local mc_bin="${MC_BIN:-mc}"
  local user="${MINIO_ROOT_USER:-forensicadmin}"
  local pass="${MINIO_ROOT_PASSWORD:-F0r3ns1c_Minio_2024!}"
  local alias="fp-check-$$"
  if ! command -v "$mc_bin" >/dev/null 2>&1; then
    echo "0"
    return 1
  fi
  "$mc_bin" alias set "$alias" "http://localhost:9000" "$user" "$pass" >/dev/null 2>&1 || {
    echo "0"
    return 1
  }
  "$mc_bin" ls "$alias/" 2>/dev/null | wc -l | tr -d ' '
}

ingest_worker_ok() {
  if docker_ok && docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-ingest-worker$'; then
    return 0
  fi
  local win
  win=$(curl -sk "http://localhost:9200/forensic-windows*/_count" 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")
  [ "${win:-0}" -gt 0 ]
}

opencti_active_connectors() {
  curl -sk "${OPENCTI_GRAPHQL_URL:-https://localhost/cti/graphql}" \
    -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN:-a1b2c3d4-e5f6-4789-a012-3456789abcde}" \
    -H "Content-Type: application/json" \
    --data-binary '{"query":"{ connectors { active } }"}' 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for c in d.get('data',{}).get('connectors',[]) if c.get('active')))" 2>/dev/null \
    || echo "0"
}

opencti_indicators_total() {
  curl -sk "${OPENCTI_GRAPHQL_URL:-https://localhost/cti/graphql}" \
    -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN:-a1b2c3d4-e5f6-4789-a012-3456789abcde}" \
    -H "Content-Type: application/json" \
    --data-binary '{"query":"{ indicatorsNumber { total } }"}' 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('data',{}).get('indicatorsNumber',{}).get('total',0))" 2>/dev/null \
    || echo "0"
}

misp_login_ok() {
  python3 - "$@" <<'PY'
import os, re, sys, requests
base = os.environ.get("MISP_URL", "http://localhost:8090").rstrip("/")
email = os.environ.get("MISP_ADMIN_EMAIL", "admin@forensic.local")
password = os.environ.get("MISP_ADMIN_PASSWORD", "F0r3ns1c_MISP_2024!")
s = requests.Session()
r = s.get(f"{base}/users/login", timeout=25)
if r.status_code != 200:
    print("FAIL")
    sys.exit(1)
key = re.search(r'name="data\[_Token\]\[key\]"[^>]*value="([^"]+)"', r.text)
fields = re.search(r'name="data\[_Token\]\[fields\]"[^>]*value="([^"]*)"', r.text)
if not key:
    print("FAIL")
    sys.exit(1)
data = {
    "_method": "POST",
    "data[_Token][key]": key.group(1),
    "data[_Token][fields]": fields.group(1) if fields else "",
    "data[_Token][unlocked]": "",
    "data[User][email]": email,
    "data[User][password]": password,
}
r2 = s.post(f"{base}/users/login", data=data, allow_redirects=False, timeout=30)
if r2.status_code not in (302, 303):
    print("FAIL")
    sys.exit(1)
r3 = s.get(f"{base}/events/index", allow_redirects=True, timeout=30)
if r3.status_code == 200 and "login" not in r3.url:
    print(f"OK:{email}")
    sys.exit(0)
print("FAIL")
sys.exit(1)
PY
}
