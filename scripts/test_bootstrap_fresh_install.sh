#!/usr/bin/env bash
# Test d'intégration — bootstrap machine vierge (simule AWS avec IP fictive).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [ -x "$ROOT/scripts/bin/jq.exe" ]; then
  export PATH="$ROOT/scripts/bin:$PATH"
fi

# shellcheck source=/dev/null
. "$ROOT/scripts/lib/host-ip.sh"

# IP fictive HORS plages documentation RFC 5737 : la plateforme traite
# volontairement 192.0.2./198.51.100./203.0.113. comme placeholders à auto-réparer.
TEST_IP="192.168.2.110"
WORKDIR="$(mktemp -d)"

# Sauvegarde des fichiers RÉELS touchés par le test — restauration garantie
# par trap même en cas d'échec (le preflight ne doit JAMAIS altérer le .env
# ou les configs de l'utilisateur).
REAL_ENV_BACKUP="$WORKDIR/.env.real"
CERT_CFG_BACKUP="$WORKDIR/config-cert.json"
IT_CFG_BACKUP="$WORKDIR/config-it.json"
TS_CONF_BACKUP="$WORKDIR/timesketch.conf"
[ -f "$ROOT/.env" ] && cp "$ROOT/.env" "$REAL_ENV_BACKUP"
cp "$ROOT/portal-cert/public/config.json" "$CERT_CFG_BACKUP"
cp "$ROOT/portal-it/public/config.json" "$IT_CFG_BACKUP"
[ -f "$ROOT/config/timesketch/timesketch.conf" ] && cp "$ROOT/config/timesketch/timesketch.conf" "$TS_CONF_BACKUP"
cleanup() {
  if [ -f "$REAL_ENV_BACKUP" ]; then cp "$REAL_ENV_BACKUP" "$ROOT/.env"; else rm -f "$ROOT/.env"; fi
  cp "$CERT_CFG_BACKUP" "$ROOT/portal-cert/public/config.json" 2>/dev/null || true
  cp "$IT_CFG_BACKUP" "$ROOT/portal-it/public/config.json" 2>/dev/null || true
  if [ -f "$TS_CONF_BACKUP" ]; then
    cp "$TS_CONF_BACKUP" "$ROOT/config/timesketch/timesketch.conf" 2>/dev/null || true
  else
    rm -f "$ROOT/config/timesketch/timesketch.conf"
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

cp "$ROOT/.env.example" "$WORKDIR/.env"
export DIR="$ROOT"
export FP_LOG_INSTALL="$WORKDIR/install.log"
export FP_LOG_DIR="$WORKDIR"

# Simule bootstrap .env (logique installer)
python3 - "$WORKDIR/.env" "$TEST_IP" <<'PY'
import re, pathlib, sys
path = pathlib.Path(sys.argv[1])
ip = sys.argv[2]
PLACEHOLDER = "192.0.2.9"
HOST_KEYS = (
    "PUBLIC_HOST", "TIMESKETCH_EXTERNAL_URL", "MISP_PUBLIC_BASE_URL",
    "GRAFANA_ROOT_URL", "GRAFANA_DOMAIN", "GRAFANA_ALLOWED_ORIGINS",
    "GRAFANA_CSRF_ORIGINS", "GRAFANA_CORS_ORIGIN",
)
def host_default(k, ip):
    return {
        "PUBLIC_HOST": ip,
        "TIMESKETCH_EXTERNAL_URL": f"https://{ip}/timesketch",
        "MISP_PUBLIC_BASE_URL": f"https://{ip}/misp",
        "GRAFANA_ROOT_URL": f"https://{ip}/grafana/",
        "GRAFANA_DOMAIN": ip,
        "GRAFANA_ALLOWED_ORIGINS": f"https://{ip},http://{ip},https://localhost,http://localhost",
        "GRAFANA_CSRF_ORIGINS": f"https://{ip},http://{ip},https://localhost,http://localhost",
        "GRAFANA_CORS_ORIGIN": f"https://{ip},http://{ip},https://localhost,http://localhost",
    }[k]
lines = path.read_text().splitlines()
existing = {}
order = []
for line in lines:
    m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
    if m:
        existing[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    order.append(line)
for k in HOST_KEYS:
    v = existing.get(k, "")
    if v == "" or v == PLACEHOLDER or PLACEHOLDER in v:
        existing[k] = host_default(k, ip)
out = []
seen = set()
for line in order:
    m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
    if m and m.group(1) in existing:
        k = m.group(1)
        out.append(f"{k}={existing[k]}")
        seen.add(k)
    else:
        out.append(line)
for k in HOST_KEYS:
    if k not in seen:
        out.append(f"{k}={existing[k]}")
path.write_text("\n".join(out) + "\n")
PY

# Vérifie .env
for key in PUBLIC_HOST GRAFANA_DOMAIN MISP_PUBLIC_BASE_URL; do
  val=$(grep "^${key}=" "$WORKDIR/.env" | cut -d= -f2-)
  case "$val" in
    *192.0.2.9*) echo "FAIL: $key contient encore 192.0.2.9 ($val)" >&2; exit 1 ;;
  esac
  case "$key" in
    MISP_PUBLIC_BASE_URL)
      case "$val" in
        https://"$TEST_IP"/misp|https://"$TEST_IP"/misp/) echo "PASS: $key=$val" ;;
        *) echo "FAIL: $key inattendu ($val)" >&2; exit 1 ;;
      esac
      ;;
    *)
      case "$val" in
        *"$TEST_IP"*) echo "PASS: $key=$val" ;;
        *) echo "FAIL: $key inattendu ($val)" >&2; exit 1 ;;
      esac
      ;;
  esac
done

# Timesketch conf depuis .env simulé (le vrai .env est restauré par le trap EXIT)
cp "$WORKDIR/.env" "$ROOT/.env"
FP_PUBLIC_HOST="$TEST_IP" bash "$ROOT/scripts/generate-timesketch-conf.sh" >/dev/null
if grep -q "192.0.2.9" "$ROOT/config/timesketch/timesketch.conf"; then
  echo "FAIL: timesketch.conf contient 192.0.2.9" >&2
  exit 1
fi
if ! grep -q "https://${TEST_IP}/timesketch" "$ROOT/config/timesketch/timesketch.conf"; then
  echo "FAIL: timesketch.conf sans IP test" >&2
  exit 1
fi
echo "PASS: timesketch.conf → https://${TEST_IP}/timesketch"

# Portails config.json — patch JSON portable : jq si présent, sinon python3
# (jq n'est pas encore installé sur une VM fraîche au moment du preflight).
for cfg in portal-cert/public/config.json portal-it/public/config.json; do
  FP_PUBLIC_HOST="$TEST_IP" bash -c "
    source scripts/lib/host-ip.sh
    ip=\$(fp_resolve_public_host)
    if command -v jq >/dev/null 2>&1; then
      jq --arg url \"https://\${ip}\" '.soc_base_url = \$url' '$cfg' > '${cfg}.tmp' && mv '${cfg}.tmp' '$cfg'
    else
      python3 - '$cfg' \"https://\${ip}\" <<'PY'
import json, sys
p, url = sys.argv[1], sys.argv[2]
d = json.load(open(p, encoding='utf-8'))
d['soc_base_url'] = url
json.dump(d, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
    fi
  "
  if grep -q '192.0.2.9' "$cfg"; then
    echo "FAIL: $cfg contient 192.0.2.9" >&2
    exit 1
  fi
  echo "PASS: $cfg patché"
done

# .env.example ne doit plus contenir de valeurs IP lab pré-remplies
if grep -E '^(PUBLIC_HOST|GRAFANA_DOMAIN|MISP_PUBLIC_BASE_URL)=.*10\.78\.0\.9' "$ROOT/.env.example"; then
  echo "FAIL: .env.example contient encore 192.0.2.9" >&2
  exit 1
fi
echo "PASS: .env.example sans IP lab figée"

# docker-compose : plus de fallback 192.0.2.9
if grep -q '10\.78\.0\.9' "$ROOT/docker-compose.yml"; then
  echo "FAIL: docker-compose.yml contient encore 192.0.2.9" >&2
  exit 1
fi
echo "PASS: docker-compose.yml sans fallback 192.0.2.9"

echo ""
echo "Bootstrap frais OK — IP test $TEST_IP"
# La restauration du vrai .env / configs est assurée par le trap EXIT (cleanup).
