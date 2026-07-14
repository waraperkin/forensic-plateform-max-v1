#!/bin/bash
# Génère timesketch.conf avec les vraies valeurs depuis .env
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -f "$DIR/.env" ]; then
  while IFS= read -r _line || [ -n "$_line" ]; do
    case "$_line" in "#"*|"") continue ;; esac
    if [[ "${_line// /}" == "" ]]; then continue; fi
    if [[ "$_line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      _k="${BASH_REMATCH[1]}"; _v="${BASH_REMATCH[2]}"
      if [[ "${_v:0:1}" == '"' && "${_v: -1}" == '"' ]]; then _v="${_v:1:${#_v}-2}"; fi
      if [[ "${_v:0:1}" == "'" && "${_v: -1}" == "'" ]]; then _v="${_v:1:${#_v}-2}"; fi
      _v="${_v//$'\r'/}"
      export "${_k}=${_v}" 2>/dev/null || true
    fi
  done < "$DIR/.env"
fi

mkdir -p "$DIR/config/timesketch"

# IP publique : .env > détection AWS/locale > localhost
HOST_IP=""
if [ -n "${TIMESKETCH_EXTERNAL_URL:-}" ]; then
  _ts_host="${TIMESKETCH_EXTERNAL_URL%/timesketch}"
  _ts_host="${_ts_host#https://}"
  _ts_host="${_ts_host#http://}"
  if [ -n "$_ts_host" ] && [ "$_ts_host" != "192.0.2.9" ] \
    && ! echo "$_ts_host" | grep -qE '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)'; then
    HOST_IP="$_ts_host"
  fi
fi
if [ -z "$HOST_IP" ] && [ -f "$DIR/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$DIR/scripts/lib/host-ip.sh"
  HOST_IP=$(fp_resolve_public_host 2>/dev/null || true)
fi
HOST_IP="${HOST_IP:-localhost}"
EXTERNAL_URL="${TIMESKETCH_EXTERNAL_URL:-}"
if [ -z "$EXTERNAL_URL" ] || echo "$EXTERNAL_URL" | grep -qE '10\.78\.0\.9|^(https?://)?(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)'; then
  EXTERNAL_URL="https://${HOST_IP}/timesketch"
fi

TS_SECRET="${TIMESKETCH_SECRET_KEY:-ts-secret-forensic-2024-changeme}"
if [ -z "${TS_SECRET// }" ]; then
  TS_SECRET="ts-secret-forensic-2024-changeme"
fi

cat > "$DIR/config/timesketch/timesketch.conf" << CONF
# Timesketch configuration — généré automatiquement par forensic.sh / generate-timesketch-conf.sh
SECRET_KEY = "${TS_SECRET}"
SQLALCHEMY_DATABASE_URI = "postgresql://${POSTGRES_USER:-forensic}:${POSTGRES_PASSWORD:-F0r3ns1c_PG_2024!}@postgres/timesketch"
SQLALCHEMY_TRACK_MODIFICATIONS = False
WTF_CSRF_ENABLED = False
OPENSEARCH_HOST = "opensearch-node1"
OPENSEARCH_PORT = 9200
OPENSEARCH_USER = None
OPENSEARCH_PASSWORD = None
OPENSEARCH_MEM_USE_SSL = False
OPENSEARCH_SSL = False
OPENSEARCH_VERIFY_CERTS = False
OPENSEARCH_FLUSH_INTERVAL = 1
OPENSEARCH_TIMEOUT = 300
CELERY_BROKER_URL = "redis://:${REDIS_PASSWORD:-F0r3ns1c_Redis_2024!}@redis:6379"
CELERY_RESULT_BACKEND = "redis://:${REDIS_PASSWORD:-F0r3ns1c_Redis_2024!}@redis:6379"
UPLOAD_ENABLED = True
UPLOAD_FOLDER = "/usr/share/timesketch/uploads"
MAX_CONTENT_LENGTH = 10737418240
PLASO_FORMATTERS = "/etc/timesketch/plaso_formatters.yaml"
TIMESKETCH_AUTHENTICATION_PROVIDERS = None
GOOGLE_OIDC_ENABLED = False
SIMILARITY_DATA_TYPES = []
GRAPH_VIEWS_PATH = "/etc/timesketch/graphs"
SIGMA_RULES_PATH = "/opt/timesketch/sigma_rules"
SIGMA_CONFIG = "/etc/timesketch/sigma_config.yaml"
TI_DATA_PATH = "/opt/timesketch/ti"
ENABLE_GRAPHS = True
SIGMA_RULES_FOLDERS = ["/opt/timesketch/sigma_rules", "/etc/timesketch/sigma/"]
SIGMA_TAG_DELIMITER = "-"
INTELLIGENCE_TAG_METADATA = "/etc/timesketch/intelligence_tag_metadata.yaml"
CONTEXT_LINKS_CONFIG_PATH = "/etc/timesketch/context_links.yaml"
LLM_PROVIDER = ""
DATA_FINDER_PATH = "/etc/timesketch/data_finder.yaml"
ENABLE_EXPERIMENTAL_UI = False
# Reverse proxy (Nginx) — voir https://timesketch.org/guides/admin/install/
REVERSE_PROXY_COUNT = 1
# URL publique du conteneur web Timesketch (port 5000 par défaut)
EXTERNAL_HOST_URL = "${EXTERNAL_URL}"
CONF
echo "[ts-conf] OK — timesketch.conf généré"
