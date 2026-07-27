#!/bin/bash
# Génère config/thehive/application.conf et config/cortex/application.conf
# depuis .env (P-04/P-14/P-15) — plus aucun secret ni IP codés en dur.
# Appelé par forensic.sh (pre_start) comme generate-timesketch-conf.sh.
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

# Hôte public dynamique (PUBLIC_HOST > AWS > routable > localhost)
if [ -f "$DIR/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$DIR/scripts/lib/host-ip.sh"
  HOST_IP=$(fp_url_identity 2>/dev/null | head -n1 || true)
fi
HOST_IP="${HOST_IP:-localhost}"

# Secrets requis — valeurs de repli explicites UNIQUEMENT pour le labo local,
# signalées par un avertissement (jamais silencieux).
_warn() { echo "[generate-thehive-cortex-conf] ATTENTION: $1 (valeur labo par défaut — définir dans .env)" >&2; }

THEHIVE_SECRET="${THEHIVE_SECRET:-}"
[ -z "$THEHIVE_SECRET" ] && { THEHIVE_SECRET="thehive-dev-secret-changeme"; _warn "THEHIVE_SECRET absent"; }
CORTEX_SECRET="${CORTEX_SECRET:-}"
[ -z "$CORTEX_SECRET" ] && { CORTEX_SECRET="cortex-dev-secret-changeme"; _warn "CORTEX_SECRET absent"; }
MINIO_AK="${MINIO_ROOT_USER:-forensicadmin}"
MINIO_SK="${MINIO_ROOT_PASSWORD:-}"
[ -z "$MINIO_SK" ] && { MINIO_SK="minio-dev-secret-changeme"; _warn "MINIO_ROOT_PASSWORD absent"; }
CORTEX_API_KEY="${CORTEX_API_KEY:-}"
[ -z "$CORTEX_API_KEY" ] && { CORTEX_API_KEY="cortex-api-key-dev-changeme"; _warn "CORTEX_API_KEY absent"; }
MISP_API_KEY="${MISP_ADMIN_API_KEY:-}"
[ -z "$MISP_API_KEY" ] && { MISP_API_KEY="misp-api-key-dev-changeme"; _warn "MISP_ADMIN_API_KEY absent"; }

mkdir -p "$DIR/config/thehive" "$DIR/config/cortex"

cat > "$DIR/config/thehive/application.conf" << CONF
# Généré par scripts/generate-thehive-cortex-conf.sh — ne pas éditer à la main.
play.http.secret.key = "${THEHIVE_SECRET}"

application.baseUrl = "https://${HOST_IP}/thehive"
play.http.context = "/thehive"

# JanusGraph : Cassandra (données) + OpenSearch (index Elasticsearch-compatible)
db.janusgraph.storage {
  backend = cql
  hostname = ["cassandra"]
  cql {
    cluster-name = forensic-thp
    keyspace = thehive
  }
}

db.janusgraph.index.search {
  backend = elasticsearch
  hostname = ["opensearch-node1"]
  index-name = thehive
}

scalligraph.modules += org.thp.thehive.connector.cortex.CortexModule
scalligraph.modules += org.thp.thehive.connector.misp.MispModule

storage {
  provider = s3
  s3 {
    bucket             = "artefacts"
    endpoint           = "http://minio:9000"
    region             = "us-east-1"
    chunkSize          = 1 MB
    readTimeout        = 1 minute
    writeTimeout       = 1 minute
    usePathAccessStyle = true
    accessKey          = "${MINIO_AK}"
    secretKey          = "${MINIO_SK}"
  }
}

cortex {
  servers = [
    {
      name     = "Cortex-Forensic"
      url      = "http://cortex:9001"
      auth.type = bearer
      auth.key  = "${CORTEX_API_KEY}"
    }
  ]
  refreshDelay         = 5 minutes
  statusCheckInterval  = 1 minute
}

misp {
  servers = [
    {
      name      = "MISP-Forensic"
      url       = "http://misp"
      auth.type = key
      auth.key  = "${MISP_API_KEY}"
      purpose   = ImportAndExport
      maxAge    = 7 days
    }
  ]
  interval = 5 minutes
}

notification.webhook.endpoints = [
  {
    name    = "forensic-portal"
    url     = "http://cert-portal:3000/api/webhook/thehive"
    version = 0
    auth { type = noauth }
    includedTheHiveOrganisations = ["*"]
  }
]

play.filters.disabled += play.filters.csrf.CSRFFilter
CONF

cat > "$DIR/config/cortex/application.conf" << CONF
# Généré par scripts/generate-thehive-cortex-conf.sh — ne pas éditer à la main.
play.http.secret.key = "${CORTEX_SECRET}"

application.baseUrl = "https://${HOST_IP}/cortex"

# Active l’auth HTTP Basic pour les healthchecks / scripts internes (réseau Docker isolé).
auth.method.basic = true

search {
  index = cortex
  uri   = "http://opensearch-node1:9200"
}

analyzer {
  urls = ["https://download.thehive-project.org/analyzers.json"]
  fork-join-executor {
    parallelism-min    = 2
    parallelism-factor = 2.0
    parallelism-max    = 4
  }
}

responder {
  urls = ["https://download.thehive-project.org/responders.json"]
}

job {
  runner    = [docker, process]
  directory = "/tmp/cortex-jobs"
}

cache.job = 10 minutes

# FP Master — API automation (scripts cortex_master_*)
play.filters.disabled = [play.filters.csrf.CSRFFilter, play.filters.allowedhosts.AllowedHostsFilter]
CONF

echo "[generate-thehive-cortex-conf] Configs TheHive/Cortex générées pour ${HOST_IP}"
