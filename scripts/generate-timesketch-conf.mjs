#!/usr/bin/env node
/** Regenerate config/timesketch/timesketch.conf from .env (CRLF-safe, Windows-friendly). */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(root, '.env');
const outPath = path.join(root, 'config', 'timesketch', 'timesketch.conf');

const env = Object.create(null);
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i < 1) continue;
    env[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
}

const localPortsPath = path.join(root, 'config', 'local-ports.env');
if (fs.existsSync(localPortsPath)) {
  for (const line of fs.readFileSync(localPortsPath, 'utf8').split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i < 1) continue;
    env[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
}

const host = (env.PUBLIC_HOST || 'localhost').trim();
const httpsPort = (env.FP_HTTPS_PORT || '443').trim();
const hostWithPort = httpsPort === '443' ? host : `${host}:${httpsPort}`;
let external = (env.TIMESKETCH_EXTERNAL_URL || env.BASE_URL || '').trim();
if (external && !external.endsWith('/timesketch')) {
  external = external.replace(/\/$/, '') + '/timesketch';
}
if (!external || /10\.78\.0\.9/.test(external)) {
  external = `https://${hostWithPort}/timesketch`;
}
const secret = (env.TIMESKETCH_SECRET_KEY || '').trim() || 'ts-secret-forensic-2024-changeme';
const pgUser = env.POSTGRES_USER || 'forensic';
const pgPass = env.POSTGRES_PASSWORD || 'F0r3ns1c_PG_2024!';
const redis = env.REDIS_PASSWORD || 'F0r3ns1c_Redis_2024!';

const conf = `# Timesketch configuration — généré automatiquement par forensic.sh / generate-timesketch-conf.sh
SECRET_KEY = "${secret}"
SQLALCHEMY_DATABASE_URI = "postgresql://${pgUser}:${pgPass}@postgres/timesketch"
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
CELERY_BROKER_URL = "redis://:${redis}@redis:6379"
CELERY_RESULT_BACKEND = "redis://:${redis}@redis:6379"
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
REVERSE_PROXY_COUNT = 1
EXTERNAL_HOST_URL = "${external}"
`;

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, conf);
console.log('[ts-conf] OK — timesketch.conf généré');
