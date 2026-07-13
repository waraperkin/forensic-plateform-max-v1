'use strict';

/**
 * Registre central des services Forensic Minimal.
 * Source unique pour URLs internes, chemins publics Nginx, health checks et pivots.
 */

function normalizeHost() {
  const raw = process.env.PUBLIC_HOST
    || process.env.GRAFANA_DOMAIN
    || process.env.PUBLIC_HOSTNAME
    || 'localhost';
  return String(raw).replace(/^https?:\/\//, '').replace(/\/.*$/, '');
}

function publicUrl(path) {
  const p = path.startsWith('/') ? path : `/${path}`;
  const host = normalizeHost();
  const rawPort = process.env.FP_HTTPS_PORT || process.env.PUBLIC_HTTPS_PORT || '443';
  const port = String(rawPort).replace(/\r|\n/g, '');
  const portSuffix = port && port !== '443' ? `:${port}` : '';
  return `https://${host}${portSuffix}${p}`;
}

function defineService(def) {
  return {
    dependencies: [],
    degradedStatuses: [],
    pivotTemplates: {},
    ...def,
    publicUrl: def.publicPath ? publicUrl(def.publicPath) : null,
  };
}

const SERVICE_DEFINITIONS = [
  defineService({
    id: 'cert',
    name: 'Portail CERT',
    category: 'portal',
    internalUrl: 'http://cert-portal:3000',
    publicPath: '/',
    healthInternal: 'http://127.0.0.1:3000/api/health',
    healthPublic: '/api/health',
    okStatuses: [200],
    dependencies: ['nginx', 'opensearch', 'redis'],
    pivotTemplates: { case_id: '/?tab=cases&q={value}' },
  }),
  defineService({
    id: 'it',
    name: 'Portail IT',
    category: 'portal',
    internalUrl: 'http://it-portal:3001',
    publicPath: '/it/',
    healthInternal: 'http://it-portal:3001/api/health',
    healthPublic: '/it/api/health',
    okStatuses: [200],
    dependencies: ['nginx', 'cert', 'redis', 'minio'],
    pivotTemplates: { case_id: '/it/?token={value}' },
  }),
  defineService({
    id: 'nginx',
    name: 'Nginx',
    category: 'infrastructure',
    internalUrl: 'http://nginx/nginx-health',
    publicPath: '/',
    healthInternal: 'http://nginx/nginx-health',
    healthPublic: '/nginx-health',
    okStatuses: [200],
    dependencies: [],
  }),
  defineService({
    id: 'opensearch',
    name: 'OpenSearch',
    category: 'siem',
    internalUrl: process.env.OPENSEARCH_URL || 'http://opensearch-node1:9200',
    publicPath: '/dashboards/',
    healthInternal: `${process.env.OPENSEARCH_URL || 'http://opensearch-node1:9200'}/_cluster/health`,
    healthPublic: '/api/opensearch/health',
    okStatuses: [200],
    degradedStatuses: [],
    dependencies: [],
    pivotTemplates: {
      host: '/dashboards/app/discover#/?q=host.name:"{value}"',
      ip: '/dashboards/app/discover#/?q=source.ip:"{value}"',
      hash: '/dashboards/app/discover#/?q=file.hash.sha256:"{value}"',
      domain: '/dashboards/app/discover#/?q=dns.question.name:"{value}"',
      case_id: '/dashboards/app/discover#/?q=case_id:"{value}"',
    },
  }),
  defineService({
    id: 'dashboards',
    name: 'OpenSearch Dashboards',
    category: 'siem',
    internalUrl: 'http://opensearch-dashboards:5601',
    publicPath: '/dashboards/',
    healthInternal: 'http://opensearch-dashboards:5601/dashboards/api/status',
    healthPublic: '/dashboards/api/status',
    okStatuses: [200],
    dependencies: ['opensearch'],
    pivotTemplates: {
      host: '/dashboards/app/discover#/?q=host.name:"{value}"',
      case_id: '/dashboards/app/discover#/?q=case_id:"{value}"',
    },
  }),
  defineService({
    id: 'grafana',
    name: 'Grafana',
    category: 'observability',
    internalUrl: 'http://grafana:3000',
    publicPath: '/grafana/',
    healthInternal: 'http://grafana:3000/api/health',
    healthPublic: '/grafana/api/health',
    okStatuses: [200],
    dependencies: ['opensearch'],
    pivotTemplates: {
      host: '/grafana/explore?left={"queries":[{"expr":"host.name=\\"{value}\\""}]}',
      case_id: '/grafana/d/fp-platform-health-gf/fp-platform-health?var-case_id={value}',
    },
  }),
  defineService({
    id: 'timesketch',
    name: 'Timesketch',
    category: 'forensic',
    internalUrl: process.env.TIMESKETCH_URL || 'http://timesketch-web:5000',
    publicPath: '/timesketch/',
    healthInternal: `${process.env.TIMESKETCH_URL || 'http://timesketch-web:5000'}/login`,
    healthPublic: '/timesketch/login',
    okStatuses: [200, 302],
    degradedStatuses: [401, 403],
    dependencies: ['opensearch'],
    pivotTemplates: {
      case_id: '/timesketch/sketch/?q={value}',
      host: '/timesketch/sketch/?q={value}',
    },
  }),
  defineService({
    id: 'opencti',
    name: 'OpenCTI',
    category: 'cti',
    internalUrl: process.env.OPENCTI_URL || 'http://opencti:8080',
    publicPath: '/cti/',
    healthInternal: `${process.env.OPENCTI_URL || 'http://opencti:8080'}/cti/health`,
    healthPublic: '/cti/health',
    okStatuses: [200, 401, 302],
    dependencies: ['opensearch'],
    pivotTemplates: {
      hash: '/cti/dashboard/search/knowledge?q={value}',
      domain: '/cti/dashboard/search/knowledge?q={value}',
      ip: '/cti/dashboard/search/knowledge?q={value}',
    },
  }),
  defineService({
    id: 'misp',
    name: 'MISP',
    category: 'cti',
    internalUrl: process.env.MISP_URL || 'http://misp:80',
    publicPath: '/misp/',
    healthInternal: `${process.env.MISP_URL || 'http://misp:80'}/users/login`,
    healthPublic: '/misp/users/login',
    okStatuses: [200, 302, 403],
    degradedStatuses: [401],
    dependencies: [],
    pivotTemplates: {
      hash: '/misp/events/index/search:{value}',
      domain: '/misp/events/index/search:{value}',
      ip: '/misp/events/index/search:{value}',
    },
  }),
  defineService({
    id: 'thehive',
    name: 'TheHive',
    category: 'ir',
    internalUrl: process.env.THEHIVE_URL || 'http://thehive:9000/thehive',
    publicPath: '/thehive/',
    healthInternal: `${process.env.THEHIVE_URL || 'http://thehive:9000/thehive'}/api/status`,
    healthPublic: '/thehive/api/status',
    okStatuses: [200],
    dependencies: ['opensearch'],
    pivotTemplates: {
      case_id: '/thehive/index.html#/cases?search={value}',
      host: '/thehive/index.html#/cases?search={value}',
    },
  }),
  defineService({
    id: 'cortex',
    name: 'Cortex',
    category: 'ir',
    internalUrl: 'http://cortex:9001',
    publicPath: '/cortex/',
    healthInternal: 'http://cortex:9001/api/status',
    healthPublic: '/cortex/api/status',
    okStatuses: [200],
    dependencies: ['thehive'],
    pivotTemplates: {
      hash: '/cortex/index.html#/jobs?search={value}',
    },
  }),
  defineService({
    id: 'minio',
    name: 'MinIO',
    category: 'storage',
    internalUrl: 'http://minio:9000',
    publicPath: '/minio/',
    healthInternal: 'http://minio:9000/minio/health/live',
    healthPublic: '/minio/',
    okStatuses: [200],
    dependencies: [],
    pivotTemplates: { case_id: '/minio/browser/evidences?prefix={value}' },
  }),
  defineService({
    id: 'helk',
    name: 'HELK',
    category: 'hunting',
    internalUrl: process.env.HELK_BRIDGE_URL || 'http://helk-bridge:8095',
    publicPath: '/helk/kibana/',
    healthInternal: `${(process.env.HELK_BRIDGE_URL || 'http://helk-bridge:8095').replace(/\/$/, '')}/health`,
    healthPublic: '/api/helk/health',
    okStatuses: [200],
    dependencies: ['opensearch'],
    pivotTemplates: {
      host: '/helk/kibana/app/discover#/?_a=(query:(language:kuery,query:\'host.name:"{value}"\'))',
      ioc: '/helk/kibana/app/discover#/?_a=(query:(language:kuery,query:\'{value}\'))',
      case_id: '/helk/kibana/app/discover#/?_a=(query:(language:kuery,query:\'case_id:"{value}"\'))',
    },
  }),
  defineService({
    id: 'velociraptor',
    name: 'Velociraptor',
    category: 'dfir',
    internalUrl: process.env.VR_BRIDGE_URL || 'http://velociraptor-bridge:8097',
    publicPath: '/velociraptor/',
    healthInternal: `${(process.env.VR_BRIDGE_URL || 'http://velociraptor-bridge:8097').replace(/\/$/, '')}/health`,
    healthPublic: '/velociraptor/api/health',
    okStatuses: [200],
    dependencies: ['opensearch'],
    pivotTemplates: {
      host: '/velociraptor/#/search?q={value}',
      case_id: '/dashboards/app/discover#/?q=_index:velociraptor-* AND case_id:"{value}"',
      hash: '/dashboards/app/discover#/?q=file.hash.sha256:"{value}"',
    },
  }),
  defineService({
    id: 'logstash',
    name: 'Logstash',
    category: 'pipeline',
    internalUrl: 'http://logstash:9700',
    publicPath: null,
    healthInternal: 'http://logstash:9700',
    healthPublic: null,
    okStatuses: [200],
    dependencies: ['opensearch'],
  }),
  defineService({
    id: 'ingest-worker',
    name: 'Ingest Worker',
    category: 'pipeline',
    internalUrl: 'http://ingest-worker:8090/health',
    publicPath: null,
    healthInternal: 'http://ingest-worker:8090/health',
    healthPublic: null,
    okStatuses: [200],
    dependencies: ['redis', 'minio', 'opensearch'],
  }),
  defineService({
    id: 'redis',
    name: 'Redis',
    category: 'infrastructure',
    internalUrl: process.env.REDIS_URL || 'redis://redis:6379',
    publicPath: null,
    healthInternal: null,
    healthPublic: null,
    okStatuses: [200],
    dependencies: [],
    checkVia: 'redis',
  }),
];

const BY_ID = Object.fromEntries(SERVICE_DEFINITIONS.map((s) => [s.id, s]));

function getServiceCatalog() {
  return SERVICE_DEFINITIONS.map((s) => ({
    id: s.id,
    name: s.name,
    category: s.category,
    publicPath: s.publicPath,
    publicUrl: s.publicUrl,
    healthPublic: s.healthPublic,
    dependencies: s.dependencies,
    pivotKeys: Object.keys(s.pivotTemplates || {}),
  }));
}

function getServiceById(id) {
  return BY_ID[id] || null;
}

function buildPivotLinks(serviceId, pivotType, value) {
  const svc = getServiceById(serviceId);
  if (!svc?.pivotTemplates?.[pivotType] || value == null || value === '') return [];
  const tpl = svc.pivotTemplates[pivotType];
  const path = tpl.replace(/\{value\}/g, encodeURIComponent(String(value)));
  return [{
    service: serviceId,
    name: svc.name,
    type: pivotType,
    path,
    url: publicUrl(path.startsWith('/') ? path : `/${path}`),
  }];
}

function buildAllPivotLinks(pivotType, value) {
  const links = [];
  SERVICE_DEFINITIONS.forEach((svc) => {
    const built = buildPivotLinks(svc.id, pivotType, value);
    links.push(...built);
  });
  return links;
}

function getHealthCheckIds() {
  return [
    'opensearch',
    'dashboards',
    'helk',
    'velociraptor',
    'timesketch',
    'grafana',
    'opencti',
    'misp',
    'thehive',
    'cortex',
    'minio',
    'logstash',
    'ingest-worker',
    'nginx',
    'cert',
    'it',
  ];
}

module.exports = {
  SERVICE_DEFINITIONS,
  getServiceCatalog,
  getServiceById,
  buildPivotLinks,
  buildAllPivotLinks,
  getHealthCheckIds,
  publicUrl,
  normalizeHost,
};
