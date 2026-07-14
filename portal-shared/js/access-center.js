'use strict';

function acBase() {
  return PortalConfig.socBaseUrl();
}

function acEsc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function acSocTools() {
  return acToolGroups().flatMap((g) => g.tools);
}

function acToolGroups() {
  return [
    {
      id: 'siem',
      titleKey: 'access.group_siem',
      tools: [
        { name: 'OpenSearch Dashboards', path: '/dashboards/' },
        { name: 'Grafana', path: '/grafana/' },
        { name: 'Timesketch', path: '/timesketch/' },
        { name: 'HELK Kibana', path: '/helk/kibana/' },
        { name: 'Logstash', path: '/logstash/' },
      ],
    },
    {
      id: 'dfir',
      titleKey: 'access.group_dfir',
      tools: [
        { name: 'TheHive', path: '/thehive/' },
        { name: 'Velociraptor', path: '/velociraptor/app/index.html' },
      ],
    },
    {
      id: 'cti',
      titleKey: 'access.group_cti',
      tools: [
        { name: 'OpenCTI', path: '/cti/' },
        { name: 'MISP', path: '/misp/' },
        { name: 'Cortex', path: '/cortex/' },
      ],
    },
    {
      id: 'storage',
      titleKey: 'access.group_storage',
      tools: [
        { name: 'MinIO', path: '/minio/' },
      ],
    },
    {
      id: 'portals',
      titleKey: 'access.group_portals',
      tools: [
        { name: i18n.t('access.portal_cert'), path: '/' },
        { name: i18n.t('health.portal_it'), path: '/it/' },
      ],
    },
  ];
}

const AC_GROUP_HUE = {
  siem: '#38bdf8',
  dfir: '#818cf8',
  cti: '#f472b6',
  storage: '#f59e0b',
  portals: '#34d399',
};

const AC_SVC_META = {
  'OpenSearch Dashboards': { abbr: 'OSD', hue: '#10b981' },
  Grafana: { abbr: 'GF', hue: '#f97316' },
  Timesketch: { abbr: 'TS', hue: '#a78bfa' },
  'HELK Kibana': { abbr: 'HK', hue: '#38bdf8' },
  Logstash: { abbr: 'LS', hue: '#64748b' },
  TheHive: { abbr: 'TH', hue: '#fb7185' },
  Velociraptor: { abbr: 'VR', hue: '#818cf8' },
  OpenCTI: { abbr: 'CTI', hue: '#ec4899' },
  MISP: { abbr: 'MI', hue: '#ef4444' },
  Cortex: { abbr: 'CX', hue: '#f472b6' },
  MinIO: { abbr: 'S3', hue: '#f59e0b' },
};

const AC_TOOL_CRED_SERVICE = {
  'OpenSearch Dashboards': 'OpenSearch Dashboards',
  Grafana: 'Grafana',
  Timesketch: 'Timesketch',
  'HELK Kibana': 'HELK Kibana',
  Logstash: 'Logstash',
  TheHive: 'TheHive',
  Velociraptor: 'Velociraptor',
  OpenCTI: 'OpenCTI',
  MISP: 'MISP',
  Cortex: 'Cortex',
  MinIO: 'MinIO',
};

const AC_SOC_SERVICES = new Set([
  ...Object.values(AC_TOOL_CRED_SERVICE),
  'Portail CERT',
  'Portail IT',
]);

const AC_ENDPOINTS = [
  { method: 'GET', path: '/api/master', descKey: 'msg.zones_master_incidents_cases_kb_assets' },
  { method: 'GET', path: '/api/overview', descKey: 'msg.synthese_plateforme_summary_health_ingest_ti' },
  { method: 'POST', path: '/api/upload', descKey: 'msg.upload_de_preuves_forensic_token_requis' },
  { method: 'GET', path: '/api/audit/events', descKey: 'msg.journal_daudit_activity_log' },
  { method: 'POST', path: '/api/auth/login', descKey: 'msg.authentification_portail_session' },
  { method: 'POST', path: '/api/auth/mfa', desc: 'Configuration / activation MFA TOTP' },
];

const AC_PORTS = [
  { port: 443, svc: 'HTTPS / Reverse proxy (Nginx)' },
  { port: 5601, svc: 'OpenSearch Dashboards' },
  { port: 9200, svc: 'OpenSearch API' },
  { port: 5000, svc: 'Timesketch' },
  { port: 9000, svc: 'TheHive' },
  { port: 9001, svc: 'Cortex / MinIO console' },
  { port: 8080, svc: 'OpenCTI' },
  { port: 9002, svc: 'MinIO API' },
  { port: 9003, svc: 'Service technique SOC' },
];

function acSvcMeta(name) {
  const key = Object.keys(AC_SVC_META).find((k) => String(name || '').toLowerCase().includes(k.toLowerCase()));
  if (key) return AC_SVC_META[key];
  const abbr = String(name || '??').replace(/[^A-Za-z0-9]/g, '').slice(0, 3).toUpperCase() || 'SOC';
  return { abbr, hue: '#64748b' };
}

function acCopy(text, btn) {
  const done = () => {
    if (!btn) return;
    const old = btn.textContent;
    btn.textContent = i18n.t('ui.copied');
    setTimeout(() => { btn.textContent = old; }, 1400);
  };
  const fallback = () => {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      done();
    } catch (_) {
      done();
    }
  };
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(done, fallback);
  } else {
    fallback();
  }
}

function acCredField(label, value, copyable, isPassword) {
  const v = value && value !== '—' ? value : null;
  if (!v) return '';
  return `<div class="fp-ac-cred-field">
    <span class="fp-ac-cred-label">${acEsc(label)}</span>
    <code class="${isPassword ? 'cc-cred-pw' : ''}">${acEsc(v)}</code>
    ${copyable ? `<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-copy-text="${acEsc(v)}">${i18n.t('ui.copy')}</button>` : ''}
  </div>`;
}

function acCredBlock(cred, isAdmin) {
  if (!isAdmin) {
    return `<div class="fp-ac-cred-block fp-muted">${i18n.t('users.admin_only')}</div>`;
  }
  const login = cred?.login;
  const password = cred?.password;
  const hasLogin = login && login !== '—';
  const hasPassword = password && password !== '—';
  if (!hasLogin && !hasPassword) {
    return `<div class="fp-ac-cred-block fp-muted">${i18n.t('access.no_local_auth')}</div>`;
  }
  return `<div class="fp-ac-cred-block">
    ${hasLogin ? acCredField(i18n.t('table_cols.login'), login, true, false) : ''}
    ${hasPassword ? acCredField(i18n.t('table_cols.password'), password, true, true) : ''}
  </div>`;
}

function acToolCard(t, groupId, cred, isAdmin) {
  const base = acBase();
  const url = `${base}${t.path}`;
  const name = t.name;
  const meta = acSvcMeta(name);
  const role = cred?.role || '';
  const credBlock = acCredBlock(cred, isAdmin);

  return `
    <article class="fp-ds-card fp-svc-card fp-ac-tool-card" data-ac-group="${acEsc(groupId)}">
      <span class="fp-svc-card-icon fp-ac-card-badge" style="background:${meta.hue}22;border:1px solid ${meta.hue}55;color:${meta.hue}">${acEsc(meta.abbr)}</span>
      <header class="fp-ac-tool-head">
        <h4 class="fp-ds-card-label">${acEsc(name)}</h4>
        ${role ? `<p class="fp-ac-tool-role fp-muted">${acEsc(role)}</p>` : ''}
      </header>
      <div class="fp-ac-tool-url">
        <a class="fp-ac-url-link" href="${acEsc(url)}" target="_blank" rel="noopener">${acEsc(url)}</a>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-copy="${acEsc(url)}" title="${i18n.t('ui.copy')}">${i18n.t('ui.copy')}</button>
      </div>
      ${credBlock}
      <footer class="fp-ac-tool-actions">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-ac-open="${acEsc(url)}">${i18n.t('ui.open')}</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-copy="${acEsc(url)}">${i18n.t('access.copy_url')}</button>
      </footer>
    </article>`;
}

function acDomainSection(group, credMap, isAdmin) {
  const hue = AC_GROUP_HUE[group.id] || '#64748b';
  const cards = group.tools.map((t) => acToolCard(t, group.id, credMap[t.name], isAdmin)).join('');
  return `
    <section class="fp-ac-domain" data-ac-domain="${acEsc(group.id)}">
      <div class="fp-ac-domain-head" style="--fp-ac-domain-hue:${hue}">
        <h3 class="fp-ac-domain-title">${i18n.t(group.titleKey)}</h3>
        <span class="fp-ac-domain-count">${i18n.t('access.tools_count', { count: group.tools.length })}</span>
      </div>
      <div class="fp-ds-grid fp-ac-domain-grid">${cards}</div>
    </section>`;
}

function acDomainSections(credMap, isAdmin) {
  return acToolGroups().map((g) => acDomainSection(g, credMap, isAdmin)).join('');
}

function acInfraTable(rows, isAdmin) {
  const infra = rows.filter((c) => !AC_SOC_SERVICES.has(c.service));
  if (!infra.length) return '';
  const body = infra.map((c) => `
    <tr>
      <td><strong>${acEsc(c.service)}</strong><div class="fp-muted fp-ac-infra-role">${acEsc(c.role || '—')}</div></td>
      <td><code>${acEsc(c.login)}</code>${isAdmin && c.login && c.login !== '—' ? `<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-copy-text="${acEsc(c.login)}">${i18n.t('ui.copy')}</button>` : ''}</td>
      <td>${isAdmin
    ? `<code class="cc-cred-pw">${acEsc(c.password)}</code><button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-copy-text="${acEsc(c.password)}">${i18n.t('ui.copy')}</button>`
    : `<span class="fp-muted">${i18n.t('users.admin_only')}</span>`}</td>
    </tr>`).join('');
  return `
    <details class="fp-ac-infra cc-pro-panel fp-section-spaced">
      <summary class="fp-section-sub">${i18n.t('access.infrastructure_services')}</summary>
      <p class="fp-muted">${i18n.t('access.infrastructure_hint')}</p>
      <div class="fp-table-wrap">
        <table class="fp-table fp-ac-infra-table">
          <thead><tr><th>${i18n.t('table_cols.service')}</th><th>${i18n.t('table_cols.login')}</th><th>${i18n.t('table_cols.password')}</th></tr></thead>
          <tbody>${body}</tbody>
        </table>
      </div>
    </details>`;
}

function acEndpointDesc(e) {
  return e.descKey ? i18n.t(e.descKey) : (e.desc || '');
}

function acEndpointRows() {
  return AC_ENDPOINTS.map((e) => `<tr>
      <td><span class="cc-method cc-method-${e.method.toLowerCase()}">${e.method}</span></td>
      <td><code class="cc-url-cell">${acEsc(e.path)}</code></td>
      <td class="fp-muted">${acEsc(acEndpointDesc(e))}</td>
      <td class="cc-soc-actions"><button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-copy="${acBase()}${e.path}">${i18n.t('ui.copy')}</button></td>
    </tr>`).join('');
}

function acPortRows() {
  return AC_PORTS.map((p) => `<tr>
      <td><code>${p.port}</code></td>
      <td>${acEsc(p.svc)}</td>
    </tr>`).join('');
}

async function acFetchCredentials() {
  const r = await fetch('/api/credentials?reveal=1&refresh=1', { credentials: 'include', cache: 'no-store' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const data = await r.json();
  const byService = Object.create(null);
  for (const c of data.credentials || []) {
    byService[c.service] = c;
  }
  const byTool = Object.create(null);
  for (const [toolName, serviceName] of Object.entries(AC_TOOL_CRED_SERVICE)) {
    if (byService[serviceName]) byTool[toolName] = byService[serviceName];
  }
  byTool[i18n.t('access.portal_cert')] = byService['Portail CERT'];
  byTool[i18n.t('health.portal_it')] = byService['Portail IT'];
  return { rows: data.credentials || [], byTool, sync: data.sync || null };
}

function acToolbar(isAdmin, syncMeta) {
  const syncChip = isAdmin && syncMeta?.ok
    ? `<span class="fp-ac-sync-chip">${i18n.t('access.credentials_sync_ok', { count: syncMeta.keys || 0 })}</span>`
    : '';
  return `
    <div class="fp-ac-toolbar cc-pro-panel">
      <div class="fp-ac-toolbar-nav">
        ${syncChip}
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-goto="users">${i18n.t('access.portal_accounts')}</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-goto="svcs">${i18n.t('access.service_health')}</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-goto="hist">${i18n.t('access.activity_log')}</button>
      </div>
      <div class="fp-ac-toolbar-actions">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" id="ac-open-all">${i18n.t('access.open_all_soc')}</button>
        <button type="button" class="fp-btn fp-btn-sm" id="ac-copy-urls">${i18n.t('access.copy_all_urls')}</button>
        ${isAdmin ? `<button type="button" class="fp-btn fp-btn-sm" id="ac-copy-creds">${i18n.t('access.copy_all_credentials')}</button>` : ''}
        ${isAdmin ? `<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" id="ac-refresh-creds">${i18n.t('access.refresh_credentials')}</button>` : ''}
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" id="ac-copy-endpoints">${i18n.t('access.copy_endpoints')}</button>
      </div>
    </div>`;
}

async function loadAccessCenter() {
  const root = document.getElementById('access-center-root');
  if (!root) return;
  try {
    if (window.i18n?.whenReady) await new Promise((resolve) => window.i18n.whenReady(resolve));
    await new Promise((resolve) => PortalConfig.whenReady(resolve));
    const base = acBase();
    const isAdmin = window.PortalSession?.isAdmin;

    let credPack = { rows: [], byTool: {}, sync: null };
    if (isAdmin) {
      try {
        credPack = await acFetchCredentials();
      } catch (e) {
        root.innerHTML = `<p class="fp-alert fp-alert-err">${acEsc(e.message)}</p>`;
        return;
      }
    }

    root.innerHTML = `
      ${acToolbar(isAdmin, credPack.sync)}
      ${isAdmin ? `<p class="fp-muted fp-ac-admin-hint">${i18n.t('access.credentials_admin_hint')}</p>` : ''}
      <div class="fp-ac-domains">${acDomainSections(credPack.byTool, isAdmin)}</div>
      ${isAdmin ? acInfraTable(credPack.rows, isAdmin) : ''}
      <details class="cc-ac-advanced cc-pro-panel fp-section-spaced">
        <summary class="fp-section-sub">${i18n.t('access.advanced_technical')}</summary>
        <section class="fp-section-spaced">
          <h3 class="fp-section-sub">${i18n.t('access.endpoints_api')}</h3>
          <div class="fp-table-wrap">
            <table class="fp-table">
              <thead><tr><th>${i18n.t('access.method_col')}</th><th>${i18n.t('access.endpoint_col')}</th><th>${i18n.t('access.description_col')}</th><th></th></tr></thead>
              <tbody>${acEndpointRows()}</tbody>
            </table>
          </div>
        </section>
        <section class="fp-section-spaced">
          <h3 class="fp-section-sub">${i18n.t('access.ports_services')}</h3>
          <div class="fp-table-wrap">
            <table class="fp-table">
              <thead><tr><th>${i18n.t('access.port_col')}</th><th>${i18n.t('table_cols.service')}</th></tr></thead>
              <tbody>${acPortRows()}</tbody>
            </table>
          </div>
        </section>
      </details>`;

    document.getElementById('ac-copy-creds')?.addEventListener('click', (e) => {
      const lines = credPack.rows.map((c) => `${c.service}\t${c.login}\t${c.password}`).join('\n');
      acCopy(lines, e.currentTarget);
    });

    document.getElementById('ac-refresh-creds')?.addEventListener('click', () => {
      loadAccessCenter();
    });

    document.getElementById('ac-open-all')?.addEventListener('click', () => {
      acSocTools().filter((t) => t.path !== '/' && t.path !== '/it/').forEach((t) => {
        window.open(`${base}${t.path}`, '_blank', 'noopener');
      });
    });

    document.getElementById('ac-copy-urls')?.addEventListener('click', (e) => {
      const urls = acSocTools().map((t) => `${t.name}: ${base}${t.path}`).join('\n');
      acCopy(urls, e.currentTarget);
    });

    document.getElementById('ac-copy-endpoints')?.addEventListener('click', (e) => {
      const eps = AC_ENDPOINTS.map((x) => `${x.method} ${base}${x.path}`).join('\n');
      acCopy(eps, e.currentTarget);
    });

    root.querySelectorAll('[data-ac-goto]').forEach((b) => {
      b.addEventListener('click', () => {
        const t = b.dataset.acGoto;
        if (t && typeof window.tab === 'function') window.tab(t);
      });
    });

    bindCopy(root);
  } catch (e) {
    root.innerHTML = `<p class="fp-alert fp-alert-err">${acEsc(e.message)}</p>`;
  }
}

function bindCopy(scope) {
  scope.querySelectorAll('[data-ac-open]').forEach((b) => {
    b.addEventListener('click', () => window.open(b.dataset.acOpen, '_blank', 'noopener'));
  });
  scope.querySelectorAll('[data-ac-copy]').forEach((b) => {
    b.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      acCopy(b.dataset.acCopy, b);
    });
  });
  scope.querySelectorAll('[data-ac-copy-text]').forEach((b) => {
    b.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      acCopy(b.dataset.acCopyText, b);
    });
  });
}

window.AccessCenter = { loadAccessCenter, acSocTools, AC_ENDPOINTS, AC_PORTS };
