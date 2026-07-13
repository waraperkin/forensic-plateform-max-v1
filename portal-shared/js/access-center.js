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
      titleKey: 'access.group_dfir',
      tools: [
        { name: 'TheHive', path: '/thehive/' },
        { name: 'Velociraptor', path: '/velociraptor/app/index.html' },
      ],
    },
    {
      titleKey: 'access.group_cti',
      tools: [
        { name: 'OpenCTI', path: '/cti/' },
        { name: 'MISP', path: '/misp/' },
        { name: 'Cortex', path: '/cortex/' },
      ],
    },
    {
      titleKey: 'access.group_storage',
      tools: [
        { name: 'MinIO', path: '/minio/' },
      ],
    },
    {
      titleKey: 'access.group_portals',
      tools: [
        { name: i18n.t('access.portal_cert'), path: '/' },
        { name: i18n.t('health.portal_it'), path: '/it/' },
      ],
    },
  ];
}

function acUrlRow(t) {
  const base = acBase();
  const url = `${base}${t.path}`;
  return `<tr>
      <td><strong>${acEsc(t.name)}</strong></td>
      <td><a class="cc-url-cell" href="${url}" target="_blank" rel="noopener">${acEsc(url)}</a></td>
      <td class="cc-soc-actions">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-ac-open="${url}">${i18n.t('ui.open')}</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-copy="${url}">${i18n.t('ui.copy')}</button>
      </td>
    </tr>`;
}

function acToolCard(t, groupKey) {
  const base = acBase();
  const url = `${base}${t.path}`;
  const name = t.name;
  const iconKey = (groupKey || '').includes('cti') ? 'ti'
    : (groupKey || '').includes('dfir') ? 'incident'
      : (groupKey || '').includes('storage') ? 'inventory'
        : (groupKey || '').includes('portals') ? 'dash'
          : 'situation';
  const abbr = String(name || '??').replace(/[^A-Za-z0-9]/g, '').slice(0, 3).toUpperCase() || 'SOC';
  return `
    <button type="button" class="fp-ds-card fp-ds-card-interactive fp-ac-card" data-ac-open="${acEsc(url)}" data-ac-icon="${acEsc(iconKey)}">
      <span class="fp-svc-card-icon fp-ac-card-badge" aria-hidden="true">${acEsc(abbr)}</span>
      <div class="fp-ds-card-label">${acEsc(name)}</div>
      <div class="fp-ds-card-value">${i18n.t('ui.open')}</div>
      <div class="fp-ds-card-meta"><code>${acEsc(url)}</code></div>
      <div class="fp-ac-card-actions">
        <span class="fp-btn fp-btn-sm fp-btn-primary fp-ac-card-open">${i18n.t('ui.open')}</span>
        <span class="fp-btn fp-btn-sm fp-btn-ghost fp-ac-card-copy" data-ac-copy="${acEsc(url)}">${i18n.t('ui.copy')}</span>
      </div>
    </button>`;
}

function acGroupedUrlSections() {
  return acToolGroups().map((group) => `
    <section class="cc-ac-domain-group cc-pro-panel fp-section-spaced">
      <h3 class="fp-section-sub">${i18n.t(group.titleKey)}</h3>
      <div class="fp-ds-grid fp-ds-grid-3 fp-ac-grid">
        ${group.tools.map((t) => acToolCard(t, group.titleKey)).join('')}
      </div>
    </section>`).join('');
}

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

function acUrlRows() {
  return acSocTools().map((t) => acUrlRow(t)).join('');
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

async function acCredentialRows(reveal = false) {
  try {
    const q = reveal ? '?reveal=1' : '';
    const r = await fetch(`/api/credentials${q}`, { credentials: 'include', cache: 'no-store' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    const rows = data.credentials || [];
    if (!rows.length) return `<p class="fp-muted">${i18n.t('ui.entry_empty')}</p>`;
    return `<div class="fp-ds-grid fp-ds-grid-3 fp-ac-cred-grid">${
      rows.map((c) => `
      <div class="fp-ds-card fp-ac-cred-card">
        <div class="fp-ds-card-label">${acEsc(c.service)}</div>
        <div class="fp-ds-card-meta">${acEsc(c.role || '—')}</div>
        <div class="fp-ac-cred-row"><span class="fp-muted">${i18n.t('table_cols.login')}</span> <code>${acEsc(c.login)}</code>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-copy-text="${acEsc(c.login)}">${i18n.t('ui.copy')}</button>
        </div>
        <div class="fp-ac-cred-row"><span class="fp-muted">${i18n.t('table_cols.password')}</span> <code class="cc-cred-pw">${acEsc(c.password)}</code>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-copy-text="${acEsc(c.password)}">${i18n.t('ui.copy')}</button>
        </div>
      </div>`).join('')
    }</div>`;
  } catch (e) {
    return `<p class="fp-alert fp-alert-err">${acEsc(e.message)}</p>`;
  }
}

async function loadAccessCenter() {
  const root = document.getElementById('access-center-root');
  if (!root) return;
  try {
  if (window.i18n?.whenReady) await new Promise((resolve) => window.i18n.whenReady(resolve));
  await new Promise((resolve) => PortalConfig.whenReady(resolve));
  const base = acBase();
  const isAdmin = window.PortalSession?.isAdmin;

  root.innerHTML = `
    <p class="cc-panel-lead">${i18n.t('access.lead')}</p>
    <div class="cc-hub-quicklinks cc-pro-panel">
      <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-goto="users">${i18n.t('access.portal_accounts')}</button>
      <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-goto="svcs">${i18n.t('access.service_health')}</button>
      <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-ac-goto="hist">${i18n.t('access.activity_log')}</button>
    </div>
    <div class="cc-ac-actions cc-pro-panel fp-section-spaced">
      <button type="button" class="fp-btn fp-btn-primary" id="ac-open-all">${i18n.t('access.open_all_soc')}</button>
      <button type="button" class="fp-btn" id="ac-copy-urls">${i18n.t('access.copy_all_urls')}</button>
      <button type="button" class="fp-btn" id="ac-copy-endpoints">${i18n.t('access.copy_endpoints')}</button>
    </div>

    <section class="cc-pro-panel fp-section-spaced">
      <h3 class="fp-section-sub">${i18n.t('access.urls_soc')}</h3>
      <p class="fp-muted">${i18n.t('access.urls_hint')}</p>
      ${acGroupedUrlSections()}
    </section>

    <section class="cc-pro-panel fp-section-spaced" id="ac-cred-section">
      <h3 class="fp-section-sub">Credentials</h3>
      ${isAdmin
        ? `<p class="fp-muted">${i18n.t('access.credentials_admin_hint')}</p>
           <div class="fp-actions-row fp-section-spaced">
             <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" id="ac-reveal-creds">${i18n.t('access.reveal_secrets')}</button>
           </div>
           <div id="ac-cred-host"><p class="fp-muted">${i18n.t('ui.loading')}</p></div>`
        : `<p class="fp-muted">${i18n.t('users.admin_only')}</p>`}
    </section>

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

  if (isAdmin) {
    let credsRevealed = false;
    const refreshCreds = () => {
      acCredentialRows(credsRevealed).then((html) => {
        const host = document.getElementById('ac-cred-host');
        if (!host) return;
        host.innerHTML = html;
        bindCopy(host);
      });
    };
    refreshCreds();
    document.getElementById('ac-reveal-creds')?.addEventListener('click', (e) => {
      credsRevealed = !credsRevealed;
      e.currentTarget.classList.toggle('fp-btn-primary', credsRevealed);
      e.currentTarget.classList.toggle('fp-btn-ghost', !credsRevealed);
      refreshCreds();
    });
  }

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
