/* global ForensicAPI, ForensicUI, ForensicUtils */
'use strict';

const MASTER_TABS = new Set([
  'dashboard-cert', 'dashboard-it', 'incidents', 'tickets', 'kb', 'assets',
  'vulnerabilities', 'notifications', 'integrations', 'users', 'workflows', 'purge',
]);

const DASHBOARD_STAT_NAV = {
  uploads_cert: { tab: 'cert', label: 'Uploads CERT' },
  active_tokens: { tab: 'tokens', label: 'Tokens actifs' },
  incidents: { tab: 'incidents', label: 'Incidents' },
  tickets: { tab: 'tickets', label: 'Tickets' },
  assets: { tab: 'assets', label: 'Assets' },
  vulnerabilities: { tab: 'vulnerabilities', label: i18n.t('hubs.it_vulns.title') },
  uploads_it: { tab: 'it', label: 'Uploads IT' },
  tokens_total: { tab: 'tokens', label: 'Tokens' },
  open_tickets: { tab: 'tickets', label: i18n.t('msg.tickets_ouverts') },
};

function esc(s) {
  if (s !== null && typeof s === 'object') return esc(JSON.stringify(s));
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function severityClass(sev) {
  const s = String(sev || '').toLowerCase();
  if (s.includes('crit')) return 'fp-sev-critical';
  if (s.includes('high')) return 'fp-sev-high';
  if (s.includes('med')) return 'fp-sev-medium';
  if (s.includes('low')) return 'fp-sev-low';
  return 'fp-sev-unknown';
}

function severityAbbr(sev) {
  const s = String(sev || '').toLowerCase();
  if (s.includes('crit')) return 'CRIT';
  if (s.includes('high')) return 'HIGH';
  if (s.includes('med')) return 'MED';
  if (s.includes('low')) return 'LOW';
  return 'UNK';
}

function discoverUrl(query, index = 'fp-events') {
  const q = String(query || '*').replace(/'/g, "\\'");
  return (
    `/dashboards/app/discover#/?_a=(columns:!(),filters:!(),index:'${index}',`
    + `interval:auto,query:(language:kuery,query:'${q}'),sort:!())`
  );
}

function closeModal() {
  const m = document.getElementById('fp-master-modal');
  if (m) m.hidden = true;
}

function openModal(title, bodyHtml) {
  let m = document.getElementById('fp-master-modal');
  if (!m) {
    m = document.createElement('div');
    m.id = 'fp-master-modal';
    m.className = 'fp-modal-overlay';
    m.innerHTML = `
      <div class="fp-modal" role="dialog" aria-modal="true">
        <div class="fp-modal-header">
          <h3 class="fp-modal-title"></h3>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm fp-modal-close" aria-label="${i18n.t('ui.close')}">✕</button>
        </div>
        <div class="fp-modal-body"></div>
      </div>`;
    document.body.appendChild(m);
    m.addEventListener('click', (e) => {
      if (e.target === m || e.target.closest('.fp-modal-close')) closeModal();
    });
  }
  m.querySelector('.fp-modal-title').textContent = title;
  m.querySelector('.fp-modal-body').innerHTML = bodyHtml;
  m.hidden = false;
}

function zoneLead(tab) {
  return (window.PortalPanelGuide && PortalPanelGuide.leadHtml(tab)) || '';
}

function zoneEmpty(tab) {
  return (window.PortalPanelGuide && PortalPanelGuide.emptyHtml(tab))
    || `<p class="fp-muted">${i18n.t('empty.no_entry')}</p>`;
}

function renderTable(el, rows, cols, opts = {}, introTab) {
  const lead = introTab ? zoneLead(introTab) : '';
  if (!rows.length) {
    el.innerHTML = lead + zoneEmpty(introTab || '');
    return;
  }
  const head = cols.map((c) => `<th>${esc(c.label)}</th>`).join('');
  const body = rows.map((r, i) => {
    const attrs = opts.rowClickable
      ? ` class="fp-row-clickable" data-row-id="${esc(r.id)}" data-row-idx="${i}" tabindex="0" role="button"`
      : '';
    return `<tr${attrs}>${cols.map((c) => `<td>${esc(r[c.key])}</td>`).join('')}</tr>`;
  }).join('');
  el.innerHTML = `${lead}<table class="fp-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
  if (opts.onRowClick) {
    el.querySelectorAll('.fp-row-clickable').forEach((tr) => {
      const handler = () => opts.onRowClick(rows[Number(tr.dataset.rowIdx)], tr.dataset.rowId);
      tr.addEventListener('click', handler);
      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handler();
        }
      });
    });
  }
}

function renderClickableDashboard(el, data, introTab) {
  const entries = Object.entries(data).filter(([k]) => !['portal', 'label'].includes(k));
  const lead = introTab ? zoneLead(introTab) : '';
  el.innerHTML = `${lead}<div class="fp-grid-3 fp-stats-row">${entries.map(([k, v]) => {
    const nav = DASHBOARD_STAT_NAV[k];
    const clickable = nav ? ' fp-stat-clickable' : '';
    const attrs = nav ? ` data-stat-key="${esc(k)}" data-stat-tab="${nav.tab}" title="Voir ${esc(nav.label)}"` : '';
    return `<div class="fp-stat${clickable}"${attrs}><div class="fp-stat-value">${esc(v)}</div><div class="fp-stat-label">${esc(k.replace(/_/g, ' '))}</div></div>`;
  }).join('')}</div><p class="fp-hint">${esc(data.label || '')}</p>`;
  el.querySelectorAll('.fp-stat-clickable').forEach((card) => {
    card.addEventListener('click', () => {
      const t = card.dataset.statTab;
      if (t && typeof window.tab === 'function') window.tab(t);
    });
  });
}

async function renderIncidentInlineDetail(api, inc, events) {
  const t = (k, fb) => (typeof i18n !== 'undefined' && i18n.t ? i18n.t(k) : (fb || k));
  const parseTs = (x) => {
    const d = new Date(String(x || ''));
    return Number.isNaN(d.getTime()) ? null : d;
  };
  const fmtTs = (x) => {
    const d = parseTs(x);
    if (!d) return String(x || '—');
    try { return d.toISOString().replace('T', ' ').replace('Z', 'Z'); } catch { return String(x || '—'); }
  };
  const pick = (e, key) => {
    if (!e || !key) return undefined;
    if (Object.prototype.hasOwnProperty.call(e, key)) return e[key];
    // support dotted keys stored flat
    if (key.includes('.') && Object.prototype.hasOwnProperty.call(e, key)) return e[key];
    return undefined;
  };
  const evSource = (e) => String(pick(e, 'source.ip') || pick(e, 'source.address') || e?.host?.name || e?.agent?.name || '—');
  const evAction = (e) => String(e?.event?.action || e?.rule?.name || pick(e, 'event.action') || pick(e, 'winlog.event_id') || '—');
  const evMsg = (e) => String(e?.message || pick(e, 'log.original') || e?.event?.original || '—');
  const topN = (m, n = 5) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  const uniq = (arr) => [...new Set(arr.filter(Boolean))];

  const tsList = events.map((e) => parseTs(e['@timestamp'])).filter(Boolean);
  const firstSeen = tsList.length ? new Date(Math.min(...tsList.map((d) => d.getTime()))) : null;
  const lastSeen = tsList.length ? new Date(Math.max(...tsList.map((d) => d.getTime()))) : null;

  const srcCounts = new Map();
  const actCounts = new Map();
  const iocs = new Set();
  const rxIp = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
  const rxHash = /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi;
  const rxDomain = /\b(?=.{4,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
  events.forEach((e) => {
    const s = evSource(e);
    const a = evAction(e);
    srcCounts.set(s, (srcCounts.get(s) || 0) + 1);
    actCounts.set(a, (actCounts.get(a) || 0) + 1);
    const msg = evMsg(e);
    (msg.match(rxIp) || []).forEach((x) => iocs.add(x));
    (msg.match(rxHash) || []).forEach((x) => iocs.add(x.toLowerCase()));
    (msg.match(rxDomain) || []).forEach((x) => {
      const v = String(x || '').toLowerCase();
      if (!v.includes('localhost')) iocs.add(v);
    });
  });

  const dUrl = discoverUrl(`case.id:"${inc.case_id || inc.id}"`);
  const eventsTable = (rows) => `<div class="fp-table-wrap fp-incident-events-wrap"><table class="fp-table"><thead><tr>
      <th>${esc(t('incidents.detail.col_time', 'Time'))}</th>
      <th>${esc(t('incidents.detail.col_source', 'Source'))}</th>
      <th>${esc(t('incidents.detail.col_action', 'Action'))}</th>
      <th>${esc(t('incidents.detail.col_message', 'Message'))}</th>
    </tr></thead><tbody>${
      rows.map((e) => {
        const msg = evMsg(e);
        return `<tr>
          <td>${esc(fmtTs(e['@timestamp'] || '—'))}</td>
          <td>${esc(evSource(e))}</td>
          <td>${esc(evAction(e))}</td>
          <td>${esc(msg.length > 220 ? `${msg.slice(0, 220)}…` : msg)}</td>
        </tr>`;
      }).join('')
    }</tbody></table></div>`;

  const eventsHtml = events.length
    ? `${eventsTable(events.slice(0, 16))}
      ${events.length > 16 ? `<details class="fp-section-spaced"><summary>${esc(t('incidents.detail.show_all_events', 'Show all events'))} (${events.length})</summary>${eventsTable(events.slice(0, 120))}</details>` : ''}`
    : `<p class="fp-muted">${i18n.t('empty.no_events')}</p>`;

  const topSources = topN(srcCounts, 5);
  const topActions = topN(actCounts, 5);
  const iocList = uniq([...iocs]).slice(0, 10);

  const summaryCards = `
    <div class="fp-ds-grid fp-ds-grid-4 fp-section-spaced">
      <div class="fp-ds-card">
        <div class="fp-ds-card-label">${esc(t('incidents.detail.first_seen', 'First seen'))}</div>
        <div class="fp-ds-card-value">${esc(firstSeen ? fmtTs(firstSeen.toISOString()) : '—')}</div>
        <div class="fp-ds-card-meta">${esc(t('incidents.detail.events_count', 'Events'))}: ${esc(String(events.length))}</div>
      </div>
      <div class="fp-ds-card">
        <div class="fp-ds-card-label">${esc(t('incidents.detail.last_seen', 'Last seen'))}</div>
        <div class="fp-ds-card-value">${esc(lastSeen ? fmtTs(lastSeen.toISOString()) : '—')}</div>
        <div class="fp-ds-card-meta">${esc(t('incidents.detail.unique_sources', 'Unique sources'))}: ${esc(String(srcCounts.size || 0))}</div>
      </div>
      <div class="fp-ds-card">
        <div class="fp-ds-card-label">${esc(t('incidents.detail.top_sources', 'Top sources'))}</div>
        <div class="fp-ds-card-meta">${topSources.length ? topSources.map(([k, v]) => `<div><code>${esc(k)}</code> · ${esc(String(v))}</div>`).join('') : '—'}</div>
      </div>
      <div class="fp-ds-card">
        <div class="fp-ds-card-label">${esc(t('incidents.detail.top_actions', 'Top actions'))}</div>
        <div class="fp-ds-card-meta">${topActions.length ? topActions.map(([k, v]) => `<div>${esc(k)} · ${esc(String(v))}</div>`).join('') : '—'}</div>
      </div>
    </div>`;

  const iocHtml = iocList.length
    ? `<details class="fp-section-spaced"><summary>${esc(t('incidents.detail.iocs', 'Extracted IOCs'))} (${iocList.length})</summary>
        <div class="fp-table-wrap"><table class="fp-table"><thead><tr><th>IOC</th><th></th></tr></thead><tbody>
          ${iocList.map((x) => `<tr><td><code>${esc(x)}</code></td><td style="white-space:nowrap">
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-ac-copy-text="${esc(x)}">${esc(t('ui.copy', 'Copy'))}</button>
          </td></tr>`).join('')}
        </tbody></table></div>
      </details>`
    : '';

  return `
    <h3 class="fp-section-sub">${esc(inc.title || inc.id)}</h3>
    <p class="fp-section-spaced"><span class="fp-incident-sev-badge ${severityClass(inc.severity)}">${esc(inc.severity || '—')}</span>
      <span class="fp-incident-status-badge">${esc(inc.status || '—')}</span></p>
    ${window.IncidentWorkflow ? IncidentWorkflow.renderWorkflowBar(inc) : ''}
    ${summaryCards}
    <dl class="fp-incident-detail-grid">
      <dt>${esc(t('incidents.detail.id', 'ID'))}</dt><dd><code>${esc(inc.id)}</code></dd>
      <dt>${esc(t('incidents.detail.case', 'Case'))}</dt><dd><code>${esc(inc.case_id || '—')}</code></dd>
      <dt>${i18n.t('table.status')}</dt><dd>${esc(inc.status || '—')}</dd>
      <dt>${i18n.t('table_cols.assignee')}</dt><dd>${esc(inc.assignee || '—')}</dd>
    </dl>
    <div class="fp-detail-actions fp-section-spaced fp-incident-pivot-row">
      <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-inc-report="${esc(inc.id)}" data-case-id="${esc(inc.case_id || inc.id)}">${i18n.t('report.open_for_incident')}</button>
      <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-goto-tab="forensic-reports">${i18n.t('sidebar.forensic_reports')}</button>
      <a class="fp-btn fp-btn-ghost fp-btn-sm" href="${esc(dUrl)}" target="_blank" rel="noopener">${esc(t('incidents.detail.discover', 'Discover'))}</a>
      <a class="fp-btn fp-btn-ghost fp-btn-sm" href="${esc(PortalConfig.socUrl('/timesketch/'))}" target="_blank" rel="noopener">${esc(t('incidents.detail.timesketch', 'Timesketch'))}</a>
      <a class="fp-btn fp-btn-ghost fp-btn-sm" href="${esc(PortalConfig.socUrl('/thehive/'))}" target="_blank" rel="noopener">${esc(t('incidents.detail.thehive', 'TheHive'))}</a>
      <a class="fp-btn fp-btn-ghost fp-btn-sm" href="${esc(PortalConfig.socUrl('/grafana/d/helk-hunts/helk-hunts'))}" target="_blank" rel="noopener">${esc(t('incidents.detail.helk', 'HELK'))}</a>
    </div>
    ${iocHtml}
    <h4 class="fp-section-sub">${i18n.t('msg.events_associes')} (${events.length})</h4>
    ${eventsHtml}`;
}

async function renderIncidentsZone(el, api) {
  el.innerHTML = `${zoneLead('incidents')}<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
  try {
    const list = await api.get('/api/master/incidents');
    const rows = Array.isArray(list) ? list : [];
    if (!rows.length) {
      el.innerHTML = zoneLead('incidents') + zoneEmpty('incidents');
      return;
    }
    const cols = Object.keys(rows[0])
      .filter((k) => !['tags', '@timestamp', 'seeded_at', 'host', 'log', 'event', 'fp', 'ti_match'].includes(k))
      .filter((k) => typeof rows[0][k] !== 'object')
      .slice(0, 6)
      .map((k) => ({ key: k, label: k }));
    let selected = rows[0];
    const split = document.createElement('div');
    split.className = 'fp-incidents-split';
    split.innerHTML = `
      <div class="fp-incidents-list" id="fp-incidents-list"></div>
      <div class="fp-incidents-detail" id="fp-incidents-detail"><p class="fp-muted">${i18n.t('ui.loading')}</p></div>`;
    const accordion = document.createElement('details');
    accordion.className = 'fp-incidents-accordion cc-pro-panel fp-section-spaced';
    accordion.innerHTML = `<summary>${i18n.t('msg.incidents_full_table')}</summary><div id="fp-incidents-table-wrap"></div>`;
    el.innerHTML = zoneLead('incidents');
    el.appendChild(split);
    el.appendChild(accordion);

    const listEl = split.querySelector('#fp-incidents-list');
    const detailEl = split.querySelector('#fp-incidents-detail');
    const tableWrap = accordion.querySelector('#fp-incidents-table-wrap');

    const paintList = () => {
      listEl.innerHTML = rows.map((r) => `
        <button type="button" class="fp-ds-card fp-ds-card-interactive fp-svc-card fp-incident-card ${severityClass(r.severity)}${r.id === selected.id ? ' is-selected' : ''}" data-inc-id="${esc(r.id)}">
          <span class="fp-svc-card-icon" style="background:var(--fp-sev-color)22;border:1px solid var(--fp-sev-color)55;color:var(--fp-sev-color)">${esc(severityAbbr(r.severity))}</span>
          <div class="fp-ds-card-label">${esc(r.title || r.id)}</div>
          <div class="fp-ds-card-value">${esc(window.IncidentWorkflow ? IncidentWorkflow.statusLabel(r.status) : String(r.status || '—'))}</div>
          <div class="fp-ds-card-meta"><code>${esc(r.case_id || r.id)}</code> · ${esc(r.severity || '—')}</div>
        </button>`).join('');
      listEl.querySelectorAll('.fp-incident-card').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const id = btn.dataset.incId;
          selected = rows.find((r) => r.id === id) || selected;
          paintList();
          await paintDetail();
        });
      });
    };

    const bindDetailInteractions = (inc, events) => {
      if (window.IncidentWorkflow) {
        const onWorkflowUpdated = async (updatedInc) => {
          const idx = rows.findIndex((r) => r.id === updatedInc.id);
          if (idx >= 0) rows[idx] = { ...rows[idx], ...updatedInc };
          selected = { ...selected, ...updatedInc };
          paintList();
          await paintDetail();
        };
        IncidentWorkflow.bindWorkflowBar(detailEl, api, onWorkflowUpdated);
      }
      detailEl.querySelectorAll('[data-ac-copy-text]').forEach((btn) => {
        btn.addEventListener('click', async (e) => {
          e.preventDefault();
          e.stopPropagation();
          const txt = btn.dataset.acCopyText || '';
          try {
            await navigator.clipboard.writeText(txt);
          } catch {
            const ta = document.createElement('textarea');
            ta.value = txt;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
          }
        });
      });
      detailEl.querySelector('[data-inc-report]')?.addEventListener('click', () => {
        if (window.ForensicReport) ForensicReport.openModalForIncident(inc);
      });
      detailEl.querySelector('[data-goto-tab]')?.addEventListener('click', (e) => {
        const t = e.currentTarget.dataset.gotoTab;
        if (t && typeof window.tab === 'function') window.tab(t);
      });
    };

    const paintDetail = async () => {
      detailEl.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
      try {
        const detail = await api.get(`/api/master/incidents/${encodeURIComponent(selected.id)}`);
        const rel = await api.get(`/api/master/incidents/${encodeURIComponent(selected.id)}/events`);
        const inc = detail.incident || detail;
        const events = rel.events || [];
        detailEl.innerHTML = await renderIncidentInlineDetail(api, inc, events);
        bindDetailInteractions(inc, events);
      } catch (e) {
        detailEl.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
      }
    };

    renderTable(tableWrap, rows, cols.length ? cols : [{ key: 'id', label: 'id' }], {
      rowClickable: true,
      onRowClick: (row) => {
        selected = row;
        paintList();
        paintDetail();
        split.scrollIntoView({ behavior: 'smooth', block: 'start' });
      },
    }, null);

    paintList();
    await paintDetail();
  } catch (e) {
    el.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
  }
}

async function showIncidentDetail(api, id) {
  openModal(i18n.t('msg.incident_detail'), `<p class="fp-muted">${i18n.t('ui.loading')}</p>`);
  try {
    const detail = await api.get(`/api/master/incidents/${encodeURIComponent(id)}`);
    const rel = await api.get(`/api/master/incidents/${encodeURIComponent(id)}/events`);
    const inc = detail.incident || detail;
    const events = rel.events || [];
    const dUrl = rel.discover_url || discoverUrl(`case.id:"${inc.case_id || inc.id}"`);
  const eventsHtml = events.length
      ? `<div class="fp-table-wrap"><table class="fp-table"><thead><tr><th>Date</th><th>Source</th><th>Message</th></tr></thead><tbody>`
        + events.slice(0, 20).map((e) => `<tr><td>${esc(e['@timestamp'] || '—')}</td><td>${esc(e['source.ip'] || e.host?.name || '—')}</td><td>${esc(String(e.message || e.event?.action || '—').slice(0, 120))}</td></tr>`).join('')
        + `</tbody></table></div>`
      : `<p class="fp-muted">${i18n.t('empty.no_events')}</p>`;
    openModal(
      inc.title || inc.id,
      `<div class="fp-detail-grid">
        <p><strong>ID:</strong> <code>${esc(inc.id)}</code></p>
        <p><strong>Case:</strong> <code>${esc(inc.case_id || '—')}</code></p>
        <p><strong>Sévérité:</strong> ${esc(inc.severity || '—')}</p>
        <p><strong>Statut:</strong> ${esc(inc.status || '—')}</p>
        <p><strong>Assigné:</strong> ${esc(inc.assignee || '—')}</p>
      </div>
      <div class="fp-detail-actions">
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" id="cc-inc-report-btn">${i18n.t('report.open_for_incident')}</button>
        <a class="fp-btn fp-btn-ghost fp-btn-sm" href="${esc(dUrl)}" target="_blank" rel="noopener">📊 Events liés (Discover)</a>
        <a class="fp-btn fp-btn-ghost fp-btn-sm" href="${esc(PortalConfig.socUrl('/timesketch/'))}" target="_blank" rel="noopener">⏱ Timesketch</a>
        <a class="fp-btn fp-btn-ghost fp-btn-sm" href="${esc(PortalConfig.socUrl('/thehive/'))}" target="_blank" rel="noopener">🐝 TheHive</a>
      </div>
      <h4 class="fp-section-title fp-section-spaced">Events associés (${events.length})</h4>
      ${eventsHtml}`,
    );
    document.getElementById('cc-inc-report-btn')?.addEventListener('click', () => {
      if (window.ForensicReport) ForensicReport.openModalForIncident(inc);
    });
  } catch (e) {
    openModal('Incident', `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`);
  }
}

function renderUsersZone(el, api) {
  el.innerHTML = `
    <div class="fp-card-toolbar">
      <p class="fp-hint" style="margin:0;flex:1">Gestion des comptes portail (OpenSearch forensic-portal-users).</p>
      <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" id="fp-user-add">+ Add user</button>
    </div>
    <div id="fp-users-table-wrap"><p class="fp-muted">${i18n.t('ui.loading')}</p></div>`;

  async function refresh() {
    const wrap = document.getElementById('fp-users-table-wrap');
    const rows = await api.get('/api/master/users');
    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      wrap.innerHTML = `<p class="fp-muted">${i18n.t('empty.no_users')}</p>`;
      return;
    }
    wrap.innerHTML = `<table class="fp-table"><thead><tr>
      <th>Login</th><th>Rôle</th><th>Portail</th><th>Actif</th><th>Actions</th>
    </tr></thead><tbody>${list.map((u) => `<tr>
      <td><code>${esc(u.login)}</code></td>
      <td>${esc(u.role)}</td>
      <td>${esc(u.portal)}</td>
      <td>${esc(u.active)}</td>
      <td>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm fp-user-edit" data-id="${esc(u.id)}">Edit</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm fp-user-del" data-id="${esc(u.id)}">Delete</button>
      </td>
    </tr>`).join('')}</tbody></table>`;
    wrap.querySelectorAll('.fp-user-edit').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const u = list.find((x) => x.id === btn.dataset.id);
        if (!u) return;
        const login = prompt('Login', u.login || '');
        if (login === null) return;
        const role = prompt(i18n.t('msg.role_analyst_manager_it_upload'), u.role || 'analyst');
        if (role === null) return;
        const portal = prompt(i18n.t('msg.portail_cert_it'), u.portal || 'cert');
        if (portal === null) return;
        await api.put(`/api/master/users/${encodeURIComponent(u.id)}`, {
          login, role, portal, active: u.active !== false,
        });
        ForensicUI.toast(i18n.t('toast.user_updated'), 'success');
        refresh();
      });
    });
    wrap.querySelectorAll('.fp-user-del').forEach((btn) => {
      btn.addEventListener('click', async () => {
        if (!confirm(i18n.t('confirm.delete_user'))) return;
        await api.delete(`/api/master/users/${encodeURIComponent(btn.dataset.id)}`);
        ForensicUI.toast(i18n.t('toast.user_deleted'), 'success');
        refresh();
      });
    });
  }

  document.getElementById('fp-user-add')?.addEventListener('click', async () => {
    const login = prompt('Login');
    if (!login) return;
    const role = prompt(i18n.t('msg.role_analyst_manager_it_upload'), 'analyst') || 'analyst';
    const portal = prompt(i18n.t('msg.portail_cert_it'), 'cert') || 'cert';
    await api.post('/api/master/users', { login, role, portal, active: true });
    ForensicUI.toast(i18n.t('toast.user_created'), 'success');
    refresh();
  });

  refresh().catch((e) => {
    el.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
  });
}

function renderPurgeZone(el, api) {
  el.innerHTML = `
    <p class="fp-hint">${i18n.t('master.purge_hint')}</p>
    <div class="fp-grid-2">
      <label class="fp-label"><input type="checkbox" id="purge-logs" checked> Logs forensics (forensic-windows*, linux*, web*, …)</label>
      <label class="fp-label"><input type="checkbox" id="purge-tokens"> Tokens IT</label>
      <label class="fp-label"><input type="checkbox" id="purge-uploads"> Métadonnées uploads (forensic-uploads*)</label>
    </div>
    <label class="fp-label">Périmètre
      <select class="fp-select" id="purge-scope">
        <option value="all">Tout</option>
        <option value="period">Par période</option>
        <option value="source">Par source (portal cert/it — uploads)</option>
      </select>
    </label>
    <div class="fp-grid-2" id="purge-period-fields" hidden>
      <label class="fp-label">Du <input type="datetime-local" class="fp-input" id="purge-from"></label>
      <label class="fp-label">Au <input type="datetime-local" class="fp-input" id="purge-to"></label>
    </div>
    <label class="fp-label" id="purge-source-field" hidden>Source portal
      <select class="fp-select" id="purge-portal"><option value="cert">cert</option><option value="it">it</option></select>
    </label>
    <label class="fp-label">Analyste (audit) <input class="fp-input" id="purge-analyst" value="cert-analyst"></label>
    <div class="fp-actions-row">
      <button type="button" class="fp-btn fp-btn-ghost" id="purge-preview">Aperçu (dry-run)</button>
      <button type="button" class="fp-btn fp-btn-primary" id="purge-run">🗑 Exécuter la purge</button>
    </div>
    <pre class="fp-console" id="purge-result" style="margin-top:1rem;min-height:4rem">—</pre>`;

  const scopeEl = document.getElementById('purge-scope');
  scopeEl?.addEventListener('change', () => {
    const v = scopeEl.value;
    document.getElementById('purge-period-fields').hidden = v !== 'period';
    document.getElementById('purge-source-field').hidden = v !== 'source';
  });

  async function runPurge(dryRun) {
    const types = [];
    if (document.getElementById('purge-logs')?.checked) types.push('logs');
    if (document.getElementById('purge-tokens')?.checked) types.push('tokens');
    if (document.getElementById('purge-uploads')?.checked) types.push('uploads');
    if (!types.length) {
      ForensicUI.toast(i18n.t('toast.select_one_type'), 'warn');
      return;
    }
    const scope = scopeEl?.value || 'all';
    const body = {
      types,
      scope,
      analyst: document.getElementById('purge-analyst')?.value || 'cert-analyst',
      dry_run: dryRun,
      confirm: !dryRun,
    };
    if (scope === 'period') {
      body.from = document.getElementById('purge-from')?.value;
      body.to = document.getElementById('purge-to')?.value;
    }
    if (scope === 'source') body.portal = document.getElementById('purge-portal')?.value;
    if (!dryRun && !confirm(i18n.t('master.confirm_purge', { types: types.join(', '), scope }))) return;

    const out = document.getElementById('purge-result');
    out.textContent = i18n.t('msg.execution');
    try {
      const r = await api.post('/api/purge', body);
      out.textContent = JSON.stringify(r, null, 2);
      ForensicUI.toast(dryRun ? i18n.t('msg.apercu_termine') : i18n.t('msg.purge_executee'), dryRun ? 'info' : 'success');
      if (!dryRun && typeof window.loadStats === 'function') window.loadStats();
    } catch (e) {
      out.textContent = e.message;
      ForensicUI.toast(e.message, 'error');
    }
  }

  document.getElementById('purge-preview')?.addEventListener('click', () => runPurge(true));
  document.getElementById('purge-run')?.addEventListener('click', () => runPurge(false));
}

function renderIntegrations(el, data) {
  const rows = (data.integrations || []).map((i) => ({
    name: i.name,
    status: i.status,
    url: i.url || '—',
  }));
  renderTable(el, rows, [
    { key: 'name', label: 'Service' },
    { key: 'status', label: 'Statut' },
    { key: 'url', label: 'URL' },
  ]);
}

async function loadMasterZone(api, tab) {
  const el = document.getElementById(`zone-${tab}`);
  if (!el) return;
  el.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
  try {
    if (tab === 'purge') {
      renderPurgeZone(el, api);
      return;
    }
    if (tab === 'users') {
      renderUsersZone(el, api);
      return;
    }
    if (tab === 'dashboard-cert') {
      renderClickableDashboard(el, await api.get('/api/master/dashboard/cert'), 'dashboard-cert');
      return;
    }
    if (tab === 'dashboard-it') {
      renderClickableDashboard(el, await api.get('/api/master/dashboard/it'), 'dashboard-it');
      return;
    }
    if (tab === 'integrations') {
      const data = await api.get('/api/master/integrations');
      el.innerHTML = zoneLead('integrations');
      const wrap = document.createElement('div');
      el.appendChild(wrap);
      renderIntegrations(wrap, data);
      return;
    }
    if (tab === 'incidents') {
      await renderIncidentsZone(el, api);
      return;
    }
    const path = tab === 'kb' ? 'kb' : tab;
    const rows = await api.get(`/api/master/${path}`);
    const list = Array.isArray(rows) ? rows : [];
    const cols = list[0]
      ? Object.keys(list[0])
        .filter((k) => !['tags', '@timestamp', 'seeded_at', 'host', 'log', 'event', 'fp', 'ti_match'].includes(k))
        .filter((k) => typeof list[0][k] !== 'object')
        .slice(0, 6)
        .map((k) => ({ key: k, label: k }))
      : [{ key: 'title', label: 'title' }];
    const incidentClick = tab === 'incidents'
      ? (row) => showIncidentDetail(api, row.id)
      : null;
    renderTable(el, list, cols.length ? cols : [{ key: 'id', label: 'id' }], {
      rowClickable: !!incidentClick,
      onRowClick: incidentClick,
    }, tab);
  } catch (e) {
    el.innerHTML = `<p class="fp-alert fp-alert-err">${esc(e.message)}</p>`;
  }
}

window.PortalMasterZones = {
  MASTER_TABS,
  loadMasterZone,
  discoverUrl,
  showIncidentDetail,
};
