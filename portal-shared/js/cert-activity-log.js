'use strict';

async function fetchAuditEvents(params = {}) {
  const q = new URLSearchParams(params);
  const r = await fetch(`/api/audit/events?${q}`, { credentials: 'include' });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function formatAuditUser(e) {
  const user = e.user || '—';
  const role = e.role || '';
  if (!role || String(role) === String(user)) return esc(user);
  return `${esc(user)} <span class="fp-muted">${esc(role)}</span>`;
}

function applyClientAuditFilter() {
  const q = (document.getElementById('audit-search')?.value || '').trim().toLowerCase();
  const tbody = document.getElementById('audit-tbody');
  if (!tbody) return;
  let visible = 0;
  tbody.querySelectorAll('.cc-audit-row').forEach((row) => {
    const text = row.dataset.search || row.textContent.toLowerCase();
    const ok = !q || text.includes(q);
    row.style.display = ok ? '' : 'none';
    if (ok) visible += 1;
  });
  const countEl = document.getElementById('audit-visible-count');
  if (countEl) {
    const total = tbody.querySelectorAll('.cc-audit-row').length;
    countEl.textContent = i18n.t('activity.visible_count', { n: visible, total });
  }
}

async function loadActivityLog() {
  if (typeof i18n !== 'undefined' && i18n.whenReady) {
    await new Promise((resolve) => i18n.whenReady(resolve));
  }
  const root = document.getElementById('activity-log-root');
  if (!root) return;

  root.innerHTML = `
    <div class="fp-ds-activity-toolbar">
      <div class="fp-ds-filter-chips" id="audit-chips" role="group" aria-label="${esc(i18n.t('activity.chip_group'))}">
        <button type="button" class="fp-ds-chip active" data-audit-type="">${i18n.t('activity.filter_all')}</button>
        <button type="button" class="fp-ds-chip" data-audit-type="user">${i18n.t('activity.chip_user')}</button>
        <button type="button" class="fp-ds-chip" data-audit-type="cert_ops">${i18n.t('activity.chip_cert_ops')}</button>
        <button type="button" class="fp-ds-chip" data-audit-type="system">${i18n.t('activity.chip_system')}</button>
      </div>
      <input type="search" class="fp-input fp-ds-input-inline" id="audit-search"
        placeholder="${esc(i18n.t('activity.search_placeholder'))}" autocomplete="off">
    </div>
    <div class="cc-glass-panel cc-audit-filters fp-ds-audit-filters">
      <label class="fp-label">${i18n.t('table.type')} <select class="fp-select" id="audit-type">
        <option value="">${i18n.t('activity.filter_all')}</option>
        <option value="user">user</option>
        <option value="cert_ops">cert_ops</option>
        <option value="system">system</option>
      </select></label>
      <label class="fp-label">${i18n.t('activity.filter_user')} <input class="fp-input" id="audit-user" placeholder="admin"></label>
      <label class="fp-label">${i18n.t('table_cols.service')} <input class="fp-input" id="audit-service" placeholder="cert-portal"></label>
      <label class="fp-label">${i18n.t('activity.filter_from')} <input class="fp-input" id="audit-from" type="datetime-local"></label>
      <label class="fp-label">${i18n.t('activity.filter_to')} <input class="fp-input" id="audit-to" type="datetime-local"></label>
      <button type="button" class="fp-btn fp-btn-primary" id="audit-refresh">${i18n.t('activity.filter_btn')}</button>
    </div>
    <p class="fp-ds-muted fp-ds-activity-count" id="audit-visible-count" aria-live="polite"></p>
    <div class="fp-table-wrap cc-glass-panel fp-section-spaced fp-ds-scroll-panel fp-ds-table-wrap">
      <table class="fp-table cc-audit-table">
        <thead><tr>
          <th>Timestamp</th><th>User</th><th>Action</th><th>IP</th><th>${i18n.t('table_cols.service')}</th><th>${i18n.t('activity.context')}</th>
        </tr></thead>
        <tbody id="audit-tbody"><tr><td colspan="6" class="fp-table-empty">${i18n.t('ui.loading')}</td></tr></tbody>
      </table>
    </div>`;

  const typeSelect = document.getElementById('audit-type');
  const chips = document.querySelectorAll('#audit-chips .fp-ds-chip');

  function syncChipsFromSelect() {
    const val = typeSelect?.value || '';
    chips.forEach((c) => {
      c.classList.toggle('active', c.dataset.auditType === val);
    });
  }

  chips.forEach((chip) => {
    chip.addEventListener('click', () => {
      if (typeSelect) typeSelect.value = chip.dataset.auditType || '';
      chips.forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      refresh();
    });
  });

  typeSelect?.addEventListener('change', () => {
    syncChipsFromSelect();
    refresh();
  });

  document.getElementById('audit-search')?.addEventListener('input', applyClientAuditFilter);

  async function refresh() {
    const tbody = document.getElementById('audit-tbody');
    tbody.innerHTML = `<tr><td colspan="6" class="fp-table-empty">${i18n.t('ui.loading')}</td></tr>`;
    try {
      const data = await fetchAuditEvents({
        type: document.getElementById('audit-type').value,
        user: document.getElementById('audit-user').value,
        service: document.getElementById('audit-service').value,
        from: document.getElementById('audit-from').value,
        to: document.getElementById('audit-to').value,
        limit: '300',
      });
      let events = data.events || [];
      if (!events.length) {
        tbody.innerHTML = `<tr><td colspan="6" class="fp-table-empty">${i18n.t('msg.aucun_evenement')}</td></tr>`;
        const countEl = document.getElementById('audit-visible-count');
        if (countEl) countEl.textContent = i18n.t('activity.visible_count', { n: 0, total: 0 });
        return;
      }
      const searchTexts = [];
      tbody.innerHTML = events
        .map(
          (e, idx) => {
            const search = [
              e['@timestamp'],
              e.user,
              e.role,
              e.action,
              e.message,
              e.ip,
              e.service,
              e.type,
              JSON.stringify(e.context || {}),
            ]
              .filter(Boolean)
              .join(' ')
              .toLowerCase();
            searchTexts[idx] = search;
            return `<tr class="cc-audit-row" data-type="${esc(e.type)}">
          <td><code>${esc(e['@timestamp'] || '')}</code></td>
          <td>${formatAuditUser(e)}</td>
          <td><strong>${esc(e.action)}</strong><br><span class="fp-muted">${esc(e.message)}</span></td>
          <td>${esc(e.ip || '—')}</td>
          <td>${esc(e.service || '—')}</td>
          <td><details><summary>JSON</summary><pre class="cc-audit-json">${esc(JSON.stringify(e.context || {}, null, 2))}</pre></details></td>
        </tr>`;
          },
        )
        .join('');
      tbody.querySelectorAll('.cc-audit-row').forEach((row, idx) => {
        row.dataset.search = searchTexts[idx] || '';
      });
      applyClientAuditFilter();
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" class="fp-alert fp-alert-err">${esc(err.message)}</td></tr>`;
    }
  }

  document.getElementById('audit-refresh')?.addEventListener('click', refresh);
  refresh();
}

window.PortalActivityLog = { loadActivityLog };
