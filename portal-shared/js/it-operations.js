'use strict';

function escOps(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function formatOpsSize(n) {
  if (window.ForensicUtils) return ForensicUtils.sz(n);
  if (!n) return '—';
  return `${Math.round(n / 1024)} Ko`;
}

async function fetchItOperations(token) {
  const r = await fetch(`api/token/operations?token=${encodeURIComponent(token)}`, { credentials: 'same-origin' });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
}

function bindOpsFilters(items) {
  const search = document.getElementById('it-ops-search');
  const chips = document.querySelectorAll('#it-ops-chips .fp-ds-chip');
  const countEl = document.getElementById('it-ops-count');

  function apply() {
    const q = (search?.value || '').trim().toLowerCase();
    const f = document.querySelector('#it-ops-chips .fp-ds-chip.active')?.dataset.ops || 'all';
    let n = 0;
    items.forEach((el) => {
      const ok = (f === 'all' || el.dataset.ops === f) && (!q || (el.dataset.search || '').includes(q));
      el.style.display = ok ? '' : 'none';
      if (ok) n += 1;
    });
    if (countEl) countEl.textContent = i18n.t('it.ops_count', { n, total: items.length });
  }

  search?.addEventListener('input', apply);
  chips.forEach((chip) => {
    chip.addEventListener('click', () => {
      chips.forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      apply();
    });
  });
  apply();
}

async function loadItOperations(token) {
  if (typeof i18n !== 'undefined' && i18n.whenReady) {
    await new Promise((resolve) => i18n.whenReady(resolve));
  }
  const root = document.getElementById('it-ops-list');
  const section = document.getElementById('it-operations');
  if (!root || !section) return;

  if (!token) {
    root.innerHTML = `<p class="fp-muted">${i18n.t('it.ops_need_token')}</p>`;
    const countEl = document.getElementById('it-ops-count');
    if (countEl) countEl.textContent = '';
    return;
  }

  root.innerHTML = `<p class="fp-muted">${i18n.t('ui.loading')}</p>`;
  try {
    const data = await fetchItOperations(token);
    const ops = data.operations || [];
    if (!ops.length) {
      root.innerHTML = `<p class="fp-muted">${i18n.t('it.ops_empty')}</p>`;
      const countEl = document.getElementById('it-ops-count');
      if (countEl) countEl.textContent = i18n.t('it.ops_count', { n: 0, total: 0 });
      return;
    }
    root.innerHTML = '';
    const items = ops.map((o) => {
      const status = o.status === 'pending' ? 'pending' : 'done';
      const search = `${o.case_id} ${o.file} ${o.bucket} ${status}`.toLowerCase();
      const div = document.createElement('div');
      div.className = 'fp-ds-list-item';
      div.dataset.ops = status;
      div.dataset.search = search;
      const ts = o.timestamp ? new Date(o.timestamp).toLocaleString() : '—';
      div.innerHTML = `<span class="fp-ds-list-time">${escOps(ts)}</span>
        <span class="fp-ds-list-badge fp-ds-list-badge-${status === 'pending' ? 'warn' : 'info'}">${escOps(status)}</span>
        <span><strong>${escOps(o.file)}</strong> — ${escOps(o.case_id)} · ${formatOpsSize(o.size)} · ${escOps(o.bucket)}</span>`;
      root.appendChild(div);
      return div;
    });
    bindOpsFilters(items);
  } catch (e) {
    root.innerHTML = `<p class="fp-alert fp-alert-err">${escOps(e.message)}</p>`;
  }
}

window.ItOperations = { loadItOperations };
