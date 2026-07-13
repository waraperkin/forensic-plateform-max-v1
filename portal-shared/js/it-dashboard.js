'use strict';

function escIt(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function fetchItDashboard() {
  const r = await fetch('api/dashboard', { credentials: 'same-origin' });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
}

function renderItKpis(data, tokenInfo) {
  const root = document.getElementById('it-kpi-root');
  if (!root) return;
  const maxFiles = data?.maxFiles ?? '—';
  const maxSize = window.ForensicUtils
    ? ForensicUtils.sz(data?.maxSizeBytes || 0)
    : `${Math.round((data?.maxSizeBytes || 0) / 1024 / 1024)} Mo`;
  const redisOk = data?.redis;
  const caseId = tokenInfo?.case_id;
  const uses = tokenInfo ? `${tokenInfo.uses_count}/${tokenInfo.max_uses}` : '—';
  const hours = tokenInfo?.hours_remaining ?? '—';

  root.innerHTML = `
    <div class="fp-ds-kpi-grid fp-ds-it-kpi-grid fp-ds-animate-in">
      <a class="fp-ds-card fp-ds-card-interactive" href="/" rel="noopener">
        <div class="fp-ds-card-label">${i18n.t('it.kpi_cert')}</div>
        <div class="fp-ds-card-value">CERT</div>
        <div class="fp-ds-card-meta">${i18n.t('it.card_cert_link')}</div>
      </a>
      <div class="fp-ds-card ${redisOk ? 'fp-ds-card--up' : 'fp-ds-card--warn'}">
        <div class="fp-ds-card-label">${i18n.t('it.kpi_service')}</div>
        <div class="fp-ds-card-value">${redisOk ? 'UP' : '—'}</div>
        <div class="fp-ds-card-meta"><span class="fp-ds-tag fp-ds-tag--${redisOk ? 'ok' : 'warn'}">Redis</span></div>
      </div>
      <div class="fp-ds-card">
        <div class="fp-ds-card-label">${i18n.t('it.kpi_limits')}</div>
        <div class="fp-ds-card-value">${maxFiles}</div>
        <div class="fp-ds-card-meta">${maxSize} / ${i18n.t('it.kpi_per_file')}</div>
      </div>
      <div class="fp-ds-card ${caseId ? 'fp-ds-card--up' : ''}">
        <div class="fp-ds-card-label">${i18n.t('it.kpi_token')}</div>
        <div class="fp-ds-card-value">${caseId ? escIt(caseId) : '—'}</div>
        <div class="fp-ds-card-meta">${caseId ? `${uses} · ~${hours}h` : i18n.t('it.kpi_no_token')}</div>
      </div>
    </div>`;
}

function renderItActions(tokenInfo) {
  const root = document.getElementById('it-actions-root');
  if (!root) return;
  const hasToken = Boolean(tokenInfo?.case_id);
  root.innerHTML = `
    <div class="fp-ds-action-grid fp-ds-animate-in">
      <a class="fp-ds-action-cell fp-ds-action-up fp-ds-action-link" href="#it-upload">${i18n.t('it.action_upload')}</a>
      <a class="fp-ds-action-cell fp-ds-action-up fp-ds-action-link" href="#it-operations">${i18n.t('it.action_ops')}</a>
      <a class="fp-ds-action-cell fp-ds-action-up fp-ds-action-link" href="/dashboards/" target="_blank" rel="noopener">${i18n.t('it.action_dashboards')}</a>
      <button type="button" class="fp-ds-action-cell fp-ds-action-up" id="it-helk-endpoint-btn">${i18n.t('it.action_helk_endpoint') || 'Voir endpoint dans HELK'}</button>
      <button type="button" class="fp-ds-action-cell fp-ds-action-up" id="it-vr-artifacts-btn">${i18n.t('it.action_vr_artifacts')}</button>
      <span class="fp-ds-action-cell ${hasToken ? 'fp-ds-action-up' : 'fp-ds-action-warn'}">${hasToken ? i18n.t('it.action_token_ok') : i18n.t('it.action_token_missing')}</span>
    </div>`;
}

async function loadItDashboard(tokenInfo) {
  const kpiRoot = document.getElementById('it-kpi-root');
  const actionsRoot = document.getElementById('it-actions-root');
  try {
    const [data] = await Promise.all([
      fetchItDashboard(),
      typeof i18n !== 'undefined' && i18n.whenReady
        ? Promise.race([
            new Promise((resolve) => i18n.whenReady(resolve)),
            new Promise((resolve) => setTimeout(resolve, 800)),
          ])
        : Promise.resolve(),
    ]);
    renderItKpis(data, tokenInfo);
    renderItActions(tokenInfo);
    document.getElementById('it-helk-endpoint-btn')?.addEventListener('click', async () => {
      const hostname = tokenInfo?.hostname || prompt("Nom d'hôte (lab) :", 'lab-linux01') || '';
      if (!hostname) return;
      try {
        const r = await fetch(`api/helk/hunt-url?hostname=${encodeURIComponent(hostname)}`, { credentials: 'same-origin' });
        const hunt = await r.json();
        const path = hunt.discover_opensearch || '/dashboards/app/discover#/?q=_index:helk-*';
        window.open(path.startsWith('http') ? path : `${window.location.origin}${path}`, '_blank', 'noopener');
      } catch (_) {
        window.open('/dashboards/app/discover#/?q=_index:helk-*', '_blank', 'noopener');
      }
    });
    document.getElementById('it-vr-artifacts-btn')?.addEventListener('click', async () => {
      const hostname = tokenInfo?.hostname || prompt("Nom d'hôte endpoint :", 'lab-linux01') || '';
      if (!hostname) return;
      try {
        const r = await fetch(`api/endpoints/velociraptor-artifacts?hostname=${encodeURIComponent(hostname)}`, { credentials: 'same-origin' });
        const data = await r.json();
        const q = encodeURIComponent(`host:"${hostname}" OR hostname:"${hostname}"`);
        const discover = `/dashboards/app/discover#/?q=_index:velociraptor-* AND ${q}`;
        if (data?.artifacts?.length) {
          alert(`Artefacts VR pour ${hostname}: ${data.artifacts.join(', ')}`);
        }
        window.open(discover, '_blank', 'noopener');
      } catch (_) {
        window.open('/dashboards/app/discover#/?q=_index:velociraptor-*', '_blank', 'noopener');
      }
    });
  } catch (e) {
    if (kpiRoot) kpiRoot.innerHTML = `<p class="fp-alert fp-alert-err">${escIt(e.message)}</p>`;
    if (actionsRoot) actionsRoot.innerHTML = '';
  }
}

window.ItDashboard = { loadItDashboard, renderItKpis, renderItActions };
