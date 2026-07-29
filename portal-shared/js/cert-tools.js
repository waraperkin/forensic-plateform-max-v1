/* global ThreatCommon */
'use strict';

/**
 * CERT Tools — Asset Investigation, Timeline Builder, IOC Correlation.
 * Collectes ciblées Sekoia.IO (on-demand).
 */
(function () {
  const TC = window.ThreatCommon;
  if (!TC) return;

  function pick(obj, keys) { for (const k of keys) { if (obj[k] != null && obj[k] !== '') return obj[k]; } return ''; }
  function getTs(e) {
    return pick(e, ['@timestamp', 'timestamp', 'created_at', 'createdAt', 'time']) || '';
  }
  function getMsg(e) {
    return String(pick(e, ['message', 'event.action', 'description', 'action', 'rule.name']) || '').slice(0, 160);
  }

  // ── Asset Investigation ─────────────────────────────────────────────────────
  function renderInvestigation() {
    const root = document.getElementById('cert-asset-investigation-root'); if (!root) return;
    root.innerHTML = TC.fetchForm('cai') + '<div id="cai-result" class="cc-tp-result"></div>';
    document.getElementById('cai-run')?.addEventListener('click', runInvestigation);
  }
  async function runInvestigation() {
    const out = document.getElementById('cai-result');
    const q = TC.readFetchForm('cai');
    if (!(q.hostname || q.ip || q.agentId)) { TC.toast(i18n.t('msg.renseignez_hostname_ip_ou_agentid'), 'warn'); return; }
    out.innerHTML = '<p class="fp-muted">Investigation en cours…</p>';
    const sek = await TC.api('/sekoia/fetch', { method: 'POST', body: q });
    const sekEv = sek.items || [];
    out.innerHTML = TC.configBanner(sek.configured ? null : sek) + (sek.token_expired ? TC.staleBanner(sek) : '')
      + `<div class="cc-tp-dashgrid">
          ${TC.statCard('Events Sekoia', sekEv.length, 'accent')}
          ${TC.statCard('Cible', q.hostname || q.ip || q.agentId)}
        </div>`
      + (sekEv.length ? TC.sendBar() : '')
      + '<h3 class="fp-section-sub">Sekoia.IO — Events</h3>'
      + TC.table([
        { label: 'Horodatage', render: (e) => TC.esc(getTs(e) || '—') },
        { label: 'Message', render: (e) => TC.esc(getMsg(e)) },
      ], sekEv, { empty: sek.configured ? i18n.t('msg.aucun_event') : 'Sekoia non configuré' });
    if (sekEv.length) TC.bindSend(out, () => sekEv, `investigation-${(q.hostname || q.ip || q.agentId || 'target')}`);
  }

  // ── Timeline Builder ────────────────────────────────────────────────────────
  function renderTimeline() {
    const root = document.getElementById('cert-timeline-builder-root'); if (!root) return;
    root.innerHTML = TC.fetchForm('ctb') + '<div id="ctb-result" class="cc-tp-result"></div>';
    document.getElementById('ctb-run')?.addEventListener('click', runTimeline);
  }
  async function runTimeline() {
    const out = document.getElementById('ctb-result');
    const q = TC.readFetchForm('ctb');
    if (!(q.hostname || q.ip || q.agentId)) { TC.toast(i18n.t('msg.renseignez_hostname_ip_ou_agentid'), 'warn'); return; }
    out.innerHTML = `<p class="fp-muted">${i18n.t('msg.construction_de_la_timeline')}</p>`;
    const sek = await TC.api('/sekoia/fetch', { method: 'POST', body: q });
    const events = (sek.items || []).map((e) => ({ ts: getTs(e), src: 'Sekoia', msg: getMsg(e) }))
      .filter((e) => e.ts)
      .sort((a, b) => new Date(a.ts) - new Date(b.ts));
    const byHour = TC.countBy(events, (e) => String(e.ts).slice(0, 13));
    out.innerHTML = TC.configBanner(sek.configured ? null : sek)
      + `<div class="fp-actions-row"><span class="fp-muted">${events.length} évènement(s) — ordre chronologique${q.toTimesketch ? ' · transmis à Timesketch' : ''}</span></div>`
      + '<div id="ctb-chart" class="cc-tp-chart"></div>'
      + TC.table([
        { label: 'Horodatage', render: (e) => TC.esc(e.ts) },
        { label: 'Source', render: (e) => `<span class="fp-tag">${TC.esc(e.src)}</span>` },
        { label: i18n.t('msg.evenement'), render: (e) => TC.esc(e.msg) },
      ], events, { empty: i18n.t('msg.aucun_evenement_date_connecteurs_non_configures') });
    if (events.length) TC.chart('ctb-chart', TC.barOption(byHour, '#00E5FF'), 240);
  }

  // ── IOC Correlation ─────────────────────────────────────────────────────────
  function renderIoc() {
    const root = document.getElementById('cert-ioc-correlation-root'); if (!root) return;
    root.innerHTML = `<div class="cc-tp-fetchform">
        <label class="fp-label">IOC (un par ligne — IP, domaine ou hash)
          <textarea class="fp-textarea" id="ioc-input" rows="4" placeholder="10.0.0.5&#10;evil.example.com&#10;44d88612fea8a8f36de82e1278abb02f"></textarea>
        </label>
        <div class="fp-form-row fp-grid-2">
          <label class="fp-label">Plage temps
            <select class="fp-select" id="ioc-timeRange"><option value="24h" selected>24 heures</option><option value="7d">7 jours</option><option value="30d">30 jours</option></select>
          </label>
        </div>
        <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary" id="ioc-run">Corréler les IOC</button></div>
      </div><div id="ioc-result" class="cc-tp-result"></div>`;
    document.getElementById('ioc-run')?.addEventListener('click', runIoc);
  }
  function iocType(v) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ip';
    if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return 'hash';
    if (/\./.test(v)) return 'domaine';
    return 'autre';
  }
  async function runIoc() {
    const out = document.getElementById('ioc-result');
    const tr = (document.getElementById('ioc-timeRange') || {}).value || '24h';
    const iocs = (document.getElementById('ioc-input').value || '').split('\n').map((s) => s.trim()).filter(Boolean);
    if (!iocs.length) { TC.toast('Saisissez au moins un IOC', 'warn'); return; }
    out.innerHTML = '<p class="fp-muted">Corrélation en cours…</p>';
    const rows = [];
    for (const ioc of iocs) {
      const type = iocType(ioc);
      const body = { timeRange: tr };
      if (type === 'ip') body.ip = ioc; else body.hostname = ioc;
      const sek = await TC.api('/sekoia/fetch', { method: 'POST', body });
      rows.push({ ioc, type, sekoia: (sek.items || []).length });
    }
    const byIoc = {}; rows.forEach((r) => { byIoc[r.ioc.slice(0, 16)] = r.sekoia; });
    out.innerHTML = '<div id="ioc-chart" class="cc-tp-chart"></div>'
      + TC.table([
        { label: 'IOC', render: (r) => `<code>${TC.esc(r.ioc)}</code>` },
        { label: 'Type', render: (r) => `<span class="fp-tag">${TC.esc(r.type)}</span>` },
        { label: 'Hits Sekoia', render: (r) => `<strong>${TC.esc(r.sekoia)}</strong>` },
      ], rows, { empty: i18n.t('msg.aucune_correlation') });
    TC.chart('ioc-chart', TC.barOption(byIoc, '#EF4444'), 240);
  }

  window.CertTools = { renderInvestigation, renderTimeline, renderIoc, runInvestigation, runTimeline, runIoc };
  TC.bind({
    'cert-asset-investigation': renderInvestigation,
    'cert-timeline-builder': renderTimeline,
    'cert-ioc-correlation': renderIoc,
  });
}());
