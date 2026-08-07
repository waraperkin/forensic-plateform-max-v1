/* global i18n */
'use strict';

/**
 * Extended Intelligence (EI) — copilote SOC/CERT × Ollama × SEP.
 *
 * Accélère le triage des alertes SIEM Sekoia et le forensic en injectant
 * le contexte SEP live dans l’IA locale (Ollama Cybercorp recommandé).
 * Alias historique : Relais / Kheish (onglets sekoia-relais / sekoia-kheish).
 */
(function () {
  const LS_CFG = 'sep-ei-config';
  const LS_CHAT = 'sep-ei-chat';
  const LS_LEGACY_CFG = 'sep-relais-config';
  const LS_LEGACY_CHAT = 'sep-relais-chat';
  const API = '/api/threat/sekoia';

  const VIEWS = [
    { id: 'command', label: 'Command Center' },
    { id: 'triage', label: 'Triage Alertes' },
    { id: 'forensic', label: 'Forensic Desk' },
    { id: 'playbooks', label: 'Skills SIEM' },
    { id: 'warroom', label: 'War Room' },
    { id: 'engine', label: 'Moteur IA' },
    { id: 'journal', label: 'Journal' },
  ];

  /** Presets 100 % locaux uniquement — aucun cloud. */
  const LOCAL_PRESETS = [
    {
      id: 'ollama-cybercorp',
      name: 'Ollama Cybercorp',
      kind: 'ollama',
      base_url: 'http://oc-gateway:8080/v1',
      model: 'llama3.1:8b',
      hint: '100 % local · N3 recommandé (llama3.1:8b)',
    },
    {
      id: 'ollama-loopback',
      name: 'Ollama gateway (localhost)',
      kind: 'ollama',
      base_url: 'http://127.0.0.1:11435/v1',
      model: 'llama3.1:8b',
      hint: 'Depuis l’hôte uniquement — bind 127.0.0.1',
    },
    {
      id: 'lmstudio',
      name: 'LM Studio (local)',
      kind: 'openai_compatible',
      base_url: 'http://host.docker.internal:1234/v1',
      model: 'local-model',
      hint: 'On-prem uniquement',
    },
  ];

  const FALLBACK_PLAYBOOKS = [
    { id: 'alert-triage', name: 'Triage file d’alertes', mode: 'triage', desc: 'Prioriser les alertes SIEM.', tags: ['siem', 'triage'], alert_kinds: ['*'] },
    { id: 'alert-deep', name: 'Analyse approfondie alerte', mode: 'triage', desc: 'Décortiquer une alerte Sekoia.', tags: ['siem', 'deep'], alert_kinds: ['*'] },
    { id: 'alert-investigate', name: 'Investigation N3 (Qevlar-grade)', mode: 'triage', desc: 'Rapport N3 : kill-chain, hypothèses, actions.', tags: ['siem', 'investigate', 'qevlar', 'n3'], alert_kinds: ['*'] },
    { id: 'fp-coach', name: 'Coach faux positifs', mode: 'triage', desc: 'Réduire le bruit SIEM.', tags: ['tuning'], alert_kinds: ['*'] },
    { id: 'malware-alert', name: 'Malware / AV / EDR', mode: 'siem', desc: 'Malware, hash, quarantine.', tags: ['malware', 'edr'], alert_kinds: ['malware', 'edr'] },
    { id: 'ransomware-early', name: 'Ransomware (signaux précoces)', mode: 'siem', desc: 'Chiffrement, VSS, notes.', tags: ['ransomware'], alert_kinds: ['ransomware'] },
    { id: 'phishing-credential', name: 'Phishing / credentials', mode: 'siem', desc: 'Mail, lien, vol d’identifiants.', tags: ['phishing'], alert_kinds: ['phishing'] },
    { id: 'bruteforce-auth', name: 'Brute-force / auth anormale', mode: 'siem', desc: 'Spray, lockouts, géo.', tags: ['auth'], alert_kinds: ['bruteforce'] },
    { id: 'account-takeover', name: 'Account takeover / ATO', mode: 'siem', desc: 'Sessions, MFA, OAuth.', tags: ['identity'], alert_kinds: ['account', 'mfa'] },
    { id: 'lateral-movement', name: 'Mouvement latéral', mode: 'siem', desc: 'PsExec, WMI, RDP, SMB.', tags: ['lateral'], alert_kinds: ['lateral'] },
    { id: 'privilege-escalation', name: 'Élévation de privilèges', mode: 'siem', desc: 'UAC, token, sudo, Kerberos.', tags: ['privesc'], alert_kinds: ['privilege'] },
    { id: 'persistence', name: 'Persistance', mode: 'siem', desc: 'Run keys, services, tasks.', tags: ['persistence'], alert_kinds: ['persistence'] },
    { id: 'c2-beacon', name: 'C2 / beacon / proxy sortant', mode: 'siem', desc: 'Callback, beaconing.', tags: ['c2'], alert_kinds: ['c2', 'beacon'] },
    { id: 'dns-tunnel', name: 'DNS tunneling / exfil DNS', mode: 'siem', desc: 'DNS long / entropie.', tags: ['dns'], alert_kinds: ['dns'] },
    { id: 'data-exfil', name: 'Exfiltration de données', mode: 'siem', desc: 'Upload massif, cloud, USB.', tags: ['exfil'], alert_kinds: ['exfiltration'] },
    { id: 'defense-evasion', name: 'Defense evasion', mode: 'siem', desc: 'Disable AV, clear logs.', tags: ['evasion'], alert_kinds: ['evasion'] },
    { id: 'cloud-aws-abuse', name: 'Cloud AWS / IAM abuse', mode: 'siem', desc: 'CloudTrail, clés, IAM.', tags: ['aws', 'cloud'], alert_kinds: ['aws'] },
    { id: 'azure-m365-abuse', name: 'Azure / M365 abuse', mode: 'siem', desc: 'Entra ID, Exchange, OAuth.', tags: ['azure', 'm365'], alert_kinds: ['azure', 'm365'] },
    { id: 'endpoint-lolbins', name: 'LOLBins / living-off-the-land', mode: 'siem', desc: 'PowerShell, certutil, mshta.', tags: ['lolbin'], alert_kinds: ['powershell', 'lolbin'] },
    { id: 'network-ids', name: 'IDS/IPS / réseau', mode: 'siem', desc: 'Signatures, scan, exploit.', tags: ['ids'], alert_kinds: ['ids', 'ips'] },
    { id: 'supply-chain', name: 'Supply chain / package abuse', mode: 'siem', desc: 'Package, update hijack.', tags: ['supply-chain'], alert_kinds: ['supply'] },
    { id: 'web-exploit', name: 'Web exploit / WAF', mode: 'siem', desc: 'SQLi, RCE, path traversal.', tags: ['web'], alert_kinds: ['web', 'waf'] },
    { id: 'silent-sources', name: 'Sources silencieuses', mode: 'telemetry', desc: 'Intakes / hôtes muets.', tags: ['telemetry'], alert_kinds: ['intake_silent'] },
    { id: 'forensic-first-hour', name: 'Forensic — première heure', mode: 'forensic', desc: 'Plan DFIR H+1.', tags: ['dfir'], alert_kinds: ['*'] },
    { id: 'ioc-hunt', name: 'Chasse IOC', mode: 'forensic', desc: 'Pivots IOC depuis alertes.', tags: ['cti'], alert_kinds: ['*'] },
    { id: 'mitre-map', name: 'Cartographie MITRE', mode: 'forensic', desc: 'Techniques ATT&CK.', tags: ['mitre'], alert_kinds: ['*'] },
    { id: 'escalation-pack', name: 'Pack escalade CERT', mode: 'response', desc: 'Note d’escalade.', tags: ['response'], alert_kinds: ['*'] },
  ];

  const DEFAULT_CFG = {
    activeProviderId: '',
    injectContext: true,
    hours: 24,
    focusAlertId: '',
  };

  function loadJson(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      if (raw) return JSON.parse(raw);
      if (key === LS_CFG) {
        const leg = localStorage.getItem(LS_LEGACY_CFG);
        if (leg) return JSON.parse(leg);
      }
      if (key === LS_CHAT) {
        const leg = localStorage.getItem(LS_LEGACY_CHAT)
          || localStorage.getItem('sep-kheish-chat');
        if (leg) return JSON.parse(leg);
      }
      return fallback;
    } catch (_) {
      return fallback;
    }
  }
  function saveJson(key, val) {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch (_) { /* noop */ }
  }

  const st = {
    view: 'command',
    cfg: Object.assign({}, DEFAULT_CFG, loadJson(LS_CFG, {})),
    chat: loadJson(LS_CHAT, []) || [],
    llmStatus: null,
    context: null,
    lastRun: null,
    busy: false,
    msg: '',
    triageFilter: '',
    triage: {
      status: 'Pending',
      urgency: '',
      type: '',
      q: '',
      hours: 168,
      items: [],
      total: null,
      facets: {},
      statuses: ['Pending', 'Ongoing', 'Acknowledged', 'Closed', 'Rejected'],
      loading: false,
      error: '',
    },
    dossier: null,
    investigating: false,
  };

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function root() { return document.getElementById('sekoia-relais-root'); }
  function toast(msg, tone) {
    if (window.ThreatCommon && ThreatCommon.toast) ThreatCommon.toast(msg, tone || 'ok');
  }
  function nowStamp() { return new Date().toTimeString().slice(0, 8); }
  function persistCfg() { saveJson(LS_CFG, st.cfg); }
  function persistChat() { saveJson(LS_CHAT, st.chat.slice(-100)); }

  function mdLite(text) {
    const raw = String(text || '');
    const parts = raw.split(/```/);
    return parts.map((chunk, i) => {
      if (i % 2 === 1) {
        return `<pre class="ei-code">${esc(chunk)}</pre>`;
      }
      return esc(chunk)
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/^### (.+)$/gm, '<div class="ei-h3">$1</div>')
        .replace(/^## (.+)$/gm, '<div class="ei-h2">$1</div>')
        .replace(/^# (.+)$/gm, '<div class="ei-h1">$1</div>')
        .replace(/^- (.+)$/gm, '<div class="ei-li">• $1</div>')
        .replace(/^\d+\.\s+(.+)$/gm, '<div class="ei-li"><strong>$&</strong></div>')
        .replace(/^\d+\) (.+)$/gm, '<div class="ei-li"><strong>$&</strong></div>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');
    }).join('');
  }

  async function sepApi(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    if (o.body && typeof o.body !== 'string') {
      o.body = JSON.stringify(o.body);
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
    }
    const r = await fetch(API + path, o);
    const d = await r.json().catch(() => ({}));
    if (!r.ok && d && d.error) throw new Error(d.error);
    return d;
  }

  async function refreshLlm() {
    try {
      st.llmStatus = await sepApi('/llm/status');
    } catch (e) {
      st.llmStatus = {
        ok: false,
        error: String(e.message || e),
        providers: [],
        playbooks: FALLBACK_PLAYBOOKS,
        mcp_servers: [],
      };
    }
  }

  async function refreshContext() {
    try {
      const q = new URLSearchParams({
        hours: String(st.cfg.hours || 24),
      });
      if (st.cfg.focusAlertId) q.set('alert_id', st.cfg.focusAlertId);
      const r = await sepApi(`/llm/ei/context?${q}`);
      st.context = (r && r.context) || null;
    } catch (e) {
      st.context = { errors: [String(e.message || e)], sic_alerts: [], sep_ingestion_alerts: [] };
    }
  }

  async function refreshAlertFeed() {
    const t = st.triage;
    t.loading = true;
    t.error = '';
    try {
      const q = new URLSearchParams({
        hours: String(t.hours || 168),
        limit: '50',
      });
      if (t.status) q.set('status', t.status);
      if (t.urgency) q.set('urgency', t.urgency);
      if (t.type) q.set('type', t.type);
      if (t.q) q.set('q', t.q);
      const r = await sepApi(`/llm/ei/alerts?${q}`);
      if (r && r.ok === false) throw new Error(r.error || 'feed alertes');
      t.items = (r && r.items) || [];
      t.total = (r && r.total != null) ? r.total : t.items.length;
      t.facets = (r && r.facets) || {};
      // enrichir la liste des types connus
      const types = Object.keys(t.facets.type || {});
      if (types.length) t._types = Array.from(new Set([...(t._types || []), ...types])).sort();
    } catch (e) {
      t.error = String(e.message || e);
      t.items = [];
    }
    t.loading = false;
  }

  async function loadStatuses() {
    try {
      const r = await sepApi('/llm/ei/alerts/statuses');
      const names = ((r && r.items) || []).map((x) => x.name).filter(Boolean);
      if (names.length) st.triage.statuses = names;
    } catch (_) { /* defaults */ }
  }

  function fmtWhen(ts) {
    if (ts == null || ts === '') return '—';
    try {
      let n = ts;
      if (typeof n === 'number' && n < 1e12) n *= 1000;
      const d = new Date(n);
      if (Number.isNaN(d.getTime())) return String(ts).slice(0, 19);
      return d.toISOString().replace('T', ' ').slice(0, 16) + 'Z';
    } catch (_) {
      return String(ts).slice(0, 19);
    }
  }

  function sevClass(sev) {
    return 'is-' + String(sev || 'unknown').toLowerCase().replace(/[^a-z0-9]+/g, '-');
  }

  function artifactChips(arts, assetNames) {
    const names = assetNames || {};
    const rows = [];
    const order = [
      ['ip', 'IP'], ['host', 'Host'], ['user', 'User'], ['hash', 'Hash'],
      ['url', 'URL'], ['email', 'Email'], ['entity', 'Entité'], ['asset', 'Asset'],
    ];
    order.forEach(([k, label]) => {
      ((arts && arts[k]) || []).slice(0, 8).forEach((v) => {
        const shown = names[v] || v;
        rows.push(`<tr>
          <td><span class="ei-art-kind is-${esc(k)}">${esc(label)}</span></td>
          <td><code class="ei-art-val" title="${esc(shown)}">${esc(shown)}</code></td>
        </tr>`);
      });
    });
    if (!rows.length) {
      return '<p class="ei-empty">Aucun artefact structuré — ouvrez une alerte ou enrichissez via events.</p>';
    }
    return `<div class="ei-art-tablewrap"><table class="ei-art-table">
      <thead><tr><th>Type</th><th>Valeur</th></tr></thead>
      <tbody>${rows.join('')}</tbody>
    </table></div>`;
  }

  function relatedListHtml(related) {
    const rows = related || [];
    if (!rows.length) {
      return '<p class="ei-empty">Aucune alerte liée sur les pivots IP / host / asset.</p>';
    }
    return `<div class="ei-related-tablewrap"><table class="ei-related-table">
      <thead><tr>
        <th>Crit.</th><th>Type</th><th>Titre</th><th>Score</th><th>Pivot</th>
      </tr></thead>
      <tbody>${rows.map((a) => `
        <tr class="ei-related-tr" data-rl="focus-alert" data-id="${esc(a.id || '')}" data-investigate="0" role="button" tabindex="0">
          <td><span class="ei-sev ${sevClass(a.severity)}">${esc(a.severity || '?')}</span></td>
          <td><span class="ei-type-pill">${esc(a.type || '—')}</span></td>
          <td>
            <strong>${esc(a.title || 'Sans titre')}</strong>
            <div class="ei-muted">${esc(a.short_id || a.id || '')}${a.entity ? ' · ' + esc(a.entity) : ''}</div>
          </td>
          <td class="ei-num">${esc(a.link_score || 0)}</td>
          <td class="ei-pivot">${esc((a.shared_artifacts || []).slice(0, 3).join(', ') || '—')}</td>
        </tr>`).join('')}
      </tbody>
    </table></div>`;
  }

  function dossierKv(focus, d) {
    if (!focus) return '';
    const pairs = [
      ['Short ID', focus.short_id || focus.id || '—'],
      ['Statut', focus.status || '—'],
      ['Criticité', focus.severity || '—'],
      ['Type', focus.type || '—'],
      ['Catégorie', focus.category || '—'],
      ['Entité', focus.entity || '—'],
      ['Règle', focus.rule || '—'],
      ['Source', focus.source || '—'],
      ['Target', focus.target || '—'],
      ['First seen', fmtWhen(focus.created_at)],
      ['Last seen', fmtWhen(focus.updated_at)],
      ['Similar Sekoia', String((d && d.similar_declared) != null ? d.similar_declared : (focus.similar || 0))],
    ];
    return `<dl class="ei-kv">${pairs.map(([k, v]) => `
      <div class="ei-kv-row">
        <dt>${esc(k)}</dt>
        <dd title="${esc(v)}">${esc(v)}</dd>
      </div>`).join('')}</dl>`;
  }

  function playbooks() {
    const fromApi = (st.llmStatus && st.llmStatus.playbooks) || [];
    return fromApi.length ? fromApi : FALLBACK_PLAYBOOKS;
  }

  function activeProvider() {
    const items = (st.llmStatus && st.llmStatus.providers) || [];
    const id = st.cfg.activeProviderId || (st.llmStatus && st.llmStatus.default_provider_id);
    if (id) {
      const hit = items.find((p) => p.id === id && p.enabled !== false);
      if (hit) return hit;
    }
    const ollama = items.find((p) => p.kind === 'ollama' && p.enabled !== false);
    return ollama || items.find((p) => p.enabled !== false) || null;
  }

  function statusChips() {
    const p = activeProvider();
    const ctx = st.context || {};
    const nSic = (ctx.sic_alerts || []).length;
    const nSep = (ctx.sep_ingestion_alerts || []).length;
    const aiCls = p ? 'is-ok is-live' : 'is-off';
    return `
      <span class="rl-chip ${aiCls}"><span class="rl-dot"></span>
        ${p ? esc(p.name) : 'IA offline'}</span>
      <span class="rl-chip is-ok">100% local</span>
      <span class="rl-chip">SIEM ${nSic}${ctx.sic_total != null ? '/' + esc(ctx.sic_total) : ''}</span>
      <span class="rl-chip">Ingest ${nSep}</span>
      <span class="rl-chip">${st.cfg.injectContext ? 'Contexte ON' : 'Contexte OFF'}</span>
      <span class="rl-chip">${esc(st.cfg.hours || 24)}h</span>`;
  }

  function verdictStrip(text) {
    const t = String(text || '').toLowerCase();
    let tone = 'muted';
    let label = 'analyse';
    if (/critique|critical|p0/.test(t)) { tone = 'danger'; label = 'critique'; }
    else if (/élevé|eleve|high/.test(t)) { tone = 'warn'; label = 'élevé'; }
    else if (/moyen|medium/.test(t)) { tone = 'accent'; label = 'moyen'; }
    else if (/faible|bruit|faux positif|fp|low/.test(t)) { tone = 'ok'; label = 'faible / bruit'; }
    else if (/insuffisant/.test(t)) { tone = 'muted'; label = 'données insuffisantes'; }
    return `<span class="ei-verdict is-${tone}">${esc(label)}</span>`;
  }

  /* ─── Views ─── */

  function commandHtml() {
    const p = activeProvider();
    const ctx = st.context || {};
    const sic = ctx.sic_alerts || [];
    const sep = ctx.sep_ingestion_alerts || [];
    const errs = ctx.errors || [];
    const sev = ctx.sep_by_severity || {};
    return `
      <div class="ei-hero">
        <div>
          <div class="ei-kicker">Sekoia Extended Platform</div>
          <h3>Extended Intelligence</h3>
          <p>Pousse le maximum de SEP et des analystes : triage SIEM accéléré,
          forensic guidé, contexte live injecté dans Ollama — décisions humaines.</p>
        </div>
        <div class="ei-hero-actions">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="pb-run" data-id="alert-triage"
            ${st.busy || !p ? 'disabled' : ''}>Trier les alertes</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="pb-run" data-id="forensic-first-hour"
            ${st.busy || !p ? 'disabled' : ''}>Forensic H+1</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="ctx-refresh">Rafraîchir contexte</button>
        </div>
      </div>
      <div class="rl-kpi-row">
        <div class="rl-kpi"><b>${p ? 'LIVE' : 'OFF'}</b><span>Moteur IA</span></div>
        <div class="rl-kpi"><b>${playbooks().length}</b><span>Skills EI</span></div>
        <div class="rl-kpi"><b>${esc(ctx.sic_total != null ? ctx.sic_total : sic.length)}</b><span>Alertes SIEM</span></div>
        <div class="rl-kpi"><b>${sep.length}</b><span>Alertes ingestion</span></div>
        <div class="rl-kpi"><b>${Object.keys(sev).length}</b><span>Sévérités ingest</span></div>
      </div>
      ${errs.length ? `<div class="ei-banner is-warn">Contexte partiel : ${esc(errs.slice(0, 3).join(' · '))}</div>` : ''}
      <div class="ei-split">
        <div class="rl-card">
          <h4>File SIEM (échantillon)</h4>
          <div class="ei-alert-list">
            ${sic.slice(0, 6).map((a) => `
              <button type="button" class="ei-alert-row" data-rl="focus-alert" data-id="${esc(a.id || '')}">
                <span class="ei-sev">${esc(a.severity || '?')}</span>
                <span class="ei-alert-main">
                  <strong>${esc(a.title || 'Sans titre')}</strong>
                  <small>${esc(a.entity || '—')} · ${esc(a.status || '')}</small>
                </span>
              </button>`).join('')
              || '<p class="fp-muted">Aucune alerte SIEM dans le contexte — vérifiez le token Sekoia.</p>'}
          </div>
          <div class="rl-toolbar">
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="view" data-view="triage">Ouvrir triage</button>
          </div>
        </div>
        <div class="rl-card">
          <h4>Ingestion SEP</h4>
          <div class="ei-sev-bars">
            ${Object.keys(sev).length
              ? Object.entries(sev).map(([k, v]) => `
                <div class="ei-sev-bar"><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join('')
              : '<p class="fp-muted">Pas d’agrégat ingestion sur la fenêtre.</p>'}
          </div>
          <ul class="ei-mini-list">
            ${sep.slice(0, 5).map((a) => `
              <li><strong>${esc(a.rule_type || 'alert')}</strong> — ${esc(a.title || a.subject || '')}</li>`
            ).join('') || '<li class="fp-muted">RAS ingestion</li>'}
          </ul>
        </div>
      </div>
      ${st.lastRun && st.lastRun.text ? `
        <div class="rl-card ei-last">
          <div class="rl-panel-head">
            <h4>Dernière analyse EI ${verdictStrip(st.lastRun.text)}</h4>
            <span class="rl-hint">${esc((st.lastRun.playbook && st.lastRun.playbook.name) || 'War Room')} · ${esc(st.lastRun.t || '')}</span>
          </div>
          <div class="ei-answer">${mdLite(st.lastRun.text)}</div>
        </div>` : ''}`;
  }

  function triageHtml() {
    const p = activeProvider();
    const t = st.triage;
    const rows = t.items || [];
    const d = st.dossier;
    const focus = (d && d.alert) || rows.find((a) => a.id === st.cfg.focusAlertId)
      || ((st.context && st.context.target_alert) || null);
    const types = t._types || Object.keys((t.facets && t.facets.type) || {}).sort();
    const arts = (d && d.artifacts) || (st.context && st.context.target_artifacts) || null;
    const related = (d && d.related_alerts) || (st.context && st.context.related_alerts) || [];
    const nMajor = rows.filter((a) => /major|urgent|critical|high/i.test(String(a.severity || ''))).length;
    const sug = suggestSkillsForAlert(focus || { title: t.q, type: t.type });
    const hasReport = !!(st.lastRun && st.lastRun.text);
    return `
      <div class="ei-wb">
        <div class="ei-wb-head">
          <div>
            <h3>Triage Alertes SIEM</h3>
            <p class="ei-wb-sub">Poste analyste — sélectionnez une alerte, lisez le dossier, lancez le rapport N3.</p>
          </div>
          <div class="ei-wb-kpis">
            <div class="ei-wb-kpi"><b>${esc(rows.length)}</b><span>affichées</span></div>
            <div class="ei-wb-kpi"><b>${t.total != null ? esc(t.total) : '—'}</b><span>total filtre</span></div>
            <div class="ei-wb-kpi ${nMajor ? 'is-hot' : ''}"><b>${esc(nMajor)}</b><span>élevées / majeures</span></div>
            <div class="ei-wb-kpi"><b>${esc(related.length || 0)}</b><span>liées (focus)</span></div>
            <div class="ei-wb-kpi ei-wb-kpi--engine">
              <b>${p ? esc((p.model || p.name || 'IA').split(':')[0]) : 'off'}</b>
              <span>${p ? 'moteur local' : 'IA offline'}</span>
            </div>
          </div>
        </div>

        <div class="ei-wb-filters">
          <label class="ei-flabel">Statut
            <select class="fp-input" id="ei-f-status">
              <option value="">Tous</option>
              ${t.statuses.map((s) =>
                `<option value="${esc(s)}"${t.status === s ? ' selected' : ''}>${esc(s)}</option>`).join('')}
            </select>
          </label>
          <label class="ei-flabel">Criticité
            <select class="fp-input" id="ei-f-urgency">
              <option value=""${!t.urgency ? ' selected' : ''}>Toutes</option>
              <option value="high"${t.urgency === 'high' ? ' selected' : ''}>High / Major / Urgent</option>
              <option value="medium"${t.urgency === 'medium' ? ' selected' : ''}>Medium</option>
              <option value="low"${t.urgency === 'low' ? ' selected' : ''}>Low / Moderate</option>
            </select>
          </label>
          <label class="ei-flabel">Type
            <select class="fp-input" id="ei-f-type">
              <option value="">Tous</option>
              ${types.map((ty) =>
                `<option value="${esc(ty)}"${t.type === ty ? ' selected' : ''}>${esc(ty)}</option>`).join('')}
            </select>
          </label>
          <label class="ei-flabel">Fenêtre
            <select class="fp-input" id="ei-f-hours">
              ${[24, 72, 168, 720].map((h) =>
                `<option value="${h}"${Number(t.hours) === h ? ' selected' : ''}>${h}h</option>`).join('')}
            </select>
          </label>
          <label class="ei-flabel ei-flabel--grow">Recherche
            <input class="fp-input" id="ei-triage-q" placeholder="Titre, entité, règle, IP, short ID…"
              value="${esc(t.q || st.triageFilter)}">
          </label>
          <div class="ei-wb-filter-actions">
            <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="triage-apply"
              ${t.loading ? 'disabled' : ''}>Appliquer</button>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="pb-run" data-id="alert-triage"
              ${st.busy || !p ? 'disabled' : ''}>Trier la file (IA)</button>
          </div>
        </div>
        ${t.error ? `<div class="ei-banner is-warn">${esc(t.error)}</div>` : ''}
        ${t.loading ? '<div class="ei-banner">Chargement de la file SIEM…</div>' : ''}

        <div class="ei-wb-split">
          <section class="ei-wb-queue" aria-label="File d’alertes">
            <div class="ei-wb-colhead">
              <h4>File</h4>
              <span class="ei-muted">${esc(t.hours)}h · clic = dossier</span>
            </div>
            <div class="ei-queue-list">
              ${rows.map((a) => `
                <button type="button" class="ei-qrow${(st.cfg.focusAlertId === a.id) ? ' is-focus' : ''}"
                  data-rl="focus-alert" data-id="${esc(a.id || '')}" data-investigate="1">
                  <div class="ei-qrow-top">
                    <span class="ei-sev ${sevClass(a.severity)}">${esc(a.severity || '?')}</span>
                    <span class="ei-type-pill">${esc(a.type || '—')}</span>
                    <span class="ei-status-pill">${esc(a.status || '—')}</span>
                  </div>
                  <strong class="ei-qrow-title">${esc(a.title || 'Sans titre')}</strong>
                  <div class="ei-qrow-meta">
                    <span>${esc(a.entity || '—')}</span>
                    <span>${esc(a.short_id || '')}</span>
                  </div>
                  <div class="ei-qrow-meta">
                    <span>${a.source ? 'src ' + esc(a.source) : esc((a.rule || '').slice(0, 42) || '—')}</span>
                    <span>${esc(fmtWhen(a.created_at).slice(5, 16))}</span>
                  </div>
                </button>`).join('')
                || `<p class="ei-empty">${t.loading ? 'Chargement…' : 'Aucune alerte pour ces filtres.'}</p>`}
            </div>
          </section>

          <section class="ei-wb-workspace" aria-label="Dossier et rapport">
            ${focus ? `
              <div class="ei-wb-dossier">
                <div class="ei-dossier-hero">
                  <div class="ei-dossier-hero-main">
                    <div class="ei-qrow-top">
                      <span class="ei-sev ${sevClass(focus.severity)}">${esc(focus.severity || '?')}</span>
                      <span class="ei-type-pill">${esc(focus.type || '—')}</span>
                      <span class="ei-status-pill">${esc(focus.status || '—')}</span>
                      <code class="ei-id">${esc(focus.short_id || focus.id || '')}</code>
                    </div>
                    <h4 class="ei-dossier-title">${esc(focus.title || 'Sans titre')}</h4>
                    <p class="ei-dossier-rule">${esc(focus.rule || '—')} · ${esc(focus.entity || '—')}</p>
                  </div>
                  <div class="ei-dossier-actions">
                    <button type="button" class="fp-btn fp-btn-primary" data-rl="investigate"
                      ${st.busy || st.investigating || !p ? 'disabled' : ''}>
                      ${st.investigating ? 'Analyse N3…' : 'Rapport N3 (IA)'}
                    </button>
                    <button type="button" class="fp-btn fp-btn-ghost" data-rl="investigate-fast"
                      ${st.busy || st.investigating ? 'disabled' : ''}>Socle factuel</button>
                  </div>
                </div>
                <div class="ei-dossier-body">
                  <div class="ei-dossier-col">
                    <h5>Identité alerte</h5>
                    ${dossierKv(focus, d)}
                  </div>
                  <div class="ei-dossier-col">
                    <h5>Artefacts</h5>
                    ${arts ? artifactChips(arts, (d && d.asset_names) || focus.asset_names)
                      : '<p class="ei-empty">Chargement des artefacts…</p>'}
                  </div>
                </div>
                <div class="ei-dossier-related">
                  <div class="ei-wb-colhead">
                    <h5>Alertes liées · ${esc(related.length)}</h5>
                    <span class="ei-muted">même IP / asset / source — clic pour pivoter</span>
                  </div>
                  ${relatedListHtml(related)}
                </div>
              </div>
            ` : `
              <div class="ei-wb-empty">
                <h4>Aucune alerte sélectionnée</h4>
                <p>Choisissez une alerte dans la file pour afficher le dossier complet
                  (identité, artefacts, corrélations) puis générer le rapport N3.</p>
              </div>`}

            <div class="ei-wb-report">
              <div class="ei-wb-colhead">
                <h4>Rapport d’investigation ${hasReport ? verdictStrip(st.lastRun.text) : ''}</h4>
                <span class="ei-muted">${st.investigating ? 'génération en cours…'
                  : (hasReport ? esc(st.lastRun.t || '') : 'en attente')}</span>
              </div>
              <div class="ei-wb-tools">
                <textarea class="ei-note" id="ei-triage-note" rows="2"
                  placeholder="Note analyste (contexte métier, hypothèse FP, change ticket…) — injectée dans le rapport N3"></textarea>
                <div class="ei-wb-toolrow">
                  <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="pb-run" data-id="alert-deep"
                    ${st.busy || !p || !focus ? 'disabled' : ''}>Analyse approfondie</button>
                  <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="pb-run" data-id="fp-coach"
                    ${st.busy || !p ? 'disabled' : ''}>Coach FP</button>
                  <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="pb-run" data-id="escalation-pack"
                    ${st.busy || !p ? 'disabled' : ''}>Pack escalade</button>
                  ${sug.length ? `<span class="ei-muted ei-skills-label">Skills :</span>
                    ${sug.slice(0, 3).map((s) =>
                      `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="pb-run" data-id="${esc(s.id)}"
                        ${st.busy || !p ? 'disabled' : ''}>${esc(s.name)}</button>`).join('')}` : ''}
                </div>
              </div>
              <div class="ei-answer ei-answer--report" id="ei-triage-out">${hasReport
                ? mdLite(st.lastRun.text)
                : `<div class="ei-report-placeholder">
                    <p><strong>Le rapport N3 s’affichera ici</strong></p>
                    <p>Verdict · chronologie · artefacts · corrélation · hypothèses · actions P0/P1/P2 · hunting · escalade CERT.</p>
                    <p class="ei-muted">Astuce : « Socle factuel » = immédiat · « Rapport N3 (IA) » = enrichissement IR.</p>
                  </div>`}</div>
            </div>
          </section>
        </div>
      </div>`;
  }

  function forensicHtml() {
    const p = activeProvider();
    return `
      <div class="rl-panel">
        <div class="rl-panel-head">
          <h3>Forensic Desk</h3>
          <span class="rl-hint">DFIR guidé par le contexte SEP + Ollama</span>
        </div>
        <p class="fp-muted ei-lead">Première heure, chasse IOC, cartographie ATT&amp;CK — toujours ancré sur les alertes et la télémétrie SEP.</p>
        <div class="rl-matrix">
          ${playbooks().filter((pb) => pb.mode === 'forensic' || (pb.tags || []).includes('dfir')
            || (pb.tags || []).includes('cti') || (pb.tags || []).includes('mitre')).map((pb) => `
            <div class="rl-skill">
              <h4>${esc(pb.name)}</h4>
              <p>${esc(pb.desc || '')}</p>
              <div class="rl-skill-tags">${(pb.tags || []).map((t) =>
                `<span class="rl-pill">${esc(t)}</span>`).join('')}</div>
              <div class="rl-skill-actions">
                <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="pb-run" data-id="${esc(pb.id)}"
                  ${st.busy || !p ? 'disabled' : ''}>Exécuter</button>
              </div>
            </div>`).join('')}
        </div>
        <div class="rl-card" style="margin-top:.75rem">
          <h4>Brief forensic libre</h4>
          <textarea class="rl-chat-input" id="ei-forensic-note" placeholder="Ex. HOST-X suspect, hash …, besoin timeline 6h…"></textarea>
          <div class="rl-toolbar">
            <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="forensic-brief"
              ${st.busy || !p ? 'disabled' : ''}>Plan forensic EI</button>
          </div>
          <div class="ei-answer">${st.lastRun && st.lastRun.mode === 'forensic' && st.lastRun.text
            ? mdLite(st.lastRun.text) : '<span class="fp-muted">Résultat forensic…</span>'}</div>
        </div>
      </div>`;
  }

  const MODE_LABELS = {
    siem: 'Alertes SIEM Sekoia',
    triage: 'Triage',
    forensic: 'Forensic',
    response: 'Réponse CERT',
    telemetry: 'Télémétrie / ingestion',
  };

  function suggestSkillsForAlert(alert) {
    const blob = [
      JSON.stringify(alert || {}),
      (alert && alert.type) || '',
      (alert && alert.category) || '',
      (alert && alert.title) || '',
    ].join(' ').toLowerCase();
    const scored = playbooks().filter((pb) => pb.mode === 'siem' || pb.id === 'alert-investigate').map((pb) => {
      const kinds = pb.alert_kinds || [];
      let score = pb.id === 'alert-investigate' ? 1 : 0;
      kinds.forEach((k) => { if (k !== '*' && blob.includes(String(k).toLowerCase())) score += 2; });
      (pb.tags || []).forEach((k) => { if (blob.includes(String(k).toLowerCase())) score += 1; });
      return { pb, score };
    }).filter((x) => x.score > 0).sort((a, b) => b.score - a.score);
    return scored.slice(0, 5).map((x) => x.pb);
  }

  function playbooksHtml() {
    const p = activeProvider();
    const groups = {};
    const order = ['siem', 'triage', 'forensic', 'response', 'telemetry'];
    playbooks().forEach((pb) => {
      const m = pb.mode || 'ops';
      (groups[m] = groups[m] || []).push(pb);
    });
    const modes = order.filter((m) => groups[m] && groups[m].length)
      .concat(Object.keys(groups).filter((m) => !order.includes(m)));
    return `
      <div class="rl-panel">
        <div class="rl-panel-head">
          <h3>Skills Extended Intelligence</h3>
          <span class="rl-hint">${playbooks().length} skills · Ollama local</span>
        </div>
        <p class="fp-muted ei-lead">Chaque skill injecte le CONTEXTE SEP (alertes SIEM Sekoia) dans Ollama
          et impose le format verdict / actions. Choisissez le skill adapté au type d’alerte.</p>
        ${modes.map((mode) => `
          <h4 class="ei-mode-label">${esc(MODE_LABELS[mode] || mode)} · ${groups[mode].length}</h4>
          <div class="rl-matrix" style="margin-bottom:.85rem">
            ${groups[mode].map((pb) => `
              <div class="rl-skill">
                <h4>${esc(pb.name)}</h4>
                <p>${esc(pb.desc || '')}</p>
                <div class="rl-skill-tags">${(pb.tags || []).map((t) =>
                  `<span class="rl-pill">${esc(t)}</span>`).join('')}</div>
                <div class="rl-skill-actions">
                  <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="pb-run" data-id="${esc(pb.id)}"
                    ${st.busy || !p ? 'disabled' : ''}>Lancer</button>
                </div>
              </div>`).join('')}
          </div>`).join('')}
      </div>`;
  }

  function warroomHtml() {
    const p = activeProvider();
    const log = (st.chat.length ? st.chat : [{
      role: 'assistant',
      text: 'War Room EI prêt. Contexte SEP injecté à chaque message. Posez une question SOC ou collez un extrait d’alerte.',
      t: '—',
    }]).map((m) => `
      <div class="rl-chat-msg is-${esc(m.role)}">
        <div class="rl-chat-meta">${esc(m.role)} · ${esc(m.t || '')}${m.meta ? ' · ' + esc(m.meta) : ''}</div>
        <div class="rl-chat-bubble">${m.role === 'assistant' ? mdLite(m.text) : esc(m.text)}</div>
      </div>`).join('');
    return `
      <div class="rl-panel">
        <div class="rl-panel-head">
          <h3>War Room</h3>
          <span class="rl-hint">${p ? `modèle · ${esc(p.model || p.name)}` : 'branchez Ollama'}</span>
        </div>
        <div class="rl-chat-log" id="rl-chat-log">${log}</div>
        <textarea class="rl-chat-input" id="rl-chat-input" placeholder="Ex. Priorise ces alertes pour le shift · pivots forensic sur l’entité focus…"></textarea>
        <div class="rl-toolbar">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="chat-send" ${st.busy ? 'disabled' : ''}>Envoyer</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="chat-clear">Vider</button>
          <label class="ei-toggle">
            <input type="checkbox" id="ei-inject" data-rl="toggle-inject" ${st.cfg.injectContext ? 'checked' : ''}>
            Injecter contexte SEP
          </label>
          <span class="rl-spacer"></span>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="view" data-view="engine">Moteur IA</button>
        </div>
      </div>`;
  }

  function engineHtml() {
    const providers = (st.llmStatus && st.llmStatus.providers) || [];
    const mcps = (st.llmStatus && st.llmStatus.mcp_servers) || [];
    const activeId = (activeProvider() || {}).id || '';
    const pRows = providers.map((p) => `<tr>
      <td>
        <label class="rl-hint" style="display:inline-flex;align-items:center;gap:.35rem">
          <input type="radio" name="rl-active-llm" data-rl="set-active" data-id="${esc(p.id)}"
            ${p.id === activeId ? ' checked' : ''}>
          <strong>${esc(p.name)}</strong>
        </label>
        <br><span class="fp-muted">${esc(p.kind)} · ${esc(p.model || '—')}</span>
      </td>
      <td><code class="fp-muted">${esc(p.base_url || '—')}</code></td>
      <td>${p.has_api_key ? 'clé ✓' : 'sans clé'} · ${p.enabled === false ? 'off' : 'on'}</td>
      <td>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-rl="llm-test" data-id="${esc(p.id)}">Tester</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-danger-ghost" data-rl="llm-del" data-id="${esc(p.id)}">Retirer</button>
      </td>
    </tr>`).join('');
    const presets = LOCAL_PRESETS.map((pr) => `
      <button type="button" class="rl-skill" data-rl="preset" data-preset="${esc(pr.id)}">
        <h4>${esc(pr.name)}</h4>
        <p>${esc(pr.hint)}</p>
        <code class="fp-muted" style="font-size:.7rem">${esc(pr.base_url)}</code>
      </button>`).join('');
    const mRows = mcps.map((m) => `<tr>
      <td><strong>${esc(m.name)}</strong></td>
      <td><code class="fp-muted">${esc(m.url || m.command || '—')}</code></td>
      <td>${(m.last_tools || []).slice(0, 5).map(esc).join(', ') || '—'}</td>
      <td>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-rl="mcp-probe" data-id="${esc(m.id)}">Probe</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-danger-ghost" data-rl="mcp-del" data-id="${esc(m.id)}">Retirer</button>
      </td>
    </tr>`).join('');
    return `
      <div class="rl-panel">
        <div class="rl-panel-head"><h3>Moteur IA — 100 % local</h3></div>
        <div class="ei-banner" style="margin-bottom:.75rem">
          <strong>Aucune donnée ne quitte l’hôte.</strong>
          Inférence Ollama on-prem uniquement — OpenAI / Anthropic / clouds refusés
          (<code>EI_LOCAL_ONLY</code>). Accès SEP → <code>http://oc-gateway:8080/v1</code>
          (gateway bind <code>127.0.0.1</code>).
        </div>
        <p class="fp-muted ei-lead">
          Stack : <strong>Ollama Cybercorp</strong> · après <code>join-sep-network.sh</code> ·
          clés Fernet control-plane.
        </p>
        <div class="rl-card">
          <h4>Fenêtre & focus</h4>
          <div class="rl-form-grid">
            <label class="fp-label">Heures contexte
              <input class="fp-input" id="ei-hours" type="number" min="1" max="168" value="${esc(st.cfg.hours || 24)}">
            </label>
            <label class="fp-label">Alert ID focus
              <input class="fp-input" id="ei-focus" value="${esc(st.cfg.focusAlertId || '')}" placeholder="uuid alerte Sekoia">
            </label>
          </div>
          <div class="rl-toolbar">
            <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="cfg-save">Enregistrer</button>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="ctx-refresh">Charger contexte</button>
          </div>
        </div>
        <h4 style="margin:.85rem 0 .45rem;font-size:.85rem">Presets</h4>
        <div class="rl-matrix" style="margin-bottom:.85rem">${presets}</div>
        <div class="rl-card">
          <h4>Ajouter manuellement</h4>
          <div class="rl-form-grid">
            <label class="fp-label">Nom<input class="fp-input" id="rl-llm-name" placeholder="Ollama Cybercorp"></label>
            <label class="fp-label">Kind
              <select class="fp-select" id="rl-llm-kind">
                <option value="ollama">Ollama (local)</option>
                <option value="openai_compatible">OpenAI-compatible (local)</option>
              </select>
            </label>
            <label class="fp-label">Base URL<input class="fp-input" id="rl-llm-url" placeholder="http://oc-gateway:8080/v1"></label>
            <label class="fp-label">Modèle<input class="fp-input" id="rl-llm-model" placeholder="llama3.2:3b"></label>
            <label class="fp-label">API key<input class="fp-input" id="rl-llm-key" type="password" autocomplete="off"></label>
          </div>
          <div class="rl-toolbar">
            <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="llm-add">Enregistrer</button>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="llm-refresh">Rafraîchir</button>
          </div>
        </div>
        <div class="fp-table-wrap" style="margin-top:.65rem"><table class="rl-table fp-table">
          <thead><tr><th>Fournisseur</th><th>URL</th><th>Auth</th><th></th></tr></thead>
          <tbody>${pRows || '<tr><td colspan="4" class="fp-muted">Aucune IA — preset Ollama Cybercorp</td></tr>'}</tbody>
        </table></div>
        <div class="rl-card" style="margin-top:.85rem">
          <h4>MCP distants</h4>
          <div class="rl-form-grid">
            <label class="fp-label">Nom<input class="fp-input" id="rl-mcp-name"></label>
            <label class="fp-label">URL<input class="fp-input" id="rl-mcp-url" placeholder="http://host.docker.internal:3001/mcp"></label>
            <label class="fp-label">Bearer<input class="fp-input" id="rl-mcp-token" type="password" autocomplete="off"></label>
          </div>
          <div class="rl-toolbar">
            <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="mcp-add">Ajouter MCP</button>
          </div>
          <div class="fp-table-wrap" style="margin-top:.55rem"><table class="rl-table fp-table">
            <thead><tr><th>Serveur</th><th>Endpoint</th><th>Tools</th><th></th></tr></thead>
            <tbody>${mRows || '<tr><td colspan="4" class="fp-muted">Aucun MCP distant</td></tr>'}</tbody>
          </table></div>
        </div>
        <div id="rl-ai-msg" class="fp-muted" style="margin-top:.55rem;font-size:.8rem">${esc(st.msg)}</div>
      </div>`;
  }

  function journalHtml() {
    const rows = st.chat.slice().reverse().slice(0, 50).map((m) => `<tr>
      <td>${esc(m.t || '')}</td>
      <td>${esc(m.role)}</td>
      <td>${esc((m.text || '').slice(0, 180))}</td>
    </tr>`).join('');
    return `
      <div class="rl-panel">
        <div class="rl-panel-head"><h3>Journal EI</h3>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="chat-clear">Purger</button>
        </div>
        <div class="fp-table-wrap"><table class="rl-table fp-table">
          <thead><tr><th>Heure</th><th>Rôle</th><th>Extrait</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="3" class="fp-muted">Aucune activité</td></tr>'}</tbody>
        </table></div>
      </div>`;
  }

  function mainHtml() {
    if (st.view === 'triage') return triageHtml();
    if (st.view === 'forensic') return forensicHtml();
    if (st.view === 'playbooks') return playbooksHtml();
    if (st.view === 'warroom' || st.view === 'chat') return warroomHtml();
    if (st.view === 'engine' || st.view === 'ai') return engineHtml();
    if (st.view === 'journal') return journalHtml();
    return commandHtml();
  }

  function sideHtml() {
    const p = activeProvider();
    const ctx = st.context || {};
    return `
      <p class="rl-section-label">Poste analyste</p>
      <div class="rl-card">
        <h4>Moteur</h4>
        <p>${p
          ? `${esc(p.name)} · <code>${esc(p.model || '—')}</code>`
          : 'Offline — Moteur IA → Ollama Cybercorp'}</p>
        <div class="rl-bind">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="view" data-view="engine">Configurer</button>
        </div>
      </div>
      <div class="rl-card">
        <h4>Contexte SEP</h4>
        <p>${(ctx.sic_alerts || []).length} SIEM · ${(ctx.sep_ingestion_alerts || []).length} ingest
          ${st.cfg.focusAlertId ? `<br>Focus <code>${esc(st.cfg.focusAlertId.slice(0, 13))}…</code>` : ''}</p>
        <div class="rl-bind">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="ctx-refresh">Refresh</button>
        </div>
      </div>
      <div class="rl-card">
        <h4>Raccourcis</h4>
        <div class="rl-bind">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="pb-run" data-id="alert-triage">Triage</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="pb-run" data-id="forensic-first-hour">Forensic</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="pb-run" data-id="escalation-pack">Escalade</button>
        </div>
      </div>
      <div class="rl-card">
        <h4>Doctrine</h4>
        <p>Contexte SEP = vérité · Ollama = accélérateur · Analyste = décideur.</p>
      </div>`;
  }

  function paint() {
    const el = root();
    if (!el) return;
    const workbench = st.view === 'triage' || st.view === 'forensic';
    const p = activeProvider();
    el.className = 'rl-root ei-root' + (workbench ? ' is-workbench' : '');
    el.innerHTML = `
      <header class="rl-top">
        <div class="rl-brand">
          <div class="ei-kicker">SEP · CYBERCORP</div>
          <h2>Extended Intelligence</h2>
          <p>Triage SIEM Sekoia + forensic accélérés par Ollama, ancrés sur le contexte SEP live.</p>
        </div>
        <div class="rl-chips">${statusChips()}${st.busy || st.investigating
          ? '<span class="rl-chip is-live">EI en cours…</span>' : ''}</div>
      </header>
      <nav class="rl-subnav" aria-label="Extended Intelligence">${VIEWS.map((v) =>
        `<button type="button" class="rl-tab${st.view === v.id ? ' is-active' : ''}" data-rl="view" data-view="${v.id}">${esc(v.label)}</button>`
      ).join('')}</nav>
      <div class="rl-body${workbench ? ' is-workbench' : ''}">
        ${workbench ? '' : `
        <aside class="rl-rail">
          <p class="rl-section-label">Modules</p>
          ${VIEWS.map((v) => `
            <button type="button" class="rl-session${st.view === v.id ? ' is-active' : ''}" data-rl="view" data-view="${v.id}">
              <div class="rl-session-title"><span>${esc(v.label)}</span></div>
            </button>`).join('')}
        </aside>`}
        <section class="rl-main">${mainHtml()}</section>
        ${workbench ? '' : `<aside class="rl-side">${sideHtml()}</aside>`}
      </div>
      <footer class="rl-footer-bar">
        <span>Extended Intelligence × SEP · Ollama</span>
        <span>${esc(st.view)} · ${esc((p || {}).name || 'off')}</span>
      </footer>`;
    bind(el);
    const chatLog = document.getElementById('rl-chat-log');
    if (chatLog) chatLog.scrollTop = chatLog.scrollHeight;
    const report = document.getElementById('ei-triage-out');
    if (report && st.lastRun && st.lastRun.text && st.view === 'triage') {
      report.scrollTop = 0;
    }
  }

  async function selectAlert(alertId, opts) {
    const id = String(alertId || '').trim();
    if (!id) return;
    st.cfg.focusAlertId = id;
    persistCfg();
    try {
      const q = new URLSearchParams({ hours: String(st.triage.hours || 720) });
      const r = await sepApi(`/llm/ei/alerts/${encodeURIComponent(id)}?${q}`);
      if (r && r.ok) {
        st.dossier = r;
        if (st.context) {
          st.context.target_alert = r.alert;
          st.context.target_artifacts = r.artifacts;
          st.context.related_alerts = r.related_alerts;
        }
      } else {
        st.dossier = null;
        toast((r && r.error) || 'Dossier alerte indisponible', 'err');
      }
    } catch (e) {
      st.dossier = null;
      toast(e.message || String(e), 'err');
    }
    // Afficher dossier + alertes liées avant l’appel LLM
    paint();
    if (opts && opts.investigate) {
      // Clic : dossier + corrélation immédiats (sans attendre Ollama)
      await runInvestigate({ useLlm: false });
    }
  }

  async function runInvestigate(opts) {
    const silent = opts && opts.silentPaint;
    const useLlm = !(opts && opts.useLlm === false);
    if (st.investigating) return;
    const p = activeProvider();
    const alertId = st.cfg.focusAlertId;
    if (!alertId) {
      toast('Sélectionnez une alerte', 'err');
      return;
    }
    if (useLlm && !p) {
      toast('Branchez Ollama (Moteur IA)', 'err');
      st.view = 'engine';
      paint();
      return;
    }
    st.investigating = true;
    st.busy = true;
    st.msg = useLlm ? 'Rapport N3 IA en cours (peut prendre plusieurs minutes)…' : 'Socle N3 factuel…';
    if (!silent) paint();
    try {
      const note = ((document.getElementById('ei-triage-note') || {}).value || '').trim();
      const r = await sepApi('/llm/ei/investigate', {
        method: 'POST',
        body: {
          alert_id: alertId,
          provider_id: (p && p.id) || '',
          user_note: note,
          hours: st.triage.hours || 720,
          max_tokens: useLlm ? 550 : 200,
          use_llm: useLlm,
        },
      });
      if (r && r.dossier) st.dossier = Object.assign({}, st.dossier || {}, r.dossier, { ok: true });
      if (r && r.ok && r.text) {
        const prefix = r.ai === false
          ? '_(Socle N3 factuel SEP — lancez « Rapport N3 (IA) » pour l’analyse complète)_\n\n'
          : '_(Rapport N3 / CERT — Extended Intelligence)_\n\n';
        st.lastRun = {
          text: prefix + r.text,
          t: nowStamp(),
          playbook: r.playbook || { name: 'Investigation N3', mode: 'triage' },
          mode: 'triage',
          ai: r.ai !== false,
          quality: 'n3',
        };
        st.chat.push({
          role: 'user',
          text: `[N3 ${useLlm ? 'IA' : 'socle'}] ${alertId}${note ? ' — ' + note : ''}`,
          t: nowStamp(),
        });
        st.chat.push({
          role: 'assistant',
          text: prefix + r.text,
          t: nowStamp(),
          meta: r.ai === false ? 'n3-scaffold' : 'n3-report',
        });
        persistChat();
        toast(r.ai === false ? 'Socle N3 prêt' : 'Rapport N3 prêt', 'ok');
      } else {
        toast((r && r.error) || 'Échec investigation', 'err');
      }
    } catch (e) {
      toast(e.message || String(e), 'err');
    }
    st.investigating = false;
    st.busy = false;
    if (!silent) paint();
  }

  async function runPlaybook(id, note) {
    if (st.busy) return;
    const p = activeProvider();
    if (!p) {
      toast('Branchez Ollama (Moteur IA)', 'err');
      st.view = 'engine';
      paint();
      return;
    }
    if (id === 'alert-investigate') {
      await runInvestigate();
      return;
    }
    st.busy = true;
    st.msg = 'EI analyse…';
    paint();
    try {
      const body = {
        playbook_id: id,
        provider_id: p.id,
        user_note: note || '',
        alert_id: st.cfg.focusAlertId || '',
        hours: st.cfg.hours || 24,
        inject_context: st.cfg.injectContext !== false,
        max_tokens: ((playbooks().find((x) => x.id === id) || {}).tags || []).includes('n3') ? 1200 : 500,
      };
      const r = await sepApi('/llm/ei/run', { method: 'POST', body });
      if (r && r.ok && r.text) {
        const pb = playbooks().find((x) => x.id === id) || {};
        st.lastRun = {
          text: r.text,
          t: nowStamp(),
          playbook: r.playbook || { name: pb.name, mode: pb.mode },
          mode: (r.playbook && r.playbook.mode) || pb.mode || 'ops',
        };
        st.chat.push({
          role: 'user',
          text: `[Playbook ${id}] ${note || pb.name || id}`,
          t: nowStamp(),
        });
        st.chat.push({
          role: 'assistant',
          text: r.text,
          t: nowStamp(),
          meta: pb.name || id,
        });
        persistChat();
        toast('Analyse EI prête', 'ok');
        if (st.view === 'command' || st.view === 'playbooks') st.view = 'warroom';
      } else {
        toast((r && r.error) || 'Échec EI', 'err');
        st.msg = (r && r.error) || 'échec';
      }
    } catch (e) {
      toast(e.message || String(e), 'err');
      st.msg = e.message || String(e);
    }
    st.busy = false;
    paint();
  }

  async function runChat(userText) {
    const msg = String(userText || '').trim();
    if (!msg || st.busy) return;
    st.busy = true;
    st.chat.push({ role: 'user', text: msg, t: nowStamp() });
    persistChat();
    paint();
    const p = activeProvider();
    try {
      if (!p) throw new Error('Aucune IA — Moteur IA → Ollama Cybercorp');
      const r = await sepApi('/llm/ei/chat', {
        method: 'POST',
        body: {
          provider_id: p.id,
          inject_context: st.cfg.injectContext !== false,
          alert_id: st.cfg.focusAlertId || '',
          hours: st.cfg.hours || 24,
          max_tokens: 640,
          messages: st.chat.filter((m) => m.role === 'user' || m.role === 'assistant')
            .slice(-10)
            .map((m) => ({ role: m.role, content: m.text })),
        },
      });
      if (r && r.ok && r.text) {
        st.chat.push({ role: 'assistant', text: r.text, t: nowStamp(), meta: 'warroom' });
        st.lastRun = { text: r.text, t: nowStamp(), playbook: { name: 'War Room' }, mode: 'warroom' };
      } else {
        st.chat.push({
          role: 'assistant',
          text: `Échec EI : ${(r && r.error) || 'réponse vide'}`,
          t: nowStamp(),
        });
      }
    } catch (e) {
      st.chat.push({ role: 'assistant', text: String(e.message || e), t: nowStamp() });
    }
    persistChat();
    st.busy = false;
    st.view = 'warroom';
    paint();
  }

  function bind(el) {
    el.addEventListener('click', (ev) => {
      const b = ev.target.closest('[data-rl]');
      if (!b) return;
      const act = b.dataset.rl;

      if (act === 'view') {
        st.view = b.dataset.view || 'command';
        if (st.view === 'triage' && !(st.triage.items || []).length && !st.triage.loading) {
          st.busy = true; paint();
          refreshAlertFeed().finally(() => { st.busy = false; paint(); });
          return;
        }
        paint();
        return;
      }
      if (act === 'ctx-refresh') {
        st.busy = true; paint();
        refreshContext().finally(() => { st.busy = false; paint(); toast('Contexte SEP à jour', 'ok'); });
        return;
      }
      if (act === 'focus-alert') {
        const id = b.dataset.id || '';
        const autoInv = b.dataset.investigate !== '0';
        st.cfg.focusAlertId = id;
        persistCfg();
        st.msg = 'Chargement dossier…';
        paint();
        selectAlert(id, { investigate: autoInv && st.view === 'triage' })
          .catch((e) => toast(e.message || String(e), 'err'))
          .finally(() => { st.msg = ''; paint(); });
        return;
      }
      if (act === 'triage-filter' || act === 'triage-apply') {
        const inp = document.getElementById('ei-triage-q');
        const stSel = document.getElementById('ei-f-status');
        const urgSel = document.getElementById('ei-f-urgency');
        const tySel = document.getElementById('ei-f-type');
        const hrSel = document.getElementById('ei-f-hours');
        st.triage.q = (inp && inp.value) || '';
        st.triageFilter = st.triage.q;
        if (stSel) st.triage.status = stSel.value || '';
        if (urgSel) st.triage.urgency = urgSel.value || '';
        if (tySel) st.triage.type = tySel.value || '';
        if (hrSel) st.triage.hours = parseInt(hrSel.value, 10) || 168;
        st.busy = true; paint();
        refreshAlertFeed().finally(() => { st.busy = false; paint(); });
        return;
      }
      if (act === 'investigate') {
        runInvestigate({ useLlm: true });
        return;
      }
      if (act === 'investigate-fast') {
        runInvestigate({ useLlm: false });
        return;
      }
      if (act === 'pb-run') {
        let note = '';
        const tn = document.getElementById('ei-triage-note');
        const fn = document.getElementById('ei-forensic-note');
        if (tn && tn.value) note = tn.value;
        else if (fn && fn.value) note = fn.value;
        runPlaybook(b.dataset.id, note);
        return;
      }
      if (act === 'forensic-brief') {
        const note = ((document.getElementById('ei-forensic-note') || {}).value || '').trim();
        runPlaybook('forensic-first-hour', note || 'Plan forensic première heure sur le contexte courant.');
        return;
      }
      if (act === 'chat-send') {
        const inp = document.getElementById('rl-chat-input');
        runChat(inp && inp.value);
        return;
      }
      if (act === 'chat-clear') {
        if (!confirm('Purger le journal Extended Intelligence ?')) return;
        st.chat = [];
        persistChat();
        paint();
        return;
      }
      if (act === 'toggle-inject') {
        st.cfg.injectContext = !!b.checked;
        persistCfg();
        return;
      }
      if (act === 'cfg-save') {
        const h = document.getElementById('ei-hours');
        const f = document.getElementById('ei-focus');
        st.cfg.hours = Math.max(1, Math.min(168, parseInt((h && h.value) || '24', 10) || 24));
        st.cfg.focusAlertId = ((f && f.value) || '').trim();
        persistCfg();
        refreshContext().then(() => { toast('Config EI enregistrée', 'ok'); paint(); });
        return;
      }
      if (act === 'set-active') {
        st.cfg.activeProviderId = b.dataset.id || '';
        persistCfg();
        paint();
        return;
      }
      if (act === 'preset') {
        const pr = LOCAL_PRESETS.find((x) => x.id === b.dataset.preset);
        if (!pr) return;
        const name = document.getElementById('rl-llm-name');
        const kind = document.getElementById('rl-llm-kind');
        const url = document.getElementById('rl-llm-url');
        const model = document.getElementById('rl-llm-model');
        if (name) name.value = pr.name;
        if (kind) kind.value = pr.kind;
        if (url) url.value = pr.base_url;
        if (model) model.value = pr.model;
        toast(`Preset ${pr.name}`, 'ok');
        return;
      }
      if (act === 'llm-refresh') {
        refreshLlm().then(() => paint());
        return;
      }
      if (act === 'llm-add') {
        const name = ((document.getElementById('rl-llm-name') || {}).value || '').trim();
        const kind = ((document.getElementById('rl-llm-kind') || {}).value || 'ollama');
        const base_url = ((document.getElementById('rl-llm-url') || {}).value || '').trim();
        const model = ((document.getElementById('rl-llm-model') || {}).value || '').trim();
        const api_key = ((document.getElementById('rl-llm-key') || {}).value || '').trim();
        if (!name || !base_url) { toast('Nom + Base URL requis', 'err'); return; }
        sepApi('/llm/providers', {
          method: 'POST',
          body: { name, kind, base_url, model, api_key, enabled: true },
        }).then((r) => {
          if (r && r.provider) {
            st.cfg.activeProviderId = r.provider.id;
            persistCfg();
          }
          return refreshLlm();
        }).then(() => { toast('IA enregistrée', 'ok'); paint(); })
          .catch((e) => toast(e.message || 'Échec', 'err'));
        return;
      }
      if (act === 'llm-del') {
        if (!confirm('Retirer cette IA ?')) return;
        sepApi(`/llm/providers/${encodeURIComponent(b.dataset.id)}`, { method: 'DELETE' })
          .then(() => {
            if (st.cfg.activeProviderId === b.dataset.id) {
              st.cfg.activeProviderId = '';
              persistCfg();
            }
            return refreshLlm();
          }).then(() => { toast('IA retirée', 'ok'); paint(); })
          .catch((e) => toast(e.message || 'Échec', 'err'));
        return;
      }
      if (act === 'llm-test') {
        const id = b.dataset.id;
        st.msg = 'Test EI…';
        paint();
        sepApi('/llm/chat', {
          method: 'POST',
          body: {
            provider_id: id,
            max_tokens: 96,
            messages: [{
              role: 'user',
              content: 'Réponds en une phrase : Extended Intelligence prêt pour le triage SEP ?',
            }],
          },
        }).then((r) => {
          st.msg = r.ok ? (r.text || 'OK') : (r.error || 'échec');
          toast(r.ok ? 'Moteur IA OK' : (r.error || 'échec'), r.ok ? 'ok' : 'err');
          if (r.ok) {
            st.cfg.activeProviderId = id;
            persistCfg();
          }
          paint();
        }).catch((e) => {
          st.msg = e.message || String(e);
          toast(st.msg, 'err');
          paint();
        });
        return;
      }
      if (act === 'mcp-add') {
        const name = ((document.getElementById('rl-mcp-name') || {}).value || '').trim();
        const url = ((document.getElementById('rl-mcp-url') || {}).value || '').trim();
        const token = ((document.getElementById('rl-mcp-token') || {}).value || '').trim();
        if (!name || !url) { toast('Nom + URL requis', 'err'); return; }
        sepApi('/mcp/servers', {
          method: 'POST',
          body: { name, transport: 'http', url, token },
        }).then(() => refreshLlm())
          .then(() => { toast('MCP ajouté', 'ok'); paint(); })
          .catch((e) => toast(e.message || 'Échec', 'err'));
        return;
      }
      if (act === 'mcp-del') {
        sepApi(`/mcp/servers/${encodeURIComponent(b.dataset.id)}`, { method: 'DELETE' })
          .then(() => refreshLlm())
          .then(() => paint())
          .catch((e) => toast(e.message || 'Échec', 'err'));
        return;
      }
      if (act === 'mcp-probe') {
        sepApi(`/mcp/servers/${encodeURIComponent(b.dataset.id)}/probe`, { method: 'POST', body: {} })
          .then((r) => {
            toast(r.ok ? `${r.count || 0} tool(s)` : (r.error || 'probe échoué'), r.ok ? 'ok' : 'err');
            return refreshLlm();
          }).then(() => paint())
          .catch((e) => toast(e.message || 'Échec', 'err'));
      }
    });

    el.addEventListener('change', (ev) => {
      const t = ev.target;
      if (t && t.id === 'ei-inject') {
        st.cfg.injectContext = !!t.checked;
        persistCfg();
      }
    });

    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' && (ev.metaKey || ev.ctrlKey)) {
        const inp = document.getElementById('rl-chat-input');
        if (inp && document.activeElement === inp) {
          ev.preventDefault();
          runChat(inp.value);
        }
      }
    });
  }

  async function mount() {
    const el = root();
    if (!el) return;
    el.innerHTML = '<p class="fp-muted">Chargement Extended Intelligence…</p>';
    await refreshLlm();
    await Promise.all([refreshContext(), loadStatuses(), refreshAlertFeed()]);
    // migration vues legacy
    if (['home', 'chat', 'ai', 'missions', 'tools'].includes(st.view)) {
      const map = { home: 'command', chat: 'warroom', ai: 'engine', missions: 'playbooks', tools: 'engine' };
      st.view = map[st.view] || 'command';
    }
    paint();
  }

  window.SekoiaRelais = { mount, paint };
  window.SekoiaEI = window.SekoiaRelais;
  window.SekoiaKheish = window.SekoiaRelais;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      const tab = (window.CertApp && CertApp.currentTab && CertApp.currentTab()) || '';
      if (tab === 'sekoia-relais' || tab === 'sekoia-kheish' || tab === 'sekoia-ei') mount();
    });
  } else if (['sekoia-relais', 'sekoia-kheish', 'sekoia-ei'].includes(
    (window.CertApp && CertApp.currentTab && CertApp.currentTab()) || '',
  )) {
    mount();
  }
}());
