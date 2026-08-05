/* global i18n */
'use strict';

/**
 * SekoiaKheish — console agent SEP (maquette branchable).
 * Thème portail partagé · Skills CRUD · Config multi-outils · Chat.
 */
(function () {
  const LS_CFG = 'sep-kheish-config';
  const LS_SKILLS = 'sep-kheish-skills';
  const LS_CHAT = 'sep-kheish-chat';

  const VIEWS = [
    { id: 'mission', label: 'Mission' },
    { id: 'chat', label: 'Chat' },
    { id: 'stream', label: 'Run Stream' },
    { id: 'approvals', label: 'Approvals' },
    { id: 'skills', label: 'Skills' },
    { id: 'connectors', label: 'Connecteurs' },
    { id: 'config', label: 'Configuration' },
    { id: 'audit', label: 'Audit' },
  ];

  const TOOL_PRESETS = [
    { id: 'sekoia', name: 'Sekoia.IO', kind: 'sekoia', baseUrl: 'https://app.sekoia.io', hint: 'UI token / API key SEP' },
    { id: 'sentinelone', name: 'SentinelOne', kind: 'sentinelone', baseUrl: 'https://eu1.sentinelone.net', hint: 'API token Management' },
    { id: 'xsoar', name: 'Cortex XSOAR', kind: 'xsoar', baseUrl: 'https://xsoar.example.com', hint: 'API key + API key ID' },
    { id: 'servicenow', name: 'ServiceNow', kind: 'servicenow', baseUrl: 'https://instance.service-now.com', hint: 'OAuth / Basic' },
    { id: 'thehive', name: 'TheHive', kind: 'thehive', baseUrl: '', hint: 'API key' },
    { id: 'misp', name: 'MISP', kind: 'misp', baseUrl: '', hint: 'Authkey' },
    { id: 'custom', name: 'API custom', kind: 'custom', baseUrl: '', hint: 'Bearer / header custom' },
  ];

  const DEFAULT_SKILLS = [
    { id: 'silent-triage', name: 'Silent Intake Triage', desc: 'Corréler silencieux / baisses / hosts, proposer enable ou escalade.', tags: ['sekoia', 'alerting'], tools: ['sekoia'] },
    { id: 's1-contain', name: 'SentinelOne Contain Host', desc: 'Proposer isolation endpoint après confirmation analyste.', tags: ['sentinelone', 'edr'], tools: ['sentinelone'] },
    { id: 'xsoar-incident', name: 'XSOAR Open Incident', desc: 'Créer / enrichir un incident XSOAR depuis un run Kheish.', tags: ['xsoar', 'soar'], tools: ['xsoar'] },
    { id: 'snow-ticket', name: 'ServiceNow Ticket', desc: 'Ouvrir un incident/change SN avec résumé du run.', tags: ['servicenow', 'itsm'], tools: ['servicenow'] },
    { id: 'rule-backtest', name: 'Rule Backtest Pack', desc: 'Backtest 7j + couverture MITRE × intakes.', tags: ['sekoia', 'rules'], tools: ['sekoia'] },
    { id: 'sol-assist', name: 'SOL Investigator', desc: 'Générer / affiner des requêtes SOL.', tags: ['sekoia', 'queries'], tools: ['sekoia'] },
    { id: 'cross-pivot', name: 'Cross-tool IOC Pivot', desc: 'Pivot IOC entre Sekoia, S1, MISP, TheHive.', tags: ['cti', 'multi'], tools: ['sekoia', 'sentinelone', 'misp'] },
    { id: 'evidence-pack', name: 'Evidence Pack', desc: 'Assembler timeline + exports.', tags: ['dfir'], tools: ['sekoia'] },
  ];

  const DEFAULT_CFG = {
    daemonUrl: 'http://127.0.0.1:4000',
    daemonToken: '',
    sagemakerUrl: '',
    sagemakerRegion: 'eu-west-1',
    sagemakerAuth: 'iam',
    engineMode: 'mock',
    connectors: [
      { id: 'c-sekoia', tool: 'sekoia', name: 'Sekoia community', baseUrl: 'https://app.sekoia.io', hasSecret: false, enabled: true },
      { id: 'c-s1', tool: 'sentinelone', name: 'SentinelOne EU', baseUrl: 'https://eu1.sentinelone.net', hasSecret: false, enabled: false },
      { id: 'c-xsoar', tool: 'xsoar', name: 'Cortex XSOAR', baseUrl: '', hasSecret: false, enabled: false },
      { id: 'c-snow', tool: 'servicenow', name: 'ServiceNow', baseUrl: '', hasSecret: false, enabled: false },
    ],
  };

  const SESSIONS = [
    { id: 'sess-silent-wave', title: 'Vague de silencieux — 24h', status: 'running', meta: 'sekoia · alerting', ago: '2m' },
    { id: 'sess-s1', title: 'Contain host suspect', status: 'waiting', meta: 'sentinelone · approval', ago: '12m' },
    { id: 'sess-snow', title: 'Ticket SN — drop intake', status: 'idle', meta: 'servicenow', ago: '1h' },
    { id: 'sess-xsoar', title: 'Enrich incident XSOAR', status: 'done', meta: 'xsoar · sekoia', ago: '3h' },
  ];

  const APPROVALS = [
    { id: 'ap-1', title: 'Disable intake silencieux', detail: 'Sekoia · impact 1 entity', risk: 'medium', tool: 'sekoia' },
    { id: 'ap-2', title: 'Isolate endpoint S1', detail: 'SentinelOne · host WIN-DC01', risk: 'high', tool: 'sentinelone' },
    { id: 'ap-3', title: 'Créer incident ServiceNow', detail: 'P2 · catégorie Security', risk: 'low', tool: 'servicenow' },
  ];

  const AUDIT = [
    { t: '19:12:04', actor: 'analyst@cert', action: 'sessions.input', target: 'sess-silent-wave', result: 'accepted' },
    { t: '19:12:06', actor: 'kheish', action: 'tool.sekoia.intakes.health', target: '66', result: 'ok' },
    { t: '19:12:14', actor: 'kheish', action: 'tool.sentinelone.agents', target: 'probe', result: 'not_configured' },
    { t: '19:12:18', actor: 'analyst@cert', action: 'approval.defer', target: 'ap-2', result: 'deferred' },
  ];

  function loadJson(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return fallback;
      return JSON.parse(raw);
    } catch (_) { return fallback; }
  }
  function saveJson(key, val) {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch (_) { /* noop */ }
  }

  const st = {
    view: 'mission',
    sessionId: SESSIONS[0].id,
    running: false,
    stream: [],
    timers: [],
    prompt: '',
    gen: 0,
    cfg: Object.assign({}, DEFAULT_CFG, loadJson(LS_CFG, {})),
    skills: loadJson(LS_SKILLS, null) || DEFAULT_SKILLS.map((s) => Object.assign({}, s)),
    chat: loadJson(LS_CHAT, []) || [],
    editSkillId: null,
    editConnId: null,
  };
  if (!Array.isArray(st.cfg.connectors)) st.cfg.connectors = DEFAULT_CFG.connectors.slice();

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function root() { return document.getElementById('sekoia-kheish-root'); }
  function clearTimers() {
    st.timers.forEach((id) => clearTimeout(id));
    st.timers = [];
  }
  function toast(msg, tone) {
    if (window.ThreatCommon && ThreatCommon.toast) ThreatCommon.toast(msg, tone || 'ok');
  }
  function persistCfg() { saveJson(LS_CFG, st.cfg); }
  function persistSkills() { saveJson(LS_SKILLS, st.skills); }
  function persistChat() { saveJson(LS_CHAT, st.chat.slice(-80)); }

  function pill(status) {
    const map = {
      running: ['run', 'running'], waiting: ['wait', 'approval'],
      idle: ['', 'idle'], done: ['ok', 'done'], high: ['danger', 'high'],
      medium: ['wait', 'medium'], low: ['ok', 'low'],
    };
    const [cls, label] = map[status] || ['', status];
    return `<span class="kh-pill${cls ? ` kh-pill-${cls}` : ''}">${esc(label)}</span>`;
  }

  function engineChips() {
    const live = st.cfg.engineMode === 'live';
    const nOn = (st.cfg.connectors || []).filter((c) => c.enabled).length;
    const sm = st.cfg.sagemakerUrl ? 'set' : 'pending';
    return `
      <span class="kh-chip ${live ? 'is-live' : 'is-off'}"><span class="kh-dot"></span> Engine <strong>${live ? 'LIVE' : 'MOCK'}</strong></span>
      <span class="kh-chip is-ok"><span class="kh-dot"></span> Connecteurs <strong>${nOn}</strong></span>
      <span class="kh-chip ${sm === 'set' ? 'is-ok' : ''}"><span class="kh-dot"></span> SageMaker <strong>${esc(sm)}</strong></span>
      <span class="kh-chip">Daemon <strong>${esc((st.cfg.daemonUrl || '').replace(/^https?:\/\//, '').slice(0, 22) || '—')}</strong></span>`;
  }

  function sessionList() {
    return SESSIONS.map((s) => `
      <button type="button" class="kh-session${s.id === st.sessionId ? ' is-active' : ''}" data-kh="session" data-id="${esc(s.id)}">
        <div class="kh-session-title"><span>${esc(s.title)}</span>${pill(s.status)}</div>
        <div class="kh-session-meta">${esc(s.meta)} · ${esc(s.ago)}</div>
      </button>`).join('');
  }

  function streamHtml() {
    if (!st.stream.length) {
      return `<div class="kh-stream-empty">Aucun événement.<br>Soumettez un run ou utilisez le Chat — le journal simule tools multi-plateformes.</div>`;
    }
    return st.stream.map((e) => `
      <article class="kh-event">
        <div class="kh-event-time">${esc(e.t)}</div>
        <div class="kh-event-body">
          <div class="kh-event-kind${e.cls ? ` is-${esc(e.cls)}` : ''}">${esc(e.kind)}</div>
          <p>${esc(e.text)}</p>
          ${e.code ? `<pre>${esc(e.code)}</pre>` : ''}
        </div>
      </article>`).join('');
  }

  function chatHtml() {
    const msgs = st.chat.length ? st.chat : [
      { role: 'assistant', text: 'Bonjour — je suis Kheish. Je peux orchestrer des appels vers Sekoia, SentinelOne, XSOAR, ServiceNow… selon les connecteurs configurés.', t: '—' },
    ];
    return `
      <div class="kh-panel">
        <div class="kh-panel-head">
          <h3>Chat opérateur</h3>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="chat-clear">Vider</button>
        </div>
        <div class="kh-chat-log" id="kh-chat-log">${msgs.map((m) => `
          <div class="kh-chat-msg is-${esc(m.role)}">
            <div class="kh-chat-meta">${esc(m.role)} · ${esc(m.t || '')}</div>
            <div class="kh-chat-bubble">${esc(m.text)}</div>
          </div>`).join('')}</div>
        <div class="kh-compose-foot" style="margin-top:.65rem;align-items:stretch">
          <textarea class="kh-chat-input" id="kh-chat-input" rows="2" placeholder="Demander une action, un pivot, un résumé… (Entrée + Ctrl pour envoyer)"></textarea>
        </div>
        <div class="kh-toolbar">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="chat-quick" data-q="Quels connecteurs sont actifs ?">Connecteurs</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="chat-quick" data-q="Triage les silencieux Sekoia et propose un ticket ServiceNow.">Triage + SN</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="chat-quick" data-q="Peux-tu isoler un host via SentinelOne après approval ?">S1 contain</button>
          <span class="kh-spacer"></span>
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-kh="chat-send">Envoyer</button>
        </div>
      </div>`;
  }

  function skillsHtml() {
    return `
      <div class="kh-panel">
        <div class="kh-panel-head">
          <h3>Skills / playbooks</h3>
          <div class="fp-actions-row">
            <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-kh="skill-add">+ Ajouter</button>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="skill-reset">Réinitialiser défauts</button>
          </div>
        </div>
        <p class="fp-muted" style="margin:0 0 .75rem;font-size:.82rem">Skills réutilisables par l’agent — liés aux connecteurs (Sekoia, S1, XSOAR, ServiceNow…).</p>
        <div class="kh-matrix">${st.skills.map((s) => `
          <div class="kh-skill">
            <h4>${esc(s.name)}</h4>
            <p>${esc(s.desc)}</p>
            <div class="kh-skill-tags">${(s.tags || []).map((t) => `<span class="kh-pill">${esc(t)}</span>`).join('')}
              ${(s.tools || []).map((t) => `<span class="kh-pill kh-pill-run">${esc(t)}</span>`).join('')}</div>
            <div class="kh-skill-actions">
              <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="skill-run" data-id="${esc(s.id)}">Lancer</button>
              <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="skill-edit" data-id="${esc(s.id)}">Modifier</button>
              <button type="button" class="fp-btn fp-btn-danger-ghost fp-btn-sm" data-kh="skill-del" data-id="${esc(s.id)}">Supprimer</button>
            </div>
          </div>`).join('')}</div>
        ${st.editSkillId != null ? skillEditorHtml() : ''}
      </div>`;
  }

  function skillEditorHtml() {
    const s = st.editSkillId === '__new__'
      ? { id: '', name: '', desc: '', tags: '', tools: '' }
      : (st.skills.find((x) => x.id === st.editSkillId) || { name: '', desc: '', tags: [], tools: [] });
    const tags = Array.isArray(s.tags) ? s.tags.join(', ') : (s.tags || '');
    const tools = Array.isArray(s.tools) ? s.tools.join(', ') : (s.tools || '');
    return `
      <div class="kh-card" style="margin-top:1rem" id="kh-skill-editor">
        <h4>${st.editSkillId === '__new__' ? 'Nouveau skill' : 'Modifier skill'}</h4>
        <div class="kh-form-grid" style="margin-top:.55rem">
          <label class="fp-label">Nom<input class="fp-input" id="kh-sk-name" value="${esc(s.name)}"></label>
          <label class="fp-label">Tags (virgules)<input class="fp-input" id="kh-sk-tags" value="${esc(tags)}"></label>
          <label class="fp-label">Outils (virgules)<input class="fp-input" id="kh-sk-tools" value="${esc(tools)}" placeholder="sekoia, sentinelone"></label>
        </div>
        <label class="fp-label" style="margin-top:.55rem;display:block">Description
          <textarea class="fp-textarea" id="kh-sk-desc" rows="3">${esc(s.desc || '')}</textarea>
        </label>
        <div class="kh-toolbar">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-kh="skill-save">Enregistrer</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="skill-cancel">Annuler</button>
        </div>
      </div>`;
  }

  function connectorsHtml() {
    const rows = (st.cfg.connectors || []).map((c) => `
      <tr class="kh-conn-row">
        <td>${c.enabled ? pill('done') : pill('idle')}</td>
        <td><strong>${esc(c.name)}</strong><br><span class="fp-muted">${esc(c.tool)}</span></td>
        <td><code>${esc(c.baseUrl || '—')}</code></td>
        <td>${c.hasSecret ? '<span class="fp-tag fp-tag-active">secret</span>' : '<span class="fp-tag">absent</span>'}</td>
        <td>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="conn-edit" data-id="${esc(c.id)}">Éditer</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="conn-toggle" data-id="${esc(c.id)}">${c.enabled ? 'Désactiver' : 'Activer'}</button>
          <button type="button" class="fp-btn fp-btn-danger-ghost fp-btn-sm" data-kh="conn-del" data-id="${esc(c.id)}">Suppr.</button>
        </td>
      </tr>`).join('');
    return `
      <div class="kh-panel">
        <div class="kh-panel-head">
          <h3>Connecteurs outils</h3>
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-kh="conn-add">+ Connecteur</button>
        </div>
        <p class="fp-muted" style="margin:0 0 .65rem;font-size:.82rem">Kheish n’est pas limité à Sekoia : chaque connecteur porte URL + secret (stockage local mock — proxy serveur en live).</p>
        <div class="fp-table-wrap"><table class="kh-table fp-table">
          <thead><tr><th>État</th><th>Nom</th><th>Base URL</th><th>Secret</th><th></th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" class="fp-muted">Aucun connecteur</td></tr>'}</tbody>
        </table></div>
        ${st.editConnId != null ? connEditorHtml() : ''}
        <div class="kh-card" style="margin-top:.85rem">
          <h4>Pivots SEP (Sekoia)</h4>
          <div class="kh-bind">
            <a class="fp-btn fp-btn-ghost fp-btn-sm" href="/sekoia?tab=sekoia-extended&view=drops">Alerting</a>
            <a class="fp-btn fp-btn-ghost fp-btn-sm" href="/sekoia?tab=sekoia-rules">Rules</a>
            <a class="fp-btn fp-btn-ghost fp-btn-sm" href="/sekoia?tab=gov-assets">Assets</a>
            <a class="fp-btn fp-btn-ghost fp-btn-sm" href="/sekoia?tab=sekoia-cc&cc=sol">Queries</a>
          </div>
        </div>
      </div>`;
  }

  function connEditorHtml() {
    const c = st.editConnId === '__new__'
      ? { id: '', tool: 'custom', name: '', baseUrl: '', enabled: true, secret: '' }
      : (st.cfg.connectors.find((x) => x.id === st.editConnId) || {});
    const opts = TOOL_PRESETS.map((p) =>
      `<option value="${esc(p.id)}"${(c.tool || '') === p.id ? ' selected' : ''}>${esc(p.name)}</option>`).join('');
    return `
      <div class="kh-card" style="margin-top:1rem" id="kh-conn-editor">
        <h4>${st.editConnId === '__new__' ? 'Nouveau connecteur' : 'Éditer connecteur'}</h4>
        <div class="kh-form-grid" style="margin-top:.55rem">
          <label class="fp-label">Outil<select class="fp-select" id="kh-cn-tool">${opts}</select></label>
          <label class="fp-label">Nom<input class="fp-input" id="kh-cn-name" value="${esc(c.name || '')}"></label>
          <label class="fp-label">Base URL<input class="fp-input" id="kh-cn-url" value="${esc(c.baseUrl || '')}" placeholder="https://…"></label>
          <label class="fp-label">API key / token
            <input class="fp-input" id="kh-cn-secret" type="password" placeholder="${c.hasSecret ? '•••••• (laisser vide = inchangé)' : 'Coller le secret'}" autocomplete="off">
            <span class="kh-help">Mock local — en production, secret chiffré côté serveur uniquement.</span>
          </label>
        </div>
        <div class="kh-toolbar">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-kh="conn-save">Enregistrer</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="conn-cancel">Annuler</button>
        </div>
      </div>`;
  }

  function configHtml() {
    const c = st.cfg;
    return `
      <div class="kh-panel">
        <div class="kh-panel-head"><h3>Configuration Kheish</h3></div>
        <p class="fp-muted" style="margin:0 0 .75rem;font-size:.82rem">Propre à Kheish (pas la config Sekoia SEP). Daemon, SageMaker, mode moteur. Les clés outils se gèrent dans <strong>Connecteurs</strong>.</p>
        <div class="kh-form-grid">
          <label class="fp-label">URL daemon Kheish
            <input class="fp-input" id="kh-cfg-daemon" value="${esc(c.daemonUrl || '')}" placeholder="http://127.0.0.1:4000">
          </label>
          <label class="fp-label">Bearer control-plane
            <input class="fp-input" id="kh-cfg-dtoken" type="password" value="" placeholder="${c.daemonToken ? '•••••• (laisser vide = inchangé)' : 'token daemon'}">
          </label>
          <label class="fp-label">SageMaker endpoint URL
            <input class="fp-input" id="kh-cfg-smurl" value="${esc(c.sagemakerUrl || '')}" placeholder="https://runtime.sagemaker.…/endpoints/…/invocations">
          </label>
          <label class="fp-label">Région
            <input class="fp-input" id="kh-cfg-smregion" value="${esc(c.sagemakerRegion || 'eu-west-1')}">
          </label>
          <label class="fp-label">Auth SageMaker
            <select class="fp-select" id="kh-cfg-smauth">
              <option value="iam"${c.sagemakerAuth === 'iam' ? ' selected' : ''}>IAM (role / clés AWS)</option>
              <option value="api_key"${c.sagemakerAuth === 'api_key' ? ' selected' : ''}>API key</option>
            </select>
          </label>
          <label class="fp-label">Mode moteur
            <select class="fp-select" id="kh-cfg-mode">
              <option value="mock"${c.engineMode !== 'live' ? ' selected' : ''}>Mock (maquette)</option>
              <option value="live"${c.engineMode === 'live' ? ' selected' : ''}>Live (daemon)</option>
            </select>
          </label>
        </div>
        <div class="kh-toolbar" style="margin-top:.85rem">
          <button type="button" class="fp-btn fp-btn-primary" data-kh="cfg-save">Enregistrer</button>
          <button type="button" class="fp-btn fp-btn-ghost" data-kh="cfg-test">Tester daemon</button>
          <button type="button" class="fp-btn fp-btn-danger-ghost" data-kh="cfg-clear-secrets">Effacer secrets locaux</button>
        </div>
        <div id="kh-cfg-msg" style="margin-top:.55rem"></div>
        <div class="kh-card" style="margin-top:.85rem">
          <h4>Contrats API (cible)</h4>
          <ul>
            <li><code>GET /api/kheish/status</code></li>
            <li><code>PUT /api/kheish/config</code></li>
            <li><code>POST /api/kheish/connectors</code></li>
            <li><code>POST /api/kheish/chat</code> · <code>POST /api/kheish/sessions/:id/input</code></li>
          </ul>
        </div>
      </div>`;
  }

  function approvalsHtml() {
    return `
      <div class="kh-panel">
        <div class="kh-panel-head"><h3>Approvals (human-in-the-loop)</h3></div>
        ${APPROVALS.map((a) => `
          <div class="kh-card">
            <h4>${esc(a.title)} ${pill(a.risk)} <span class="kh-pill kh-pill-run">${esc(a.tool)}</span></h4>
            <p>${esc(a.detail)}</p>
            <div class="kh-toolbar">
              <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-kh="approve" data-id="${esc(a.id)}">Approuver</button>
              <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="defer" data-id="${esc(a.id)}">Différer</button>
              <button type="button" class="fp-btn fp-btn-danger-ghost fp-btn-sm" data-kh="deny" data-id="${esc(a.id)}">Refuser</button>
            </div>
          </div>`).join('')}
      </div>`;
  }

  function auditHtml() {
    return `<div class="kh-panel"><div class="fp-table-wrap"><table class="kh-table fp-table">
      <thead><tr><th>Heure</th><th>Acteur</th><th>Action</th><th>Cible</th><th>Résultat</th></tr></thead>
      <tbody>${AUDIT.map((r) => `<tr>
        <td>${esc(r.t)}</td><td>${esc(r.actor)}</td><td>${esc(r.action)}</td>
        <td>${esc(r.target)}</td><td>${esc(r.result)}</td>
      </tr>`).join('')}</tbody></table></div></div>`;
  }

  function missionHtml() {
    const nConn = (st.cfg.connectors || []).filter((c) => c.enabled).length;
    return `
      <div class="kh-kpi-row">
        <div class="kh-kpi"><b>${st.skills.length}</b><span>Skills</span></div>
        <div class="kh-kpi"><b>${nConn}</b><span>Connecteurs ON</span></div>
        <div class="kh-kpi"><b>${APPROVALS.length}</b><span>Approvals</span></div>
        <div class="kh-kpi"><b>${st.chat.length}</b><span>Msgs chat</span></div>
      </div>
      <div class="kh-card">
        <h4>Kheish — control plane multi-outils</h4>
        <p>Orchestration d’agents pour le CERT/SOC : Sekoia (SEP), SentinelOne, Cortex XSOAR, ServiceNow, et APIs custom. La config et les secrets sont dédiés à Kheish — indépendants de la config Sekoia SEP.</p>
        <div class="kh-bind" style="margin-top:.55rem">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-kh="view" data-view="chat">Ouvrir Chat</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="view" data-view="config">Configuration</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="view" data-view="connectors">Connecteurs</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="demo">Démo run</button>
        </div>
      </div>
      <div class="kh-banner">Maquette branchable — enregistrez daemon / SageMaker / clés outils dans Configuration & Connecteurs. Mode mock jusqu’au câblage live.</div>`;
  }

  function streamPanelHtml() {
    const sess = SESSIONS.find((s) => s.id === st.sessionId) || SESSIONS[0];
    return `
      <div class="kh-panel kh-compose">
        <div class="kh-panel-head">
          <h3>${esc(sess.title)}</h3>
          <span class="kh-chip">${esc(sess.id)}</span>
        </div>
        <textarea id="kh-prompt" placeholder="Mission multi-outils… ex. « Triage silencieux Sekoia, ouvre un ticket ServiceNow, prépare contain S1 sous approval. »">${esc(st.prompt)}</textarea>
        <div class="kh-compose-foot">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="preset" data-p="multi">Preset multi</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="preset" data-p="silent">Preset Sekoia</button>
          <span class="kh-spacer"></span>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="clear-stream">Vider</button>
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-kh="run" ${st.running ? 'disabled' : ''}>${st.running ? 'Run…' : 'Submit run'}</button>
        </div>
      </div>
      <div class="kh-stream" id="kh-stream">${streamHtml()}</div>`;
  }

  function mainHtml() {
    if (st.view === 'mission') return missionHtml();
    if (st.view === 'chat') return chatHtml();
    if (st.view === 'skills') return skillsHtml();
    if (st.view === 'connectors') return connectorsHtml();
    if (st.view === 'config') return configHtml();
    if (st.view === 'approvals') return approvalsHtml();
    if (st.view === 'audit') return auditHtml();
    return streamPanelHtml();
  }

  function paint() {
    const el = root(); if (!el) return;
    el.className = 'kh-root';
    el.innerHTML = `
      <header class="kh-top">
        <div class="kh-brand">
          <h2>Kheish</h2>
          <p>Agent control plane CERT/SOC — multi-outils (Sekoia, SentinelOne, XSOAR, ServiceNow…) · branchable daemon / SageMaker</p>
        </div>
        <div class="kh-chips">${engineChips()}</div>
      </header>
      <nav class="kh-subnav" aria-label="Kheish">${VIEWS.map((v) =>
        `<button type="button" class="kh-tab${st.view === v.id ? ' is-active' : ''}" data-kh="view" data-view="${v.id}">${esc(v.label)}</button>`).join('')}</nav>
      <div class="kh-body">
        <aside class="kh-rail">
          <p class="kh-section-label">Sessions</p>
          ${sessionList()}
          <div class="kh-toolbar" style="margin-top:.5rem">
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="new-session" style="width:100%">+ Session</button>
          </div>
        </aside>
        <section class="kh-main">${mainHtml()}</section>
        <aside class="kh-side">
          <p class="kh-section-label">Contexte</p>
          <div class="kh-card">
            <h4>Connecteurs actifs</h4>
            <ul>${(st.cfg.connectors || []).filter((c) => c.enabled).map((c) =>
              `<li>${esc(c.name)} <span class="fp-muted">(${esc(c.tool)})</span></li>`).join('') || '<li class="fp-muted">Aucun — activez-en dans Connecteurs</li>'}</ul>
          </div>
          <div class="kh-card">
            <h4>Raccourcis</h4>
            <div class="kh-bind">
              <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="view" data-view="chat">Chat</button>
              <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="view" data-view="config">Config</button>
              <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="view" data-view="skills">Skills</button>
            </div>
          </div>
          <div class="kh-card">
            <h4>Approvals</h4>
            <p>${APPROVALS.length} en attente (actions gated multi-outils).</p>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-kh="view" data-view="approvals" style="margin-top:.4rem">Ouvrir</button>
          </div>
        </aside>
      </div>
      <footer class="kh-footer-bar">
        <span>Kheish × SEP · CYBERCORP</span>
        <span>mode=${esc(st.cfg.engineMode)} · skills=${st.skills.length} · view=${esc(st.view)}</span>
      </footer>`;
    bind(el);
    const stream = document.getElementById('kh-stream');
    if (stream) stream.scrollTop = stream.scrollHeight;
    const chatLog = document.getElementById('kh-chat-log');
    if (chatLog) chatLog.scrollTop = chatLog.scrollHeight;
  }

  function nowStamp() { return new Date().toTimeString().slice(0, 8); }

  function pushEvent(kind, text, opts) {
    const o = opts || {};
    st.stream.push({ t: nowStamp(), kind, text, code: o.code || '', cls: o.cls || '' });
    if (st.view === 'stream') paint();
  }

  function runDemo(prompt) {
    clearTimers();
    st.gen += 1;
    const gen = st.gen;
    st.running = true;
    st.view = 'stream';
    st.prompt = prompt || st.prompt;
    st.stream = [];
    paint();
    const steps = [
      { d: 200, kind: 'SESSION', text: 'Input accepté — run détaché (invariant Kheish).' },
      { d: 600, kind: 'TOOL', text: 'sekoia.intakes.health', cls: 'tool', code: '{ "silent": 12 }' },
      { d: 1100, kind: 'TOOL', text: 'servicenow.incident.draft (dry-run)', cls: 'tool' },
      { d: 1600, kind: 'TOOL', text: 'sentinelone.agents.lookup — connecteur off → skip', cls: 'tool' },
      { d: 2100, kind: 'APPROVAL', text: 'Gate : ticket SN + éventuel contain S1', cls: 'approval' },
      { d: 2600, kind: 'RESULT', text: 'Run en pause sur approval. Journal rejouable.' },
    ];
    steps.forEach((step, i) => {
      st.timers.push(setTimeout(() => {
        if (gen !== st.gen) return;
        pushEvent(step.kind, step.text, { code: step.code, cls: step.cls });
        if (i === steps.length - 1) { st.running = false; paint(); }
      }, step.d));
    });
  }

  function chatReply(userText) {
    const on = (st.cfg.connectors || []).filter((c) => c.enabled).map((c) => c.tool);
    let reply;
    const q = userText.toLowerCase();
    if (q.indexOf('connecteur') >= 0) {
      reply = on.length
        ? `Connecteurs actifs : ${on.join(', ')}. Les autres restent configurables dans l’onglet Connecteurs.`
        : 'Aucun connecteur actif. Activez Sekoia, SentinelOne, XSOAR ou ServiceNow dans Connecteurs.';
    } else if (q.indexOf('sentinel') >= 0 || q.indexOf('isol') >= 0) {
      reply = 'Pour un contain SentinelOne : skill « SentinelOne Contain Host » → run avec approval obligatoire. Vérifiez que le connecteur S1 a un secret.';
    } else if (q.indexOf('servicenow') >= 0 || q.indexOf('ticket') >= 0) {
      reply = 'Je peux préparer un incident ServiceNow (dry-run) après triage Sekoia. Activez le connecteur SN puis lancez le skill « ServiceNow Ticket ».';
    } else {
      reply = `Compris : « ${userText.slice(0, 180)} ». En mode mock je simule le raisonnement ; en live le daemon Kheish / SageMaker exécutera les tools (${on.join(', ') || 'aucun connecteur'}).`;
    }
    st.chat.push({ role: 'assistant', text: reply, t: nowStamp() });
    persistChat();
  }

  function sendChat(text) {
    const msg = String(text || '').trim();
    if (!msg) return;
    st.chat.push({ role: 'user', text: msg, t: nowStamp() });
    persistChat();
    paint();
    setTimeout(() => { chatReply(msg); paint(); }, 350);
  }

  const PRESETS = {
    multi: 'Triage silencieux Sekoia 24h, draft ticket ServiceNow P2, et si host critique → propose contain SentinelOne sous approval.',
    silent: 'Triage les intakes silencieux et baisses ≥50 % (Sekoia uniquement), propose escalades gated.',
  };

  function bind(el) {
    el.addEventListener('click', (ev) => {
      const b = ev.target.closest('[data-kh]'); if (!b) return;
      const act = b.dataset.kh;

      if (act === 'view') { st.view = b.dataset.view || 'mission'; paint(); return; }
      if (act === 'session') { st.sessionId = b.dataset.id; st.view = 'stream'; paint(); return; }
      if (act === 'new-session') {
        const id = `sess-${Date.now().toString(36).slice(-6)}`;
        SESSIONS.unshift({ id, title: 'Nouvelle mission', status: 'idle', meta: 'draft', ago: 'now' });
        st.sessionId = id; st.stream = []; st.prompt = ''; st.view = 'stream'; paint(); return;
      }
      if (act === 'preset') { st.prompt = PRESETS[b.dataset.p] || ''; st.view = 'stream'; paint(); return; }
      if (act === 'clear-stream') { clearTimers(); st.stream = []; st.running = false; paint(); return; }
      if (act === 'run' || act === 'demo') {
        const ta = document.getElementById('kh-prompt');
        if (ta) st.prompt = ta.value;
        runDemo(act === 'demo' ? PRESETS.multi : (st.prompt || PRESETS.multi));
        return;
      }
      if (act === 'approve' || act === 'defer' || act === 'deny') {
        st.view = 'stream';
        pushEvent('APPROVAL', `${act.toUpperCase()} ${b.dataset.id}`, { cls: 'approval' });
        paint();
        return;
      }

      /* Skills CRUD */
      if (act === 'skill-add') { st.editSkillId = '__new__'; st.view = 'skills'; paint(); return; }
      if (act === 'skill-edit') { st.editSkillId = b.dataset.id; paint(); return; }
      if (act === 'skill-cancel') { st.editSkillId = null; paint(); return; }
      if (act === 'skill-del') {
        if (!confirm('Supprimer ce skill ?')) return;
        st.skills = st.skills.filter((s) => s.id !== b.dataset.id);
        persistSkills(); toast('Skill supprimé', 'ok'); paint(); return;
      }
      if (act === 'skill-reset') {
        if (!confirm('Réinitialiser les skills par défaut ?')) return;
        st.skills = DEFAULT_SKILLS.map((s) => Object.assign({}, s));
        persistSkills(); toast('Skills réinitialisés', 'ok'); paint(); return;
      }
      if (act === 'skill-run') {
        const s = st.skills.find((x) => x.id === b.dataset.id);
        st.prompt = s ? `Exécuter skill « ${s.name} » : ${s.desc}` : '';
        runDemo(st.prompt); return;
      }
      if (act === 'skill-save') {
        const name = (document.getElementById('kh-sk-name') || {}).value || '';
        const desc = (document.getElementById('kh-sk-desc') || {}).value || '';
        const tags = String((document.getElementById('kh-sk-tags') || {}).value || '')
          .split(',').map((x) => x.trim()).filter(Boolean);
        const tools = String((document.getElementById('kh-sk-tools') || {}).value || '')
          .split(',').map((x) => x.trim()).filter(Boolean);
        if (!name.trim()) { toast('Nom requis', 'warn'); return; }
        if (st.editSkillId === '__new__') {
          st.skills.unshift({
            id: `sk-${Date.now().toString(36).slice(-6)}`,
            name: name.trim(), desc, tags, tools,
          });
        } else {
          const s = st.skills.find((x) => x.id === st.editSkillId);
          if (s) { s.name = name.trim(); s.desc = desc; s.tags = tags; s.tools = tools; }
        }
        st.editSkillId = null;
        persistSkills(); toast('Skill enregistré', 'ok'); paint(); return;
      }

      /* Connectors CRUD */
      if (act === 'conn-add') { st.editConnId = '__new__'; st.view = 'connectors'; paint(); return; }
      if (act === 'conn-edit') { st.editConnId = b.dataset.id; paint(); return; }
      if (act === 'conn-cancel') { st.editConnId = null; paint(); return; }
      if (act === 'conn-del') {
        if (!confirm('Supprimer ce connecteur ?')) return;
        st.cfg.connectors = st.cfg.connectors.filter((c) => c.id !== b.dataset.id);
        persistCfg(); paint(); return;
      }
      if (act === 'conn-toggle') {
        const c = st.cfg.connectors.find((x) => x.id === b.dataset.id);
        if (c) { c.enabled = !c.enabled; persistCfg(); paint(); }
        return;
      }
      if (act === 'conn-save') {
        const tool = (document.getElementById('kh-cn-tool') || {}).value || 'custom';
        const name = ((document.getElementById('kh-cn-name') || {}).value || '').trim();
        const baseUrl = ((document.getElementById('kh-cn-url') || {}).value || '').trim();
        const secret = ((document.getElementById('kh-cn-secret') || {}).value || '').trim();
        if (!name) { toast('Nom requis', 'warn'); return; }
        if (st.editConnId === '__new__') {
          st.cfg.connectors.push({
            id: `c-${Date.now().toString(36).slice(-6)}`,
            tool, name, baseUrl, enabled: true, hasSecret: !!secret,
          });
        } else {
          const c = st.cfg.connectors.find((x) => x.id === st.editConnId);
          if (c) {
            c.tool = tool; c.name = name; c.baseUrl = baseUrl;
            if (secret) c.hasSecret = true;
          }
        }
        st.editConnId = null;
        persistCfg(); toast('Connecteur enregistré', 'ok'); paint(); return;
      }

      /* Config */
      if (act === 'cfg-save') {
        st.cfg.daemonUrl = ((document.getElementById('kh-cfg-daemon') || {}).value || '').trim();
        const tok = ((document.getElementById('kh-cfg-dtoken') || {}).value || '').trim();
        if (tok) st.cfg.daemonToken = '***';
        st.cfg.sagemakerUrl = ((document.getElementById('kh-cfg-smurl') || {}).value || '').trim();
        st.cfg.sagemakerRegion = ((document.getElementById('kh-cfg-smregion') || {}).value || '').trim();
        st.cfg.sagemakerAuth = (document.getElementById('kh-cfg-smauth') || {}).value || 'iam';
        st.cfg.engineMode = (document.getElementById('kh-cfg-mode') || {}).value || 'mock';
        persistCfg();
        const msg = document.getElementById('kh-cfg-msg');
        if (msg) msg.innerHTML = '<div class="fp-alert fp-alert-ok">Configuration Kheish enregistrée (local).</div>';
        toast('Config Kheish enregistrée', 'ok');
        paint();
        return;
      }
      if (act === 'cfg-test') {
        const msg = document.getElementById('kh-cfg-msg');
        if (msg) {
          msg.innerHTML = st.cfg.engineMode === 'live'
            ? '<div class="fp-alert fp-alert-warn">Mode live — probe daemon non câblé (stub). URL : '
              + esc(st.cfg.daemonUrl) + '</div>'
            : '<div class="fp-alert fp-alert-ok">Mode mock — UI OK. Passez en live après câblage proxy.</div>';
        }
        return;
      }
      if (act === 'cfg-clear-secrets') {
        if (!confirm('Effacer les indicateurs de secrets locaux ?')) return;
        st.cfg.daemonToken = '';
        (st.cfg.connectors || []).forEach((c) => { c.hasSecret = false; });
        persistCfg(); toast('Secrets locaux effacés', 'ok'); paint(); return;
      }

      /* Chat */
      if (act === 'chat-clear') { st.chat = []; persistChat(); paint(); return; }
      if (act === 'chat-quick') { sendChat(b.dataset.q || ''); return; }
      if (act === 'chat-send') {
        const inp = document.getElementById('kh-chat-input');
        sendChat(inp && inp.value);
        return;
      }
    });

    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey) && ev.target && ev.target.id === 'kh-chat-input') {
        ev.preventDefault();
        sendChat(ev.target.value);
      }
    });
  }

  function mount() {
    const el = root(); if (!el) return;
    el.dataset.khMounted = '1';
    paint();
  }

  function setBackend(cfg) {
    if (cfg && cfg.mode) st.cfg.engineMode = cfg.mode === 'live' ? 'live' : 'mock';
    if (cfg && cfg.baseUrl) st.cfg.daemonUrl = cfg.baseUrl;
    persistCfg();
    paint();
  }

  window.SekoiaKheish = { mount, setBackend, paint };

  document.addEventListener('DOMContentLoaded', () => {
    if (location.pathname.indexOf('/sekoia') === 0
      && new URLSearchParams(location.search).get('tab') === 'sekoia-kheish') {
      mount();
    }
  });
}());
