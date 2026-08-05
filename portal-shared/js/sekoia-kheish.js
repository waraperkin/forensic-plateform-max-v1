/* global i18n */
'use strict';

/**
 * SekoiaKheish — console agent premium SEP (maquette branchable).
 *
 * Aujourd'hui : UI mock ultra-complète CERT/SOC, pivots SEP.
 * Demain : `SekoiaKheish.setBackend({ mode: 'live', baseUrl, token })`
 * branché sur le daemon Kheish (+ route SageMaker côté serveur).
 */
(function () {
  const VIEWS = [
    { id: 'mission', label: 'Mission Control' },
    { id: 'sessions', label: 'Sessions' },
    { id: 'stream', label: 'Run Stream' },
    { id: 'approvals', label: 'Approvals' },
    { id: 'bindings', label: 'SEP Bindings' },
    { id: 'skills', label: 'Playbooks & Skills' },
    { id: 'audit', label: 'Audit Trail' },
  ];

  const SKILLS = [
    { id: 'silent-triage', name: 'Silent Intake Triage', desc: 'Corréler silencieux / baisses / hosts, proposer enable ou escalade.', tags: ['intakes', 'alerting'] },
    { id: 'rule-backtest', name: 'Rule Backtest Pack', desc: 'Backtest 7j + couverture MITRE × datasources intakes.', tags: ['rules', 'mitre'] },
    { id: 'unmanaged-hunt', name: 'Unmanaged Host Hunt', desc: 'Lister hôtes hors inventaire, lier intakes, draft assets.', tags: ['assets', 'hosts'] },
    { id: 'sol-assist', name: 'SOL Investigator', desc: 'Générer / affiner des requêtes SOL et deep-link résultats.', tags: ['queries', 'sol'] },
    { id: 'keys-hygiene', name: 'API Key Hygiene', desc: 'Buckets expiration, tags, lots dry-run disable/regen.', tags: ['apikeys'] },
    { id: 'vol-forecast', name: 'Volumétrie Forecast', desc: 'Expliquer dérives 1h/24h et anomalies vs baseline.', tags: ['volumétrie'] },
    { id: 'ioc-pivot', name: 'IOC ↔ SEP Pivot', desc: 'Relier IOC CERT aux intakes / rules / assets SEP.', tags: ['cti', 'sep'] },
    { id: 'evidence-pack', name: 'Evidence Pack', desc: 'Assembler timeline + exports Timesketch / OpenSearch.', tags: ['dfir', 'export'] },
  ];

  const st = {
    view: 'mission',
    sessionId: 'sess-silent-wave',
    running: false,
    engine: 'mock', // mock | live
    stream: [],
    timers: [],
    prompt: '',
    gen: 0,
  };

  const SESSIONS = [
    { id: 'sess-silent-wave', title: 'Vague de silencieux — 24h', status: 'running', meta: 'sidechain · intakes×alerting', ago: '2m' },
    { id: 'sess-rule-cov', title: 'Couverture MITRE Rules', status: 'waiting', meta: 'approval · backtest-batch', ago: '18m' },
    { id: 'sess-unmanaged', title: 'Hôtes non inventoriés', status: 'idle', meta: 'assets intelligence', ago: '1h' },
    { id: 'sess-sol-apt', title: 'SOL — hunting APT', status: 'done', meta: 'queries · export', ago: '3h' },
    { id: 'sess-keys', title: 'Hygiène API keys ≤7j', status: 'done', meta: 'apikeys · dry-run', ago: 'hier' },
  ];

  const APPROVALS = [
    { id: 'ap-1', title: 'Disable intake « Cisco-Access-Point »', detail: 'Baseline nulle · 3 h silencieux · impact: 1 entity', risk: 'medium' },
    { id: 'ap-2', title: 'Escalade critique — 4 silencieux', detail: 'Écrire alertes manual_escalate (SageMaker + daemon)', risk: 'high' },
    { id: 'ap-3', title: 'Créer 12 assets unmanaged-review', detail: 'Bulk Asset Management v2 · tags sep-bulk', risk: 'low' },
  ];

  const AUDIT = [
    { t: '19:12:04', actor: 'analyst@cert', action: 'sessions.input', target: 'sess-silent-wave', result: 'accepted' },
    { t: '19:12:06', actor: 'kheish-daemon', action: 'tool.sekoia.intakes.health', target: '66 intakes', result: 'ok' },
    { t: '19:12:11', actor: 'kheish-daemon', action: 'tool.sekoia.alerting.alerts', target: 'dedupe=1', result: '76 unique' },
    { t: '19:12:18', actor: 'analyst@cert', action: 'approval.defer', target: 'ap-1', result: 'deferred' },
    { t: '19:10:02', actor: 'system', action: 'engine.probe', target: 'sagemaker', result: 'stub' },
  ];

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

  function pill(status) {
    const map = {
      running: ['run', 'running'],
      waiting: ['wait', 'approval'],
      idle: ['', 'idle'],
      done: ['ok', 'done'],
    };
    const [cls, label] = map[status] || ['', status];
    return `<span class="kh-pill${cls ? ` kh-pill-${cls}` : ''}">${esc(label)}</span>`;
  }

  function engineChips() {
    const live = st.engine === 'live';
    return `
      <span class="kh-chip ${live ? 'is-live' : 'is-off'}"><span class="kh-dot"></span> Engine <strong>${live ? 'LIVE' : 'MOCK'}</strong></span>
      <span class="kh-chip is-ok"><span class="kh-dot"></span> SEP <strong>bound</strong></span>
      <span class="kh-chip"><span class="kh-dot"></span> SageMaker <strong>pending</strong></span>
      <span class="kh-chip">Daemon <strong>HTTP/SSE</strong></span>`;
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
      return `<div class="kh-stream-empty">Aucun événement pour cette session.<br>
        Lancez une mission depuis le composeur — le stream simule le journal Kheish (tools, approvals, pivots SEP).</div>`;
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

  function approvalsHtml() {
    return APPROVALS.map((a) => `
      <div class="kh-card kh-approval">
        <h3>${esc(a.title)} ${pill(a.risk === 'high' ? 'waiting' : 'idle')}</h3>
        <p>${esc(a.detail)}</p>
        <div class="kh-approval-actions">
          <button type="button" class="kh-btn kh-btn-primary" data-kh="approve" data-id="${esc(a.id)}">Approuver</button>
          <button type="button" class="kh-btn" data-kh="defer" data-id="${esc(a.id)}">Différer</button>
          <button type="button" class="kh-btn kh-btn-danger" data-kh="deny" data-id="${esc(a.id)}">Refuser</button>
        </div>
      </div>`).join('');
  }

  function bindingsHtml() {
    const links = [
      ['Inventaire intakes', '/sekoia?tab=sekoia-assets&sub=intakes'],
      ['Volumétrie', '/sekoia?tab=sekoia-ingest'],
      ['Alerting & drops', '/sekoia?tab=sekoia-extended&view=drops'],
      ['Rules', '/sekoia?tab=sekoia-rules'],
      ['API keys', '/sekoia?tab=sekoia-apikeys'],
      ['Assets', '/sekoia?tab=gov-assets'],
      ['Queries / SOL', '/sekoia?tab=sekoia-cc&cc=sol'],
      ['Hosts', '/sekoia?tab=sekoia-cc&cc=hosts'],
      ['Events', '/sekoia?tab=sekoia-fetch'],
    ];
    return `
      <div class="kh-card">
        <h3>Contexte SEP injecté dans l’agent</h3>
        <p>Chaque run Kheish reçoit un binding lecture (et actions gated) vers les missions SEP — pas un chat générique.</p>
        <div class="kh-bind">${links.map(([l, href]) =>
          `<a href="${esc(href)}">${esc(l)}</a>`).join('')}</div>
      </div>
      <div class="kh-card">
        <h3>Contrats API prêts (stub)</h3>
        <ul>
          <li><code>GET /api/kheish/status</code> — daemon + SageMaker</li>
          <li><code>POST /api/kheish/sessions</code> — ouvrir une session</li>
          <li><code>POST /api/kheish/sessions/:id/input</code> — soumettre</li>
          <li><code>GET /api/kheish/runs/:id/stream</code> — SSE journal</li>
          <li><code>POST /api/kheish/approvals/:id</code> — human-in-the-loop</li>
        </ul>
      </div>
      <div class="kh-card">
        <h3>Outils SEP exposés au daemon</h3>
        <p>intakes.health · alerting.escalate · rules.backtest · assets.intelligence · sol.run · apikeys.bulk (dry-run)</p>
      </div>`;
  }

  function skillsHtml() {
    return `<div class="kh-matrix">${SKILLS.map((s) => `
      <button type="button" class="kh-skill" data-kh="skill" data-id="${esc(s.id)}">
        <h3>${esc(s.name)}</h3>
        <p>${esc(s.desc)}</p>
        <div class="kh-skill-tags">${s.tags.map((t) => `<span class="kh-pill">${esc(t)}</span>`).join('')}</div>
      </button>`).join('')}</div>`;
  }

  function auditHtml() {
    return `<table class="kh-table"><thead><tr>
      <th>Heure</th><th>Acteur</th><th>Action</th><th>Cible</th><th>Résultat</th>
    </tr></thead><tbody>${AUDIT.map((r) => `<tr>
      <td>${esc(r.t)}</td><td>${esc(r.actor)}</td><td>${esc(r.action)}</td>
      <td>${esc(r.target)}</td><td>${esc(r.result)}</td>
    </tr>`).join('')}</tbody></table>`;
  }

  function missionHtml() {
    return `
      <div class="kh-kpi-row">
        <div class="kh-kpi"><b>5</b><span>Sessions</span></div>
        <div class="kh-kpi"><b>3</b><span>Approvals</span></div>
        <div class="kh-kpi"><b>8</b><span>Skills SEP</span></div>
      </div>
      <div class="kh-card">
        <h3>Mission Control — agents qui survivent aux callers</h3>
        <p>Kheish orchestre des runs durables : vous soumettez depuis SEP, le daemon continue (tools, approvals, journal) même si l’UI se ferme. Cette console est la surface opérateur CERT/SOC — le moteur se branche derrière sans changer le shell.</p>
      </div>
      <div class="kh-card">
        <h3>Playbooks prioritaires</h3>
        <ul>
          <li>Triage silencieux ↔ drops ↔ hosts non inventoriés</li>
          <li>Backtest rules + couverture MITRE liée aux intakes</li>
          <li>Investigation SOL avec historique et deep-link</li>
        </ul>
        <div class="kh-bind" style="margin-top:.6rem">
          <button type="button" data-kh="view" data-view="stream">Ouvrir Run Stream</button>
          <button type="button" data-kh="view" data-view="skills">Voir Skills</button>
          <button type="button" data-kh="demo">Lancer démo triage</button>
        </div>
      </div>`;
  }

  function paint() {
    const el = root(); if (!el) return;
    const sess = SESSIONS.find((s) => s.id === st.sessionId) || SESSIONS[0];
    el.className = `kh-root${st.running ? ' is-running' : ''}`;
    el.innerHTML = `
      <header class="kh-top">
        <div class="kh-brand">
          <div class="kh-mark" aria-hidden="true">K</div>
          <div class="kh-brand-text">
            <h1>Kheish</h1>
            <p>Agent control plane · SEP</p>
          </div>
        </div>
        <div class="kh-chips">${engineChips()}</div>
        <div class="kh-top-actions">
          <button type="button" class="kh-btn kh-btn-ghost" data-kh="toggle-engine">${st.engine === 'live' ? 'Mode mock' : 'Préparer live'}</button>
          <button type="button" class="kh-btn" data-kh="new-session">+ Session</button>
          <button type="button" class="kh-btn kh-btn-primary" data-kh="demo">Démo triage</button>
        </div>
      </header>
      <div class="kh-banner">Maquette premium branchable — le daemon <code>kheish</code> et SageMaker se connectent via proxy serveur.
        Aucun secret AWS dans le navigateur. Pivots SEP actifs dès maintenant.</div>
      <nav class="kh-subnav" aria-label="Kheish views">${VIEWS.map((v) =>
        `<button type="button" class="kh-tab${st.view === v.id ? ' is-active' : ''}" data-kh="view" data-view="${v.id}">${esc(v.label)}</button>`).join('')}</nav>
      <div class="kh-body">
        <aside class="kh-rail">
          <p class="kh-section-label">Sessions</p>
          ${sessionList()}
        </aside>
        <section class="kh-main">
          ${st.view === 'mission' || st.view === 'skills' || st.view === 'audit' || st.view === 'bindings' || st.view === 'approvals'
            ? `<div class="kh-panel-view is-active">${
              st.view === 'mission' ? missionHtml()
                : st.view === 'skills' ? skillsHtml()
                  : st.view === 'audit' ? auditHtml()
                    : st.view === 'bindings' ? bindingsHtml()
                      : approvalsHtml()
            }</div>`
            : `
          <div class="kh-compose">
            <div class="kh-compose-head">
              <h2>${esc(sess.title)}</h2>
              <span class="kh-chip">${esc(sess.id)}</span>
            </div>
            <textarea id="kh-prompt" placeholder="Décrire la mission CERT/SOC… ex. « Triage les silencieux 24h, croise alerting & hosts unmanaged, propose escalades. »">${esc(st.prompt)}</textarea>
            <div class="kh-compose-foot">
              <button type="button" class="kh-btn" data-kh="preset" data-p="silent">Preset silencieux</button>
              <button type="button" class="kh-btn" data-kh="preset" data-p="rules">Preset rules/MITRE</button>
              <button type="button" class="kh-btn" data-kh="preset" data-p="sol">Preset SOL</button>
              <span class="kh-spacer"></span>
              <button type="button" class="kh-btn kh-btn-ghost" data-kh="clear-stream">Vider stream</button>
              <button type="button" class="kh-btn kh-btn-primary" data-kh="run" ${st.running ? 'disabled' : ''}>${st.running ? 'Run en cours…' : 'Submit run'}</button>
            </div>
          </div>
          <div class="kh-stream" id="kh-stream">
            <div class="kh-scanline" aria-hidden="true"></div>
            ${streamHtml()}
          </div>`}
        </section>
        <aside class="kh-side">
          <p class="kh-section-label">SEP context</p>
          <div class="kh-card">
            <h3>Bindings actifs</h3>
            <ul>
              <li>Intakes health · 66</li>
              <li>Alerting dedupe · 76</li>
              <li>Rules catalog · 1180</li>
              <li>Assets v2 · 106k+</li>
            </ul>
            <div class="kh-bind">
              <a href="/sekoia?tab=sekoia-extended&view=drops">→ Drops</a>
              <a href="/sekoia?tab=sekoia-rules">→ Rules</a>
              <a href="/sekoia?tab=gov-assets">→ Assets</a>
            </div>
          </div>
          <div class="kh-card">
            <h3>Gate d’approbation</h3>
            <p>${APPROVALS.length} action(s) en attente — human-in-the-loop obligatoire avant écriture Sekoia.</p>
            <div class="kh-bind"><button type="button" data-kh="view" data-view="approvals">Ouvrir Approvals</button></div>
          </div>
          <div class="kh-card">
            <h3>Runtime</h3>
            <p>Provider route : SageMaker (à câbler)<br>Journal : append-only mock<br>Lease credentials : brokered</p>
          </div>
        </aside>
      </div>
      <footer class="kh-footer-bar">
        <span>Kheish × SEP · surface opérateur CYBERCORP</span>
        <span>mode=${esc(st.engine)} · session=${esc(st.sessionId)} · events=${st.stream.length}</span>
      </footer>`;
    bind(el);
    const stream = document.getElementById('kh-stream');
    if (stream) stream.scrollTop = stream.scrollHeight;
  }

  function nowStamp() {
    const d = new Date();
    return d.toTimeString().slice(0, 8);
  }

  function pushEvent(kind, text, opts) {
    const o = opts || {};
    st.stream.push({
      t: nowStamp(),
      kind,
      text,
      code: o.code || '',
      cls: o.cls || '',
    });
    if (st.view === 'stream' || st.view === 'sessions') paint();
    else {
      const stream = document.getElementById('kh-stream');
      if (stream) {
        // partial update when already on stream layout
        paint();
      }
    }
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
      { d: 200, kind: 'SESSION', text: 'Input accepté — run détaché du caller UI (invariant Kheish).', cls: '' },
      { d: 700, kind: 'TOOL', text: 'sekoia.intakes.health → 66 intakes · silencieux détectés', cls: 'tool', code: '{ "silent": 12, "drops_ge_50": 4 }' },
      { d: 1200, kind: 'TOOL', text: 'sekoia.alerting.alerts?dedupe=1 → corrélation silence↔drop', cls: 'tool' },
      { d: 1700, kind: 'SEP', text: 'Pivot SEP : ouverture contexte Alerting & drops + Hosts unmanaged', cls: 'sep' },
      { d: 2200, kind: 'TOOL', text: 'sekoia.assets.intelligence → hosts_unmanaged', cls: 'tool', code: '{ "hosts_unmanaged": 37, "coverage_pct": 91.2 }' },
      { d: 2800, kind: 'REASONING', text: '4 silencieux avec baseline > 0 + 2 hosts hors inventaire sur les mêmes intakes → escalade recommandée.' },
      { d: 3400, kind: 'APPROVAL', text: 'Gate : escalade critique + création assets unmanaged-review (dry-run préparé)', cls: 'approval' },
      { d: 4000, kind: 'RESULT', text: 'Run en pause sur approval humaine. Journal rejouable après restart daemon.', cls: '' },
    ];

    steps.forEach((step) => {
      const tid = setTimeout(() => {
        if (gen !== st.gen) return;
        pushEvent(step.kind, step.text, { code: step.code, cls: step.cls });
        if (step === steps[steps.length - 1]) {
          st.running = false;
          paint();
        }
      }, step.d);
      st.timers.push(tid);
    });
  }

  const PRESETS = {
    silent: 'Triage les intakes silencieux et baisses ≥50 % sur 24h. Croise alerting dédupliqué et hosts unmanaged. Propose enable/disable et escalades gated.',
    rules: 'Pour les rules enabled high-sev, lance un backtest 7j et croise datasources avec l’inventaire intakes. Résume couverture MITRE et angles morts.',
    sol: 'Aide à investiguer via SOL : propose une requête hunting sur process rare + deep-link résultat Queries SEP, avec historique local.',
  };

  function bind(el) {
    el.addEventListener('click', (ev) => {
      const b = ev.target.closest('[data-kh]'); if (!b) return;
      const act = b.dataset.kh;
      if (act === 'view') {
        st.view = b.dataset.view || 'mission';
        if (st.view === 'sessions') st.view = 'stream';
        paint();
        return;
      }
      if (act === 'session') {
        st.sessionId = b.dataset.id;
        st.view = 'stream';
        paint();
        return;
      }
      if (act === 'toggle-engine') {
        st.engine = st.engine === 'live' ? 'mock' : 'live';
        paint();
        return;
      }
      if (act === 'new-session') {
        const id = `sess-${Date.now().toString(36).slice(-6)}`;
        SESSIONS.unshift({
          id, title: 'Nouvelle mission CERT', status: 'idle',
          meta: 'session · draft', ago: 'now',
        });
        st.sessionId = id;
        st.stream = [];
        st.view = 'stream';
        st.prompt = '';
        paint();
        return;
      }
      if (act === 'preset') {
        st.prompt = PRESETS[b.dataset.p] || '';
        st.view = 'stream';
        paint();
        return;
      }
      if (act === 'clear-stream') {
        clearTimers();
        st.stream = [];
        st.running = false;
        paint();
        return;
      }
      if (act === 'run' || act === 'demo') {
        const ta = document.getElementById('kh-prompt');
        if (ta) st.prompt = ta.value;
        runDemo(act === 'demo' ? PRESETS.silent : (st.prompt || PRESETS.silent));
        return;
      }
      if (act === 'skill') {
        const sk = SKILLS.find((x) => x.id === b.dataset.id);
        st.prompt = sk ? `Exécuter skill « ${sk.name} » : ${sk.desc}` : '';
        st.view = 'stream';
        paint();
        return;
      }
      if (act === 'approve' || act === 'defer' || act === 'deny') {
        pushEvent('APPROVAL', `${act.toUpperCase()} ${b.dataset.id} — enregistré (mock, journal daemon à brancher)`, { cls: 'approval' });
        st.view = 'stream';
        paint();
      }
    });
  }

  function mount() {
    const el = root(); if (!el) return;
    if (el.dataset.khMounted === '1' && el.querySelector('.kh-top')) return;
    el.dataset.khMounted = '1';
    st.view = 'mission';
    paint();
  }

  function setBackend(cfg) {
    // Point d’extension futur : { mode:'live', baseUrl, token }
    if (cfg && cfg.mode) st.engine = cfg.mode === 'live' ? 'live' : 'mock';
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
