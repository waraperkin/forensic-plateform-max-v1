/* global i18n */
'use strict';

/**
 * Relais — copilote CERT branché sur n'importe quelle IA locale via MCP.
 *
 * Vision : l'analyste CERT branche Ollama, LM Studio, vLLM, LocalAI…
 * (endpoint OpenAI-compatible ou serveur MCP). Relais dialogue avec cette IA
 * et lui donne accès aux outils SEP (intakes, alertes, notifications…).
 */
(function () {
  const LS_CFG = 'sep-relais-config';
  const LS_MISSIONS = 'sep-relais-missions';
  const LS_CHAT = 'sep-relais-chat';
  const API = '/api/threat/sekoia';

  const VIEWS = [
    { id: 'home', label: 'Accueil' },
    { id: 'chat', label: 'Chat CERT' },
    { id: 'ai', label: 'IA locale' },
    { id: 'missions', label: 'Missions CERT' },
    { id: 'tools', label: 'Outils SEP' },
    { id: 'journal', label: 'Journal' },
  ];

  /** Presets d'IA déployables en local (MCP / OpenAI-compatible). */
  const LOCAL_PRESETS = [
    {
      id: 'ollama',
      name: 'Ollama',
      kind: 'ollama',
      base_url: 'http://host.docker.internal:11434/v1',
      model: 'llama3.2',
      hint: 'ollama serve · modèles locaux',
    },
    {
      id: 'lmstudio',
      name: 'LM Studio',
      kind: 'openai_compatible',
      base_url: 'http://host.docker.internal:1234/v1',
      model: 'local-model',
      hint: 'Local Server → Enable CORS',
    },
    {
      id: 'vllm',
      name: 'vLLM',
      kind: 'openai_compatible',
      base_url: 'http://host.docker.internal:8000/v1',
      model: 'local',
      hint: 'OpenAI-compatible API',
    },
    {
      id: 'localai',
      name: 'LocalAI',
      kind: 'openai_compatible',
      base_url: 'http://host.docker.internal:8080/v1',
      model: 'gpt-4',
      hint: 'drop-in OpenAI local',
    },
    {
      id: 'llamacpp',
      name: 'llama.cpp server',
      kind: 'openai_compatible',
      base_url: 'http://host.docker.internal:8080/v1',
      model: 'local',
      hint: 'server --api',
    },
  ];

  const CERT_MISSIONS = [
    {
      id: 'silent-triage',
      name: 'Triage intakes silencieux',
      desc: 'Identifier les sources muettes, proposer enable / escalade / ticket.',
      prompt: 'En tant qu’analyste CERT, trie les intakes silencieux SEP des dernières 24h. Liste les plus critiques et propose une action (réactiver, escalader, ignorer) avec justification courte.',
      tags: ['alerting', 'intakes'],
    },
    {
      id: 'volume-drop',
      name: 'Baisses de volume',
      desc: 'Corréler drops ≥50 % et impacts détection.',
      prompt: 'Analyse les baisses de volume d’ingestion SEP. Quels intakes menacent la détection ? Priorise et propose des checks (agent, réseau, parsing).',
      tags: ['alerting', 'telemetry'],
    },
    {
      id: 'apikey-watch',
      name: 'Veille clés API',
      desc: 'Détecter créations / anomalies de clés API Sekoia.',
      prompt: 'Résume les nouvelles clés API détectées et les risques (trop permissives, comptes partagés). Propose un contrôle d’accès CERT.',
      tags: ['iam', 'api'],
    },
    {
      id: 'ioc-pivot',
      name: 'Pivot IOC',
      desc: 'Croiser IOC entre SEP, MISP, TheHive.',
      prompt: 'À partir d’un IOC fourni par l’analyste, explique comment pivoter via les outils SEP/MCP (alertes, intakes, notifications). Demande l’IOC si absent.',
      tags: ['cti', 'dfir'],
    },
    {
      id: 'draft-escalation',
      name: 'Draft escalade',
      desc: 'Rédiger une note d’escalade CERT actionnable.',
      prompt: 'Rédige une note d’escalade CERT (contexte, impact, actions déjà faites, demande). Style concis, prêt à coller dans TheHive / ticket.',
      tags: ['response', 'comms'],
    },
    {
      id: 'notify-channels',
      name: 'Test canaux SOC',
      desc: 'Vérifier mail / Slack / Teams / Mattermost.',
      prompt: 'Explique comment tester les canaux de notification SEP (mail + webhook Slack/Teams/Mattermost) et quoi vérifier côté SOC.',
      tags: ['notify'],
    },
  ];

  const DEFAULT_CFG = {
    activeProviderId: '',
    systemPrompt:
      'Tu es Relais, copilote CERT/SOC de la Sekoia Extended Platform. '
      + 'Tu aides l’analyste : triage, télémétrie, clés API, escalades. '
      + 'Réponses courtes, actionnables, en français. '
      + 'Tu peux t’appuyer sur les outils SEP exposés via MCP.',
  };

  function loadJson(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      if (!raw) {
        // migration depuis l’ancienne console Kheish
        if (key === LS_CHAT) {
          const legacy = localStorage.getItem('sep-kheish-chat');
          if (legacy) return JSON.parse(legacy);
        }
        return fallback;
      }
      return JSON.parse(raw);
    } catch (_) {
      return fallback;
    }
  }
  function saveJson(key, val) {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch (_) { /* noop */ }
  }

  const st = {
    view: 'home',
    cfg: Object.assign({}, DEFAULT_CFG, loadJson(LS_CFG, {})),
    missions: loadJson(LS_MISSIONS, null) || CERT_MISSIONS.map((m) => Object.assign({}, m)),
    chat: loadJson(LS_CHAT, []) || [],
    llmStatus: null,
    busy: false,
    msg: '',
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
  function persistChat() { saveJson(LS_CHAT, st.chat.slice(-80)); }
  function persistMissions() { saveJson(LS_MISSIONS, st.missions); }

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
        mcp_servers: [],
      };
    }
  }

  function activeProvider() {
    const items = (st.llmStatus && st.llmStatus.providers) || [];
    const id = st.cfg.activeProviderId;
    if (id) {
      const hit = items.find((p) => p.id === id && p.enabled !== false);
      if (hit) return hit;
    }
    return items.find((p) => p.enabled !== false) || null;
  }

  function statusChips() {
    const p = activeProvider();
    const nProv = ((st.llmStatus && st.llmStatus.providers) || []).length;
    const nMcp = ((st.llmStatus && st.llmStatus.mcp_servers) || []).length;
    const aiCls = p ? 'is-ok is-live' : 'is-off';
    return `
      <span class="rl-chip ${aiCls}"><span class="rl-dot"></span>
        IA ${p ? esc(p.name) : 'non branchée'}</span>
      <span class="rl-chip">${nProv} fournisseur(s)</span>
      <span class="rl-chip">${nMcp} MCP distant(s)</span>
      <span class="rl-chip">SEP MCP · stdio</span>`;
  }

  function homeHtml() {
    const p = activeProvider();
    return `
      <div class="rl-kpi-row">
        <div class="rl-kpi"><b>${p ? 'ON' : 'OFF'}</b><span>IA locale</span></div>
        <div class="rl-kpi"><b>${st.missions.length}</b><span>Missions CERT</span></div>
        <div class="rl-kpi"><b>${st.chat.length}</b><span>Messages</span></div>
        <div class="rl-kpi"><b>${((st.llmStatus && st.llmStatus.mcp_servers) || []).length}</b><span>MCP</span></div>
      </div>
      <div class="rl-banner">
        <strong>Relais</strong> relie le CERT à <em>n’importe quelle IA déployée en local</em>
        (Ollama, LM Studio, vLLM, LocalAI, llama.cpp…) via endpoint OpenAI-compatible ou MCP.
        L’IA consomme les outils SEP (alertes, intakes, notifications) exposés par
        <code>connectors/sekoia-mcp</code>.
      </div>
      <div class="rl-card">
        <h4>Démarrage rapide CERT</h4>
        <ol style="margin:.35rem 0 0;padding-left:1.2rem;color:var(--rl-muted);font-size:.8rem;line-height:1.5">
          <li>Déployez une IA locale (ex. <code>ollama run llama3.2</code>).</li>
          <li>Onglet <strong>IA locale</strong> → ajouter le preset → tester.</li>
          <li>Ouvrez <strong>Chat CERT</strong> ou lancez une <strong>Mission</strong>.</li>
          <li>Option Cursor : serveur MCP <code>sep</code> dans <code>.cursor/mcp.json</code>.</li>
        </ol>
        <div class="rl-bind" style="margin-top:.65rem">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="view" data-view="ai">Brancher une IA</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="view" data-view="chat">Chat CERT</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="view" data-view="missions">Missions</button>
        </div>
      </div>
      <div class="rl-card">
        <h4>Périmètre CERT</h4>
        <p>Triage silencieux · baisses de volume · veille clés API · pivot IOC · drafts d’escalade · tests canaux SOC.
        Relais ne remplace pas le jugement analyste : il accélère la boucle avec une IA que vous contrôlez on-prem.</p>
      </div>`;
  }

  function chatHtml() {
    const p = activeProvider();
    const log = (st.chat.length ? st.chat : [{
      role: 'assistant',
      text: 'Relais prêt. Branchez une IA locale, puis posez une question CERT — ou lancez une mission.',
      t: '—',
    }]).map((m) => `
      <div class="rl-chat-msg is-${esc(m.role)}">
        <div class="rl-chat-meta">${esc(m.role)} · ${esc(m.t || '')}</div>
        <div class="rl-chat-bubble">${esc(m.text)}</div>
      </div>`).join('');
    return `
      <div class="rl-panel">
        <div class="rl-panel-head">
          <h3>Chat CERT</h3>
          <span class="rl-hint">${p ? `modèle · ${esc(p.model || p.name)}` : 'aucune IA — onglet IA locale'}</span>
        </div>
        <div class="rl-chat-log" id="rl-chat-log">${log}</div>
        <textarea class="rl-chat-input" id="rl-chat-input" placeholder="Ex. Quels intakes sont silencieux ? Draft une escalade pour HOST-X…"></textarea>
        <div class="rl-toolbar">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="chat-send" ${st.busy ? 'disabled' : ''}>Envoyer</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="chat-clear">Vider</button>
          <span class="rl-spacer"></span>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="view" data-view="ai">Configurer IA</button>
        </div>
      </div>`;
  }

  function aiHtml() {
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
      <td><strong>${esc(m.name)}</strong><br><span class="fp-muted">${esc(m.transport)}</span></td>
      <td><code class="fp-muted">${esc(m.url || m.command || '—')}</code></td>
      <td>${(m.last_tools || []).slice(0, 5).map(esc).join(', ') || '—'}</td>
      <td>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-rl="mcp-probe" data-id="${esc(m.id)}">Probe</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-danger-ghost" data-rl="mcp-del" data-id="${esc(m.id)}">Retirer</button>
      </td>
    </tr>`).join('');
    return `
      <div class="rl-panel">
        <div class="rl-panel-head"><h3>IA locale via MCP / OpenAI-compatible</h3></div>
        <p class="fp-muted" style="margin:0 0 .75rem;font-size:.82rem">
          Relais ne dépend d’aucun cloud. Branchez l’IA que vous déployez on-prem.
          Les clés (si besoin) sont chiffrées Fernet côté control-plane, comme la clé Sekoia.
          Depuis le conteneur Docker, utilisez <code>host.docker.internal</code> pour joindre l’hôte.
        </p>
        <h4 style="margin:0 0 .45rem;font-size:.85rem">Presets locaux</h4>
        <div class="rl-matrix" style="margin-bottom:.85rem">${presets}</div>
        <div class="rl-card">
          <h4>Ajouter manuellement</h4>
          <div class="rl-form-grid">
            <label class="fp-label">Nom<input class="fp-input" id="rl-llm-name" placeholder="Ollama lab"></label>
            <label class="fp-label">Kind
              <select class="fp-select" id="rl-llm-kind">
                <option value="ollama">Ollama</option>
                <option value="openai_compatible">OpenAI-compatible</option>
                <option value="openai">OpenAI (distant)</option>
                <option value="anthropic">Anthropic (distant)</option>
              </select>
            </label>
            <label class="fp-label">Base URL<input class="fp-input" id="rl-llm-url" placeholder="http://host.docker.internal:11434/v1"></label>
            <label class="fp-label">Modèle<input class="fp-input" id="rl-llm-model" placeholder="llama3.2"></label>
            <label class="fp-label">API key (opt.)<input class="fp-input" id="rl-llm-key" type="password" placeholder="souvent vide en local" autocomplete="off"></label>
          </div>
          <div class="rl-toolbar">
            <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="llm-add">Enregistrer</button>
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="llm-refresh">Rafraîchir</button>
          </div>
        </div>
        <div class="fp-table-wrap" style="margin-top:.65rem"><table class="rl-table fp-table">
          <thead><tr><th>Fournisseur (actif = radio)</th><th>URL</th><th>Auth</th><th></th></tr></thead>
          <tbody>${pRows || '<tr><td colspan="4" class="fp-muted">Aucune IA — choisissez un preset</td></tr>'}</tbody>
        </table></div>
        <div class="rl-card" style="margin-top:.85rem">
          <h4>Serveurs MCP distants (HTTP)</h4>
          <p>Pour une IA qui expose déjà un endpoint MCP Streamable HTTP, enregistrez-la ici. Le serveur SEP inbound pour Cursor reste <code>connectors/sekoia-mcp/server.py</code>.</p>
          <div class="rl-form-grid" style="margin-top:.45rem">
            <label class="fp-label">Nom<input class="fp-input" id="rl-mcp-name" placeholder="mon-mcp-local"></label>
            <label class="fp-label">URL<input class="fp-input" id="rl-mcp-url" placeholder="http://host.docker.internal:3001/mcp"></label>
            <label class="fp-label">Bearer (opt.)<input class="fp-input" id="rl-mcp-token" type="password" autocomplete="off"></label>
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

  function missionsHtml() {
    return `
      <div class="rl-panel">
        <div class="rl-panel-head">
          <h3>Missions CERT</h3>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="missions-reset">Réinitialiser</button>
        </div>
        <p class="fp-muted" style="margin:0 0 .65rem;font-size:.82rem">
          Chaque mission envoie un prompt CERT à l’IA locale active. L’analyste reste décideur.
        </p>
        <div class="rl-matrix">${st.missions.map((m) => `
          <div class="rl-skill">
            <h4>${esc(m.name)}</h4>
            <p>${esc(m.desc)}</p>
            <div class="rl-skill-tags">${(m.tags || []).map((t) =>
              `<span class="rl-pill">${esc(t)}</span>`).join('')}</div>
            <div class="rl-skill-actions">
              <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-rl="mission-run" data-id="${esc(m.id)}"
                ${st.busy ? 'disabled' : ''}>Lancer</button>
            </div>
          </div>`).join('')}
        </div>
      </div>`;
  }

  function toolsHtml() {
    return `
      <div class="rl-panel">
        <div class="rl-panel-head"><h3>Outils SEP (via MCP)</h3></div>
        <p class="fp-muted" style="margin:0 0 .65rem;font-size:.82rem">
          Relais s’appuie sur le control-plane SEP. Cursor (ou une IA MCP) peut appeler les mêmes tools
          via le serveur stdio <code>connectors/sekoia-mcp</code>.
        </p>
        <div class="rl-card">
          <h4>Tools exposés</h4>
          <ul>
            <li><code>sep_health</code> · santé control-plane</li>
            <li><code>sep_alerts</code> · alertes d’ingestion</li>
            <li><code>sep_intakes_health</code> · santé intakes</li>
            <li><code>sep_notify_channels</code> / <code>sep_mail_config</code></li>
            <li><code>sep_llm_status</code> / <code>sep_llm_chat</code></li>
            <li><code>sep_gateway_catalog</code></li>
          </ul>
          <div class="rl-toolbar">
            <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="probe-sep">Ping SEP</button>
          </div>
          <div id="rl-tools-msg" class="fp-muted" style="margin-top:.45rem;font-size:.8rem"></div>
        </div>
        <div class="rl-card">
          <h4>Config Cursor</h4>
          <p>Fichier <code>.cursor/mcp.json</code> — serveur <code>sep</code>.
          Variables : <code>SEKOIA_CONTROLPLANE_URL=http://127.0.0.1:8901</code>
          et <code>INTERNAL_API_TOKEN</code>.</p>
        </div>
      </div>`;
  }

  function journalHtml() {
    const rows = st.chat.slice().reverse().slice(0, 40).map((m) => `<tr>
      <td>${esc(m.t || '')}</td>
      <td>${esc(m.role)}</td>
      <td>${esc((m.text || '').slice(0, 160))}</td>
    </tr>`).join('');
    return `
      <div class="rl-panel">
        <div class="rl-panel-head"><h3>Journal de session</h3>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="chat-clear">Purger chat</button>
        </div>
        <div class="fp-table-wrap"><table class="rl-table fp-table">
          <thead><tr><th>Heure</th><th>Rôle</th><th>Extrait</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="3" class="fp-muted">Aucune activité</td></tr>'}</tbody>
        </table></div>
      </div>`;
  }

  function mainHtml() {
    if (st.view === 'chat') return chatHtml();
    if (st.view === 'ai') return aiHtml();
    if (st.view === 'missions') return missionsHtml();
    if (st.view === 'tools') return toolsHtml();
    if (st.view === 'journal') return journalHtml();
    return homeHtml();
  }

  function sideHtml() {
    const p = activeProvider();
    return `
      <p class="rl-section-label">Contexte CERT</p>
      <div class="rl-card">
        <h4>IA active</h4>
        <p>${p
          ? `${esc(p.name)} · <code>${esc(p.model || '—')}</code>`
          : 'Aucune — branchez Ollama / LM Studio…'}</p>
        <div class="rl-bind">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="view" data-view="ai">Configurer</button>
        </div>
      </div>
      <div class="rl-card">
        <h4>Missions rapides</h4>
        <div class="rl-bind">
          ${st.missions.slice(0, 3).map((m) =>
            `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-rl="mission-run" data-id="${esc(m.id)}">${esc(m.name)}</button>`
          ).join('')}
        </div>
      </div>
      <div class="rl-card">
        <h4>Principe</h4>
        <p>IA locale sous votre contrôle · outils SEP via MCP · décisions humaines.</p>
      </div>`;
  }

  function paint() {
    const el = root();
    if (!el) return;
    el.className = 'rl-root';
    el.innerHTML = `
      <header class="rl-top">
        <div class="rl-brand">
          <h2>Relais</h2>
          <p>Copilote CERT · branchez n’importe quelle IA locale via MCP / OpenAI-compatible — outils SEP à portée.</p>
        </div>
        <div class="rl-chips">${statusChips()}</div>
      </header>
      <nav class="rl-subnav" aria-label="Relais">${VIEWS.map((v) =>
        `<button type="button" class="rl-tab${st.view === v.id ? ' is-active' : ''}" data-rl="view" data-view="${v.id}">${esc(v.label)}</button>`
      ).join('')}</nav>
      <div class="rl-body">
        <aside class="rl-rail">
          <p class="rl-section-label">Navigation</p>
          ${VIEWS.map((v) => `
            <button type="button" class="rl-session${st.view === v.id ? ' is-active' : ''}" data-rl="view" data-view="${v.id}">
              <div class="rl-session-title"><span>${esc(v.label)}</span></div>
            </button>`).join('')}
        </aside>
        <section class="rl-main">${mainHtml()}</section>
        <aside class="rl-side">${sideHtml()}</aside>
      </div>
      <footer class="rl-footer-bar">
        <span>Relais × SEP · CYBERCORP</span>
        <span>view=${esc(st.view)} · IA=${esc((activeProvider() || {}).name || 'off')}</span>
      </footer>`;
    bind(el);
    const chatLog = document.getElementById('rl-chat-log');
    if (chatLog) chatLog.scrollTop = chatLog.scrollHeight;
  }

  async function runChat(userText, opts) {
    const msg = String(userText || '').trim();
    if (!msg || st.busy) return;
    const o = opts || {};
    st.busy = true;
    if (!o.silentUser) {
      st.chat.push({ role: 'user', text: msg, t: nowStamp() });
      persistChat();
    }
    paint();
    const p = activeProvider();
    try {
      if (!p) throw new Error('Aucune IA locale configurée — onglet IA locale');
      const r = await sepApi('/llm/chat', {
        method: 'POST',
        body: {
          provider_id: p.id,
          messages: [
            { role: 'system', content: st.cfg.systemPrompt || DEFAULT_CFG.systemPrompt },
            ...st.chat.filter((m) => m.role === 'user' || m.role === 'assistant').slice(-12).map((m) => ({
              role: m.role,
              content: m.text,
            })),
          ],
        },
      });
      if (r && r.ok && r.text) {
        st.chat.push({ role: 'assistant', text: r.text, t: nowStamp() });
      } else {
        st.chat.push({
          role: 'assistant',
          text: `Échec IA : ${(r && r.error) || 'réponse vide'}. Vérifiez que le service local écoute et que l’URL est joignable depuis le control-plane.`,
          t: nowStamp(),
        });
      }
    } catch (e) {
      st.chat.push({
        role: 'assistant',
        text: String(e.message || e),
        t: nowStamp(),
      });
    }
    persistChat();
    st.busy = false;
    st.view = 'chat';
    paint();
  }

  function bind(el) {
    el.addEventListener('click', (ev) => {
      const b = ev.target.closest('[data-rl]');
      if (!b) return;
      const act = b.dataset.rl;

      if (act === 'view') {
        st.view = b.dataset.view || 'home';
        if (st.view === 'ai') {
          paint();
          refreshLlm().then(() => paint());
          return;
        }
        paint();
        return;
      }
      if (act === 'chat-send') {
        const ta = document.getElementById('rl-chat-input');
        runChat(ta && ta.value);
        return;
      }
      if (act === 'chat-clear') {
        if (!confirm('Purger l’historique Relais ?')) return;
        st.chat = [];
        persistChat();
        paint();
        return;
      }
      if (act === 'llm-refresh') {
        refreshLlm().then(() => { toast('État IA rafraîchi', 'ok'); paint(); });
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
        const nameEl = document.getElementById('rl-llm-name');
        const kindEl = document.getElementById('rl-llm-kind');
        const urlEl = document.getElementById('rl-llm-url');
        const modelEl = document.getElementById('rl-llm-model');
        if (nameEl) nameEl.value = pr.name;
        if (kindEl) kindEl.value = pr.kind;
        if (urlEl) urlEl.value = pr.base_url;
        if (modelEl) modelEl.value = pr.model;
        toast(`Preset ${pr.name} chargé — Enregistrer pour activer`, 'ok');
        return;
      }
      if (act === 'llm-add') {
        const name = ((document.getElementById('rl-llm-name') || {}).value || '').trim();
        const kind = ((document.getElementById('rl-llm-kind') || {}).value || 'ollama').trim();
        const base_url = ((document.getElementById('rl-llm-url') || {}).value || '').trim();
        const model = ((document.getElementById('rl-llm-model') || {}).value || '').trim();
        const api_key = ((document.getElementById('rl-llm-key') || {}).value || '').trim();
        if (!base_url && kind !== 'openai' && kind !== 'anthropic') {
          toast('Base URL requise pour une IA locale', 'err');
          return;
        }
        sepApi('/llm/providers', {
          method: 'POST',
          body: { name: name || kind, kind, base_url, model, api_key },
        }).then((r) => {
          if (r && r.provider && r.provider.id) {
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
        st.msg = 'Test en cours…';
        paint();
        sepApi('/llm/chat', {
          method: 'POST',
          body: {
            provider_id: id,
            messages: [{ role: 'user', content: 'Réponds en une phrase : Relais CERT OK ?' }],
          },
        }).then((r) => {
          st.msg = r.ok ? (r.text || 'OK') : (r.error || 'échec');
          toast(r.ok ? 'IA locale OK' : (r.error || 'échec'), r.ok ? 'ok' : 'err');
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
        if (!url) { toast('URL MCP requise', 'err'); return; }
        sepApi('/mcp/servers', {
          method: 'POST',
          body: { name: name || 'mcp-local', transport: 'http', url, token },
        }).then(() => refreshLlm()).then(() => { toast('MCP ajouté', 'ok'); paint(); })
          .catch((e) => toast(e.message || 'Échec', 'err'));
        return;
      }
      if (act === 'mcp-del') {
        if (!confirm('Retirer ce MCP ?')) return;
        sepApi(`/mcp/servers/${encodeURIComponent(b.dataset.id)}`, { method: 'DELETE' })
          .then(() => refreshLlm()).then(() => { toast('MCP retiré', 'ok'); paint(); })
          .catch((e) => toast(e.message || 'Échec', 'err'));
        return;
      }
      if (act === 'mcp-probe') {
        sepApi(`/mcp/servers/${encodeURIComponent(b.dataset.id)}/probe`, { method: 'POST' })
          .then((r) => {
            toast(r.ok ? `${r.count || 0} tool(s)` : (r.error || 'probe échoué'), r.ok ? 'ok' : 'err');
            return refreshLlm();
          }).then(() => paint())
          .catch((e) => toast(e.message || 'Échec', 'err'));
        return;
      }
      if (act === 'mission-run') {
        const m = st.missions.find((x) => x.id === b.dataset.id);
        if (!m) return;
        st.view = 'chat';
        runChat(m.prompt);
        return;
      }
      if (act === 'missions-reset') {
        if (!confirm('Réinitialiser les missions CERT par défaut ?')) return;
        st.missions = CERT_MISSIONS.map((m) => Object.assign({}, m));
        persistMissions();
        toast('Missions réinitialisées', 'ok');
        paint();
        return;
      }
      if (act === 'probe-sep') {
        const box = document.getElementById('rl-tools-msg');
        sepApi('/llm/status').then((r) => {
          if (box) {
            box.textContent = r.ok
              ? `SEP OK · ${(r.providers || []).length} IA · store ${r.secrets_store || '?'}`
              : (r.error || 'échec');
          }
          toast('Ping SEP OK', 'ok');
        }).catch((e) => {
          if (box) box.textContent = e.message || String(e);
          toast('SEP injoignable', 'err');
        });
      }
    });

    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' && (ev.metaKey || ev.ctrlKey)) {
        const ta = document.getElementById('rl-chat-input');
        if (ta && el.contains(ta)) {
          ev.preventDefault();
          runChat(ta.value);
        }
      }
    });
  }

  function mount() {
    refreshLlm().finally(() => paint());
  }

  window.SekoiaRelais = { mount, paint };
  // compat ancien nom
  window.SekoiaKheish = window.SekoiaRelais;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      const tab = new URLSearchParams(location.search).get('tab');
      if (tab === 'sekoia-relais' || tab === 'sekoia-kheish') mount();
    });
  } else if (['sekoia-relais', 'sekoia-kheish'].includes(
    new URLSearchParams(location.search).get('tab')
  )) {
    mount();
  }
})();
