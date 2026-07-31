/* ═══════════════════════════════════════════════════════════════════════════
   PSOAR — console d'incidents.

   Reprend le systeme de design du workbench Sekoia (.swb-*) : meme densite,
   memes etats dessines, meme ergonomie clavier. Un analyste qui passe de la
   supervision a la reponse ne change pas de langage visuel.

   Parti pris :
   - la FILE est l'ecran principal, le detail arrive en volet lateral ;
   - le clic sur une LIGNE ouvre le detail (exigence non negociable) ;
   - le SLA est un compte a rebours vivant, pas une date morte ;
   - la progression des taches est lisible d'un coup d'oeil, par phase NIST ;
   - aucune action destructive sans confirmation explicite.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  const TC = window.ThreatCommon || null;
  const esc = (s) => (TC && TC.esc ? TC.esc(s) : String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));
  const toast = (m, c) => { if (TC && TC.toast) TC.toast(m, c); };

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const STATUSES = ['new', 'in_progress', 'contained', 'closed', 'purged'];
  const OPEN = ['new', 'in_progress', 'contained'];
  const FLOW = ['new', 'in_progress', 'contained', 'closed'];
  const PHASES = [
    ['detection', 'Détection'], ['analysis', 'Analyse'], ['containment', 'Confinement'],
    ['eradication', 'Éradication'], ['recovery', 'Récupération'], ['lessons', 'Leçons'],
  ];
  const SEV_TONE = { critical: 'danger', high: 'warn', medium: 'mute', low: 'mute', info: 'mute' };
  const STATUS_TONE = { new: 'danger', in_progress: 'warn', contained: 'ok', closed: 'mute', purged: 'mute' };
  const STATUS_LABEL = {
    new: 'nouveau', in_progress: 'en cours', contained: 'confiné',
    closed: 'clôturé', purged: 'purgé',
  };

  const st = { list: [], detail: null, tab: 'timeline', loading: false, error: null,
    q: '', filters: {}, sort: null, sortDir: -1 };

  const lang = () => ((window.i18n && i18n.getLanguage && i18n.getLanguage() === 'en') ? 'en-US' : 'fr-FR');
  function nf(n) {
    if (n === null || n === undefined || n === '') return '—';
    const v = Number(n);
    return Number.isFinite(v) ? v.toLocaleString(lang()) : String(n);
  }
  function dt(s) {
    if (!s) return '—';
    return String(s).replace('T', ' ').replace(/\.\d+Z?$/, '').slice(0, 16);
  }
  /** Durée signée lisible : « 3 h 12 » ou « −2 j 4 h » pour un SLA dépassé. */
  function dur(ms) {
    const neg = ms < 0;
    const a = Math.abs(ms);
    const d = Math.floor(a / 86400000);
    const h = Math.floor((a % 86400000) / 3600000);
    const m = Math.floor((a % 3600000) / 60000);
    const txt = d ? `${d} j ${h} h` : (h ? `${h} h ${m}` : `${m} min`);
    return (neg ? '−' : '') + txt;
  }

  async function api(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    if (o.body && typeof o.body !== 'string') {
      o.body = JSON.stringify(o.body);
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
    }
    const r = await fetch('/api' + path, o);
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  }

  function root() { return document.getElementById('psoar-root'); }

  // ── Briques (alignees sur le systeme de design du workbench) ──────────────
  function kpi(label, value, tone, hint) {
    return `<div class="swb-kpi${tone ? ` swb-kpi-${tone}` : ''}">
      <div class="swb-kpi-value">${esc(value)}</div>
      <div class="swb-kpi-label">${esc(label)}</div>
      ${hint ? `<div class="swb-kpi-hint">${esc(hint)}</div>` : ''}</div>`;
  }
  function pill(text, tone, flat) {
    return `<span class="swb-pill swb-pill-${tone || 'mute'}${flat ? ' swb-pill-flat' : ''}">${esc(text)}</span>`;
  }
  function meter(pct, tone) {
    const p = Math.max(0, Math.min(100, Math.round(pct)));
    return `<span class="swb-meter swb-meter-${tone || 'ok'}" role="img" aria-label="${p} %"><span style="width:${p}%"></span></span>`;
  }
  function skeleton(n) {
    let s = '<div class="swb-panel">';
    for (let i = 0; i < (n || 6); i += 1) s += `<div class="swb-skel" style="width:${88 - i * 7}%"></div>`;
    return s + '</div>';
  }
  function degraded(msg) {
    return `<div class="swb-state swb-state-degraded" role="status">
      <p class="swb-state-title">Donnée momentanément indisponible</p>
      <p class="swb-state-msg">${esc(msg)}</p>
      <button type="button" class="fp-btn fp-btn-sm" data-pso-act="reload">Réessayer</button></div>`;
  }

  /** SLA vivant : reste, dépassement, ou sans objet si l'incident est clos. */
  function sla(inc) {
    if (!inc.sla_due) return pill('sans SLA', 'mute', true);
    if (!OPEN.includes(inc.status)) return pill('sans objet', 'mute', true);
    const ms = new Date(inc.sla_due).getTime() - Date.now();
    if (!Number.isFinite(ms)) return pill('—', 'mute', true);
    if (ms < 0) return pill(`dépassé de ${dur(ms).replace('−', '')}`, 'danger');
    return pill(`${dur(ms)} restant`, ms < 4 * 3600000 ? 'warn' : 'ok');
  }
  /** Le SLA se lit IDENTIQUEMENT dans la file et dans le dossier : la file
   *  annoncait « depasse de 57 min » quand le dossier n'affichait qu'une date. */
  function slaKpi(inc) {
    if (!inc.sla_due) return kpi('SLA', 'sans objet', 'mute', 'aucune echeance definie');
    if (!OPEN.includes(inc.status)) {
      return kpi('SLA', dt(inc.sla_due), 'mute', 'incident clos — compteur arrêté');
    }
    const ms = new Date(inc.sla_due).getTime() - Date.now();
    if (!Number.isFinite(ms)) return kpi('SLA', '—', 'mute');
    return ms < 0
      ? kpi('SLA', `dépassé de ${dur(ms).replace('−', '')}`, 'danger', `échéance ${dt(inc.sla_due)}`)
      : kpi('SLA', `${dur(ms)} restant`, ms < 4 * 3600000 ? 'warn' : 'ok', `échéance ${dt(inc.sla_due)}`);
  }

  function tasks(inc) {
    const t = Array.isArray(inc.tasks) ? inc.tasks : [];
    const done = t.filter((x) => x.done).length;
    return { done, total: t.length, pct: t.length ? (done / t.length) * 100 : 0 };
  }

  // ── File d'incidents ──────────────────────────────────────────────────────
  function renderQueue() {
    const all = st.list;
    const open = all.filter((r) => OPEN.includes(r.status));
    const crit = open.filter((r) => ['critical', 'high'].includes(r.severity));
    const overdue = open.filter((r) => r.sla_due && new Date(r.sla_due) < new Date());
    const unassigned = open.filter((r) => !r.assignee);

    const f = st.filters;
    let rows = all.filter((r) => {
      if (st.q) {
        const hay = `${r.incident_id} ${r.title} ${r.assignee || ''} ${(r.tags || []).join(' ')}`.toLowerCase();
        if (!hay.includes(st.q.toLowerCase())) return false;
      }
      if (f.status && r.status !== f.status) return false;
      if (f.severity && r.severity !== f.severity) return false;
      if (f.scope === 'open' && !OPEN.includes(r.status)) return false;
      if (f.scope === 'overdue' && !(r.sla_due && new Date(r.sla_due) < new Date() && OPEN.includes(r.status))) return false;
      if (f.scope === 'mine' && !r.assignee) return false;
      return true;
    });
    const key = st.sort || 'created_at';
    const dir = st.sort ? st.sortDir : -1;
    rows = rows.slice().sort((a, b) => {
      if (key === 'severity') {
        return (SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)) * -dir;
      }
      return String(a[key] ?? '').localeCompare(String(b[key] ?? ''), lang()) * dir;
    });

    const body = rows.map((r) => {
      const t = tasks(r);
      return `<tr class="swb-clickable" data-pso-act="open" data-id="${esc(r.incident_id)}">
        <td>${pill(r.severity, SEV_TONE[r.severity] || 'mute')}</td>
        <td class="swb-mono">${esc(r.incident_id)}</td>
        <td class="swb-truncate" title="${esc(r.title)}">${esc(r.title)}</td>
        <td>${pill(STATUS_LABEL[r.status] || r.status, STATUS_TONE[r.status] || 'mute', true)}</td>
        <td>${sla(r)}</td>
        <td>${t.total ? `${meter(t.pct, t.pct === 100 ? 'ok' : 'warn')} <span class="swb-hint">${t.done}/${t.total}</span>`
    : '<span class="swb-hint">aucune tâche</span>'}</td>
        <td class="swb-truncate">${esc(r.assignee || '—')}</td>
        <td class="swb-hint">${esc(dt(r.created_at))}</td></tr>`;
    }).join('');

    const opt = (v, l, cur) => `<option value="${esc(v)}"${cur === v ? ' selected' : ''}>${esc(l)}</option>`;
    return `<nav class="swb-nav" style="position:static">
        <button type="button" class="swb-tab" aria-selected="true">File d'incidents</button>
        <button type="button" class="swb-tab" aria-selected="false" data-pso-act="intake">Candidats corrélés${
  st.intakeCount ? `<span class="swb-tab-badge swb-tab-badge-danger">${esc(st.intakeCount)}</span>` : ''}</button>
      </nav>
      <div class="swb-head">
        <div><h2 class="swb-title">File d'incidents</h2>
          <p class="swb-sub">Triage, SLA et progression des playbooks. Le clic sur une ligne ouvre le dossier.</p></div>
        <div class="swb-actions">
          <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pso-act="new">Nouvel incident</button>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pso-act="reload">↻ Rafraîchir</button></div></div>
      <div class="swb-kpis">
        ${kpi('Ouverts', nf(open.length), open.length ? 'warn' : 'ok', `${nf(all.length)} au total`)}
        ${kpi('Critiques et élevés', nf(crit.length), crit.length ? 'danger' : 'ok')}
        ${kpi('SLA dépassés', nf(overdue.length), overdue.length ? 'danger' : 'ok')}
        ${kpi('Non assignés', nf(unassigned.length), unassigned.length ? 'warn' : 'ok')}
      </div>
      <div class="swb-filters">
        <input type="search" class="swb-input swb-search" id="pso-q" placeholder="Rechercher un incident, un analyste, un tag…"
               value="${esc(st.q)}" aria-label="Rechercher">
        <select class="swb-select" data-pso-filter="scope" aria-label="Périmètre">
          ${opt('', 'Tous les incidents', f.scope)}${opt('open', 'Ouverts', f.scope)}
          ${opt('overdue', 'SLA dépassé', f.scope)}${opt('mine', 'Assignés', f.scope)}
        </select>
        <select class="swb-select" data-pso-filter="severity" aria-label="Sévérité">
          ${opt('', 'Toutes sévérités', f.severity)}${SEVERITIES.map((s) => opt(s, s, f.severity)).join('')}
        </select>
        <select class="swb-select" data-pso-filter="status" aria-label="Statut">
          ${opt('', 'Tous statuts', f.status)}${STATUSES.map((s) => opt(s, STATUS_LABEL[s], f.status)).join('')}
        </select>
        <span class="swb-count">${nf(rows.length)} / ${nf(all.length)}</span>
        <span class="swb-nav-spacer"></span>
        <span class="swb-hint"><span class="swb-kbd">/</span> rechercher · <span class="swb-kbd">n</span> nouveau · <span class="swb-kbd">Échap</span> fermer</span>
      </div>
      <div class="swb-panel" style="padding:0"><div class="swb-tablewrap"><table class="swb-table"><thead><tr>
        ${thh('Sévérité', 'severity')}${thh('Identifiant', 'incident_id')}${thh('Titre', 'title')}
        ${thh('Statut', 'status')}<th>SLA</th><th>Playbook</th>${thh('Assigné', 'assignee')}${thh('Créé', 'created_at')}
      </tr></thead><tbody>${body || `<tr><td colspan="8">${emptyQueue(all.length)}</td></tr>`}</tbody></table></div></div>`;
  }
  function thh(label, key) {
    const on = st.sort === key;
    return `<th class="swb-sortable" data-pso-sort="${key}">${esc(label)}${on ? (st.sortDir < 0 ? ' ↓' : ' ↑') : ''}</th>`;
  }
  function emptyQueue(total) {
    return total
      ? '<p class="swb-hint" style="padding:1rem">Aucun incident ne correspond aux filtres.</p>'
      : `<div class="swb-state" style="margin:1rem"><p class="swb-state-title">Aucun incident ouvert</p>
        <p class="swb-state-msg">Créez un incident pour ouvrir un dossier d'investigation : timeline, evidences, IOC,
        playbooks exécutables et rapport de clôture y sont rattachés.</p>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pso-act="new">Créer un incident</button></div>`;
  }

  // ── Candidats corréles ────────────────────────────────────────────────────
  function renderIntake() {
    const d = st.intake;
    if (!d) return degraded('Moteur de corrélation injoignable.');
    const cl = d.clusters || [];
    const promotable = cl.filter((c) => !c.promoted_incident_id);

    const rows = cl.map((c) => {
      const tone = c.score >= 80 ? 'danger' : c.score >= 60 ? 'warn' : 'mute';
      return `<tr>
        <td class="swb-num">${pill(String(c.score), tone)}</td>
        <td>${pill(c.max_severity, SEV_TONE[c.max_severity] || 'mute', true)}</td>
        <td class="swb-truncate" title="${esc(c.rule_family)}">${esc(c.rule_family)}</td>
        <td class="swb-truncate" title="${esc(c.axis)}">${esc(c.axis)}</td>
        <td class="swb-num">${esc(c.alert_count)}</td>
        <td class="swb-num">${esc(c.targets.length)}</td>
        <td class="swb-hint swb-truncate" title="${esc(c.rationale)}">${esc(c.rationale)}</td>
        <td>${c.promoted_incident_id
    ? `<span class="swb-hint">→ ${esc(c.promoted_incident_id)}</span>`
    : `<button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pso-act="promote"
         data-key="${esc(c.correlation_key)}">Ouvrir un incident</button>`}</td></tr>`;
    }).join('');

    return `<nav class="swb-nav" style="position:static">
        <button type="button" class="swb-tab" aria-selected="false" data-pso-act="queue">File d'incidents</button>
        <button type="button" class="swb-tab" aria-selected="true">Candidats corrélés</button>
      </nav>
      <div class="swb-head">
        <div><h2 class="swb-title">Candidats d'incident</h2>
          <p class="swb-sub">Alertes du SIEM et de l'ingestion, dédupliquées puis regroupées par cause probable
            sur une fenêtre de ${esc(d.window_min)} min. Le score est décomposé : il doit pouvoir être contesté.</p></div>
        <div class="swb-actions">
          <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pso-act="intake">↻ Réévaluer</button></div></div>
      <div class="swb-kpis">
        ${kpi('Alertes collectées', nf(d.collected), 'ok', `${nf(d.in_window)} dans la fenêtre`)}
        ${kpi('Doublons écartés', nf(d.deduplicated), d.deduplicated ? 'warn' : 'ok')}
        ${kpi('Grappes', nf(d.clusters_total), 'ok', `${nf(promotable.length)} promouvables`)}
        ${kpi('Promotion auto', d.auto_promote ? `≥ ${d.auto_min_score}` : 'désactivée',
    d.auto_promote ? 'warn' : 'ok', d.auto_promote ? 'ouverture sans intervention' : 'l\'analyste décide')}
      </div>
      ${d.errors ? `<div class="swb-state swb-state-degraded"><p class="swb-state-title">Sources partiellement indisponibles</p>
        <p class="swb-state-msg">${esc(d.errors.join(' · '))}</p></div>` : ''}
      <div class="swb-panel" style="padding:0"><div class="swb-tablewrap"><table class="swb-table"><thead><tr>
        <th class="swb-num">Score</th><th>Sévérité</th><th>Famille</th><th>Axe de corrélation</th>
        <th class="swb-num">Alertes</th><th class="swb-num">Cibles</th><th>Justification</th><th></th>
      </tr></thead><tbody>${rows || `<tr><td colspan="8"><div class="swb-state" style="margin:1rem">
        <p class="swb-state-title">Aucun candidat</p>
        <p class="swb-state-msg">Aucune alerte corrélable sur la fenêtre. Les alertes d'ingestion apparaissent
        ici dès qu'une source décroche.</p></div></td></tr>`}</tbody></table></div></div>`;
  }

  // ── Dossier d'incident ────────────────────────────────────────────────────
  const WS_TABS = [['timeline', 'Timeline'], ['tasks', 'Playbook'], ['iocs', 'IOC'],
    ['evidence', 'Evidences'], ['report', 'Rapport']];

  function stepper(inc) {
    const cur = FLOW.indexOf(inc.status);
    return `<div class="pso-stepper">${FLOW.map((s, i) => {
      const cls = inc.status === 'purged' ? '' : (i < cur ? ' pso-step-done' : i === cur ? ' pso-step-current' : '');
      return `<button type="button" class="pso-step${cls}" data-pso-act="status" data-status="${s}"
        title="Passer en « ${esc(STATUS_LABEL[s])} »">${esc(STATUS_LABEL[s])}</button>`;
    }).join('')}</div>`;
  }

  function renderDetail() {
    const d = st.detail;
    const inc = d.incident;
    const evts = d.events || [];
    const t = tasks(inc);
    const byKind = (k) => evts.filter((e) => e.kind === k);

    let panel = '';
    if (st.tab === 'timeline') {
      const items = evts.filter((e) => ['timeline', 'note', 'status'].includes(e.kind))
        .slice().reverse();
      panel = items.length ? `<ol class="pso-timeline">${items.map((e) => `<li>
          <span class="pso-time">${esc(dt(e.event_at || e.created_at))}</span>
          <span class="pso-dot pso-dot-${e.kind === 'status' ? 'status' : 'note'}"></span>
          <div><strong>${esc(e.title)}</strong>
            ${e.description ? `<p class="swb-hint">${esc(e.description)}</p>` : ''}
            <p class="swb-hint">par ${esc(e.created_by || '—')}</p></div></li>`).join('')}</ol>`
        : '<p class="swb-hint">Aucun événement. Ajoutez une note pour tracer votre analyse.</p>';
      panel += `<div class="swb-filters" style="margin-top:.8rem">
        <input class="swb-input swb-search" id="pso-note" placeholder="Ajouter une note à la timeline…">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pso-act="add-note">Ajouter</button></div>`;
    } else if (st.tab === 'tasks') {
      const all = Array.isArray(inc.tasks) ? inc.tasks : [];
      panel = PHASES.map(([ph, label]) => {
        const items = all.filter((x) => x.phase === ph);
        if (!items.length) return '';
        return `<div class="pso-phase"><h4 class="swb-panel-title">${esc(label)}
            <span class="swb-hint">${items.filter((x) => x.done).length}/${items.length}</span></h4>
          <ul class="pso-tasks">${items.map((x) => `<li>
            <label><input type="checkbox" data-pso-act="task-toggle" data-id="${esc(x.id)}"
              ${x.done ? 'checked' : ''}> <span${x.done ? ' class="pso-done"' : ''}>${esc(x.title)}</span></label>
            ${x.assignee ? `<span class="swb-hint">${esc(x.assignee)}</span>` : ''}</li>`).join('')}</ul></div>`;
      }).join('') || '<p class="swb-hint">Aucune tâche. Exécutez un playbook depuis l\'onglet PSOAR — Playbooks pour en générer.</p>';
      panel = `<div style="margin-bottom:.6rem">${meter(t.pct, t.pct === 100 ? 'ok' : 'warn')}
        <span class="swb-hint">${t.done}/${t.total} tâches terminées</span></div>` + panel;
    } else if (st.tab === 'iocs') {
      const iocs = byKind('ioc');
      panel = `<div class="swb-filters">
          <input class="swb-input swb-search" id="pso-ioc" placeholder="IP, domaine, hash, URL…">
          <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pso-act="add-ioc">Ajouter l'IOC</button>
          <button type="button" class="fp-btn fp-btn-sm" data-pso-act="scan">Scanner les logs ingérés</button></div>`
        + (iocs.length ? `<div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          <th>Valeur</th><th>Type</th><th>Ajouté</th></tr></thead><tbody>${iocs.map((e) => `<tr>
            <td class="swb-mono">${esc(e.value)}</td><td>${pill(e.ioc_type || '?', 'mute', true)}</td>
            <td class="swb-hint">${esc(dt(e.created_at))}</td></tr>`).join('')}</tbody></table></div>`
          : '<p class="swb-hint">Aucun IOC rattaché. Le scan compare les IOC de l\'incident et les watchlists Sekoia aux logs ingérés.</p>');
    } else if (st.tab === 'evidence') {
      const ev = byKind('evidence');
      const ups = d.uploads || [];
      panel = `<h4 class="swb-panel-title">Fichiers ingérés (${nf(ups.length)})</h4>`
        + (ups.length ? `<div class="swb-tablewrap" style="max-height:26vh"><table class="swb-table"><tbody>${ups.map((u) => `<tr>
            <td class="swb-truncate">${esc(u.file && u.file.name)}</td>
            <td class="swb-num swb-hint">${nf(u.file && u.file.size)} o</td>
            <td class="swb-hint">${esc(dt(u['@timestamp']))}</td></tr>`).join('')}</tbody></table></div>`
          : '<p class="swb-hint">Aucun fichier. Utilisez « Upload evidences » avec l\'identifiant de l\'incident comme case.</p>')
        + `<h4 class="swb-panel-title" style="margin-top:1rem">Evidences consignées (${nf(ev.length)})</h4>`
        + (ev.length ? ev.map((e) => `<details class="pso-evidence"><summary>${esc(e.title)}
            <span class="swb-hint">${esc(dt(e.created_at))}</span></summary>
            <pre class="swb-mono">${esc(String(e.description || '').slice(0, 4000))}</pre></details>`).join('')
          : '<p class="swb-hint">Aucune evidence. Le scan IOC en produit automatiquement.</p>');
    } else {
      panel = `<div class="swb-filters">
          <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pso-act="report">Générer le rapport</button>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-danger" data-pso-act="purge">Purge de fin d'investigation…</button></div>
        <p class="swb-hint">Le rapport reprend le dossier complet : description, fichiers ingérés, playbook, timeline, evidences et IOC.
        La purge simule d'abord, puis exige une confirmation explicite.</p>
        ${st.report ? `<pre class="swb-mono pso-report">${esc(st.report)}</pre>` : ''}
        ${st.purge ? `<div class="swb-panel" style="border-left:3px solid var(--swb-warn);margin-top:.8rem">
          <h4 class="swb-panel-title">Simulation de purge</h4>
          <pre class="swb-mono">${esc(JSON.stringify(st.purge, null, 1).slice(0, 2500))}</pre>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-danger" data-pso-act="purge-confirm">Confirmer la purge définitive</button></div>` : ''}`;
    }

    return `<div class="swb-head">
        <div><h2 class="swb-title">${esc(inc.title)}</h2>
          <p class="swb-sub"><span class="swb-mono">${esc(inc.incident_id)}</span> ·
            créé le ${esc(dt(inc.created_at))} par ${esc(inc.created_by || '—')}</p></div>
        <div class="swb-actions">
          <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pso-act="back">← Retour à la file</button></div></div>
      <div class="swb-kpis">
        ${kpi('Sévérité', inc.severity, SEV_TONE[inc.severity] || 'mute')}
        ${kpi('Statut', STATUS_LABEL[inc.status] || inc.status, STATUS_TONE[inc.status] || 'mute')}
        ${slaKpi(inc)}
        ${kpi('Playbook', `${t.done}/${t.total}`, t.total && t.pct === 100 ? 'ok' : 'warn')}
        ${kpi('Assigné à', inc.assignee || 'personne', inc.assignee ? 'ok' : 'warn')}
      </div>
      ${stepper(inc)}
      <nav class="swb-nav" style="position:static">${WS_TABS.map(([k, l]) => `<button type="button"
        class="swb-tab" aria-selected="${st.tab === k}" data-pso-tab="${k}">${esc(l)}</button>`).join('')}</nav>
      <div class="swb-panel">${panel}</div>`;
  }

  // ── Rendu ─────────────────────────────────────────────────────────────────
  function paint() {
    const el = root();
    if (!el) return;
    el.className = 'swb';
    if (st.loading) { el.innerHTML = skeleton(7); return; }
    if (st.error) { el.innerHTML = degraded(st.error); return; }
    el.innerHTML = st.detail ? renderDetail() : (st.view === 'intake' ? renderIntake() : renderQueue());
  }

  async function load() {
    st.loading = true; st.error = null; paint();
    try { st.list = await api('/incidents'); } catch (e) { st.error = e.message; }
    st.loading = false; paint();
  }
  async function open(id) {
    st.loading = true; paint();
    try {
      st.detail = await api('/incidents/' + encodeURIComponent(id));
      st.tab = 'timeline'; st.report = null; st.purge = null;
    } catch (e) { st.error = e.message; }
    st.loading = false; paint();
  }
  async function refreshDetail() {
    if (!st.detail) return;
    st.detail = await api('/incidents/' + encodeURIComponent(st.detail.incident.incident_id));
    paint();
  }

  // ── Interactions ──────────────────────────────────────────────────────────
  function bind(el) {
    if (el.dataset.psoBound) return;
    el.dataset.psoBound = '1';

    el.addEventListener('input', (ev) => {
      if (ev.target.id !== 'pso-q') return;
      st.q = ev.target.value;
      const pos = ev.target.selectionStart;
      paint();
      const again = document.getElementById('pso-q');
      if (again) { again.focus(); again.setSelectionRange(pos, pos); }
    });
    el.addEventListener('change', async (ev) => {
      const f = ev.target.closest('[data-pso-filter]');
      if (f) { st.filters[f.dataset.psoFilter] = f.value; paint(); return; }
      const cb = ev.target.closest('[data-pso-act="task-toggle"]');
      if (cb && st.detail) {
        try {
          await api(`/incidents/${encodeURIComponent(st.detail.incident.incident_id)}/tasks/${encodeURIComponent(cb.dataset.id)}`,
            { method: 'PATCH', body: { done: cb.checked } });
          await refreshDetail();
        } catch (e) { toast(e.message, 'err'); }
      }
    });

    el.addEventListener('click', async (ev) => {
      const tab = ev.target.closest('[data-pso-tab]');
      if (tab) { st.tab = tab.dataset.psoTab; paint(); return; }
      const so = ev.target.closest('[data-pso-sort]');
      if (so) {
        const k = so.dataset.psoSort;
        st.sortDir = (st.sort === k) ? -st.sortDir : -1;
        st.sort = k; paint(); return;
      }
      // Le clic sur une LIGNE ouvre le dossier — pas seulement sur un bouton.
      const row = ev.target.closest('tr[data-pso-act]');
      const b = ev.target.closest('[data-pso-act]') || row;
      if (!b) return;
      const act = b.dataset.psoAct;
      const inc = st.detail && st.detail.incident;
      try {
        if (act === 'reload') { st.detail = null; load(); return; }
        if (act === 'queue') { st.view = 'queue'; st.detail = null; load(); return; }
        if (act === 'intake') {
          st.view = 'intake'; st.detail = null; st.loading = true; paint();
          try {
            st.intake = await api('/alert-intake?hours=24');
            st.intakeCount = (st.intake.clusters || []).filter((c) => !c.promoted_incident_id).length;
          } catch (e) { st.error = e.message; }
          st.loading = false; paint(); return;
        }
        if (act === 'promote') {
          const r = await api('/alert-intake/promote', {
            method: 'POST', body: { correlation_key: b.dataset.key, hours: 24 },
          });
          toast(`Incident ${r.incident_id} ouvert`, 'ok');
          st.intake = await api('/alert-intake?hours=24');
          st.intakeCount = (st.intake.clusters || []).filter((c) => !c.promoted_incident_id).length;
          paint(); return;
        }
        if (act === 'open') { open(b.dataset.id); return; }
        if (act === 'back') { st.detail = null; load(); return; }
        if (act === 'new') {
          const title = window.prompt('Titre de l\'incident');
          if (!title) return;
          const sev = window.prompt(`Sévérité (${SEVERITIES.join(', ')})`, 'medium');
          const r = await api('/incidents', { method: 'POST', body: { title, severity: sev || 'medium' } });
          toast(`Incident ${r.incident.incident_id} créé`, 'ok');
          open(r.incident.incident_id); return;
        }
        if (act === 'status' && inc) {
          await api('/incidents/' + encodeURIComponent(inc.incident_id),
            { method: 'PATCH', body: { status: b.dataset.status } });
          await refreshDetail(); toast('Statut mis à jour', 'ok'); return;
        }
        if (act === 'add-note' && inc) {
          const v = (document.getElementById('pso-note') || {}).value || '';
          if (!v.trim()) { toast('Saisissez une note', 'err'); return; }
          await api(`/incidents/${encodeURIComponent(inc.incident_id)}/events`,
            { method: 'POST', body: { kind: 'note', title: v.trim() } });
          await refreshDetail(); return;
        }
        if (act === 'add-ioc' && inc) {
          const v = (document.getElementById('pso-ioc') || {}).value || '';
          if (!v.trim()) { toast('Saisissez un IOC', 'err'); return; }
          await api(`/incidents/${encodeURIComponent(inc.incident_id)}/events`,
            { method: 'POST', body: { kind: 'ioc', title: `IOC ${v.trim()}`, value: v.trim() } });
          await refreshDetail(); return;
        }
        if (act === 'scan' && inc) {
          toast('Scan en cours…', 'ok');
          const r = await api(`/incidents/${encodeURIComponent(inc.incident_id)}/scan`, { method: 'POST', body: {} });
          toast(`${r.matches.length} correspondance(s) sur ${r.iocs_scanned} IOC`, r.matches.length ? 'warn' : 'ok');
          await refreshDetail(); return;
        }
        if (act === 'report' && inc) {
          const r = await api(`/incidents/${encodeURIComponent(inc.incident_id)}/report`);
          st.report = r.report; paint(); return;
        }
        if (act === 'purge' && inc) {
          st.purge = await api(`/incidents/${encodeURIComponent(inc.incident_id)}/purge`,
            { method: 'POST', body: { dry_run: true } });
          paint(); return;
        }
        if (act === 'purge-confirm' && inc) {
          // Action irreversible : double garde explicite.
          if (!window.confirm(`Purge DÉFINITIVE de ${inc.incident_id} : logs, fichiers MinIO et sketch Timesketch seront supprimés. Confirmer ?`)) return;
          const r = await api(`/incidents/${encodeURIComponent(inc.incident_id)}/purge`,
            { method: 'POST', body: { dry_run: false, confirm: true } });
          toast(r.ok ? 'Purge exécutée' : 'Échec de la purge', r.ok ? 'ok' : 'err');
          st.purge = null; await refreshDetail(); return;
        }
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  function keys(ev) {
    const el = root();
    if (!el || !el.offsetParent) return;
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(ev.target.tagName || '')) return;
    if (ev.key === 'Escape' && st.detail) { st.detail = null; load(); return; }
    if (ev.key === '/') {
      const q = document.getElementById('pso-q');
      if (q) { ev.preventDefault(); q.focus(); }
    }
    if (ev.key === 'n' && !st.detail) {
      const b = el.querySelector('[data-pso-act="new"]');
      if (b) b.click();
    }
  }

  function init() {
    const el = root();
    if (!el) return;
    bind(el);
    if (!window.__psoKeys) { document.addEventListener('keydown', keys); window.__psoKeys = true; }
    load();
  }

  window.PsoarConsole = { init, load };
  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.querySelector('[data-tab-btn="psoar"]');
    if (btn) btn.addEventListener('click', () => setTimeout(init, 60));
  });
}());
