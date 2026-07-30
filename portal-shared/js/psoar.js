/* global i18n, ThreatCommon */
'use strict';

/**
 * PSOAR — Plateforme SOAR du portail CERT (niveau XSOAR / Resilient).
 *
 * - File d'incidents : KPIs temps réel, filtres dynamiques (statut, sévérité,
 *   recherche plein texte), tri, badges SLA, âge, progression des tâches.
 * - Workspace incident : stepper de statut cliquable, tâches groupées par
 *   phases NIST, playbooks bilingues applicables en un clic, SLA avec alerte
 *   de dépassement, timeline/notes/évidences/IOCs, scan IOC (watchlists
 *   Sekoia + IOCs incident) avec échantillons, statistiques de parsing,
 *   rapport Markdown téléchargeable, purge complète dry-run/apply.
 * - Bibliothèque de playbooks (onglet dédié).
 *
 * Backend : /api/incidents (portal-cert/routes/incident-routes.js).
 * 100% additif : n'altère aucun module existant.
 */
(function () {
  const TC = window.ThreatCommon || null;
  const esc = (s) => (TC && TC.esc ? TC.esc(s) : String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));
  // psoar.* d'abord, repli sur sekoia.* (clés partagées : status_*, inc_*, col_*…)
  const T = (k, vars) => {
    const v = i18n.t(`psoar.${k}`, vars);
    return v === `psoar.${k}` ? i18n.t(`sekoia.${k}`, vars) : v;
  };
  const toast = (m, c) => { if (TC && TC.toast) TC.toast(m, c); };
  const table = (cols, rows, opts) => (TC && TC.table
    ? TC.table(cols, rows, opts)
    : `<p class="fp-muted">${esc(T('msg_aucun_element'))}</p>`);
  const statCard = (label, value, tone) => (TC && TC.statCard
    ? TC.statCard(label, value, tone)
    : `<div class="fp-stat"><div class="fp-stat-value">${esc(value)}</div><div class="fp-stat-label">${esc(label)}</div></div>`);
  const val = (id) => (document.getElementById(id) || {}).value || '';
  const lang = () => ((window.i18n && i18n.getLanguage && i18n.getLanguage() === 'en') ? 'en' : 'fr');

  function delegate(root, handlers) {
    root.addEventListener('click', (e) => {
      let el = e.target.closest('[data-act]');
      // P21 — UX SOAR : un clic sur la LIGNE (pas seulement le bouton) ouvre
      // l'élément. On délègue alors au premier bouton d'action de la ligne.
      if ((!el || !root.contains(el))) {
        const tr = e.target.closest && e.target.closest('tr, .pso-rail-item');
        if (tr && root.contains(tr)) {
          const btn = tr.querySelector('[data-act]');
          if (btn) el = btn;
        }
      }
      if (!el || !root.contains(el)) return;
      const h = handlers[el.dataset.act]; if (h) h(el);
    });
  }

  function crudForm(title, fields, initial) {
    return new Promise((resolve) => {
      const ov = document.createElement('div');
      ov.className = 'cc-modal-overlay';
      const inputs = fields.map((f) => {
        const v = initial && initial[f.key] != null ? initial[f.key] : '';
        const req = f.required ? ' <span class="fp-muted">*</span>' : '';
        if (f.type === 'textarea') {
          return `<label class="fp-label">${esc(f.label)}${req}<textarea class="fp-input" id="pso-${esc(f.key)}" rows="6" placeholder="${esc(f.placeholder || '')}">${esc(v)}</textarea></label>`;
        }
        if (f.type === 'select') {
          const opts = (f.options || []).map((o) => `<option value="${esc(o.value)}"${String(o.value) === String(v) ? ' selected' : ''}>${esc(o.label)}</option>`).join('');
          return `<label class="fp-label">${esc(f.label)}${req}<select class="fp-select" id="pso-${esc(f.key)}">${opts}</select></label>`;
        }
        return `<label class="fp-label">${esc(f.label)}${req}<input class="fp-input" id="pso-${esc(f.key)}" type="text" value="${esc(v)}" placeholder="${esc(f.placeholder || '')}" autocomplete="off"></label>`;
      }).join('');
      ov.innerHTML = `<div class="cc-modal cc-modal-wide"><h3>${esc(title)}</h3>
        <div class="cc-crud-form">${inputs}</div>
        <div class="fp-actions-row fp-section-spaced">
          <button type="button" class="fp-btn fp-btn-ghost" data-x="cancel">${esc(T('act_cancel'))}</button>
          <button type="button" class="fp-btn fp-btn-primary" data-x="ok">${esc(T('act_validate'))}</button></div></div>`;
      document.body.appendChild(ov);
      const done = (out) => { ov.remove(); resolve(out); };
      ov.addEventListener('click', (e) => {
        const b = e.target.closest('[data-x]');
        if (e.target === ov || (b && b.dataset.x === 'cancel')) return done(null);
        if (b && b.dataset.x === 'ok') {
          const out = {};
          for (const f of fields) {
            const el = ov.querySelector(`#pso-${CSS.escape(f.key)}`);
            if (el) out[f.key] = el.value;
          }
          for (const f of fields) {
            if (f.required && String(out[f.key] || '').trim() === '') {
              toast(T('msg_champ_requis', { label: f.label }), 'warn');
              return;
            }
          }
          return done(out);
        }
      });
      ov.addEventListener('keydown', (e) => { if (e.key === 'Escape') done(null); });
    });
  }

  function confirmBox(title, message) {
    return new Promise((resolve) => {
      const ov = document.createElement('div');
      ov.className = 'cc-modal-overlay';
      ov.innerHTML = `<div class="cc-modal"><h3>${esc(title)}</h3>
        <p>${esc(message)}</p>
        <div class="fp-actions-row fp-section-spaced">
          <button type="button" class="fp-btn fp-btn-ghost" data-x="cancel">${esc(T('act_cancel'))}</button>
          <button type="button" class="fp-btn fp-btn-danger" data-x="ok">${esc(T('act_validate'))}</button></div></div>`;
      document.body.appendChild(ov);
      const done = (v) => { ov.remove(); resolve(v); };
      ov.addEventListener('click', (e) => {
        const b = e.target.closest('[data-x]');
        if (e.target === ov || (b && b.dataset.x === 'cancel')) return done(false);
        if (b && b.dataset.x === 'ok') return done(true);
      });
      ov.addEventListener('keydown', (e) => { if (e.key === 'Escape') done(false); });
    });
  }

  async function askText(title, label, initial) {
    const out = await crudForm(title, [{ key: 'v', label, type: 'text', required: true }], { v: initial || '' });
    return out ? String(out.v || '').trim() : null;
  }

  /* ── API backend ──────────────────────────────────────────────────────── */
  async function api(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    if (o.body && typeof o.body !== 'string') {
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
      o.body = JSON.stringify(o.body);
    }
    const r = await fetch(`/api/incidents${path}`, o);
    try { return await r.json(); } catch { return {}; }
  }

  /* ── Constantes SOAR ──────────────────────────────────────────────────── */
  const STATUSES = ['new', 'in_progress', 'contained', 'closed', 'purged'];
  const FLOW = ['new', 'in_progress', 'contained', 'closed'];
  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const PHASES = ['detection', 'analysis', 'containment', 'eradication', 'recovery', 'lessons'];
  const OPEN_STATUSES = ['new', 'in_progress', 'contained'];

  function sevBadge(v) {
    const s = SEVERITIES.includes(String(v)) ? v : 'info';
    return `<span class="sev-badge sev-${s}">${esc(s)}</span>`;
  }
  function statusTag(s) {
    const map = { new: 'fp-tag-danger', in_progress: 'fp-tag-warn', contained: 'fp-tag-ok', closed: '', purged: '' };
    return `<span class="fp-tag ${map[s] || ''}">${esc(T(`status_${s}`) || s)}</span>`;
  }
  function fmtDur(ms) {
    const a = Math.abs(ms);
    const h = Math.floor(a / 3600000);
    const m = Math.floor((a % 3600000) / 60000);
    const d = Math.floor(h / 24);
    if (d >= 2) return `${d} ${T('unit_d')}`;
    if (h >= 1) return `${h} ${T('unit_h')} ${String(m).padStart(2, '0')}`;
    return `${m} ${T('unit_min')}`;
  }
  function ageOf(created) {
    if (!created) return '—';
    return fmtDur(Date.now() - new Date(created).getTime());
  }
  function slaChip(inc) {
    if (!inc.sla_due) return '<span class="fp-muted">—</span>';
    if (['closed', 'purged'].includes(inc.status)) return '<span class="fp-tag">✓</span>';
    const ms = new Date(inc.sla_due).getTime() - Date.now();
    if (ms < 0) return `<span class="fp-tag fp-tag-danger" title="${esc(inc.sla_due)}">⚠ +${esc(fmtDur(ms))}</span>`;
    const cls = ms < 4 * 3600000 ? 'fp-tag-warn' : 'fp-tag-ok';
    return `<span class="fp-tag ${cls}" title="${esc(inc.sla_due)}">${esc(fmtDur(ms))}</span>`;
  }
  function taskProgress(inc) {
    const tasks = Array.isArray(inc.tasks) ? inc.tasks : [];
    const done = tasks.filter((t) => t.done).length;
    return { done, total: tasks.length, pct: tasks.length ? Math.round((done / tasks.length) * 100) : 0 };
  }

  /* ── Playbooks NIST bilingues ─────────────────────────────────────────── */
  const PLAYBOOKS = {
    nist: {
      label: { fr: 'NIST — Réponse standard', en: 'NIST — Standard response' },
      desc: {
        fr: 'Cycle complet NIST 800-61 : détection, analyse, confinement, éradication, récupération, leçons apprises.',
        en: 'Full NIST 800-61 cycle: detection, analysis, containment, eradication, recovery, lessons learned.',
      },
      tasks: [
        ['detection', { fr: 'Qualifier et documenter l\'alerte initiale', en: 'Triage and document the initial alert' }],
        ['detection', { fr: 'Vérifier la source de détection (SIEM, EDR, utilisateur)', en: 'Verify the detection source (SIEM, EDR, user)' }],
        ['detection', { fr: 'Déclarer l\'incident et horodater la détection', en: 'Declare the incident and timestamp detection' }],
        ['analysis', { fr: 'Uploader et ingérer les logs pertinents (tous formats)', en: 'Upload and ingest relevant logs (all formats)' }],
        ['analysis', { fr: 'Lancer le scan IOC (watchlists Sekoia + IOCs incident)', en: 'Run IOC scan (Sekoia watchlists + incident IOCs)' }],
        ['analysis', { fr: 'Construire la timeline des événements', en: 'Build the events timeline' }],
        ['analysis', { fr: 'Identifier le périmètre (hôtes, comptes, IPs)', en: 'Identify the scope (hosts, accounts, IPs)' }],
        ['containment', { fr: 'Isoler les hôtes compromis', en: 'Isolate compromised hosts' }],
        ['containment', { fr: 'Bloquer les IOCs (firewall, EDR, DNS)', en: 'Block IOCs (firewall, EDR, DNS)' }],
        ['containment', { fr: 'Préserver les evidences (exports, snapshots)', en: 'Preserve evidence (exports, snapshots)' }],
        ['eradication', { fr: 'Supprimer persistence et malware', en: 'Remove persistence and malware' }],
        ['eradication', { fr: 'Réinitialiser les credentials compromis', en: 'Reset compromised credentials' }],
        ['recovery', { fr: 'Restaurer les systèmes en production', en: 'Restore systems to production' }],
        ['recovery', { fr: 'Surveiller la réapparition (volumétrie, alertes)', en: 'Monitor for recurrence (volumetry, alerts)' }],
        ['lessons', { fr: 'Rédiger le rapport d\'investigation', en: 'Write the investigation report' }],
        ['lessons', { fr: 'Exécuter la purge de fin d\'investigation', en: 'Run the end-of-investigation purge' }],
        ['lessons', { fr: 'Partager les leçons apprises (KB, règles de détection)', en: 'Share lessons learned (KB, detection rules)' }],
      ],
    },
    ransomware: {
      label: { fr: 'Ransomware', en: 'Ransomware' },
      desc: {
        fr: 'Réponse ransomware : identification de souche, isolation des segments, restauration depuis sauvegardes saines.',
        en: 'Ransomware response: strain identification, segment isolation, restore from clean backups.',
      },
      tasks: [
        ['detection', { fr: 'Confirmer le chiffrement (extensions, note de rançon)', en: 'Confirm encryption (extensions, ransom note)' }],
        ['detection', { fr: 'Identifier la souche (ID Ransomware, hash du binaire)', en: 'Identify the strain (ID Ransomware, binary hash)' }],
        ['analysis', { fr: 'Ingérer les logs EDR/Windows des hôtes touchés', en: 'Ingest EDR/Windows logs from affected hosts' }],
        ['analysis', { fr: 'Tracer le vecteur initial (mail, RDP, VPN)', en: 'Trace the initial vector (mail, RDP, VPN)' }],
        ['analysis', { fr: 'Scanner les IOCs sur l\'ensemble des logs ingérés', en: 'Scan IOCs across all ingested logs' }],
        ['containment', { fr: 'Couper le réseau des segments touchés', en: 'Disconnect affected network segments' }],
        ['containment', { fr: 'Désactiver les comptes compromis', en: 'Disable compromised accounts' }],
        ['containment', { fr: 'Suspendre les partages SMB exposés', en: 'Suspend exposed SMB shares' }],
        ['eradication', { fr: 'Supprimer binaires, tâches planifiées et clés de persistence', en: 'Remove binaries, scheduled tasks and persistence keys' }],
        ['eradication', { fr: 'Corriger la vulnérabilité d\'entrée', en: 'Patch the entry vulnerability' }],
        ['recovery', { fr: 'Restaurer depuis des sauvegardes saines et vérifiées', en: 'Restore from clean, verified backups' }],
        ['recovery', { fr: 'Surveiller la réapparition avant remise en production', en: 'Monitor for recurrence before production' }],
        ['lessons', { fr: 'Rapport d\'investigation + purge des données', en: 'Investigation report + data purge' }],
      ],
    },
    phishing: {
      label: { fr: 'Phishing / BEC', en: 'Phishing / BEC' },
      desc: {
        fr: 'Campagne de phishing : suppression des BAL, blocage expéditeur/domaines, reset des credentials saisis.',
        en: 'Phishing campaign: mailbox purge, sender/domain blocking, reset of submitted credentials.',
      },
      tasks: [
        ['detection', { fr: 'Récupérer le mail source (headers complets, .eml)', en: 'Retrieve the source email (full headers, .eml)' }],
        ['detection', { fr: 'Identifier tous les destinataires de la campagne', en: 'Identify all campaign recipients' }],
        ['analysis', { fr: 'Ingérer les logs mail, proxy et DNS', en: 'Ingest mail, proxy and DNS logs' }],
        ['analysis', { fr: 'Extraire et scanner les IOCs (URLs, domaines, pièces jointes)', en: 'Extract and scan IOCs (URLs, domains, attachments)' }],
        ['analysis', { fr: 'Vérifier les clics et saisies de credentials', en: 'Check clicks and credential submissions' }],
        ['containment', { fr: 'Supprimer le mail de toutes les BAL', en: 'Purge the email from all mailboxes' }],
        ['containment', { fr: 'Bloquer expéditeur, domaines et URLs au proxy/mailgw', en: 'Block sender, domains and URLs at proxy/mail gateway' }],
        ['containment', { fr: 'Réinitialiser les comptes ayant saisi leurs credentials', en: 'Reset accounts that entered credentials' }],
        ['eradication', { fr: 'Vérifier les règles de redirection BAL malveillantes', en: 'Check for malicious mailbox forwarding rules' }],
        ['recovery', { fr: 'Surveiller les connexions anormales post-incident', en: 'Monitor abnormal logins post-incident' }],
        ['lessons', { fr: 'Sensibilisation ciblée + rapport + purge', en: 'Targeted awareness + report + purge' }],
      ],
    },
    account: {
      label: { fr: 'Compte compromis', en: 'Account compromise' },
      desc: {
        fr: 'Compromission de compte : révocation des sessions, reset MFA, suppression des accès persistants.',
        en: 'Account compromise: session revocation, MFA reset, removal of persistent access.',
      },
      tasks: [
        ['detection', { fr: 'Confirmer la compromission (impossible travel, MFA fatigue)', en: 'Confirm compromise (impossible travel, MFA fatigue)' }],
        ['analysis', { fr: 'Ingérer les logs d\'authentification (SSO, AD, VPN, O365)', en: 'Ingest authentication logs (SSO, AD, VPN, O365)' }],
        ['analysis', { fr: 'Lister les sessions et accès du compte sur la période', en: 'List account sessions and access over the period' }],
        ['analysis', { fr: 'Scanner les IOCs et identifier le point d\'entrée', en: 'Scan IOCs and identify the entry point' }],
        ['containment', { fr: 'Révoquer toutes les sessions et tokens', en: 'Revoke all sessions and tokens' }],
        ['containment', { fr: 'Réinitialiser le mot de passe et forcer le MFA', en: 'Reset password and enforce MFA' }],
        ['eradication', { fr: 'Supprimer les accès persistants (clés API, apps OAuth)', en: 'Remove persistent access (API keys, OAuth apps)' }],
        ['recovery', { fr: 'Réactiver le compte avec surveillance renforcée', en: 'Re-enable account with enhanced monitoring' }],
        ['lessons', { fr: 'Rapport + purge des données d\'investigation', en: 'Report + investigation data purge' }],
      ],
    },
  };

  /* ── État ─────────────────────────────────────────────────────────────── */
  const st = {
    list: null, detail: null, tab: 'resume',
    scan: null, report: null, purge: null,
    flt: { status: '', severity: '', q: '' },
  };

  function root() { return document.getElementById('psoar-root'); }

  /* ── File d'attente (queue) ───────────────────────────────────────────── */
  function kpis(list) {
    const open = list.filter((r) => OPEN_STATUSES.includes(r.status));
    const crit = open.filter((r) => ['critical', 'high'].includes(r.severity));
    const overdue = open.filter((r) => r.sla_due && new Date(r.sla_due) < new Date());
    const tasks = list.reduce((a, r) => a + taskProgress(r).done, 0);
    const tasksTotal = list.reduce((a, r) => a + taskProgress(r).total, 0);
    return `<div class="cc-tp-dashgrid pso-kpis">
      ${statCard(T('kpi_open'), open.length, open.length ? 'warn' : 'accent')}
      ${statCard(T('kpi_critical'), crit.length, crit.length ? 'danger' : 'accent')}
      ${statCard(T('kpi_overdue'), overdue.length, overdue.length ? 'danger' : 'accent')}
      ${statCard(T('kpi_tasks'), `${tasks}/${tasksTotal}`, 'accent')}
    </div>`;
  }

  function filterBar() {
    const f = st.flt;
    const statusOpts = [`<option value="">${esc(T('flt_status_all'))}</option>`]
      .concat(STATUSES.map((s) => `<option value="${s}"${f.status === s ? ' selected' : ''}>${esc(T(`status_${s}`))}</option>`)).join('');
    const sevOpts = [`<option value="">${esc(T('flt_sev_all'))}</option>`]
      .concat(SEVERITIES.map((s) => `<option value="${s}"${f.severity === s ? ' selected' : ''}>${esc(s)}</option>`)).join('');
    return `<div class="cc-tp-filterbar pso-filterbar">
      <input class="fp-input fp-input-sm" id="pso-flt-q" placeholder="🔎 ${esc(T('flt_search_ph'))}" value="${esc(f.q)}">
      <select class="fp-select fp-input-sm" id="pso-flt-status">${statusOpts}</select>
      <select class="fp-select fp-input-sm" id="pso-flt-sev">${sevOpts}</select>
      <span class="cc-tp-filter-actions">
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="pso-flt-reset">${esc(T('act_reset'))}</button>
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="pso-new">${esc(T('act_inc_new'))}</button>
      </span>
    </div>`;
  }

  function filtered() {
    const f = st.flt;
    const q = f.q.trim().toLowerCase();
    return (st.list || []).filter((r) => {
      if (f.status && r.status !== f.status) return false;
      if (f.severity && r.severity !== f.severity) return false;
      if (q) {
        const hay = `${r.title} ${r.incident_id} ${r.assignee || ''} ${(r.tags || []).join(' ')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  function queueTable(rows) {
    return table([
      { label: T('col_titre'), render: (r) => `<strong>${esc(r.title)}</strong><br><code class="pso-inc-id">${esc(r.incident_id)}</code>` },
      { label: T('col_severite'), render: (r) => sevBadge(r.severity) },
      { label: T('col_statut'), render: (r) => statusTag(r.status) },
      { label: T('col_sla'), render: (r) => slaChip(r) },
      { label: T('col_tasks'), render: (r) => { const p = taskProgress(r); return p.total ? `${p.done}/${p.total}` : '—'; } },
      { label: T('col_assignee'), render: (r) => esc(r.assignee || '—') },
      { label: T('col_age'), render: (r) => esc(ageOf(r.created_at)) },
      { label: '', render: (r) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="pso-open" data-id="${esc(r.incident_id)}">${esc(T('act_open'))}</button>` },
    ], rows, { empty: T('queue_empty') });
  }

  function queueRail(rows) {
    if (!rows.length) return `<p class="fp-muted">${esc(T('queue_empty'))}</p>`;
    return rows.map((r) => {
      const cur = st.detail && st.detail.incident.incident_id === r.incident_id;
      return `<button type="button" class="pso-rail-item${cur ? ' active' : ''}" data-act="pso-open" data-id="${esc(r.incident_id)}">
        <span class="pso-rail-sev pso-sev-${esc(r.severity || 'info')}"></span>
        <span class="pso-rail-main"><strong>${esc(r.title)}</strong>
        <span class="fp-muted">${esc(r.incident_id)} · ${esc(ageOf(r.created_at))}</span></span>
        ${slaChip(r)}
      </button>`;
    }).join('');
  }

  /* ── Workspace incident ───────────────────────────────────────────────── */
  const WS_TABS = [
    ['resume', 'inc_tab_resume'], ['tasks', 'inc_tab_tasks'], ['timeline', 'inc_tab_timeline'],
    ['evidences', 'inc_tab_evidences'], ['scan', 'inc_tab_scan'], ['report', 'inc_tab_report'],
    ['purge', 'inc_tab_purge'],
  ];

  function stepperHtml(inc) {
    const cur = FLOW.indexOf(inc.status);
    const purged = inc.status === 'purged';
    const steps = FLOW.map((s, i) => {
      const state = purged ? '' : (i < cur ? ' done' : i === cur ? ' current' : '');
      return `<button type="button" class="cc-inc-step${state}" data-act="pso-step" data-status="${s}"${purged ? ' disabled' : ''}>
        <span class="cc-inc-step-dot">${i < cur && !purged ? '✓' : i + 1}</span><span class="cc-inc-step-lbl">${esc(T(`status_${s}`))}</span></button>`;
    }).join('<span class="cc-inc-step-bar"></span>');
    return `<div class="cc-inc-stepper" title="${esc(T('inc_step_hint'))}">${steps}${purged ? `<span class="fp-tag fp-tag-warn cc-inc-purged-tag">${esc(T('status_purged'))}</span>` : ''}</div>`;
  }

  function slaBadge(inc) {
    if (!inc.sla_due) return '';
    if (['closed', 'purged'].includes(inc.status)) return '<span class="fp-tag">SLA ✓</span>';
    const ms = new Date(inc.sla_due).getTime() - Date.now();
    if (ms < 0) return `<span class="fp-tag fp-tag-danger" title="${esc(inc.sla_due)}">⚠ ${esc(T('inc_sla_overdue'))} +${esc(fmtDur(ms))}</span>`;
    const cls = ms < 4 * 3600000 ? 'fp-tag-warn' : 'fp-tag-ok';
    return `<span class="fp-tag ${cls}" title="${esc(inc.sla_due)}">${esc(T('inc_sla_left', { t: fmtDur(ms) }))}</span>`;
  }

  function wsTabHtml(tab, inc, d) {
    const events = d.events || [];
    const uploads = d.uploads || [];
    if (tab === 'tasks') return tasksHtml(inc);
    if (tab === 'timeline') return `<div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="pso-ev-add">${esc(T('act_ev_add'))}</button></div>
      <div class="fp-section-spaced">${eventsHtml(events)}</div>`;
    if (tab === 'evidences') return `<p class="fp-muted">${esc(T('msg_inc_upload_hint', { id: inc.case_id }))}</p>
      <div>${uploadsHtml(uploads)}</div>`;
    if (tab === 'scan') return `<div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="pso-scan">${esc(T('act_inc_scan'))}</button></div>
      <div id="pso-scan-zone" class="fp-section-spaced"></div>`;
    if (tab === 'report') return `<div class="fp-actions-row">
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="pso-report">${esc(T('act_inc_report'))}</button>
        ${st.report ? `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="pso-report-copy">${esc(T('act_copy'))}</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="pso-report-dl">${esc(T('act_download'))}</button>` : ''}
      </div><div id="pso-report-zone" class="fp-section-spaced"></div>`;
    if (tab === 'purge') return `<div class="cc-tp-fetchform cc-inc-danger"><p class="fp-muted">${esc(T('msg_inc_purge_warn'))}</p>
        <div class="fp-actions-row">
          <button type="button" class="fp-btn fp-btn-ghost" data-act="pso-purge-dry">${esc(T('act_purge_dry'))}</button>
          <button type="button" class="fp-btn fp-btn-danger" data-act="pso-purge-apply">${esc(T('act_purge_apply'))}</button>
          <button type="button" class="fp-btn fp-btn-ghost" data-act="pso-delete">${esc(T('act_inc_delete'))}</button>
        </div>
        <div id="pso-purge-zone" class="fp-section-spaced"></div>
      </div>`;
    // resume
    return `<div class="cc-tp-grid2">
      <div class="cc-tp-fetchform">
        <h4 class="fp-section-sub">${esc(T('inc_desc_tags'))}</h4>
        <label class="fp-label">${esc(T('form_description'))}
          <textarea class="fp-textarea" id="pso-inc-desc" rows="5">${esc(inc.description || '')}</textarea></label>
        <label class="fp-label">${esc(T('col_tags'))}
          <input class="fp-input" id="pso-inc-tags" value="${esc((inc.tags || []).join(', '))}" placeholder="${esc(T('inc_tags_ph'))}"></label>
        <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="pso-meta-save">${esc(T('act_save'))}</button></div>
      </div>
      <div class="cc-tp-fetchform">
        <h4 class="fp-section-sub">${esc(T('inc_meta'))}</h4>
        <div class="fp-form-row fp-grid-2">
          <label class="fp-label">${esc(T('col_statut'))}
            <select class="fp-select" id="pso-inc-status">${STATUSES.map((s) => `<option value="${s}"${s === inc.status ? ' selected' : ''}>${esc(T(`status_${s}`))}</option>`).join('')}</select></label>
          <label class="fp-label">${esc(T('col_assignee'))}
            <input class="fp-input" id="pso-inc-assignee" value="${esc(inc.assignee || '')}"></label>
        </div>
        <div class="fp-actions-row"><button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="pso-status-apply">${esc(T('act_apply'))}</button></div>
        <div class="cc-inc-metagrid">
          <div><span class="fp-muted">${esc(T('col_created_by'))}</span><br>${esc(inc.created_by || '—')}</div>
          <div><span class="fp-muted">${esc(T('col_cree_le'))}</span><br>${esc((inc.created_at || '').replace('T', ' ').slice(0, 16))}</div>
          <div><span class="fp-muted">${esc(T('col_updated'))}</span><br>${esc((inc.updated_at || '').replace('T', ' ').slice(0, 16))}</div>
          <div><span class="fp-muted">Case ID</span><br><code>${esc(inc.case_id || '—')}</code></div>
        </div>
        <div class="fp-actions-row fp-section-spaced"><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="pso-link">${esc(T('act_inc_link'))}</button>
          ${(inc.linked_cases || []).length ? `<span class="fp-muted">${esc(T('msg_linked_cases', { cases: inc.linked_cases.join(', ') }))}</span>` : ''}</div>
      </div>
    </div>`;
  }

  function tasksHtml(inc) {
    const tasks = Array.isArray(inc.tasks) ? inc.tasks : [];
    const L = lang();
    const pbBtns = Object.keys(PLAYBOOKS).map((k) =>
      `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="pso-playbook" data-pb="${k}" title="${esc(PLAYBOOKS[k].desc[L])}">${esc(PLAYBOOKS[k].label[L])}</button>`).join('');
    let html = `<div class="fp-actions-row">
        <span class="fp-muted">${esc(T('inc_playbook_apply'))}</span>${pbBtns}
        <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="pso-task-add">${esc(T('inc_task_add'))}</button>
      </div>`;
    if (!tasks.length) return html + `<p class="fp-muted fp-section-spaced">${esc(T('inc_tasks_empty'))}</p>`;
    for (const ph of PHASES) {
      const items = tasks.filter((t) => t.phase === ph);
      if (!items.length) continue;
      const phDone = items.filter((t) => t.done).length;
      html += `<div class="cc-inc-phase"><h4 class="fp-section-sub">${esc(T(`inc_phase_${ph}`))} <span class="fp-muted">${phDone}/${items.length}</span></h4>`;
      html += items.map((t) => `<div class="cc-task-item${t.done ? ' done' : ''}">
          <button type="button" class="cc-task-check" data-act="pso-task-toggle" data-id="${esc(t.id)}" data-done="${t.done ? '0' : '1'}" aria-label="toggle">${t.done ? '☑' : '☐'}</button>
          <span class="cc-task-title">${esc(t.title)}</span>
          ${t.assignee ? `<span class="fp-tag">${esc(t.assignee)}</span>` : ''}
          ${t.done && t.done_at ? `<span class="fp-muted">${esc(t.done_at.replace('T', ' ').slice(0, 16))}${t.done_by ? ` · ${esc(t.done_by)}` : ''}</span>` : ''}
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-xs" data-act="pso-task-edit" data-id="${esc(t.id)}">✎</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-xs" data-act="pso-task-del" data-id="${esc(t.id)}">✕</button>
        </div>`).join('');
      html += '</div>';
    }
    return html;
  }

  function eventsHtml(events) {
    const KIND = { timeline: T('kind_timeline'), note: T('kind_note'), evidence: T('kind_evidence'), ioc: T('kind_ioc'), status: T('kind_status') };
    return table([
      { label: T('col_date'), render: (r) => esc((r.event_at || r.created_at || '').replace('T', ' ').slice(0, 16)) },
      { label: T('col_kind'), render: (r) => `<span class="fp-tag">${esc(KIND[r.kind] || r.kind)}</span>` },
      { label: T('col_titre'), render: (r) => (r.kind === 'ioc' ? `<strong>${esc(r.value || '')}</strong> <span class="fp-tag">${esc(r.ioc_type || '')}</span> — ${esc(r.title)}` : esc(r.title)) },
      { label: T('col_description'), render: (r) => esc((r.description || '').slice(0, 160)) },
      { label: '', render: (r) => `<button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="pso-ev-del" data-id="${esc(r.event_id)}">${esc(T('act_delete'))}</button>` },
    ], events.slice().reverse(), { empty: T('msg_ev_empty') });
  }

  function uploadsHtml(uploads) {
    return table([
      { label: T('col_fichier'), render: (r) => esc((TC && TC.deep(r, 'file.name')) || '—') },
      { label: T('col_taille'), render: (r) => { const n = TC && TC.deep(r, 'file.size'); return n != null ? `${(n / 1024).toFixed(1)} Ko` : '—'; } },
      { label: T('col_bucket'), render: (r) => `<span class="fp-tag">${esc((TC && TC.deep(r, 'storage.bucket')) || '—')}</span>` },
      { label: 'OS', render: (r) => esc(r.os_type || '—') },
      { label: T('col_date'), render: (r) => esc((r['@timestamp'] || '').replace('T', ' ').slice(0, 16)) },
    ], uploads, { empty: T('msg_inc_no_uploads') });
  }

  /* ── Rendus scan / rapport / purge ────────────────────────────────────── */
  function renderScan() {
    const zone = document.getElementById('pso-scan-zone'); if (!zone) return;
    const s = st.scan;
    if (!s) { zone.innerHTML = ''; return; }
    if (!s.ok) { zone.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc(s.error || i18n.t('msg.echec'))}</span></p>`; return; }
    const stats = s.stats || {};
    zone.innerHTML = `<h4 class="fp-section-sub">${esc(T('msg_inc_scan_done', { n: (s.matches || []).length, t: s.iocs_scanned ?? 0 }))}</h4>
      ${s.watchlists_error ? `<p class="fp-muted">${esc(T('msg_watchlists_indispo', { err: s.watchlists_error }))}</p>` : ''}
      <div class="cc-tp-dashgrid">
        ${statCard(T('col_docs'), stats.total_docs ?? 0, 'accent')}
        ${statCard('IOCs', s.iocs_scanned ?? 0)}
        ${statCard(T('col_hits'), (s.matches || []).length, (s.matches || []).length ? 'warn' : 'accent')}
      </div>
      <h4 class="fp-section-sub fp-section-spaced">${esc(T('lbl_inc_stats'))}</h4>`
      + table([
        { label: T('col_index'), render: (r) => `<span class="fp-tag">${esc(r.index)}</span>` },
        { label: T('col_docs'), render: (r) => String(r.count) },
      ], stats.indices || [], { empty: T('msg_aucun_element') })
      + `<h4 class="fp-section-sub fp-section-spaced">${esc(T('msg_top_talkers'))} (source.ip)</h4>`
      + table([
        { label: 'IP', render: (r) => esc(r.value) },
        { label: T('col_volume'), render: (r) => String(r.count) },
      ], stats.top_source_ip || [], { empty: T('msg_aucun_element') })
      + ((s.matches || []).length ? `<h4 class="fp-section-sub fp-section-spaced">${esc(T('col_ioc_matches'))}</h4>`
        + table([
          { label: T('col_ioc_value'), render: (r) => `<strong>${esc(r.value)}</strong> <span class="fp-tag">${esc(r.ioc_type)}</span>` },
          { label: T('col_origin'), render: (r) => esc(r.origin === 'watchlist' ? 'Watchlist Sekoia' : 'Incident') },
          { label: T('col_hits'), render: (r) => `<strong>${r.hits}</strong>` },
          { label: T('col_samples'), render: (r) => esc((r.samples || []).map((x) => `${x.index} @ ${(x.ts || '').slice(0, 19)}`).join(' · ')).slice(0, 200) },
        ], s.matches, { empty: T('msg_aucun_element') }) : '');
  }

  function renderReport() {
    const zone = document.getElementById('pso-report-zone'); if (!zone) return;
    if (!st.report) { zone.innerHTML = ''; return; }
    zone.innerHTML = `<pre class="cc-pre cc-inc-report">${esc(st.report)}</pre>`;
  }

  function renderPurge() {
    const zone = document.getElementById('pso-purge-zone'); if (!zone) return;
    const p = st.purge; if (!p) { zone.innerHTML = ''; return; }
    if (!p.ok) { zone.innerHTML = `<p><span class="fp-tag fp-tag-danger">${esc(p.error || i18n.t('msg.echec'))}</span></p>`; return; }
    const osRows = Object.entries(p.opensearch || {}).map(([index, count]) => ({ index, count }));
    zone.innerHTML = `<p><span class="fp-tag ${p.dry_run ? 'fp-tag-warn' : 'fp-tag-ok'}">${esc(p.dry_run ? T('act_purge_dry') : T('msg_purged'))}</span></p>`
      + table([
        { label: T('col_index'), render: (r) => `<span class="fp-tag">${esc(r.index)}</span>` },
        { label: p.dry_run ? T('col_docs') : T('msg_supprimes'), render: (r) => String(r.count) },
      ], osRows, { empty: T('msg_aucun_element') })
      + `<p class="fp-muted">${esc(T('msg_purge_detail', {
        u: p.uploads ? (p.uploads.count ?? p.uploads.deleted ?? 0) : 0,
        m: (p.minio && p.minio.objects) ?? 0,
        ts: Object.values(p.timesketch || {}).map((t) => (t.ok ? '✔' : t.skipped ? '—' : '✘')).join(' ') || '—',
      }))}</p>
      <p class="fp-muted">${esc((p.helk && p.helk.note) || '')}</p>`;
  }

  /* ── Actions ──────────────────────────────────────────────────────────── */
  async function refresh() {
    const list = await api('');
    st.list = Array.isArray(list) ? list : [];
  }

  async function load() {
    const host = root(); if (!host) return;
    if (!host.__psoBound) bindRoot(host);
    if (st.detail) { renderSplit(); return; }
    host.innerHTML = `<p class="fp-muted">${esc(i18n.t('ui.loading'))}</p>`;
    await refresh();
    renderQueue();
  }

  function renderQueue() {
    const host = root(); if (!host || st.detail) return;
    const rows = filtered();
    host.innerHTML = `<div class="pso-queue">
      ${kpis(st.list || [])}
      ${filterBar()}
      <div class="pso-queue-count fp-muted">${rows.length} / ${(st.list || []).length} ${esc(T('queue_count'))}</div>
      <div class="pso-queue-table">${queueTable(rows)}</div>
    </div>`;
  }

  function renderSplit() {
    // Vue workspace : rail de file à gauche + workspace à droite (style XSOAR).
    const host = root(); if (!host) return;
    const rows = filtered();
    host.innerHTML = `<div class="pso-split">
      <aside class="pso-rail">
        <div class="pso-rail-head">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-act="pso-back">← ${esc(T('ws_queue'))}</button>
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-act="pso-new">${esc(T('act_inc_new'))}</button>
        </div>
        <div class="pso-rail-list">${queueRail(rows)}</div>
      </aside>
      <div class="pso-main" id="pso-main"></div>
    </div>`;
    // Le workspace se rend dans #pso-main via renderWorkspaceInto.
    const main = document.getElementById('pso-main');
    if (main) {
      const saved = host.__psoMain;
      host.__psoMain = main;
      renderWorkspaceInto(main);
      host.__psoMain = saved;
    }
  }

  function renderWorkspaceInto(target) {
    if (!st.detail || !target) return;
    const d = st.detail;
    const inc = d.incident || {};
    const p = taskProgress(inc);
    const tab = WS_TABS.some(([k]) => k === st.tab) ? st.tab : 'resume';
    st.tab = tab;
    target.innerHTML = `<div class="cc-inc-ws pso-ws">
      <div class="fp-actions-row cc-inc-head">
        <h3 class="cc-inc-title">${esc(inc.title)} <span class="fp-muted">${esc(inc.incident_id)}</span></h3>
        ${sevBadge(inc.severity)}${slaBadge(inc)}
      </div>
      ${stepperHtml(inc)}
      <div class="cc-inc-progressrow">
        <div class="cc-progress"><div class="cc-progress-fill" style="width:${p.pct}%"></div></div>
        <span class="fp-muted">${esc(T('inc_tasks_progress', { done: p.done, total: p.total }))} — ${p.pct}%</span>
      </div>
      <div class="cc-inc-tabs">${WS_TABS.map(([k, lbl]) => `<button type="button" class="fp-btn fp-btn-sm cc-subtab${k === tab ? ' active' : ''}" data-act="pso-tab" data-tab="${k}">${esc(T(lbl))}</button>`).join('')}</div>
      <div id="pso-ws-body" class="cc-inc-ws-body">${wsTabHtml(tab, inc, d)}</div>
    </div>`;
    if (tab === 'scan' && st.scan) renderScan();
    if (tab === 'report' && st.report) renderReport();
    if (tab === 'purge' && st.purge) renderPurge();
  }

  function renderCurrent() {
    if (st.detail) renderSplit();
    else renderQueue();
  }

  async function openIncident(id, soft) {
    const d = await api(`/${encodeURIComponent(id)}`);
    if (!d || !d.incident) { toast((d && d.error) || T('msg_inc_not_found'), 'warn'); return; }
    const same = st.detail && st.detail.incident.incident_id === d.incident.incident_id;
    if (!soft || !same) { st.tab = 'resume'; st.scan = null; st.report = null; st.purge = null; }
    st.detail = d;
    renderSplit();
  }

  async function newIncident() {
    const out = await crudForm(T('act_inc_new'), [
      { key: 'title', label: T('col_titre'), type: 'text', required: true, placeholder: T('ph_inc_title') },
      { key: 'severity', label: T('col_severite'), type: 'select', options: SEVERITIES.map((s) => ({ value: s, label: s })) },
      { key: 'description', label: T('form_description'), type: 'textarea' },
    ], { severity: 'medium' });
    if (!out) return;
    const r = await api('', { method: 'POST', body: out });
    if (r && r.ok) {
      toast(T('msg_inc_created', { id: r.incident.incident_id }), 'ok');
      await refresh();
      openIncident(r.incident.incident_id);
    } else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function setStatus(status) {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id || !STATUSES.includes(status)) return;
    const r = await api(`/${encodeURIComponent(id)}`, { method: 'PATCH', body: { status } });
    if (r && r.ok) { toast(T('msg_updated'), 'ok'); await openIncident(id, true); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function applyStatusForm() {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const r = await api(`/${encodeURIComponent(id)}`, {
      method: 'PATCH', body: { status: val('pso-inc-status'), assignee: val('pso-inc-assignee') },
    });
    if (r && r.ok) { toast(T('msg_updated'), 'ok'); await openIncident(id, true); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function saveMeta() {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const tags = val('pso-inc-tags').split(',').map((s) => s.trim()).filter(Boolean).slice(0, 10);
    const r = await api(`/${encodeURIComponent(id)}`, { method: 'PATCH', body: { description: val('pso-inc-desc'), tags } });
    if (r && r.ok) { toast(T('msg_saved'), 'ok'); await openIncident(id, true); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  function taskForm(initial) {
    return crudForm(initial ? T('inc_task_edit') : T('inc_task_add'), [
      { key: 'title', label: T('col_titre'), type: 'text', required: true },
      { key: 'phase', label: T('inc_phase_label'), type: 'select', options: PHASES.map((p) => ({ value: p, label: T(`inc_phase_${p}`) })) },
      { key: 'assignee', label: T('col_assignee'), type: 'text' },
    ], initial || { phase: 'detection' });
  }

  async function taskAdd() {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const out = await taskForm(null);
    if (!out) return;
    const r = await api(`/${encodeURIComponent(id)}/tasks`, { method: 'POST', body: out });
    if (r && r.ok) { toast(T('msg_task_added'), 'ok'); await openIncident(id, true); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function taskToggle(taskId, done) {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const r = await api(`/${encodeURIComponent(id)}/tasks/${encodeURIComponent(taskId)}`, { method: 'PATCH', body: { done } });
    if (r && r.ok) await openIncident(id, true);
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function taskEdit(taskId) {
    const id = st.detail && st.detail.incident.incident_id;
    const t = ((st.detail && st.detail.incident.tasks) || []).find((x) => x.id === taskId);
    if (!id || !t) return;
    const out = await taskForm(t);
    if (!out) return;
    const r = await api(`/${encodeURIComponent(id)}/tasks/${encodeURIComponent(taskId)}`, { method: 'PATCH', body: out });
    if (r && r.ok) { toast(T('msg_task_updated'), 'ok'); await openIncident(id, true); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function taskDel(taskId) {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const r = await api(`/${encodeURIComponent(id)}/tasks/${encodeURIComponent(taskId)}`, { method: 'DELETE' });
    if (r && r.ok) { toast(T('msg_task_deleted'), 'ok'); await openIncident(id, true); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function applyPlaybook(key) {
    const id = st.detail && st.detail.incident.incident_id;
    const pb = PLAYBOOKS[key];
    if (!id || !pb) return;
    const L = lang();
    const tasks = pb.tasks.map(([phase, t]) => ({ phase, title: t[L] }));
    const r = await api(`/${encodeURIComponent(id)}/tasks`, { method: 'POST', body: { tasks } });
    if (r && r.ok) { toast(T('msg_pb_applied', { n: r.added }), 'ok'); await openIncident(id, true); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function evAdd() {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const out = await crudForm(T('act_ev_add'), [
      { key: 'kind', label: T('col_kind'), type: 'select', options: [
        { value: 'timeline', label: T('kind_timeline') }, { value: 'note', label: T('kind_note') },
        { value: 'evidence', label: T('kind_evidence') }, { value: 'ioc', label: T('kind_ioc') }] },
      { key: 'title', label: T('col_titre'), type: 'text', required: true },
      { key: 'value', label: T('lbl_ev_value'), type: 'text', placeholder: T('ph_ev_value') },
      { key: 'description', label: T('col_description'), type: 'textarea' },
    ], { kind: 'timeline' });
    if (!out) return;
    const r = await api(`/${encodeURIComponent(id)}/events`, { method: 'POST', body: out });
    if (r && r.ok) { toast(T('msg_ajoute'), 'ok'); await openIncident(id, true); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function evDel(eventId) {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const r = await api(`/${encodeURIComponent(id)}/events/${encodeURIComponent(eventId)}`, { method: 'DELETE' });
    if (r && r.ok) { toast(T('msg_supprime'), 'ok'); await openIncident(id, true); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function linkCase() {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const caseId = await askText(T('act_inc_link'), 'case_id', '');
    if (!caseId) return;
    const r = await api(`/${encodeURIComponent(id)}/link-case`, { method: 'POST', body: { case_id: caseId } });
    if (r && r.ok) { toast(T('msg_inc_linked'), 'ok'); await openIncident(id, true); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  async function runScan() {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const zone = document.getElementById('pso-scan-zone');
    if (zone) zone.innerHTML = `<p class="fp-muted">${esc(T('msg_inc_scan_running'))}</p>`;
    st.scan = await api(`/${encodeURIComponent(id)}/scan`, { method: 'POST', body: { save: true } });
    renderScan();
    if (st.scan && st.scan.ok) await openIncident(id, true);
  }

  async function runReport() {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const r = await api(`/${encodeURIComponent(id)}/report`);
    if (r && r.ok) { st.report = r.report; renderWorkspaceInto(document.getElementById('pso-main') || root()); }
    else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  function downloadReport() {
    if (!st.report) return;
    const id = (st.detail && st.detail.incident.incident_id) || 'incident';
    const blob = new Blob([st.report], { type: 'text/markdown;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `rapport-${id}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  }

  async function runPurge(dry) {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    if (!dry) {
      const preview = await api(`/${encodeURIComponent(id)}/purge`, { method: 'POST', body: { dry_run: true } });
      const nDocs = Object.values(preview.opensearch || {}).reduce((a, b) => a + b, 0);
      const ok = await confirmBox(T('act_purge_apply'),
        T('msg_purge_confirm', { id, n: nDocs, u: (preview.uploads && preview.uploads.count) ?? 0 }));
      if (!ok) return;
    }
    st.purge = await api(`/${encodeURIComponent(id)}/purge`, {
      method: 'POST', body: dry ? { dry_run: true } : { dry_run: false, confirm: true },
    });
    renderPurge();
    if (!dry && st.purge && st.purge.ok) { toast(T('msg_purged'), 'ok'); await openIncident(id, true); }
  }

  async function deleteIncident() {
    const id = st.detail && st.detail.incident.incident_id;
    if (!id) return;
    const ok = await confirmBox(T('act_inc_delete'), T('msg_inc_delete_confirm', { id }));
    if (!ok) return;
    const r = await api(`/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (r && r.ok) {
      toast(T('msg_inc_deleted'), 'ok');
      st.detail = null;
      await refresh();
      renderQueue();
    } else toast((r && r.error) || i18n.t('msg.echec'), 'warn');
  }

  /* ── Bibliothèque de playbooks ────────────────────────────────────────── */
  function loadPlaybooks() {
    const host = document.getElementById('psoar-playbooks-root'); if (!host) return;
    const L = lang();
    host.innerHTML = `<div class="pso-pb-grid">${Object.entries(PLAYBOOKS).map(([key, pb]) => {
      const byPhase = PHASES.map((ph) => ({ ph, items: pb.tasks.filter(([p]) => p === ph) })).filter((g) => g.items.length);
      return `<article class="cc-tp-fetchform pso-pb-card">
        <h4 class="fp-section-sub">${esc(pb.label[L])} <span class="fp-tag">${pb.tasks.length} ${esc(T('pb_tasks'))}</span></h4>
        <p class="fp-muted">${esc(pb.desc[L])}</p>
        ${byPhase.map((g) => `<div class="cc-inc-phase">
          <h5 class="pso-pb-phase">${esc(T(`inc_phase_${g.ph}`))} <span class="fp-muted">${g.items.length}</span></h5>
          <ul class="pso-pb-tasks">${g.items.map(([, t]) => `<li>${esc(t[L])}</li>`).join('')}</ul>
        </div>`).join('')}
        <p class="fp-muted pso-pb-hint">${esc(T('pb_apply_hint'))}</p>
      </article>`;
    }).join('')}</div>`;
  }

  /* ── Binding ──────────────────────────────────────────────────────────── */
  function bindRoot(host) {
    host.__psoBound = true;
    delegate(host, {
      'pso-new': () => newIncident(),
      'pso-open': (el) => openIncident(el.dataset.id),
      'pso-back': async () => { st.detail = null; await refresh(); renderQueue(); },
      'pso-flt-reset': () => { st.flt = { status: '', severity: '', q: '' }; renderQueue(); },
      'pso-tab': (el) => { st.tab = el.dataset.tab; renderWorkspaceInto(document.getElementById('pso-main') || host); },
      'pso-step': (el) => setStatus(el.dataset.status),
      'pso-status-apply': () => applyStatusForm(),
      'pso-meta-save': () => saveMeta(),
      'pso-task-add': () => taskAdd(),
      'pso-task-toggle': (el) => taskToggle(el.dataset.id, el.dataset.done === '1'),
      'pso-task-edit': (el) => taskEdit(el.dataset.id),
      'pso-task-del': (el) => taskDel(el.dataset.id),
      'pso-playbook': (el) => applyPlaybook(el.dataset.pb),
      'pso-ev-add': () => evAdd(),
      'pso-ev-del': (el) => evDel(el.dataset.id),
      'pso-link': () => linkCase(),
      'pso-scan': () => runScan(),
      'pso-report': () => runReport(),
      'pso-report-copy': () => { if (st.report && TC) TC.copy(st.report); },
      'pso-report-dl': () => downloadReport(),
      'pso-purge-dry': () => runPurge(true),
      'pso-purge-apply': () => runPurge(false),
      'pso-delete': () => deleteIncident(),
    });
    host.addEventListener('input', (e) => {
      if (!e.target) return;
      if (e.target.id === 'pso-flt-q') { st.flt.q = e.target.value; debouncedRender(); }
    });
    host.addEventListener('change', (e) => {
      if (!e.target) return;
      if (e.target.id === 'pso-flt-status') { st.flt.status = e.target.value; renderQueue(); }
      if (e.target.id === 'pso-flt-sev') { st.flt.severity = e.target.value; renderQueue(); }
    });
  }

  let renderTimer = null;
  function debouncedRender() {
    if (renderTimer) clearTimeout(renderTimer);
    renderTimer = setTimeout(() => { if (!st.detail) renderQueue(); }, 150);
  }

  window.PSOAR = { load, loadPlaybooks, openIncident };
  if (TC && TC.bind) TC.bind({ psoar: load, 'psoar-playbooks': loadPlaybooks });
})();
