/* ═══════════════════════════════════════════════════════════════════════════
   PSOAR — Workflow Designer (module 3.8).

   Construire un playbook exigeait d'écrire du JSON : étapes typées, cibles de
   saut, conditions. Autant dire que seul un développeur pouvait le faire, alors
   que le playbook est un objet MÉTIER qui appartient à l'analyste.

   Ce concepteur permet de bâtir un workflow complet sans écrire une ligne :
   - ajout d'étapes typées par formulaire, le catalogue d'actions étant servi
     par le serveur (aucune liste codée en dur côté navigateur) ;
   - branchement visuel : chaque étape déclare sa suite, une condition déclare
     ses deux issues, une approbation sa voie de refus ;
   - VALIDATION EN CONTINU : les cibles de saut inexistantes, les identifiants
     en double et les étapes orphelines sont signalés AVANT l'enregistrement ;
   - aperçu du graphe et simulation en un clic sur un incident réel.

   Parti pris : pas de glisser-déposer. Sur un graphe d'exécution, la précision
   prime sur le geste — une cible mal reliée casse un run, et un formulaire
   explicite se relit, se corrige et s'explique. Le rendu montre le graphe,
   l'édition reste déterministe.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  const TC = window.ThreatCommon || null;
  const esc = (s) => (TC && TC.esc ? TC.esc(s) : String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));
  const toast = (m, c) => { if (TC && TC.toast) TC.toast(m, c); };

  const PHASES = [
    ['detection', 'Détection'], ['analysis', 'Analyse'], ['containment', 'Confinement'],
    ['eradication', 'Éradication'], ['recovery', 'Récupération'], ['lessons', 'Leçons'],
  ];
  const STEP_LABELS = {
    action: 'Action', condition: 'Condition', approval: 'Approbation',
    parallel: 'Parallèle', note: 'Note',
  };
  const STEP_ICON = { action: '▸', condition: '◆', approval: '⏸', parallel: '⇉', note: '·' };
  const OPS = [['eq', 'égal à'], ['ne', 'différent de'], ['gt', 'supérieur à'],
    ['lt', 'inférieur à'], ['contains', 'contient'], ['exists', 'est renseigné']];
  const FIELDS = [
    ['incident.severity', 'Sévérité de l\'incident'],
    ['incident.status', 'Statut de l\'incident'],
    ['incident.assignee', 'Analyste assigné'],
    ['vars.ioc_count', 'Nombre d\'IOC recensés'],
    ['vars.silent_intakes', 'Sources Sekoia silencieuses'],
    ['vars.health_score', 'Score de santé Sekoia'],
  ];

  const st = { steps: [], meta: { name: '', description: '', framework: 'NIST' },
    actions: [], incidents: [], editing: null, open: false };

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

  function root() { return document.getElementById('psoar-designer-root'); }
  const uid = () => `s${Math.random().toString(36).slice(2, 7)}`;

  /**
   * Validation locale, miroir de celle du serveur. La signaler AVANT
   * l'enregistrement évite à l'analyste un aller-retour et un message d'erreur
   * sur un graphe qu'il ne voit plus.
   */
  function validate() {
    const errs = [];
    const ids = st.steps.map((s) => s.id);
    if (!st.meta.name.trim()) errs.push('Le playbook doit porter un nom.');
    if (!st.steps.length) errs.push('Ajoutez au moins une étape.');
    ids.forEach((id, i) => {
      if (ids.indexOf(id) !== i) errs.push(`Identifiant en double : « ${id} ».`);
    });
    st.steps.forEach((s) => {
      const targets = [s.next, s.on_true, s.on_false, s.on_reject, ...(s.branches || [])];
      targets.filter(Boolean).forEach((tg) => {
        if (!ids.includes(tg)) errs.push(`Étape « ${s.name || s.id} » : cible « ${tg} » inexistante.`);
      });
      if (s.type === 'action' && !s.action) errs.push(`Étape « ${s.name || s.id} » : action non choisie.`);
      if (s.type === 'condition' && !s.condition?.field) {
        errs.push(`Étape « ${s.name || s.id} » : champ de condition non choisi.`);
      }
    });
    // Étapes orphelines : atteignables par personne alors qu'elles ne sont pas
    // le point d'entrée. Ce n'est pas bloquant, mais c'est presque toujours un
    // oubli de branchement.
    const reachable = new Set(st.steps.length ? [st.steps[0].id] : []);
    let grew = true;
    while (grew) {
      grew = false;
      st.steps.forEach((s) => {
        if (!reachable.has(s.id)) return;
        [s.next, s.on_true, s.on_false, s.on_reject, ...(s.branches || [])]
          .filter(Boolean).forEach((tg) => { if (!reachable.has(tg)) { reachable.add(tg); grew = true; } });
      });
    }
    const orphans = st.steps.filter((s) => !reachable.has(s.id)).map((s) => s.name || s.id);
    return { errors: [...new Set(errs)], orphans };
  }

  function stepCard(s, i) {
    const targets = [];
    if (s.type === 'condition') {
      targets.push(['si vrai', s.on_true], ['si faux', s.on_false]);
    } else if (s.type === 'approval') {
      targets.push(['si approuvé', s.next], ['si refusé', s.on_reject]);
    } else if (s.type === 'parallel') {
      (s.branches || []).forEach((b, k) => targets.push([`branche ${k + 1}`, b]));
      targets.push(['ensuite', s.next]);
    } else {
      targets.push(['ensuite', s.next]);
    }
    const flow = targets.map(([lbl, tg]) => `<span class="pdz-arrow">${esc(lbl)} →
      <b>${tg ? esc(tg) : 'fin'}</b></span>`).join('');
    const detail = s.type === 'action' ? esc(s.action || '—')
      : s.type === 'condition'
        ? `${esc(s.condition?.field || '?')} ${esc((OPS.find((o) => o[0] === s.condition?.op) || [])[1] || '')} ${esc(JSON.stringify(s.condition?.value ?? ''))}`
        : s.type === 'approval' ? esc(s.prompt || '') : '';
    return `<article class="pdz-step" data-idx="${i}">
      <div class="pdz-step-head">
        <span class="pdz-step-id">${esc(STEP_ICON[s.type])} ${esc(s.id)}</span>
        <strong>${esc(s.name || '(sans nom)')}</strong>
        <span class="swb-pill swb-pill-mute swb-pill-flat">${esc(STEP_LABELS[s.type])}</span>
        <span class="swb-hint">${esc((PHASES.find((pp) => pp[0] === s.phase) || [])[1] || s.phase)}</span>
        <span class="swb-nav-spacer"></span>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pdz-act="up" data-idx="${i}" title="Monter">↑</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pdz-act="down" data-idx="${i}" title="Descendre">↓</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pdz-act="edit" data-idx="${i}">Modifier</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pdz-act="del" data-idx="${i}">Retirer</button>
      </div>
      ${detail ? `<p class="swb-hint pdz-detail">${detail}</p>` : ''}
      <div class="pdz-flow">${flow}</div>
    </article>`;
  }

  function editor() {
    const s = st.editing;
    if (!s) return '';
    const ids = st.steps.filter((x) => x.id !== s.id).map((x) => x.id);
    const sel = (name, val, options, extra) => `<label>${esc(name)}
      <select class="swb-select" data-pdz-field="${extra}">
        ${options.map(([v, l]) => `<option value="${esc(v)}"${String(val) === String(v) ? ' selected' : ''}>${esc(l)}</option>`).join('')}
      </select></label>`;
    const targetSel = (label, field, val) => sel(label, val || '',
      [['', 'fin du playbook'], ...ids.map((x) => [x, x])], field);

    let specific = '';
    if (s.type === 'action') {
      specific = sel('Action', s.action, st.actions.map((a) => [a.action,
        `${a.label}${a.ready ? '' : ' — intégration indisponible'}`]), 'action')
        + `<label>Paramètres (JSON)<input class="swb-input" data-pdz-field="params"
             value="${esc(JSON.stringify(s.params || {}))}"></label>`
        + targetSel('Ensuite', 'next', s.next);
    } else if (s.type === 'condition') {
      specific = sel('Champ observé', s.condition?.field, FIELDS, 'cond_field')
        + sel('Comparateur', s.condition?.op, OPS, 'cond_op')
        + `<label>Valeur<input class="swb-input" data-pdz-field="cond_value"
             value="${esc(s.condition?.value ?? '')}"></label>`
        + targetSel('Si vrai', 'on_true', s.on_true)
        + targetSel('Si faux', 'on_false', s.on_false);
    } else if (s.type === 'approval') {
      specific = `<label>Question posée<input class="swb-input" data-pdz-field="prompt"
             value="${esc(s.prompt || '')}"></label>`
        + `<label>Approbateurs (séparés par des virgules)<input class="swb-input" data-pdz-field="approvers"
             value="${esc((s.approvers || []).join(', '))}"></label>`
        + targetSel('Si approuvé', 'next', s.next)
        + targetSel('Si refusé', 'on_reject', s.on_reject);
    } else if (s.type === 'parallel') {
      specific = `<label>Branches (identifiants séparés par des virgules)<input class="swb-input"
             data-pdz-field="branches" value="${esc((s.branches || []).join(', '))}"></label>`
        + targetSel('Ensuite', 'next', s.next);
    } else {
      specific = targetSel('Ensuite', 'next', s.next);
    }

    return `<div class="swb-scrim" data-pdz-act="cancel"></div>
      <aside class="swb-drawer" role="dialog" aria-label="Édition d'étape">
        <div class="swb-drawer-head">
          <div><h3 class="swb-title">${esc(STEP_LABELS[s.type])} — ${esc(s.id)}</h3>
            <p class="swb-sub">Les cibles proposées sont limitées aux étapes existantes : une référence
              inexistante est impossible à saisir.</p></div>
          <button type="button" class="swb-drawer-close" data-pdz-act="cancel" aria-label="Fermer">✕</button>
        </div>
        <div class="swb-drawer-body">
          <div class="pdz-form">
            <label>Nom<input class="swb-input" data-pdz-field="name" value="${esc(s.name || '')}"></label>
            ${sel('Phase', s.phase, PHASES, 'phase')}
            ${specific}
          </div>
          <div class="swb-filters" style="margin-top:1rem">
            <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pdz-act="apply">Appliquer</button>
            <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pdz-act="cancel">Annuler</button>
          </div>
        </div>
      </aside>`;
  }

  function render() {
    const el = root();
    if (!el) return;
    if (!st.open) {
      el.innerHTML = `<div class="swb-filters">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pdz-act="open">
          Concevoir un playbook sans code</button>
        <span class="swb-hint">Étapes typées, branches, approbations — sans écrire de JSON.</span></div>`;
      return;
    }
    const v = validate();
    const incOpts = st.incidents.map((i) => `<option value="${esc(i.incident_id)}">${esc(i.incident_id)}
      — ${esc(String(i.title || '').slice(0, 40))}</option>`).join('');

    el.innerHTML = `<div class="swb">
      <div class="swb-head">
        <div><h3 class="swb-title">Concepteur de playbook</h3>
          <p class="swb-sub">Le graphe est validé en continu : cibles inexistantes, identifiants en double
            et étapes orphelines sont signalés avant l'enregistrement.</p></div>
        <div class="swb-actions">
          <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pdz-act="close">Fermer</button></div>
      </div>
      <div class="swb-panel">
        <div class="pdz-form">
          <label>Nom du playbook<input class="swb-input" data-pdz-meta="name" value="${esc(st.meta.name)}"
            placeholder="Confinement d'un poste compromis"></label>
          <label>Cadre<input class="swb-input" data-pdz-meta="framework" value="${esc(st.meta.framework)}"></label>
          <label style="flex:1 1 100%">Description<input class="swb-input" data-pdz-meta="description"
            value="${esc(st.meta.description)}" placeholder="Ce que fait ce playbook et quand l'utiliser"></label>
        </div>
      </div>
      <div class="swb-filters">
        ${Object.entries(STEP_LABELS).map(([k, l]) => `<button type="button" class="fp-btn fp-btn-sm"
          data-pdz-act="add" data-type="${k}">+ ${esc(l)}</button>`).join('')}
      </div>
      ${v.errors.length ? `<div class="swb-state swb-state-degraded">
        <p class="swb-state-title">${v.errors.length} point(s) à corriger avant enregistrement</p>
        <ul style="margin:.3rem 0 0;padding-left:1.1rem;font-size:.82rem">
          ${v.errors.map((e) => `<li>${esc(e)}</li>`).join('')}</ul></div>` : ''}
      ${v.orphans.length ? `<div class="swb-state" style="border-left:3px solid var(--swb-warn);text-align:left">
        <p class="swb-state-title">Étapes jamais atteintes</p>
        <p class="swb-state-msg">${esc(v.orphans.join(', '))} — aucune autre étape n'y renvoie.
        Ce n'est pas bloquant, mais c'est presque toujours un oubli de branchement.</p></div>` : ''}
      <div class="pdz-steps">${st.steps.map(stepCard).join('')
    || '<p class="swb-hint">Aucune étape. La première étape ajoutée devient le point d\'entrée.</p>'}</div>
      <div class="swb-panel"><div class="swb-filters">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pdz-act="save"
          ${v.errors.length ? 'disabled' : ''}>Enregistrer le playbook</button>
        <select class="swb-select" id="pdz-incident">${incOpts || '<option value="">aucun incident</option>'}</select>
        <button type="button" class="fp-btn fp-btn-sm" data-pdz-act="simulate"
          ${v.errors.length ? 'disabled' : ''}>Enregistrer et simuler</button>
        <span class="swb-hint">La simulation ne produit aucun effet de bord.</span>
      </div></div>
      ${editor()}</div>`;
  }

  function newStep(type) {
    const s = { id: uid(), type, name: '', phase: 'analysis', next: null };
    if (type === 'action') { s.action = (st.actions[0] || {}).action || ''; s.params = {}; }
    if (type === 'condition') {
      s.condition = { field: FIELDS[0][0], op: 'eq', value: '' };
      s.on_true = null; s.on_false = null;
    }
    if (type === 'approval') { s.prompt = 'Confirmer cette action ?'; s.approvers = []; s.on_reject = null; }
    if (type === 'parallel') s.branches = [];
    // Chaînage automatique : la nouvelle étape prend la suite de la précédente.
    // Sans cela, chaque ajout crée une étape orpheline à relier à la main.
    if (st.steps.length) {
      const last = st.steps[st.steps.length - 1];
      if (last.type !== 'condition' && !last.next) last.next = s.id;
    }
    return s;
  }

  function applyEdit(el) {
    const s = st.editing;
    if (!s) return;
    el.querySelectorAll('[data-pdz-field]').forEach((f) => {
      const k = f.dataset.pdzField;
      const v = f.value;
      if (k === 'name' || k === 'phase' || k === 'action' || k === 'prompt') s[k] = v;
      else if (k === 'next' || k === 'on_true' || k === 'on_false' || k === 'on_reject') s[k] = v || null;
      else if (k === 'approvers' || k === 'branches') {
        s[k] = v.split(',').map((x) => x.trim()).filter(Boolean);
      } else if (k === 'params') {
        try { s.params = JSON.parse(v || '{}'); } catch { toast('Paramètres : JSON invalide, ignorés', 'err'); }
      } else if (k.startsWith('cond_')) {
        s.condition = s.condition || {};
        s.condition[k.replace('cond_', '')] = v;
      }
    });
    st.editing = null;
    render();
  }

  async function save(simulate) {
    const body = {
      name: st.meta.name, description: st.meta.description, framework: st.meta.framework,
      steps: st.steps,
    };
    const r = await api('/playbooks', { method: 'POST', body });
    toast(`Playbook « ${r.playbook.name} » enregistré`, 'ok');
    if (simulate) {
      const incident = (document.getElementById('pdz-incident') || {}).value;
      if (!incident) { toast('Sélectionnez un incident pour la simulation', 'err'); return; }
      const run = await api(`/playbooks/${encodeURIComponent(r.playbook.id)}/run`, {
        method: 'POST', body: { incident_id: incident, dry_run: true },
      });
      toast(`Simulation : ${run.run.status}, ${run.run.journal.length} étape(s)`, 'ok');
    }
    st.open = false;
    render();
    if (window.PsoarOrchestrator) window.PsoarOrchestrator.load();
  }

  function bind(el) {
    if (el.dataset.pdzBound) return;
    el.dataset.pdzBound = '1';
    el.addEventListener('input', (ev) => {
      const m = ev.target.closest('[data-pdz-meta]');
      if (m) { st.meta[m.dataset.pdzMeta] = m.value; }
    });
    el.addEventListener('click', async (ev) => {
      const b = ev.target.closest('[data-pdz-act]');
      if (!b) return;
      const act = b.dataset.pdzAct;
      const idx = Number(b.dataset.idx);
      try {
        if (act === 'open') {
          st.open = true;
          const r = await Promise.all([
            api('/playbooks/actions'),
            api('/incidents').catch(() => []),
          ]);
          st.actions = (r[0].actions || []);
          st.incidents = Array.isArray(r[1]) ? r[1] : [];
          render(); return;
        }
        if (act === 'close') { st.open = false; render(); return; }
        if (act === 'add') { st.steps.push(newStep(b.dataset.type)); render(); return; }
        if (act === 'edit') { st.editing = st.steps[idx]; render(); return; }
        if (act === 'del') {
          const gone = st.steps[idx].id;
          st.steps.splice(idx, 1);
          // Les références vers l'étape retirée sont nettoyées : laisser une
          // cible morte produirait un graphe invalide au prochain rendu.
          st.steps.forEach((s) => {
            ['next', 'on_true', 'on_false', 'on_reject'].forEach((k) => {
              if (s[k] === gone) s[k] = null;
            });
            if (s.branches) s.branches = s.branches.filter((x) => x !== gone);
          });
          render(); return;
        }
        if (act === 'up' && idx > 0) {
          [st.steps[idx - 1], st.steps[idx]] = [st.steps[idx], st.steps[idx - 1]];
          render(); return;
        }
        if (act === 'down' && idx < st.steps.length - 1) {
          [st.steps[idx + 1], st.steps[idx]] = [st.steps[idx], st.steps[idx + 1]];
          render(); return;
        }
        if (act === 'apply') { applyEdit(el); return; }
        if (act === 'cancel') { st.editing = null; render(); return; }
        if (act === 'save') { await save(false); return; }
        if (act === 'simulate') { await save(true); return; }
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  function init() {
    const el = root();
    if (!el) return;
    bind(el);
    render();
  }

  window.PsoarDesigner = { init, render };
  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.querySelector('[data-tab-btn="psoar-playbooks"]');
    if (btn) btn.addEventListener('click', () => setTimeout(init, 70));
  });
}());
