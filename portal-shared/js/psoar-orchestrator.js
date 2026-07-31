/* PSOAR — Orchestrateur de playbooks (interface du moteur d'exécution).
 *
 * L'onglet Playbooks n'exposait que des modèles statiques : des check-lists
 * qu'un analyste recopiait à la main. Le moteur d'orchestration existe désormais
 * côté serveur (étapes typées, branches, approbations, journal) mais restait
 * injoignable depuis le portail.
 *
 * Cette console le rend utilisable : créer un playbook depuis un modèle, le
 * SIMULER sans effet de bord, l'exécuter sur un incident, arbitrer les
 * approbations bloquantes, et relire le journal pas à pas de chaque exécution.
 */
(function () {
  'use strict';

  const TC = window.ThreatCommon || null;
  const esc = (s) => (TC && TC.esc ? TC.esc(s) : String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));
  const toast = (m, c) => { if (TC && TC.toast) TC.toast(m, c); };

  const st = { playbooks: [], runs: [], incidents: [], run: null, loading: false, error: null };

  /**
   * Modèle NIST livré prêt à l'emploi : il démontre les quatre capacités qui
   * distinguent un orchestrateur d'une check-list — une action, une condition
   * qui branche, une approbation bloquante, et une voie de repli.
   */
  const TEMPLATE = {
    name: 'Confinement gouverné — NIST IR',
    framework: 'NIST',
    description: 'Relève la volumétrie, branche sur la sévérité, exige une approbation '
      + 'avant confinement et trace la décision. Voie de repli si la sévérité est faible '
      + 'ou si le confinement est refusé.',
    steps: [
      { id: 's1', type: 'note', name: 'Ouverture du playbook', phase: 'detection', next: 's2' },
      { id: 's2', type: 'action', name: 'Relever la volumétrie Sekoia',
        action: 'sekoia.volumetry', phase: 'analysis', next: 's3' },
      { id: 's3', type: 'action', name: 'Recenser les IOC de l’incident',
        action: 'ioc.scan', phase: 'analysis', next: 's4' },
      { id: 's4', type: 'condition', name: 'Sévérité élevée ou critique ?', phase: 'analysis',
        condition: { field: 'incident.severity', op: 'contains', value: 'high' },
        on_true: 's5', on_false: 's8' },
      { id: 's5', type: 'approval', name: 'Validation du confinement', phase: 'containment',
        prompt: 'Confirmer le confinement ? Cette action change le statut de l’incident.',
        approvers: ['soc-lead'], on_reject: 's8', next: 's6' },
      { id: 's6', type: 'action', name: 'Passer l’incident en confinement',
        action: 'incident.status', phase: 'containment',
        params: { status: 'contained' }, next: 's7' },
      { id: 's7', type: 'action', name: 'Tracer la décision', action: 'incident.note',
        phase: 'containment',
        params: { title: 'Confinement appliqué par playbook',
          description: 'Décision approuvée puis exécutée par l’orchestrateur PSOAR.' },
        next: null },
      { id: 's8', type: 'note', name: 'Clôture sans confinement', phase: 'lessons', next: null },
    ],
  };

  async function api(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    if (o.body && typeof o.body !== 'string') {
      o.body = JSON.stringify(o.body);
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
    }
    const r = await fetch('/api' + path, o);
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    return d;
  }

  function root() { return document.getElementById('psoar-orchestrator-root'); }

  const STEP_ICON = { action: '▸', condition: '◆', approval: '⏸', parallel: '⇉', note: '·' };

  function journal(run) {
    if (!run) return '';
    const rows = (run.journal || []).map(function (e, i) {
      const tone = e.ok === false ? 'danger' : (e.simulated ? 'warn' : 'ok');
      const decision = (e.decision === true) ? ' <span class="fp-tag fp-tag-ok">vrai</span>'
        : (e.decision === false ? ' <span class="fp-tag">faux</span>' : '');
      return '<tr><td class="sep-num">' + (i + 1) + '</td>'
        + '<td>' + esc(STEP_ICON[e.type] || '·') + ' <code>' + esc(e.type) + '</code></td>'
        + '<td>' + esc(e.name || e.step_id) + decision + '</td>'
        + '<td class="fp-muted">' + esc(e.detail || e.error || '') + '</td>'
        + '<td><span class="fp-tag fp-tag-' + tone + '">'
        + (e.ok === false ? 'échec' : (e.simulated ? 'simulé' : 'exécuté')) + '</span></td></tr>';
    }).join('');

    const wait = run.status === 'waiting_approval' && run.awaiting
      ? '<div class="fp-card pso-approval"><h4>Approbation requise</h4>'
        + '<p>' + esc(run.awaiting.prompt) + '</p>'
        + '<p class="fp-muted">Étape « ' + esc(run.awaiting.step_id) + ' »'
        + (run.awaiting.approvers && run.awaiting.approvers.length
          ? ' — approbateurs : ' + esc(run.awaiting.approvers.join(', ')) : '') + '</p>'
        + '<button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pbo-act="approve" data-id="'
        + esc(run.run_id) + '" data-ok="1">Approuver et reprendre</button> '
        + '<button type="button" class="fp-btn fp-btn-sm fp-btn-danger" data-pbo-act="approve" data-id="'
        + esc(run.run_id) + '" data-ok="0">Rejeter</button></div>'
      : '';

    const statusTone = { completed: 'ok', failed: 'danger', waiting_approval: 'warn',
      cancelled: '', running: 'warn' }[run.status] || '';
    return '<div class="fp-card"><div class="sep-row-between">'
      + '<h3 class="fp-section-title">Journal — ' + esc(run.playbook_name) + '</h3>'
      + '<span class="fp-tag fp-tag-' + statusTone + '">' + esc(run.status)
      + (run.dry_run ? ' · simulation' : '') + '</span></div>'
      + '<p class="fp-muted">Incident ' + esc(run.incident_id) + ' · version ' + esc(run.playbook_version)
      + ' · lancé par ' + esc(run.started_by) + ' le ' + esc(run.started_at) + '</p>'
      + wait
      + '<div class="sep-scroll"><table class="fp-table sep-table"><thead><tr>'
      + '<th>#</th><th>Type</th><th>Étape</th><th>Détail</th><th>État</th>'
      + '</tr></thead><tbody>' + rows + '</tbody></table></div>'
      + '<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pbo-act="close-run">Fermer</button></div>';
  }

  // Etat de la file : sans ce bandeau, une execution confiee au worker serait
  // invisible pour l'analyste qui l'a lancee.
  function queueBanner() {
    const q = st.queue;
    if (!q) return '';
    const by = q.by_status || {};
    const chip = (k, l, cls) => (by[k]
      ? '<span class="fp-tag' + (cls ? ' ' + cls : '') + '">' + esc(l) + ' : ' + esc(by[k]) + '</span> ' : '');
    return '<div class="fp-card" style="border-left:3px solid var(--swb-accent,#38a0ff)">'
      + '<div class="sep-row-between"><h4 class="fp-section-sub">File d\'exécution</h4>'
      + '<span class="fp-muted" style="font-size:.75rem">worker ' + esc(q.worker_id)
      + ' · ' + esc(q.in_flight) + '/' + esc(q.concurrency) + ' en vol · reprise '
      + esc((q.retry || {}).attempts) + ' tentatives</span></div>'
      + '<p style="margin:.4rem 0 0">'
      + chip('queued', 'en file', 'fp-tag-warn')
      + chip('running', 'en cours', 'fp-tag-warn')
      + chip('waiting_approval', 'attente d\'approbation', 'fp-tag-warn')
      + chip('completed', 'terminés', 'fp-tag-ok')
      + chip('failed', 'échoués', 'fp-tag-danger')
      + (Object.keys(by).length ? '' : '<span class="fp-muted">Aucune exécution enregistrée.</span>')
      + '</p></div>';
  }

  function render() {
    const el = root();
    if (!el) return;
    if (st.loading) { el.innerHTML = '<p class="fp-muted">Chargement…</p>'; return; }
    if (st.error) {
      el.innerHTML = '<div class="fp-card sep-degraded"><p class="sep-degraded-title">Orchestrateur indisponible</p>'
        + '<p class="fp-muted">' + esc(st.error) + '</p>'
        + '<button type="button" class="fp-btn fp-btn-sm" data-pbo-act="reload">Réessayer</button></div>';
      return;
    }

    const incOpts = st.incidents.map(function (i) {
      return '<option value="' + esc(i.incident_id) + '">' + esc(i.incident_id)
        + ' — ' + esc(String(i.title || '').slice(0, 50)) + ' (' + esc(i.severity) + ')</option>';
    }).join('');

    const pbCards = st.playbooks.length ? st.playbooks.map(function (p) {
      const counts = {};
      (p.steps || []).forEach(function (s) { counts[s.type] = (counts[s.type] || 0) + 1; });
      const badges = Object.keys(counts).map(function (t) {
        return '<span class="fp-tag">' + esc(STEP_ICON[t] || '·') + ' ' + esc(t) + ' ×' + counts[t] + '</span>';
      }).join(' ');
      return '<article class="fp-card pso-pb-orch"><div class="sep-row-between">'
        + '<h4 class="fp-section-sub">' + esc(p.name) + '</h4>'
        + '<span class="fp-tag">v' + esc(p.version || 1) + '</span></div>'
        + '<p class="fp-muted">' + esc(p.description || '') + '</p>'
        + '<p class="pso-pb-badges">' + badges + '</p>'
        + '<div class="sep-form">'
        + '<button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-pbo-act="run" data-id="'
        + esc(p.id) + '" data-dry="1">Simuler</button>'
        + '<button type="button" class="fp-btn fp-btn-sm fp-btn-danger" data-pbo-act="run" data-id="'
        + esc(p.id) + '" data-dry="0">Exécuter</button>'
        + '<button type="button" class="fp-btn fp-btn-sm" data-pbo-act="run" data-id="'
        + esc(p.id) + '" data-dry="0" data-async="1" title="Confie l\'exécution au worker : '
        + 'la page n\'attend pas, le playbook survit à la fermeture de l\'onglet">Exécuter en file</button>'
        + '<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pbo-act="delete" data-id="'
        + esc(p.id) + '">Supprimer</button>'
        + '</div></article>';
    }).join('') : '<div class="fp-card"><p class="fp-muted">Aucun playbook exécutable. '
      + 'Créez-en un depuis le modèle NIST pour disposer d’un parcours complet '
      + '(action, condition, approbation, repli).</p></div>';

    const runRows = st.runs.slice(0, 15).map(function (r) {
      const tone = { completed: 'ok', failed: 'danger', waiting_approval: 'warn' }[r.status] || '';
      return '<tr data-pbo-act="open-run" data-id="' + esc(r.run_id) + '" class="pso-run-row">'
        + '<td class="fp-muted">' + esc(r.started_at) + '</td>'
        + '<td>' + esc(r.playbook_name) + '</td>'
        + '<td>' + esc(r.incident_id) + '</td>'
        + '<td>' + (r.dry_run ? '<span class="fp-tag">simulation</span>' : '<span class="fp-tag fp-tag-warn">réel</span>') + '</td>'
        + '<td><span class="fp-tag fp-tag-' + tone + '">' + esc(r.status) + '</span></td>'
        + '<td class="sep-num">' + ((r.journal || []).length) + '</td></tr>';
    }).join('');

    el.innerHTML = '<div class="sep-row-between">'
      + '<h3 class="fp-section-title">Orchestrateur — playbooks exécutables</h3>'
      + '<div class="sep-range">'
      + '<button type="button" class="fp-btn fp-btn-sm" data-pbo-act="seed">Créer depuis le modèle NIST</button>'
      + '<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-pbo-act="reload">↻ Rafraîchir</button>'
      + '</div></div>'
      + '<p class="fp-muted">Étapes typées, branches conditionnelles, approbations bloquantes et journal '
      + 'd’exécution — à la différence des modèles ci-dessous, qui restent des check-lists.</p>'
      + '<div class="sep-form"><label>Incident cible<select id="pbo-incident">'
      + (incOpts || '<option value="">aucun incident</option>') + '</select></label></div>'
      + queueBanner()
      + '<div class="sep-grid2">' + pbCards + '</div>'
      + (st.run ? journal(st.run) : '')
      + '<div class="fp-card sep-table-wrap"><h3 class="fp-section-title">Exécutions récentes</h3>'
      + '<p class="fp-muted">Un clic sur une ligne ouvre le journal pas à pas.</p>'
      + '<div class="sep-scroll"><table class="fp-table sep-table"><thead><tr>'
      + '<th>Date</th><th>Playbook</th><th>Incident</th><th>Mode</th><th>Statut</th><th>Étapes</th>'
      + '</tr></thead><tbody>'
      + (runRows || '<tr><td colspan="6" class="fp-muted">Aucune exécution.</td></tr>')
      + '</tbody></table></div></div>';
  }

  const TERMINAL = ['completed', 'failed', 'cancelled', 'waiting_approval'];
  async function pollRun(runId, tries) {
    if (tries > 20) return;
    setTimeout(async function () {
      try {
        const run = await api('/playbook-runs/' + encodeURIComponent(runId));
        if (st.run && st.run.run_id === runId) { st.run = run; }
        st.queue = await api('/playbook-queue').catch(function () { return st.queue; });
        st.runs = await api('/playbook-runs').catch(function () { return st.runs; });
        render();
        if (!TERMINAL.includes(run.status)) pollRun(runId, tries + 1);
        else if (run.status !== 'waiting_approval') {
          toast('Exécution ' + run.status, run.status === 'failed' ? 'err' : 'ok');
        }
      } catch (e) { /* le suivi ne doit jamais casser l'ecran */ }
    }, 2000);
  }

  async function load() {
    st.loading = true; st.error = null; render();
    try {
      const res = await Promise.all([
        api('/playbooks'),
        api('/playbook-runs'),
        api('/incidents').catch(function () { return []; }),
        api('/playbook-queue').catch(function () { return null; }),
      ]);
      st.playbooks = Array.isArray(res[0]) ? res[0] : [];
      st.runs = Array.isArray(res[1]) ? res[1] : [];
      st.incidents = Array.isArray(res[2]) ? res[2] : [];
      st.queue = res[3];
    } catch (e) { st.error = e.message; }
    st.loading = false; render();
  }

  function bind(el) {
    if (el.dataset.pboBound) return;
    el.dataset.pboBound = '1';
    el.addEventListener('click', async function (ev) {
      // Le clic sur une LIGNE du tableau ouvre le journal, pas seulement un bouton.
      const row = ev.target.closest('tr[data-pbo-act]');
      const btn = ev.target.closest('[data-pbo-act]') || row;
      if (!btn) return;
      const act = btn.dataset.pboAct;
      const id = btn.dataset.id;
      try {
        if (act === 'reload') { load(); return; }
        if (act === 'close-run') { st.run = null; render(); return; }
        if (act === 'seed') {
          const r = await api('/playbooks', { method: 'POST', body: TEMPLATE });
          toast('Playbook « ' + r.playbook.name +' » créé', 'ok');
          load(); return;
        }
        if (act === 'delete') {
          await api('/playbooks/' + encodeURIComponent(id), { method: 'DELETE' });
          toast('Playbook supprimé', 'ok'); load(); return;
        }
        if (act === 'open-run') {
          st.run = await api('/playbook-runs/' + encodeURIComponent(id));
          render(); return;
        }
        if (act === 'run') {
          const incident = (document.getElementById('pbo-incident') || {}).value;
          if (!incident) { toast('Sélectionnez un incident cible', 'err'); return; }
          const dry = btn.dataset.dry === '1';
          const asyncMode = btn.dataset.async === '1';
          const r = await api('/playbooks/' + encodeURIComponent(id) + '/run', {
            method: 'POST', body: { incident_id: incident, dry_run: dry, async: asyncMode },
          });
          st.run = r.run;
          if (r.queued) {
            toast('Exécution mise en file — le worker la reprend', 'ok');
            // Suivi discret : on rafraichit tant que le run avance, sans
            // bloquer l'analyste ni marteler le serveur.
            pollRun(r.run.run_id, 0);
          } else {
            const s = r.run.status;
            toast(s === 'waiting_approval' ? 'Exécution en attente d’approbation'
              : (dry ? 'Simulation terminée : ' + s : 'Exécution terminée : ' + s),
            s === 'failed' ? 'err' : 'ok');
          }
          st.runs = await api('/playbook-runs').catch(function () { return st.runs; });
          render(); return;
        }
        if (act === 'approve') {
          const r = await api('/playbook-runs/' + encodeURIComponent(id) + '/approve', {
            method: 'POST', body: { approved: btn.dataset.ok === '1' },
          });
          st.run = r.run;
          toast('Décision enregistrée — exécution ' + r.run.status, 'ok');
          st.runs = await api('/playbook-runs').catch(function () { return st.runs; });
          render(); return;
        }
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  function init() {
    const el = root();
    if (!el) return;
    bind(el);
    load();
  }

  window.PsoarOrchestrator = { init: init, load: load };
  document.addEventListener('DOMContentLoaded', function () {
    const btn = document.querySelector('[data-tab-btn="psoar-playbooks"]');
    if (btn) btn.addEventListener('click', function () { setTimeout(init, 60); });
  });
}());
