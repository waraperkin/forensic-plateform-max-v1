/*
  SAGF — console de gouvernance adossée.

  Onglet AUTONOME, volontairement séparé de la Sekoia Extended Platform : SAGF
  n'est pas une vue du SIEM, c'est une couche qui s'y adosse. Les mêler ferait
  croire qu'il en fait partie, ce que la Loi L8 (fidélité sémantique) interdit.

  Sept vues, couvrant l'intégralité du back :
    Conformité · Mécanismes · SAGQL · Mémoire · Dette & Risque · Journal · Miroir

  Trois principes de rendu, hérités du document 12 :
  - le VERDICT avant le chiffre — un nombre sans lecture n'aide personne ;
  - la FRAÎCHEUR et l'INCERTITUDE à côté de la valeur, jamais en note ;
  - les LIMITES visibles sans avoir à les chercher.
*/
(function () {
  'use strict';

  const API = '/api/threat/sagf';

  const VIEWS = [
    ['compliance', 'sg.v_compliance'],
    ['mechanisms', 'sg.v_mechanisms'],
    ['sagql', 'sg.v_sagql'],
    ['memory', 'sg.v_memory'],
    ['debt', 'sg.v_debt'],
    ['feedback', 'sg.v_feedback'],
    ['conflicts', 'sg.v_conflicts'],
    ['code', 'sg.v_code'],
    ['economics', 'sg.v_eco'],
    ['efficacy', 'sg.v_eff'],
    ['adversary', 'sg.v_adv'],
    ['twin', 'sg.v_twin'],
    ['harness', 'sg.v_har'],
    ['insurance', 'sg.v_ins'],
    ['journal', 'sg.v_journal'],
    ['mirror', 'sg.v_mirror'],
  ];

  const st = {
    view: 'compliance', loading: false, error: null, data: {},
    query: 'SELECT Rule WHERE verdict = "jamais_satisfiable"',
    nlq: 'montre-moi les règles inertes',
    since: '', mounted: false,
  };

  // ── Utilitaires ───────────────────────────────────────────────────────────
  function T(key, vars) {
    if (window.i18n && typeof i18n.t === 'function') {
      const out = i18n.t('swb.' + key, vars);
      if (out && out !== 'swb.' + key) return out;
    }
    return key;
  }
  function esc(v) {
    return String(v === null || v === undefined ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
  function nf(n) {
    if (n === null || n === undefined || n === '') return '—';
    const v = Number(n);
    return Number.isFinite(v) ? v.toLocaleString(
      (window.i18n && i18n.getLanguage && i18n.getLanguage() === 'en') ? 'en-US' : 'fr-FR')
      : String(n);
  }
  function pill(text, tone, flat) {
    return `<span class="swb-pill swb-pill-${tone || 'mute'}${flat ? ' swb-pill-flat' : ''}">${esc(text)}</span>`;
  }
  function kpi(label, value, tone, hint) {
    return `<div class="swb-kpi swb-kpi-${tone || 'ok'}"><div class="swb-kpi-value">${value}</div>
      <div class="swb-kpi-label">${esc(label)}</div>
      ${hint ? `<div class="swb-kpi-hint">${esc(hint)}</div>` : ''}</div>`;
  }
  function panel(title, body, tone) {
    return `<div class="swb-panel"${tone ? ` style="border-left:3px solid var(--swb-${tone})"` : ''}>
      ${title ? `<div class="swb-panel-head"><h3 class="swb-panel-title">${esc(title)}</h3></div>` : ''}
      ${body}</div>`;
  }

  async function api(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    if (o.body && typeof o.body !== 'string') {
      o.body = JSON.stringify(o.body);
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
    }
    // Délai navigateur : jamais de squelette éternel (voir QA 04/08/2026).
    if (!o.signal && typeof AbortSignal !== 'undefined' && AbortSignal.timeout) {
      o.signal = AbortSignal.timeout(Number(window.THREAT_FETCH_TIMEOUT_MS || 180000));
    }
    let r;
    try {
      r = await fetch(API + path, o);
    } catch (e) {
      if (e && (e.name === 'TimeoutError' || e.name === 'AbortError')) {
        throw new Error('Délai dépassé (3 min). Le calcul se poursuit côté serveur — réessayez dans un instant.');
      }
      throw e;
    }
    const d = await r.json().catch(() => ({}));
    if (!r.ok && d && d.error) throw new Error(d.error);
    return d;
  }

  // ── Vue : conformité ──────────────────────────────────────────────────────
  function viewCompliance() {
    const c = st.data.compliance || {};
    const r = st.data.report || {};
    const laws = st.data.laws || {};

    const checks = [
      ['L3', T('sg.l3'), c.L3 && c.L3.reversible, c.L3 && c.L3.verdict, c.L3 && c.L3.refutation],
      ['L8', T('sg.l8'), c.L8 && c.L8.faithful, c.L8 && c.L8.verdict, c.L8 && c.L8.refutation],
      ['L11', T('sg.l11'), c.L11 && c.L11.aligned, c.L11 && c.L11.verdict, c.L11 && c.L11.refutation],
      ['I11', T('sg.i11'), c.I11 && c.I11.separated, c.I11 && c.I11.verdict, c.I11 && c.I11.refutation],
    ];

    const rows = checks.map(([id, label, ok, verdict, refut]) => `<tr>
      <td style="width:3.5rem"><span class="swb-mono">${esc(id)}</span></td>
      <td>${esc(label)}<div class="swb-hint">${esc(verdict || '')}</div></td>
      <td style="width:7rem">${ok === undefined ? '<span class="swb-hint">—</span>'
        : ok ? pill(T('sg.verified'), 'ok') : pill(T('sg.violated'), 'danger')}</td>
      <td class="swb-hint swb-truncate" title="${esc(refut || '')}">${esc(refut || '')}</td>
    </tr>`).join('');

    // Les douze lois et treize invariants, avec l'endroit où chacun est porté.
    const lawRows = (r.laws || []).map((l) => `<tr>
      <td><span class="swb-mono">${esc(l.id)}</span></td>
      <td>${l.enforced === 'code' ? pill(T('sg.by_code'), 'ok') : pill(esc(l.enforced), 'warn')}</td>
      <td class="swb-hint swb-truncate" title="${esc(l.where)}">${esc(l.where)}</td>
    </tr>`).join('');
    const invRows = (r.invariants || []).map((i) => `<tr>
      <td><span class="swb-mono">${esc(i.id)}</span></td>
      <td class="swb-truncate" title="${esc(i.name)}">${esc(i.name)}</td>
      <td>${i.enforced === 'code' ? pill(T('sg.by_code'), 'ok') : pill(esc(i.enforced), 'warn')}</td>
      <td class="swb-hint swb-truncate" title="${esc(i.where)}">${esc(i.where)}</td>
    </tr>`).join('');

    return `${kpis(r)}
      ${panel(T('sg.compliance'), `<p class="swb-hint" style="margin:.2rem 0 .6rem">${T('sg.compliance_sub')}</p>
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          <th>#</th><th>${T('sg.control')}</th><th>${T('sg.state')}</th><th>${T('sg.refutation')}</th>
        </tr></thead><tbody>${rows}</tbody></table></div>`)}
      ${limitsBlock(r)}
      ${panel(T('sg.sovereignty'), `<div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          <th style="width:50%">${T('sg.sekoia_owns')}</th><th>${T('sg.sagf_owns')}</th></tr></thead>
        <tbody><tr>
          <td>${(laws.sekoia_owned || []).map((x) => `<span class="swb-pill swb-pill-mute swb-pill-flat">${esc(x)}</span>`).join(' ')}</td>
          <td>${(laws.sagf_owned || []).map((x) => `<span class="swb-pill swb-pill-ok swb-pill-flat">${esc(x)}</span>`).join(' ')}</td>
        </tr></tbody></table></div>
        <p class="swb-hint" style="margin:.5rem 0 0">${T('sg.sovereignty_note')}</p>`)}
      <div class="swb-panel" style="padding:0"><div class="swb-panel-head" style="padding:.8rem .9rem 0">
        <h3 class="swb-panel-title">${T('sg.laws')}</h3></div>
        <div class="swb-tablewrap" style="max-height:26vh"><table class="swb-table"><thead><tr>
          <th>#</th><th>${T('sg.enforced')}</th><th>${T('sg.where')}</th></tr></thead>
          <tbody>${lawRows}</tbody></table></div></div>
      <div class="swb-panel" style="padding:0"><div class="swb-panel-head" style="padding:.8rem .9rem 0">
        <h3 class="swb-panel-title">${T('sg.invariants')}</h3></div>
        <div class="swb-tablewrap" style="max-height:30vh"><table class="swb-table"><thead><tr>
          <th>#</th><th>${T('sg.name')}</th><th>${T('sg.enforced')}</th><th>${T('sg.where')}</th></tr></thead>
          <tbody>${invRows}</tbody></table></div></div>`;
  }

  function kpis(r) {
    const b = r.budget || {};
    return `<div class="swb-kpis">
      ${kpi(T('sg.k_mech'), `${nf(r.mechanisms_implemented)}/${nf(r.mechanisms_total)}`,
        (r.mechanisms_missing || []).length ? 'warn' : 'ok')}
      ${kpi(T('sg.k_laws'), `${nf(12 - (r.laws_not_code_enforced || []).length)}/12`,
        (r.laws_not_code_enforced || []).length ? 'warn' : 'ok', T('sg.k_laws_h'))}
      ${kpi(T('sg.k_inv'), `${nf(13 - (r.invariants_not_fully_enforced || []).length)}/13`,
        (r.invariants_not_fully_enforced || []).length ? 'warn' : 'ok', T('sg.k_inv_h'))}
      ${kpi(T('sg.k_budget'), `${nf(b.remaining)}/${nf(b.per_hour)}`, 'ok', T('sg.k_budget_h'))}
    </div>`;
  }

  // Les limites sont montrées AVANT tout tableau flatteur. Un écran qui affiche
  // « 20/20 » sans elles se lit comme une promesse de perfection.
  function limitsBlock(r) {
    const lim = r.always_limited || {};
    if (!Object.keys(lim).length) return '';
    return `<div class="swb-panel" style="border-left:3px solid var(--swb-warn)">
      <div class="swb-panel-head"><h3 class="swb-panel-title">${T('sg.limits')}</h3></div>
      <p class="swb-hint" style="margin:.2rem 0 .5rem">${T('sg.limits_sub')}</p>
      <ul style="margin:0;padding-left:1.1rem">${Object.entries(lim).map(([k, v]) =>
        `<li class="swb-hint"><span class="swb-mono">${esc(k)}</span> — ${esc(Array.isArray(v) ? v.join(', ') : v)}</li>`).join('')}</ul></div>`;
  }

  // ── Vue : mécanismes ──────────────────────────────────────────────────────
  function viewMechanisms() {
    const m = st.data.mechanisms || {};
    const items = m.implemented || [];
    const on = items.filter((x) => x.implemented).length;
    return `<div class="swb-kpis">
        ${kpi(T('sg.k_mech'), `${nf(on)}/${nf(items.length)}`, on === items.length ? 'ok' : 'warn')}
        ${kpi(T('sg.k_delegating'), nf(items.filter((x) => x.delegates_to).length), 'ok', T('sg.k_delegating_h'))}
        ${kpi(T('sg.k_cost'), nf(items.reduce((a, x) => a + (x.cost_units || 0), 0)), 'ok', T('sg.k_cost_h'))}
        ${kpi(T('sg.k_refutable'), `${nf(items.filter((x) => x.refutation).length)}/${nf(items.length)}`, 'ok', T('sg.k_refutable_h'))}
      </div>
      ${panel('', `<p class="swb-hint" style="margin:0">${esc(m.note || '')}</p>`, 'accent')}
      <div class="swb-panel" style="padding:0">
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          <th>${T('sg.state')}</th><th>#</th><th>${T('sg.name')}</th>
          <th>${T('sg.input')}</th><th>${T('sg.output')}</th>
          <th>${T('sg.delegates')}</th><th>${T('sg.guarantee')}</th><th>${T('sg.refutation')}</th>
        </tr></thead><tbody>${items.map((x) => `<tr>
          <td>${x.implemented ? pill(T('sg.on'), 'ok') : pill(T('sg.off'), 'mute')}</td>
          <td><span class="swb-mono">${esc(x.code)}</span></td>
          <td class="swb-truncate" title="${esc(x.name)}">${esc(x.name)}</td>
          <td class="swb-hint swb-truncate" title="${esc(x.inputs)}">${esc(x.inputs)}</td>
          <td class="swb-hint swb-truncate" title="${esc(x.outputs)}">${esc(x.outputs)}</td>
          <td class="swb-hint swb-truncate">${esc(x.delegates_to || '—')}</td>
          <td class="swb-hint swb-truncate" title="${esc(x.guarantee)}">${esc(x.guarantee)}</td>
          <td class="swb-hint swb-truncate" title="${esc(x.refutation)}">${esc(x.refutation)}</td>
        </tr>`).join('')}</tbody></table></div></div>`;
  }

  // ── Vue : SAGQL ───────────────────────────────────────────────────────────
  function viewSagql() {
    const q = st.data.query;
    const nl = st.data.nl;
    const fam = (st.data.report || {}).predicates_missing_or_partial || [];

    let result = '';
    if (q && q.ok === false) {
      result = `<div class="swb-panel" style="border-left:3px solid var(--swb-danger)">
        <p style="margin:0"><strong>${T('sg.refused')}</strong> ${esc(q.error)}</p>
        ${q.hint ? `<p class="swb-hint swb-mono" style="margin:.3rem 0 0">${esc(q.hint)}</p>` : ''}
        <p class="swb-hint" style="margin:.3rem 0 0">${T('sg.refuse_note')}</p></div>`;
    } else if (q) {
      const e = q.explain || {};
      result = `<div class="swb-panel" style="border-left:3px solid var(--swb-accent)">
        <p class="swb-hint" style="margin:0">${T('sg.cost', { n: nf(e.cost_units), b: nf(e.budget_remaining) })}
          · ${esc(e.source || '')} · ${T('sg.limit')} ${nf(e.limit)}</p>
        ${(e.predicates || []).length ? `<p class="swb-hint" style="margin:.3rem 0 0">${
          e.predicates.map((p) => `<span class="swb-pill swb-pill-mute swb-pill-flat">${
            esc(p.family)}${p.field ? ' · ' + esc(p.field) : ''}</span>`).join(' ')}</p>` : ''}
        ${q.shape ? `<p class="swb-hint swb-mono" style="margin:.4rem 0 0">${
          T('sg.tree')} ${esc(q.shape.tree)}</p>
          <p class="swb-hint" style="margin:.2rem 0 0">${esc(q.shape.note)}</p>` : ''}
        ${q.executed ? `<p style="margin:.5rem 0 0"><strong>${nf(q.matched)}</strong> ${
            T('sg.matched', { n: nf(q.scanned) })}</p>
          <p class="swb-hint swb-mono" style="margin:.2rem 0 0">${
            esc(((q.provenance || {}).chain || []).join(' ← '))}</p>
          ${q.grouped ? `<p class="swb-hint" style="margin:.3rem 0 0">${
              T('sg.groups', { g: nf(q.groups), a: nf(q.absent_rows) })}</p>
            <p class="swb-hint" style="margin:.2rem 0 0">${esc(q.note || '')}</p>
            <div class="swb-tablewrap" style="max-height:34vh;margin-top:.5rem"><table class="swb-table"><tbody>
              ${(q.items || []).map((g) => `<tr>
                <td class="swb-truncate swb-mono" title="${esc(Object.values(g.key).join(' · '))}">${esc(Object.values(g.key).join(' · '))}</td>
                <td style="text-align:right"><strong>${nf(g.count)}</strong></td>
              </tr>`).join('')}</tbody></table></div>`
          : `<div class="swb-tablewrap" style="max-height:34vh;margin-top:.5rem"><table class="swb-table"><tbody>
            ${(q.items || []).slice(0, 60).map((it) => `<tr>
              <td class="swb-truncate" title="${esc(it.rule_name || it.intake_name || it.field || it.dialect_uuid || '—')}">${esc(it.rule_name || it.intake_name || it.field || it.dialect_uuid || '—')}</td>
              <td class="swb-hint swb-truncate">${esc(it.verdict || it.intake_status || it.reason || '')}</td>
            </tr>`).join('')}</tbody></table></div>`}`
          : `<p class="swb-hint" style="margin:.4rem 0 0">${T('sg.not_executed')}</p>`}</div>`;
    }

    const nlBlock = !nl ? '' : (nl.ok
      ? `<div class="swb-panel" style="border-left:3px solid var(--swb-ok)">
          <p style="margin:0"><span class="swb-mono">${esc(nl.sagql)}</span></p>
          <p class="swb-hint" style="margin:.3rem 0 0">${esc(nl.note)}</p></div>`
      : `<div class="swb-panel" style="border-left:3px solid var(--swb-warn)">
          <p style="margin:0"><strong>${T('sg.refused')}</strong> ${esc(nl.reason)}</p>
          ${(nl.readings || []).length ? `<p class="swb-hint" style="margin:.3rem 0 0">${
            T('sg.readings')} ${nl.readings.map((r) => `<span class="swb-mono">${esc(r)}</span>`).join(' · ')}</p>` : ''}
          ${nl.note ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(nl.note)}</p>` : ''}</div>`);

    return `${panel(T('sg.console'), `
        <div class="swb-filters">
          <input class="swb-input swb-search" id="sagf-q" style="flex:1"
            placeholder="SELECT Rule WHERE a = 1 AND (b = 2 OR c = 3) GROUP BY …" value="${esc(st.query)}">
          <button type="button" class="fp-btn fp-btn-sm" data-sagf-act="explain">${T('sg.explain')}</button>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-sagf-act="run">${T('sg.run')}</button>
        </div>
        <p class="swb-hint" style="margin:.4rem 0 0">${T('sg.console_sub')}</p>`)}
      ${result}
      ${panel(T('sg.nl'), `
        <div class="swb-filters">
          <input class="swb-input swb-search" id="sagf-nl" style="flex:1"
            placeholder="${T('sg.nl_ph')}" value="${esc(st.nlq)}">
          <button type="button" class="fp-btn fp-btn-sm" data-sagf-act="nl">${T('sg.translate')}</button>
        </div>
        <p class="swb-hint" style="margin:.4rem 0 0">${T('sg.nl_sub')}</p>`)}
      ${nlBlock}
      ${panel(T('sg.families'), `<p class="swb-hint" style="margin:0 0 .4rem">${T('sg.families_sub')}</p>
        ${fam.map((f) => `<div class="swb-hint" style="margin:.2rem 0">
          <span class="swb-pill swb-pill-warn swb-pill-flat">${esc(f.family)}</span> ${esc(f.state)}</div>`).join('')
          || `<p class="swb-hint" style="margin:0">${T('sg.families_all')}</p>`}`)}`;
  }

  // ── Vue : mémoire de configuration ────────────────────────────────────────
  function viewMemory() {
    const rec = st.data.reconcile;
    const dif = st.data.diff;
    const snap = st.data.snapshot;
    return `${panel(T('sg.memory'), `<p class="swb-hint" style="margin:0 0 .6rem">${T('sg.memory_sub')}</p>
        <div class="swb-filters">
          <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-sagf-act="snapshot">${T('sg.snapshot')}</button>
          <button type="button" class="fp-btn fp-btn-sm" data-sagf-act="reconcile">${T('sg.reconcile')}</button>
          <input class="swb-input" id="sagf-since" style="max-width:15rem"
            placeholder="2026-08-01T00:00:00.000Z" value="${esc(st.since)}">
          <button type="button" class="fp-btn fp-btn-sm" data-sagf-act="diff">${T('sg.diff')}</button>
        </div>`)}
      ${!snap ? '' : panel('', `<p style="margin:0">${T('sg.snapshot_done', {
          w: nf(snap.written), u: nf(snap.unchanged) })}</p>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(snap.idempotent_note || '')}</p>`, 'ok')}
      ${!rec ? '' : panel(T('sg.reconcile'), `
        <div class="swb-kpis">
          ${kpi(T('sg.upstream'), nf(rec.upstream), 'ok')}
          ${kpi(T('sg.in_memory'), nf(rec.in_memory), 'ok')}
          ${kpi(T('sg.only_memory'), nf(rec.only_memory), rec.only_memory ? 'danger' : 'ok', T('sg.only_memory_h'))}
          ${kpi(T('sg.coherent'), rec.coherent ? T('sg.yes') : T('sg.no'), rec.coherent ? 'ok' : 'danger')}
        </div>
        <p class="swb-hint" style="margin:.4rem 0 0">${esc(rec.verdict)}</p>`)}
      ${!dif ? '' : (dif.available === false
        ? panel(T('sg.diff'), `<p class="swb-hint" style="margin:0">${esc(dif.reason || '')}</p>`)
        : panel(T('sg.diff'), `<div class="swb-kpis">
            ${kpi(T('sg.added'), nf(dif.added), 'ok')}
            ${kpi(T('sg.removed'), nf(dif.removed), dif.removed ? 'warn' : 'ok')}
            ${kpi(T('sg.changed'), nf(dif.changed), dif.changed ? 'warn' : 'ok')}
          </div>
          <p class="swb-hint" style="margin:.4rem 0 0">${esc(dif.silent_note || '')}</p>
          ${((dif.items || {}).changed || []).length ? `<div class="swb-tablewrap" style="max-height:28vh;margin-top:.5rem">
            <table class="swb-table"><tbody>${dif.items.changed.slice(0, 40).map((c) => `<tr>
              <td class="swb-mono swb-truncate">${esc(c.object_id)}</td>
              <td class="swb-hint swb-truncate">${esc(Object.keys(c.changes || {}).join(', '))}</td>
            </tr>`).join('')}</tbody></table></div>` : ''}`))}`;
  }

  // ── Vue : dette & risque ──────────────────────────────────────────────────
  function viewDebt() {
    const d = st.data.debt;
    const rk = st.data.risk;
    if (!d && !rk) {
      return panel('', `<p class="swb-hint" style="margin:0">${T('sg.debt_idle')}</p>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" style="margin-top:.5rem"
          data-sagf-act="debt">${T('sg.compute')}</button>`);
    }
    const m = (d || {}).measure || {};
    return `${!d ? '' : `<div class="swb-kpis">
        ${kpi(T('sg.k_debt'), nf(d.total), d.total > 100 ? 'danger' : 'warn', T('sg.k_debt_h'))}
        ${(d.components || []).map((c) => kpi(esc(c.code), nf(c.count), 'mute',
          `× ${esc(c.weight)} = ${nf(c.count * c.weight)}`)).join('')}
      </div>
      ${panel('', `<p class="swb-hint" style="margin:0">${esc(d.note)}</p>
        <p class="swb-hint" style="margin:.3rem 0 0"><strong>${T('sg.refutation')} :</strong> ${esc(d.refutation)}</p>
        ${m.at ? `<p class="swb-hint" style="margin:.3rem 0 0">${T('sg.measured', {
          a: nf(m.age_s), u: esc(Math.round((m.uncertainty || 0) * 10) / 10) })}
          ${m.stale ? pill(T('sg.stale'), 'danger') : pill(T('sg.fresh'), 'ok')}</p>` : ''}`, 'accent')}
      ${(d.reducible_now || []).length ? panel(T('sg.reducible'), `
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          <th>${T('sg.field')}</th><th class="swb-num">${T('sg.rules_recovered')}</th>
          <th class="swb-num">${T('sg.debt_cut')}</th></tr></thead><tbody>
          ${d.reducible_now.map((x) => `<tr><td><span class="swb-mono">${esc(x.field)}</span></td>
            <td class="swb-num"><strong>${nf(x.rules_recovered)}</strong></td>
            <td class="swb-num">${nf(x.debt_reduction)}</td></tr>`).join('')}
        </tbody></table></div>`) : ''}`}
      ${!rk ? '' : panel(T('sg.risk'), `
        <p class="swb-hint" style="margin:0 0 .4rem"><strong>${T('sg.caution')} :</strong> ${esc(rk.caution)}</p>
        <div class="swb-tablewrap" style="max-height:30vh"><table class="swb-table"><thead><tr>
          <th>${T('sg.name')}</th><th class="swb-num">${T('sg.severity')}</th><th>${T('sg.reason')}</th>
        </tr></thead><tbody>${(rk.items || []).slice(0, 40).map((x) => `<tr>
          <td class="swb-truncate" title="${esc(x.rule_name)}">${esc(x.rule_name)}</td>
          <td class="swb-num">${pill(String(x.severity), x.severity >= 80 ? 'danger' : 'warn', true)}</td>
          <td class="swb-hint swb-truncate">${esc(x.reason)}</td></tr>`).join('')}
        </tbody></table></div>`)}
      <div class="swb-filters"><button type="button" class="fp-btn fp-btn-sm" data-sagf-act="debt">${T('sg.recompute')}</button></div>`;
  }

  // ── Vue : journal (M-15) ──────────────────────────────────────────────────
  function viewJournal() {
    const j = st.data.journal || {};
    const items = j.items || [];
    return `${panel(T('sg.journal'), `<p class="swb-hint" style="margin:0 0 .6rem">${T('sg.journal_sub')}</p>
        <div class="swb-filters">
          <input class="swb-input" id="sagf-jref" style="max-width:14rem" placeholder="${T('sg.object_ref')}">
          <select class="swb-select" id="sagf-jkind">
            <option value="decision">${T('sg.kind_decision')}</option>
            <option value="note">${T('sg.kind_note')}</option>
            <option value="evidence">${T('sg.kind_evidence')}</option>
            <option value="dispute">${T('sg.kind_dispute')}</option>
          </select>
          <input class="swb-input" id="sagf-jauthor" style="max-width:10rem" placeholder="${T('sg.author')}">
          <input class="swb-input swb-search" id="sagf-jtext" style="flex:1" placeholder="${T('sg.reason')}">
          <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-sagf-act="journal-add">${T('sg.record')}</button>
        </div>
        <p class="swb-hint" style="margin:.4rem 0 0">${T('sg.journal_attr')}</p>`)}
      ${st.data.journalErr ? panel('', `<p class="swb-hint" style="margin:0">${esc(st.data.journalErr)}</p>`, 'danger') : ''}
      <div class="swb-panel" style="padding:0"><div class="swb-tablewrap" style="max-height:44vh">
        <table class="swb-table"><thead><tr>
          <th>${T('sg.when')}</th><th>${T('sg.object_ref')}</th><th>${T('sg.kind')}</th>
          <th>${T('sg.author')}</th><th>${T('sg.reason')}</th><th>${T('sg.text')}</th>
        </tr></thead><tbody>${items.map((e) => `<tr>
          <td class="swb-hint">${esc((e.at || '').slice(0, 19).replace('T', ' '))}</td>
          <td class="swb-mono swb-truncate">${esc(e.object_ref)}</td>
          <td>${pill(esc(e.kind), 'mute', true)}</td>
          <td class="swb-truncate" title="${esc(e.author)}">${esc(e.author)}</td>
          <td class="swb-hint swb-truncate">${esc(e.reason)}</td>
          <td class="swb-truncate" title="${esc(e.text)}">${esc(e.text)}</td></tr>`).join('')
          || `<tr><td colspan="6"><p class="swb-hint" style="padding:1rem">${T('sg.journal_empty')}</p></td></tr>`}
        </tbody></table></div></div>`;
  }

  // ── Vue : miroir (I13) ────────────────────────────────────────────────────
  function viewMirror() {
    const r = st.data.report || {};
    const list = (title, items, tone) => panel(title,
      `<ul style="margin:0;padding-left:1.1rem">${(items || []).map((x) =>
        `<li class="swb-hint">${esc(typeof x === 'string' ? x
          : (x.code ? `${x.code} — ${x.name}` : (x.family ? `${x.family} — ${x.state}`
            : (x.dep ? `${x.dep} — ${x.why}` : JSON.stringify(x)))))}</li>`).join('')
        || `<li class="swb-hint">${T('sg.none')}</li>`}</ul>`, tone);
    return `${panel('', `<p style="margin:0"><strong>${T('sg.mirror_head')}</strong></p>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(r.honesty_note || '')}</p>`, 'warn')}
      ${limitsBlock(r)}
      ${list(T('sg.mech_missing'), r.mechanisms_missing, 'mute')}
      ${list(T('sg.pred_partial'), r.predicates_missing_or_partial, 'mute')}
      ${list(T('sg.modules_partial'), r.modules_partial, 'mute')}
      ${list(T('sg.inv_gaps'), (r.invariants_not_fully_enforced || []).map((i) => `${i.id} — ${i.name}`), 'mute')}
      ${list(T('sg.law_gaps'), (r.laws_not_code_enforced || []).map((l) => `${l.id} — ${l.where}`), 'mute')}
      ${list(T('sg.deps'), r.unverified_dependencies, 'mute')}
      ${panel(T('sg.stale_measures'), `<p class="swb-hint" style="margin:0">${
        T('sg.stale_count', { n: nf(r.measures_stale), t: nf(r.measures_total) })}</p>`)}`;
  }


  // ── Vue : retour analyste (LOT 1) ─────────────────────────────────────────
  function viewFeedback() {
    const cov = st.data.fbCoverage;
    const rates = st.data.fbRates;
    const codes = (st.data.fbCodes || {}).codes || {};
    const err = st.data.fbErr;

    // La couverture de qualification passe AVANT les taux : une précision
    // calculée sur 2 % des alertes décrit l'échantillon, pas la règle.
    const covBlock = !cov ? '' : `<div class="swb-panel" style="border-left:3px solid ${
      cov.usable ? 'var(--swb-ok)' : 'var(--swb-warn)'}">
      <div class="swb-panel-head"><h3 class="swb-panel-title">${T('sg.fb_coverage')}</h3>
        ${pill(`${esc(cov.coverage_pct)} %`, cov.usable ? 'ok' : 'warn', true)}</div>
      <p style="margin:.3rem 0 0">${esc(cov.verdict)}</p>
      <p class="swb-hint" style="margin:.3rem 0 0">${T('sg.fb_coverage_sub', {
        q: nf(cov.alerts_qualified), s: nf(cov.alerts_seen) })}</p></div>`;

    const rows = ((rates || {}).items || []).map((r) => {
      const p = r.precision || {};
      return `<tr>
        <td class="swb-truncate" title="${esc(r.rule_ref || r.rule_uuid || r.analyst || '—')}">${esc(r.rule_ref || r.rule_uuid || r.analyst || '—')}</td>
        <td class="swb-num">${nf(r.verdicts)}</td>
        <td class="swb-num">${nf(r.true_positive)}</td>
        <td class="swb-num">${nf(r.false_positive)}</td>
        <td class="swb-num swb-hint">${nf(r.neutral)}</td>
        <td>${p.publishable
          ? `<strong>${esc(p.point)} %</strong> <span class="swb-hint">[${esc(p.low)}–${esc(p.high)}]</span>`
          : `<span class="swb-hint">${esc(p.reason || '—')}</span>`}</td>
        <td class="swb-num swb-hint">${r.median_time_s === null ? '—' : nf(r.median_time_s) + ' s'}</td>
      </tr>`;
    }).join('');

    return `${covBlock}
      ${panel(T('sg.fb_submit'), `
        <div class="swb-filters">
          <input class="swb-input" id="fb-alert" style="max-width:12rem" placeholder="${T('sg.fb_alert')}">
          <input class="swb-input" id="fb-rule" style="flex:1" placeholder="${T('sg.fb_rule')}">
          <select class="swb-select" id="fb-code">
            ${Object.entries(codes).map(([k, v]) =>
              `<option value="${esc(k)}">${esc(k)} — ${esc(v)}</option>`).join('')}
          </select>
          <input class="swb-input" id="fb-analyst" style="max-width:9rem" placeholder="${T('sg.author')}">
          <input class="swb-input" id="fb-time" style="max-width:7rem" placeholder="${T('sg.fb_time')}">
          <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-sagf-act="fb-send">${T('sg.record')}</button>
        </div>
        <p class="swb-hint" style="margin:.4rem 0 0">${T('sg.fb_submit_sub')}</p>`)}
      ${err ? panel('', `<p style="margin:0">${esc(err)}</p>`, 'danger') : ''}
      ${panel('', `<p class="swb-hint" style="margin:0">${esc((rates || {}).note || '')}</p>
        <p class="swb-hint" style="margin:.3rem 0 0"><strong>${T('sg.refutation')} :</strong> ${
          esc((rates || {}).refutation || '')}</p>`, 'accent')}
      <div class="swb-panel" style="padding:0">
        <div class="swb-panel-head" style="padding:.8rem .9rem 0">
          <h3 class="swb-panel-title">${T('sg.fb_rates')}</h3>
          <div class="swb-filters" style="margin:0">
            ${['rule_ref', 'rule_uuid', 'analyst'].map((b) => `<button type="button"
              class="fp-btn fp-btn-sm${(st.fbBy || 'rule_ref') === b ? ' fp-btn-primary' : ''}"
              data-sagf-act="fb-by" data-by="${b}">${esc(b)}</button>`).join('')}
          </div></div>
        <div class="swb-tablewrap" style="max-height:38vh"><table class="swb-table"><thead><tr>
          <th>${T('sg.fb_group')}</th><th class="swb-num">${T('sg.fb_verdicts')}</th>
          <th class="swb-num">VP</th><th class="swb-num">FP</th>
          <th class="swb-num">${T('sg.fb_neutral')}</th>
          <th>${T('sg.fb_precision')}</th><th class="swb-num">${T('sg.fb_median')}</th>
        </tr></thead><tbody>${rows || `<tr><td colspan="7">
          <p class="swb-hint" style="padding:1rem">${T('sg.fb_empty')}</p></td></tr>`}
        </tbody></table></div></div>`;
  }

  // ── Vue : conflits (LOT 3) ────────────────────────────────────────────────
  function viewConflicts() {
    const c = st.data.conflicts;
    if (!c) {
      return panel('', `<p class="swb-hint" style="margin:0">${T('sg.cf_idle')}</p>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" style="margin-top:.5rem"
          data-sagf-act="cf-run">${T('sg.compute')}</button>`);
    }
    const rel = c.by_relation || {};
    const tone = { critique: 'danger', haute: 'danger', moyenne: 'warn', basse: 'mute' };

    // La troncature est annoncée AVANT les chiffres : une analyse incomplète
    // présentée comme complète serait trompeuse.
    const trunc = c.truncated ? `<div class="swb-panel" style="border-left:3px solid var(--swb-danger)">
      <p style="margin:0"><strong>${T('sg.cf_truncated')}</strong></p>
      <p class="swb-hint" style="margin:.3rem 0 0">${esc(c.truncation_note || '')}</p></div>` : '';

    const rows = (c.items || []).slice(0, 120).map((f) => `<tr>
      <td>${pill(T('sg.cf_' + f.relation), tone[f.severity] || 'mute')}</td>
      <td>${f.both_enabled ? pill(T('sg.cf_both_on'), 'danger', true) : '<span class="swb-hint">—</span>'}</td>
      <td class="swb-truncate" title="${esc(f.a.rule_name)}">${esc(f.a.rule_name)}</td>
      <td class="swb-truncate" title="${esc(f.b.rule_name)}">${esc(f.b.rule_name)}</td>
      <td class="swb-hint swb-truncate" title="${esc(f.detail)}">${esc(f.detail)}</td>
      <td class="swb-hint swb-mono swb-truncate">${esc((f.shared || []).slice(0, 2)
        .map((x) => Array.isArray(x) ? x.filter(Boolean).join(':') : x).join(' · '))}</td>
    </tr>`).join('');

    return `${trunc}
      <div class="swb-kpis">
        ${kpi(T('sg.cf_contradiction'), nf(rel.contradiction || 0), rel.contradiction ? 'danger' : 'ok', T('sg.cf_contradiction_h'))}
        ${kpi(T('sg.cf_identique'), nf(rel.identique || 0), rel.identique ? 'warn' : 'ok', T('sg.cf_identique_h'))}
        ${kpi(T('sg.cf_subsomption'), nf(rel.subsomption || 0), 'mute')}
        ${kpi(T('sg.cf_both'), nf(c.findings_both_enabled), c.findings_both_enabled ? 'warn' : 'ok', T('sg.cf_both_h'))}
      </div>
      ${panel('', `<p style="margin:0"><strong>${esc(c.headline)}</strong></p>
        <p class="swb-hint" style="margin:.4rem 0 0">${esc(c.method_note)}</p>
        <p class="swb-hint" style="margin:.3rem 0 0"><strong>${T('sg.refutation')} :</strong> ${esc(c.refutation)}</p>
        <p class="swb-hint" style="margin:.3rem 0 0"><strong>${T('sg.cf_no_merge')}</strong> ${esc(c.no_auto_merge)}</p>`, 'accent')}
      <div class="swb-filters">
        ${['', 'contradiction', 'identique', 'subsomption', 'recouvrement'].map((r) => `<button
          type="button" class="fp-btn fp-btn-sm${(st.cfRel || '') === r ? ' fp-btn-primary' : ''}"
          data-sagf-act="cf-filter" data-rel="${r}">${r ? T('sg.cf_' + r) : T('sg.cf_all')}</button>`).join('')}
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-sagf-act="cf-run">${T('sg.recompute')}</button>
      </div>
      <div class="swb-panel" style="padding:0">
        <div class="swb-tablewrap" style="max-height:40vh"><table class="swb-table"><thead><tr>
          <th>${T('sg.cf_relation')}</th><th>${T('sg.state')}</th>
          <th>${T('sg.cf_rule_a')}</th><th>${T('sg.cf_rule_b')}</th>
          <th>${T('sg.cf_detail')}</th><th>${T('sg.cf_shared')}</th>
        </tr></thead><tbody>${rows || `<tr><td colspan="6">
          <p class="swb-hint" style="padding:1rem">${T('sg.cf_none')}</p></td></tr>`}
        </tbody></table></div></div>
      ${(c.unreadable || []).length ? panel(T('sg.cf_unreadable'), `
        <p class="swb-hint" style="margin:0 0 .4rem">${T('sg.cf_unreadable_sub', { n: nf(c.rules_unreadable) })}</p>
        <div class="swb-tablewrap" style="max-height:20vh"><table class="swb-table"><tbody>
          ${c.unreadable.slice(0, 30).map((u) => `<tr>
            <td class="swb-truncate" title="${esc(u.rule_name)}">${esc(u.rule_name)}</td>
            <td class="swb-hint swb-truncate">${esc(u.reason)}</td></tr>`).join('')}
        </tbody></table></div>`) : ''}`;
  }


  // ── Vue : détection-as-code (LOT 2) ───────────────────────────────────────
  function viewCode() {
    const e = st.data.dacExport;
    const p = st.data.dacPlan;
    return `${panel(T('sg.dac_export'), `
        <p class="swb-hint" style="margin:0 0 .6rem">${T('sg.dac_export_sub')}</p>
        <div class="swb-filters">
          <select class="swb-select" id="dac-entity">
            <option value="rules">rules</option><option value="intakes">intakes</option>
          </select>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-sagf-act="dac-export">${T('sg.dac_do_export')}</button>
        </div>
        ${e ? `<div class="swb-kpis" style="margin-top:.6rem">
            ${kpi(T('sg.dac_objects'), nf(e.objects), 'ok')}
            ${kpi(T('sg.dac_size'), `${nf(Math.round((e.bytes || 0) / 1024))} Ko`, 'ok')}
            ${kpi(T('sg.dac_fingerprint'), `<span class="swb-mono" style="font-size:.8em">${esc((e.fingerprint || '').slice(0, 12))}…</span>`, 'ok', T('sg.dac_fingerprint_h'))}
          </div>
          <p class="swb-hint" style="margin:.4rem 0 0">${esc(e.note || '')}</p>
          <div class="swb-tablewrap" style="max-height:26vh;margin-top:.5rem">
            <pre class="swb-mono swb-hint" style="margin:0;white-space:pre-wrap;font-size:.78em">${
              esc((e.content || '').slice(0, 4000))}</pre></div>` : ''}`)}
      ${panel(T('sg.dac_plan'), `
        <p class="swb-hint" style="margin:0 0 .6rem">${T('sg.dac_plan_sub')}</p>
        <textarea class="swb-input" id="dac-target" rows="6" style="width:100%;font-family:monospace;font-size:.8em"
          placeholder="${T('sg.dac_paste')}"></textarea>
        <div class="swb-filters" style="margin-top:.5rem">
          <button type="button" class="fp-btn fp-btn-sm" data-sagf-act="dac-plan">${T('sg.dac_do_plan')}</button>
        </div>`)}
      ${!p ? '' : (p.ok === false
        ? `<div class="swb-panel" style="border-left:3px solid var(--swb-danger)">
            <p style="margin:0"><strong>${T('sg.refused')}</strong> ${esc(p.error)}</p></div>`
        : `<div class="swb-panel" style="border-left:3px solid var(--swb-accent)">
            <div class="swb-kpis">
              ${kpi(T('sg.dac_changes'), nf(p.changes), p.changes ? 'warn' : 'ok')}
              ${kpi(T('sg.dac_unchanged'), nf(p.unchanged), 'ok')}
              ${kpi(T('sg.dac_unknown'), nf(p.unknown), p.unknown ? 'warn' : 'ok', T('sg.dac_unknown_h'))}
            </div>
            <p class="swb-hint" style="margin:.4rem 0 0">${esc(p.note || '')}</p>
            <p class="swb-hint" style="margin:.3rem 0 0"><strong>${T('sg.refutation')} :</strong> ${esc(p.refutation || '')}</p>
            ${(p.items || []).length ? `<div class="swb-tablewrap" style="max-height:26vh;margin-top:.5rem">
              <table class="swb-table"><thead><tr><th>${T('sg.name')}</th>
                <th>${T('sg.dac_before')}</th><th>${T('sg.dac_after')}</th></tr></thead><tbody>
              ${p.items.slice(0, 60).map((it) => `<tr>
                <td class="swb-truncate" title="${esc(it.name || it.id)}">${esc(it.name || it.id)}</td>
                <td class="swb-hint swb-mono">${esc(JSON.stringify(it.before || {}))}</td>
                <td class="swb-mono">${esc(JSON.stringify(it.patch || {}))}</td>
              </tr>`).join('')}</tbody></table></div>` : ''}
            ${(p.unknown_items || []).length ? `<p class="swb-hint" style="margin:.4rem 0 0">
              ${T('sg.dac_unknown_note')}</p>` : ''}
          </div>`)}`;
  }


  // ── Vue : économie (LOT 9) ────────────────────────────────────────────────
  function viewEconomics() {
    const e = st.data.eco;
    if (!e) {
      return panel('', `<p class="swb-hint" style="margin:0">${T('sg.eco_idle')}</p>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" style="margin-top:.5rem"
          data-sagf-act="eco-run">${T('sg.compute')}</button>`);
    }
    if (e.available === false) {
      return panel('', `<p class="swb-hint" style="margin:0">${esc(e.reason || '')}</p>`);
    }
    const f = e.forecast || {};
    const a = e.arbitration;

    // La mise en garde sur l'unité passe AVANT les chiffres : un coût pris
    // pour une facture ferait décider sur une monnaie qui n'existe pas.
    return `${panel('', `<p style="margin:0"><strong>${T('sg.eco_caution')}</strong></p>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(e.caution || '')}</p>
        <p class="swb-hint" style="margin:.3rem 0 0">${T('sg.eco_unit')} ${esc(e.cost_unit || '')}</p>`, 'warn')}
      <div class="swb-kpis">
        ${kpi(T('sg.eco_total'), nf(e.collection_cost_total), 'ok', T('sg.eco_total_h'))}
        ${kpi(T('sg.eco_mute'), nf(e.mute_cost), e.mute_share_pct > 30 ? 'danger' : 'warn',
          `${esc(e.mute_share_pct)} % ${T('sg.eco_of_cost')}`)}
        ${kpi(T('sg.eco_hours'), nf(e.handling_hours_total), 'ok', T('sg.eco_hours_h'))}
        ${kpi(T('sg.eco_sources'), nf(e.sources), 'ok')}
      </div>
      ${panel(T('sg.eco_forecast'), `
        <p class="swb-hint" style="margin:0 0 .5rem">${esc(f.note || '')} · ${esc(f.basis || '')}</p>
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          <th>${T('sg.eco_horizon')}</th><th class="swb-num">${T('sg.eco_point')}</th>
          <th class="swb-num">${T('sg.eco_range')}</th></tr></thead><tbody>
          ${['30d', '90d'].map((k) => {
            const p = f[k] || {};
            return `<tr><td>${esc(k)}</td>
              <td class="swb-num">${p.value === null ? '<span class="swb-hint">—</span>' : nf(p.value)}</td>
              <td class="swb-num swb-hint">${p.low === null || p.low === undefined ? esc(p.reason || '—')
                : `${nf(p.low)} – ${nf(p.high)}`}</td></tr>`;
          }).join('')}</tbody></table></div>`)}
      ${panel(T('sg.eco_arbitrate'), `
        <div class="swb-filters">
          <input class="swb-input" id="eco-budget" style="max-width:9rem"
            placeholder="${T('sg.eco_budget')}" value="${esc(st.ecoBudget || '')}">
          <button type="button" class="fp-btn fp-btn-sm" data-sagf-act="eco-arbitrate">${T('sg.eco_do')}</button>
        </div>
        ${!a ? `<p class="swb-hint" style="margin:.4rem 0 0">${T('sg.eco_arbitrate_sub')}</p>` : `
          <div class="swb-kpis" style="margin-top:.6rem">
            ${kpi(T('sg.eco_kept'), nf(a.kept), 'ok')}
            ${kpi(T('sg.eco_dropped'), nf(a.dropped), a.dropped ? 'warn' : 'ok')}
            ${kpi(T('sg.eco_used'), nf(a.total_noise_per_day), 'ok', `/ ${nf(a.budget)}`)}
          </div>
          <p class="swb-hint" style="margin:.4rem 0 0"><strong>${T('sg.caution')} :</strong> ${esc(a.warning)}</p>
          <p class="swb-hint" style="margin:.3rem 0 0">${esc(a.optimality)}</p>
          ${(a.dropped_items || []).length ? `<div class="swb-tablewrap" style="max-height:22vh;margin-top:.5rem">
            <table class="swb-table"><tbody>${a.dropped_items.map((d) => `<tr>
              <td class="swb-truncate" title="${esc(d.name)}">${esc(d.name)}</td>
              <td class="swb-num swb-hint">${T('sg.eco_gain')} ${nf(d.gain)}</td></tr>`).join('')}
            </tbody></table></div>` : ''}`}`)}
      <div class="swb-panel" style="padding:0">
        <div class="swb-panel-head" style="padding:.8rem .9rem 0">
          <h3 class="swb-panel-title">${T('sg.eco_per_source')}</h3></div>
        <div class="swb-tablewrap" style="max-height:34vh"><table class="swb-table"><thead><tr>
          <th>${T('sg.col_source')}</th><th class="swb-num">${T('sg.eco_events')}</th>
          <th class="swb-num">${T('sg.eco_cost')}</th><th class="swb-num">${T('sg.eco_alerts')}</th>
          <th class="swb-num">${T('sg.eco_per_alert')}</th><th>${T('sg.eco_lose')}</th>
        </tr></thead><tbody>${(e.items || []).slice(0, 60).map((r) => `<tr>
          <td class="swb-truncate" title="${esc(r.intake_name)}">${esc(r.intake_name)}</td>
          <td class="swb-num">${nf(r.events_period)}</td>
          <td class="swb-num">${nf(r.collection_cost)}</td>
          <td class="swb-num">${nf(r.alerts)}</td>
          <td class="swb-num">${r.cost_per_alert === null ? '<span class="swb-hint">—</span>' : nf(r.cost_per_alert)}</td>
          <td class="swb-hint swb-truncate" title="${esc((r.would_lose || {}).note || '')}">${
            (r.would_lose || {}).techniques ? pill(`${nf(r.would_lose.techniques)} ${T('sg.eco_tech')}`, 'warn', true)
              : `<span class="swb-hint">${T('sg.eco_none_known')}</span>`}</td>
        </tr>`).join('')}</tbody></table></div></div>
      ${panel('', `<p class="swb-hint" style="margin:0"><strong>${T('sg.refutation')} :</strong> ${esc(e.refutation || '')}</p>`, 'accent')}`;
  }


  // ── Vues des lots 4, 5, 6, 7, 10 ──────────────────────────────────────────
  // Toutes suivent le même contrat : verdict avant chiffre, réserve visible,
  // condition de réfutation affichée.
  function lazy(key, act, label) {
    return panel('', `<p class="swb-hint" style="margin:0">${esc(label)}</p>
      <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" style="margin-top:.5rem"
        data-sagf-act="${act}">${T('sg.compute')}</button>`);
  }
  function head(d, tone) {
    return `${panel('', `<p style="margin:0"><strong>${esc(d.headline || '')}</strong></p>
      ${d.note ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(d.note)}</p>` : ''}
      ${d.method_note ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(d.method_note)}</p>` : ''}
      ${d.no_prediction ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(d.no_prediction)}</p>` : ''}
      ${d.no_action ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(d.no_action)}</p>` : ''}
      ${d.caveat ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(d.caveat)}</p>` : ''}
      ${d.refutation ? `<p class="swb-hint" style="margin:.3rem 0 0"><strong>${
        T('sg.refutation')} :</strong> ${esc(d.refutation)}</p>` : ''}`, tone || 'accent')}`;
  }

  function viewEfficacy() {
    const d = st.data.eff;
    if (!d) return lazy('eff', 'eff-run', T('sg.eff_idle'));
    const by = d.by_position || {};
    const cov = d.feedback_coverage || {};
    return `${!cov.usable ? panel('', `<p style="margin:0"><strong>${T('sg.eff_blocked')}</strong></p>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(cov.verdict || '')}</p>`, 'warn') : ''}
      <div class="swb-kpis">
        ${kpi(T('sg.eff_broyeuse'), nf(by.broyeuse || 0), by.broyeuse ? 'danger' : 'ok', T('sg.eff_broyeuse_h'))}
        ${kpi(T('sg.eff_pilier'), nf(by.pilier || 0), 'ok')}
        ${kpi(T('sg.eff_dormante'), nf(by.dormante || 0), by.dormante ? 'warn' : 'ok')}
        ${kpi(T('sg.eff_indet'), nf(d.indeterminate), d.indeterminate ? 'warn' : 'ok', T('sg.eff_indet_h'))}
      </div>${head(d)}
      <div class="swb-panel" style="padding:0"><div class="swb-tablewrap" style="max-height:40vh">
        <table class="swb-table"><thead><tr><th>${T('sg.eff_pos')}</th><th>${T('sg.col_rule')}</th>
          <th class="swb-num">${T('sg.eco_alerts')}/j</th><th>${T('sg.fb_precision')}</th>
          <th>${T('sg.eff_action')}</th><th>${T('sg.eff_why')}</th></tr></thead><tbody>
        ${(d.items || []).slice(0, 80).map((r) => `<tr>
          <td>${pill(esc(r.position), r.position === 'broyeuse' ? 'danger'
            : r.position === 'pilier' ? 'ok' : 'mute')}</td>
          <td class="swb-truncate" title="${esc(r.rule_name)}">${esc(r.rule_name)}</td>
          <td class="swb-num">${nf(r.alerts_per_day)}</td>
          <td class="swb-hint">${(r.precision || {}).publishable
            ? `${esc(r.precision.point)} %` : '—'}</td>
          <td class="swb-hint swb-truncate">${esc(r.action)}</td>
          <td class="swb-hint swb-truncate" title="${esc(r.reason)}">${esc(r.reason)}</td>
        </tr>`).join('')}</tbody></table></div></div>`;
  }

  function viewAdversary() {
    const d = st.data.adv;
    if (!d) return lazy('adv', 'adv-run', T('sg.adv_idle'));
    return `<div class="swb-kpis">
        ${kpi(T('sg.adv_weighted'), `${esc(d.coverage_weighted_pct)} %`,
          d.coverage_weighted_pct < 70 ? 'danger' : 'ok', T('sg.adv_weighted_h'))}
        ${kpi(T('sg.adv_declared'), `${esc(d.coverage_declared_pct)} %`, 'mute', T('sg.adv_declared_h'))}
        ${kpi(T('sg.adv_active'), nf(d.techniques_active), 'ok')}
        ${kpi(T('sg.adv_gap'), nf(d.active_uncovered), d.active_uncovered ? 'danger' : 'ok')}
      </div>${head(d)}
      <div class="swb-panel" style="padding:0"><div class="swb-panel-head" style="padding:.8rem .9rem 0">
        <h3 class="swb-panel-title">${T('sg.adv_gap_title')}</h3></div>
        <div class="swb-tablewrap" style="max-height:34vh"><table class="swb-table"><tbody>
        ${(d.gap || []).map((g) => `<tr><td class="swb-mono">${esc(g.technique)}</td>
          <td class="swb-num">${nf(g.activity)} ${T('sg.adv_seen')}</td></tr>`).join('')
          || `<tr><td><p class="swb-hint" style="padding:1rem">${T('sg.adv_none')}</p></td></tr>`}
        </tbody></table></div></div>`;
  }

  function viewTwin() {
    const d = st.data.twin; const o = st.data.twinOutage;
    if (!d) return lazy('twin', 'twin-run', T('sg.twin_idle'));
    return `<div class="swb-kpis">
        ${kpi(T('sg.twin_single'), nf(d.single_source_formats), d.single_source_formats ? 'danger' : 'ok', T('sg.twin_single_h'))}
        ${kpi(T('sg.twin_intakes'), nf(d.intakes), 'ok')}
        ${kpi(T('sg.twin_formats'), nf(d.formats), 'ok')}
      </div>${head(d)}
      ${o ? panel(T('sg.twin_outage'), `<p style="margin:0"><strong>${esc(o.verdict || o.error || '')}</strong></p>
        ${o.techniques_lost && o.techniques_lost.length ? `<p class="swb-hint" style="margin:.3rem 0 0">${
          T('sg.twin_lost')} ${esc(o.techniques_lost.slice(0, 12).join(' · '))}</p>` : ''}
        ${o.caveat ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(o.caveat)}</p>` : ''}`, 'warn') : ''}
      <div class="swb-panel" style="padding:0"><div class="swb-tablewrap" style="max-height:36vh">
        <table class="swb-table"><thead><tr><th>${T('sg.col_source')}</th>
          <th class="swb-num">${T('sg.twin_risk')}</th><th></th></tr></thead><tbody>
        ${(d.items || []).map((i) => `<tr><td class="swb-truncate" title="${esc(i.intake_name)}">${esc(i.intake_name)}</td>
          <td class="swb-num">${nf(i.rules_at_risk)}</td>
          <td><button type="button" class="fp-btn fp-btn-sm fp-btn-ghost"
            data-sagf-act="twin-out" data-id="${esc(i.intake_uuid)}">${T('sg.twin_sim')}</button></td>
        </tr>`).join('')}</tbody></table></div></div>`;
  }

  function viewHarness() {
    const d = st.data.har;
    return `${panel(T('sg.har_title'), `<p class="swb-hint" style="margin:0 0 .6rem">${T('sg.har_sub')}</p>
        <div class="swb-filters">
          <button type="button" class="fp-btn fp-btn-sm" data-sagf-act="har-capture">${T('sg.har_capture')}</button>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-sagf-act="har-check">${T('sg.har_check')}</button>
        </div>`)}
      ${!d ? '' : (d.ok !== undefined
        ? panel('', `<p style="margin:0">${T('sg.har_captured', { n: nf(d.formats) })}</p>
          ${(d.skipped || []).length ? `<p class="swb-hint" style="margin:.3rem 0 0">${
            T('sg.har_skipped', { n: nf(d.skipped.length) })}</p>` : ''}`, 'ok')
        : `${head(d)}<div class="swb-kpis">
            ${kpi(T('sg.har_reg'), nf(d.regressions), d.regressions ? 'danger' : 'ok')}
            ${kpi(T('sg.har_conform'), nf(d.formats_conform), 'ok')}
            ${kpi(T('sg.har_corpus'), nf(d.formats_in_corpus), 'ok')}
          </div>
          <div class="swb-panel" style="padding:0"><div class="swb-tablewrap" style="max-height:32vh">
            <table class="swb-table"><thead><tr><th>${T('sg.field')}</th>
              <th class="swb-num">${T('sg.har_before')}</th><th class="swb-num">${T('sg.har_after')}</th>
              <th>${T('sg.har_cause')}</th></tr></thead><tbody>
            ${(d.items || []).map((r) => `<tr><td class="swb-mono swb-truncate">${esc(r.field)}</td>
              <td class="swb-num">${esc(r.coverage_before)} %</td>
              <td class="swb-num">${r.coverage_after === null ? '—' : esc(r.coverage_after) + ' %'}</td>
              <td class="swb-hint swb-truncate" title="${esc(r.text)}">${esc(r.text)}</td>
            </tr>`).join('') || `<tr><td colspan="4"><p class="swb-hint" style="padding:1rem">${
              T('sg.har_none')}</p></td></tr>`}</tbody></table></div></div>`)}`;
  }

  function viewInsurance() {
    const d = st.data.ins;
    if (!d) return lazy('ins', 'ins-run', T('sg.ins_idle'));
    return `<div class="swb-kpis">
        ${kpi(T('sg.ins_fragile'), nf(d.fragile), d.fragile ? 'danger' : 'ok', T('sg.ins_fragile_h'))}
        ${kpi(T('sg.ins_uncovered'), nf(d.uncovered), d.uncovered ? 'warn' : 'ok')}
        ${kpi(T('sg.ins_tech'), nf(d.techniques), 'ok')}
        ${kpi(T('sg.ins_spof'), nf((d.single_points_of_failure || []).length),
          (d.single_points_of_failure || []).length ? 'danger' : 'ok', T('sg.ins_spof_h'))}
      </div>${head(d)}
      ${(d.single_points_of_failure || []).length ? panel(T('sg.ins_spof_title'), `
        <div class="swb-tablewrap" style="max-height:24vh"><table class="swb-table"><tbody>
        ${d.single_points_of_failure.map((p) => `<tr>
          <td class="swb-mono swb-truncate">${esc(p.format)}</td>
          <td class="swb-num"><strong>${nf(p.techniques_lost)}</strong> ${T('sg.ins_lost')}</td>
          <td class="swb-hint swb-truncate">${esc((p.examples || []).join(' · '))}</td>
        </tr>`).join('')}</tbody></table></div>`) : ''}
      <div class="swb-panel" style="padding:0"><div class="swb-tablewrap" style="max-height:32vh">
        <table class="swb-table"><thead><tr><th>${T('sg.ins_technique')}</th>
          <th class="swb-num">${T('sg.ins_redundancy')}</th><th class="swb-num">${T('sg.ins_rules')}</th>
          <th>${T('sg.state')}</th></tr></thead><tbody>
        ${(d.items || []).slice(0, 80).map((t) => `<tr>
          <td class="swb-mono">${esc(t.technique)}</td>
          <td class="swb-num">${nf(t.redundancy)}</td>
          <td class="swb-num swb-hint">${nf(t.rules_live)}/${nf(t.rules_total)}</td>
          <td>${t.uncovered ? pill(T('sg.ins_none'), 'danger')
            : t.fragile ? pill(T('sg.ins_frag'), 'warn') : pill(T('sg.ins_ok'), 'ok')}</td>
        </tr>`).join('')}</tbody></table></div></div>`;
  }

  // ── Rendu ─────────────────────────────────────────────────────────────────
  function nav() {
    return `<nav class="swb-nav">${VIEWS.map(([id, key]) => `<button type="button"
      class="swb-tab" aria-selected="${st.view === id}" data-sagf-view="${id}">${T(key)}</button>`).join('')}
      <span style="flex:1"></span>
      <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-sagf-act="reload">↻ ${T('act.refresh')}</button></nav>`;
  }

  function paint() {
    const el = document.getElementById('sagf-root');
    if (!el) return;
    let body;
    if (st.loading) {
      body = `<p class="swb-hint" style="padding:2rem">${T('sg.loading')}</p>`;
    } else if (st.error) {
      body = `<div class="swb-panel" style="border-left:3px solid var(--swb-danger)">
        <p style="margin:0">${esc(st.error)}</p></div>`;
    } else if (st.view === 'compliance') body = viewCompliance();
    else if (st.view === 'mechanisms') body = viewMechanisms();
    else if (st.view === 'sagql') body = viewSagql();
    else if (st.view === 'memory') body = viewMemory();
    else if (st.view === 'debt') body = viewDebt();
    else if (st.view === 'feedback') body = viewFeedback();
    else if (st.view === 'conflicts') body = viewConflicts();
    else if (st.view === 'code') body = viewCode();
    else if (st.view === 'economics') body = viewEconomics();
    else if (st.view === 'efficacy') body = viewEfficacy();
    else if (st.view === 'adversary') body = viewAdversary();
    else if (st.view === 'twin') body = viewTwin();
    else if (st.view === 'harness') body = viewHarness();
    else if (st.view === 'insurance') body = viewInsurance();
    else if (st.view === 'journal') body = viewJournal();
    else body = viewMirror();

    el.className = 'swb';
    el.innerHTML = `<div class="swb-head">
        <div><h2 class="swb-title">${T('sg.title')}</h2>
          <p class="swb-sub">${T('sg.sub')}</p></div></div>
      ${nav()}<div class="swb-body">${body}</div>`;
    bind(el);
  }

  // Meme garde que le poste analyste : le bouton « Rafraichir » declenche
  // `load()` a chaque clic, et un clic rapide avant la fin du precedent
  // laisserait la reponse la PLUS LENTE peindre en dernier, meme si elle est
  // la plus ancienne.
  let loadGen = 0;
  async function load() {
    const myGen = ++loadGen;
    st.loading = true; st.error = null; paint();
    try {
      const r = await Promise.all([
        api('/laws').catch(() => null),
        api('/mechanisms').catch(() => null),
        api('/self-report').catch(() => null),
        api('/compliance').catch(() => null),
      ]);
      if (myGen !== loadGen) return;   // supplantee par un rafraichissement plus recent
      st.data.laws = r[0]; st.data.mechanisms = r[1];
      st.data.report = r[2]; st.data.compliance = r[3];
      if (!r[2]) st.error = T('sg.down');
    } catch (e) { if (myGen === loadGen) st.error = e.message; else return; }
    st.loading = false; paint();
  }

  function bind(el) {
    if (el.dataset.sagfBound) return;
    el.dataset.sagfBound = '1';
    el.addEventListener('click', async (ev) => {
      const v = ev.target.closest('[data-sagf-view]');
      if (v) { st.view = v.dataset.sagfView; paint(); return; }
      const b = ev.target.closest('[data-sagf-act]');
      if (!b) return;
      const act = b.dataset.sagfAct;
      const val = (id) => (document.getElementById(id) || {}).value || '';
      try {
        if (act === 'reload') { load(); return; }
        if (act === 'run' || act === 'explain') {
          st.query = val('sagf-q') || st.query;
          const q = act === 'explain' ? `${st.query} EXPLAIN` : st.query;
          st.data.query = await api('/query', { method: 'POST', body: { q } });
          paint(); return;
        }
        if (act === 'nl') {
          st.nlq = val('sagf-nl') || st.nlq;
          st.data.nl = await api('/nl', { method: 'POST', body: { question: st.nlq } });
          paint(); return;
        }
        if (act === 'snapshot') {
          st.data.snapshot = await api('/config/snapshot?entity=Rule&author=ui&reason=releve%20manuel',
            { method: 'POST' });
          paint(); return;
        }
        if (act === 'reconcile') {
          st.data.reconcile = await api('/reconcile?entity=Rule'); paint(); return;
        }
        if (act === 'diff') {
          st.since = val('sagf-since') || st.since;
          if (!st.since) { st.data.diff = { available: false, reason: T('sg.need_since') }; paint(); return; }
          st.data.diff = await api(`/config/diff?entity=Rule&since=${encodeURIComponent(st.since)}`);
          paint(); return;
        }
        if (act === 'debt') {
          st.loading = true; paint();
          const r = await Promise.all([api('/debt').catch(() => null), api('/risk').catch(() => null)]);
          st.data.debt = r[0]; st.data.risk = r[1];
          st.loading = false; paint(); return;
        }
        if (act === 'fb-send') {
          st.data.fbErr = null;
          const r = await api('/feedback', { method: 'POST', body: {
            alert_id: val('fb-alert'), rule_ref: val('fb-rule'),
            reason_code: val('fb-code'), analyst: val('fb-analyst'),
            time_spent_s: val('fb-time') || null } });
          if (r && r.ok === false) st.data.fbErr = r.error;
          st.data.fbRates = await api(`/feedback/rates?by=${st.fbBy || 'rule_ref'}`)
            .catch(() => st.data.fbRates);
          paint(); return;
        }
        if (act === 'fb-by') {
          st.fbBy = b.dataset.by;
          st.data.fbRates = await api(`/feedback/rates?by=${st.fbBy}`);
          paint(); return;
        }
        if (act === 'cf-run' || act === 'cf-filter') {
          if (act === 'cf-filter') st.cfRel = b.dataset.rel;
          st.loading = true; paint();
          st.data.conflicts = await api(
            `/conflicts${st.cfRel ? `?relation=${encodeURIComponent(st.cfRel)}` : ''}`)
            .catch((e) => ({ headline: e.message, by_relation: {}, items: [] }));
          st.loading = false; paint(); return;
        }
        if (act === 'dac-export') {
          st.loading = true; paint();
          st.data.dacExport = await api(
            `/dac/export?entity=${encodeURIComponent(val('dac-entity') || 'rules')}`);
          st.loading = false; paint(); return;
        }
        if (act === 'dac-plan') {
          const body = val('dac-target');
          if (!body.trim()) { st.data.dacPlan = { ok: false, error: T('sg.dac_need') }; paint(); return; }
          st.loading = true; paint();
          const r = await fetch(API + `/dac/plan?entity=${encodeURIComponent(val('dac-entity') || 'rules')}`,
            { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'text/plain' }, body });
          st.data.dacPlan = await r.json().catch(() => ({ ok: false, error: 'réponse illisible' }));
          st.loading = false; paint(); return;
        }
        if (act === 'eco-run' || act === 'eco-arbitrate') {
          if (act === 'eco-arbitrate') st.ecoBudget = val('eco-budget');
          st.loading = true; paint();
          const q = st.ecoBudget ? `?budget=${encodeURIComponent(st.ecoBudget)}` : '';
          st.data.eco = await api(`/economics${q}`)
            .catch((err) => ({ available: false, reason: err.message }));
          st.loading = false; paint(); return;
        }
        const lazyMap = { 'eff-run': ['eff', '/efficacy'], 'adv-run': ['adv', '/adversary'],
          'twin-run': ['twin', '/twin'], 'ins-run': ['ins', '/insurance'] };
        if (lazyMap[act]) {
          const [key, path] = lazyMap[act];
          st.loading = true; paint();
          st.data[key] = await api(path).catch((e) => ({ headline: e.message, items: [] }));
          st.loading = false; paint(); return;
        }
        if (act === 'twin-out') {
          st.data.twinOutage = await api(`/twin/outage/${encodeURIComponent(b.dataset.id)}`)
            .catch((e) => ({ error: e.message }));
          paint(); return;
        }
        if (act === 'har-capture' || act === 'har-check') {
          st.loading = true; paint();
          st.data.har = await api(act === 'har-capture'
            ? '/harness/capture' : '/harness/check',
            act === 'har-capture' ? { method: 'POST' } : undefined)
            .catch((e) => ({ headline: e.message, items: [] }));
          st.loading = false; paint(); return;
        }
        if (act === 'journal-add') {
          st.data.journalErr = null;
          const r = await api('/journal', { method: 'POST', body: {
            object_ref: val('sagf-jref'), kind: val('sagf-jkind'),
            text: val('sagf-jtext'),
            attribution: { author: val('sagf-jauthor'), reason: val('sagf-jtext') } } });
          if (r && r.ok === false) st.data.journalErr = r.error;
          st.data.journal = await api('/journal').catch(() => st.data.journal);
          paint(); return;
        }
      } catch (e) {
        st.error = e.message; st.loading = false; paint();
      }
    });
  }

  function mount() {
    if (st.mounted) { paint(); return; }
    st.mounted = true;
    load();
    api('/journal').then((j) => { st.data.journal = j; if (st.view === 'journal') paint(); })
      .catch(() => {});
    // Le lot 1 est peu coûteux : on le charge d'emblée. Le lot 3 parcourt des
    // dizaines de milliers de paires — il reste à la demande.
    Promise.all([
      api('/feedback/codes').catch(() => null),
      api('/feedback/rates?by=rule_ref').catch(() => null),
      api('/feedback/coverage').catch(() => null),
    ]).then((r) => {
      st.data.fbCodes = r[0]; st.data.fbRates = r[1]; st.data.fbCoverage = r[2];
      if (st.view === 'feedback') paint();
    });
  }

  // L'onglet est autonome : on ne s'accroche qu'à son propre bouton.
  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.querySelector('[data-tab-btn="sagf"]');
    if (btn) btn.addEventListener('click', () => setTimeout(mount, 60));
    if (document.getElementById('sagf-root')
        && document.getElementById('tab-sagf')
        && !document.getElementById('tab-sagf').hidden) {
      setTimeout(mount, 200);
    }
  });
  window.addEventListener('i18n:language-changed', () => { if (st.mounted) paint(); });
})();
