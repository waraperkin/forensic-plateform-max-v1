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
    const r = await fetch(API + path, o);
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
      <td class="swb-truncate">${esc(i.name)}</td>
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
          <td class="swb-truncate">${esc(x.name)}</td>
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
        ${q.executed ? `<p style="margin:.5rem 0 0"><strong>${nf(q.matched)}</strong> ${
            T('sg.matched', { n: nf(q.scanned) })}</p>
          <p class="swb-hint swb-mono" style="margin:.2rem 0 0">${
            esc(((q.provenance || {}).chain || []).join(' ← '))}</p>
          <div class="swb-tablewrap" style="max-height:34vh;margin-top:.5rem"><table class="swb-table"><tbody>
            ${(q.items || []).slice(0, 60).map((it) => `<tr>
              <td class="swb-truncate">${esc(it.rule_name || it.intake_name || it.field || it.dialect_uuid || '—')}</td>
              <td class="swb-hint swb-truncate">${esc(it.verdict || it.intake_status || it.reason || '')}</td>
            </tr>`).join('')}</tbody></table></div>`
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
            placeholder="SELECT Rule WHERE …" value="${esc(st.query)}">
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
          <td class="swb-truncate">${esc(x.rule_name)}</td>
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
          <td class="swb-truncate">${esc(e.author)}</td>
          <td class="swb-hint swb-truncate">${esc(e.reason)}</td>
          <td class="swb-truncate">${esc(e.text)}</td></tr>`).join('')
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
    else if (st.view === 'journal') body = viewJournal();
    else body = viewMirror();

    el.className = 'swb';
    el.innerHTML = `<div class="swb-head">
        <div><h2 class="swb-title">${T('sg.title')}</h2>
          <p class="swb-sub">${T('sg.sub')}</p></div></div>
      ${nav()}<div class="swb-body">${body}</div>`;
    bind(el);
  }

  async function load() {
    st.loading = true; st.error = null; paint();
    try {
      const r = await Promise.all([
        api('/laws').catch(() => null),
        api('/mechanisms').catch(() => null),
        api('/self-report').catch(() => null),
        api('/compliance').catch(() => null),
      ]);
      st.data.laws = r[0]; st.data.mechanisms = r[1];
      st.data.report = r[2]; st.data.compliance = r[3];
      if (!r[2]) st.error = T('sg.down');
    } catch (e) { st.error = e.message; }
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
