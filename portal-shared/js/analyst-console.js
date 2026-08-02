/* Extension Sekoia — console analystes.
 *
 * Cinq tableaux de bord opérationnels : sources, règles, actifs, intakes,
  * sources multi-hôtes. Chaque panneau affiche la mesure, SON INCERTITUDE et SA FRAÎCHEUR
 * — les trois ensemble, toujours. Un chiffre sans date se lit comme un état
 * actuel alors qu'il décrit peut-être la semaine dernière.
 *
 * Aucune action de cette console n'écrit dans Sekoia.io. Les étiquettes vivent
 * dans l'extension.
 */
(function () {
  'use strict';
  const API = '/api/threat/analyst';

  const VIEWS = [
    ['sources', 'an.v_sources'],
    ['rules', 'an.v_rules'],
    ['assets', 'an.v_assets'],
    ['intakes', 'an.v_intakes'],
    ['hostnames', 'an.v_hosts'],
    ['inventory', 'an.v_inv'],
    ['tags', 'an.v_tags'],
  ];

  const st = { view: 'sources', data: {}, loading: false, error: null,
               entity: 'intakes' };

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
    return (n === null || n === undefined || isNaN(n)) ? '—'
      : Number(n).toLocaleString('fr-FR');
  }
  async function api(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    const r = await fetch(API + path, o);
    const d = await r.json().catch(() => ({}));
    if (!r.ok && d && d.error) throw new Error(d.error);
    return d;
  }

  function panel(title, inner, tone) {
    return `<div class="swb-panel${tone ? ' swb-panel-' + tone : ''}"
      ${tone ? `style="border-left:3px solid var(--swb-${tone})"` : ''}>
      ${title ? `<h3 class="swb-panel-title">${esc(title)}</h3>` : ''}${inner}</div>`;
  }

  /* La fraîcheur n'est jamais optionnelle : sans elle, l'analyste lit une
   * mesure ancienne comme un état courant. */
  function freshness(d) {
    const f = (d && d.freshness) || {};
    const label = f.label || (d && d.measured_at ? '' : T('an.no_date'));
    return `<span class="swb-pill swb-pill-mute swb-pill-flat">${
      T('an.measured')} ${esc(label)}</span>`;
  }

  function verdictRow(v) {
    const tone = v.severity === 'alerte' ? 'danger'
      : v.severity === 'attention' ? 'warn' : 'mute';
    return `<tr>
      <td class="swb-truncate"><strong>${esc(v.subject)}</strong></td>
      <td>${esc(v.verdict)}</td>
      <td class="swb-hint swb-truncate" title="${esc(v.uncertainty)}">${
        esc(v.uncertainty)}</td>
      <td>${(v.tags || []).map((t) => `<span class="swb-pill swb-pill-${
        tone} swb-pill-flat">${esc(t)}</span>`).join(' ')}</td>
      <td class="swb-hint">${esc(((v.freshness) || {}).label || '')}</td>
    </tr>`;
  }

  function verdictTable(items) {
    if (!items || !items.length) {
      return `<p class="swb-hint" style="margin:0">${T('an.nothing')}</p>`;
    }
    return `<div class="swb-tablewrap" style="max-height:44vh"><table class="swb-table">
      <thead><tr><th>${T('an.c_subject')}</th><th>${T('an.c_verdict')}</th>
        <th>${T('an.c_uncertainty')}</th><th>${T('an.c_tags')}</th>
        <th>${T('an.c_fresh')}</th></tr></thead>
      <tbody>${items.map(verdictRow).join('')}</tbody></table></div>`;
  }

  function panelBlock(p) {
    const items = p.items || (p.inert ? [] : []);
    const head = `<p style="margin:0"><strong>${esc(p.headline || '')}</strong></p>
      <p style="margin:.3rem 0 0">${freshness(p)}</p>
      ${p.method ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(p.method)}</p>` : ''}
      ${p.why ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(p.why)}</p>` : ''}`;
    /* Le tableau de bord des règles renvoie quatre familles nommées plutôt
     * qu'une liste plate : on les rend chacune avec son intitulé. */
    const families = ['inert', 'never_triggered', 'noisy', 'obsolete'];
    const hasFamilies = families.some((f) => p[f]);
    if (hasFamilies) {
      return panel('', head + families.filter((f) => p[f] && p[f].count).map((f) =>
        `<h4 class="swb-panel-title" style="margin-top:.8rem">${T('an.f_' + f)} — ${
          nf(p[f].count)}</h4>${verdictTable(p[f].items)}`).join(''), 'accent');
    }
    if (p.relay_summary && p.relay_summary.length) {
      return panel('', head + `<div class="swb-tablewrap" style="max-height:22vh;margin-top:.5rem">
        <table class="swb-table"><thead><tr><th>${T('an.c_intake')}</th>
          <th>${T('an.c_hosts')}</th><th>${T('an.c_family')}</th></tr></thead>
        <tbody>${p.relay_summary.map((r) => `<tr>
          <td class="swb-truncate">${esc(r.intake_name)}</td>
          <td class="swb-num"><strong>${nf(r.hosts)}</strong></td>
          <td class="swb-hint">${esc(r.family || '—')}</td></tr>`).join('')}
        </tbody></table></div>` + verdictTable(p.items), 'accent');
    }
    const groups = ['without_logs', 'without_source', 'without_coverage'];
    if (groups.some((g) => p[g])) {
      return panel('', head + groups.filter((g) => p[g] && p[g].count).map((g) =>
        `<h4 class="swb-panel-title" style="margin-top:.8rem">${T('an.g_' + g)} — ${
          nf(p[g].count)}</h4>${verdictTable(p[g].items)}`).join(''), 'accent');
    }
    return panel('', head + verdictTable(items), 'accent');
  }

  function viewDashboard(name) {
    const d = st.data['dash_' + name];
    if (!d) {
      return panel('', `<p class="swb-hint" style="margin:0">${T('an.idle')}</p>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary"
          style="margin-top:.5rem" data-an-act="dash:${name}">${T('an.compute')}</button>`);
    }
    if (d.ok === false) {
      return panel('', `<p style="margin:0">${esc(d.error)}</p>`, 'danger');
    }
    return `${panel('', `<p style="margin:0"><strong>${esc(d.headline || '')}</strong></p>
        <p style="margin:.3rem 0 0">${freshness(d)}</p>
        ${(d.actions || []).length ? `<p class="swb-hint" style="margin:.4rem 0 0">${
          T('an.actions')} ${d.actions.map((a) => `<span class="swb-pill swb-pill-mute
            swb-pill-flat">${esc(a)}</span>`).join(' ')}</p>
          <p class="swb-hint" style="margin:.3rem 0 0">${T('an.no_write')}</p>` : ''}`,
      'accent')}
      ${(d.panels || []).map(panelBlock).join('')}`;
  }

  function viewInventory() {
    const d = st.data.inv;
    const sel = ['intakes', 'sources', 'rules', 'assets', 'detections',
                 'fields', 'formats'];
    return `${panel(T('an.inv'), `
      <div class="swb-filters">
        <select class="swb-input" id="an-entity">${sel.map((e) =>
          `<option value="${e}"${e === st.entity ? ' selected' : ''}>${e}</option>`
          ).join('')}</select>
        <button type="button" class="fp-btn fp-btn-sm" data-an-act="inv">${
          T('an.read')}</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary"
          data-an-act="inv-refresh">${T('an.recollect')}</button>
      </div>
      <p class="swb-hint" style="margin:.4rem 0 0">${T('an.inv_sub')}</p>`)}
      ${!d ? '' : panel('', `<p style="margin:0"><strong>${nf(d.total)}</strong> ${
        T('an.objects')} · ${freshness(d)}</p>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(d.note || '')}</p>
        <div class="swb-tablewrap" style="max-height:40vh;margin-top:.5rem">
        <table class="swb-table"><tbody>${(d.items || []).slice(0, 200).map((i) =>
          `<tr><td class="swb-truncate">${esc(i.intake_name || i.rule_name
            || i.name || i.field || i.dialect_name || '—')}</td>
          <td class="swb-hint swb-truncate">${esc(i.intake_status
            || i.connector_name || i.rule_enabled || '')}</td></tr>`).join('')}
        </tbody></table></div>`, 'accent')}`;
  }

  function viewTags() {
    const d = st.data.tags;
    return `${panel(T('an.tags'), `<p class="swb-hint" style="margin:0 0 .5rem">${
        T('an.tags_sub')}</p>
      <button type="button" class="fp-btn fp-btn-sm fp-btn-primary"
        data-an-act="tags">${T('an.read')}</button>`)}
      ${!d ? '' : panel('', `<p style="margin:0"><strong>${nf(d.count)}</strong> ${
        T('an.tags_set')}</p>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(d.note || '')}</p>
        <p style="margin:.4rem 0 0">${(d.catalogue || []).map((t) =>
          `<span class="swb-pill swb-pill-mute swb-pill-flat">${esc(t)}</span>`
          ).join(' ')}</p>
        <div class="swb-tablewrap" style="max-height:34vh;margin-top:.5rem">
        <table class="swb-table"><tbody>${(d.items || []).map((i) =>
          `<tr><td class="swb-truncate">${esc(i.id)}</td>
           <td><span class="swb-pill swb-pill-warn swb-pill-flat">${esc(i.tag)}</span></td>
           <td class="swb-hint swb-truncate">${esc(i.reason)}</td></tr>`).join('')}
        </tbody></table></div>`, 'accent')}`;
  }

  function nav() {
    return `<nav class="swb-nav">${VIEWS.map(([id, key]) => `<button type="button"
      class="swb-tab" aria-selected="${st.view === id}" data-an-view="${id}">${
      T(key)}</button>`).join('')}</nav>`;
  }

  function paint() {
    const el = document.getElementById('analyst-root');
    if (!el) return;
    let body;
    if (st.loading) {
      body = `<p class="swb-hint" style="padding:2rem">${T('an.loading')}</p>`;
    } else if (st.error) {
      body = panel('', `<p style="margin:0">${esc(st.error)}</p>`, 'danger');
    } else if (st.view === 'inventory') body = viewInventory();
    else if (st.view === 'tags') body = viewTags();
    else body = viewDashboard(st.view);

    el.className = 'swb';
    el.innerHTML = `<div class="swb-head">
        <div><h2 class="swb-title">${T('an.title')}</h2>
          <p class="swb-sub">${T('an.sub')}</p></div></div>
      ${nav()}<div class="swb-body">${body}</div>`;
    bind(el);
  }

  function bind(el) {
    if (el.dataset.anBound) return;
    el.dataset.anBound = '1';
    el.addEventListener('click', async (ev) => {
      const v = ev.target.closest('[data-an-view]');
      if (v) { st.view = v.dataset.anView; paint(); return; }
      const b = ev.target.closest('[data-an-act]');
      if (!b) return;
      const act = b.dataset.anAct;
      st.loading = true; st.error = null; paint();
      try {
        if (act.startsWith('dash:')) {
          const n = act.slice(5);
          st.data['dash_' + n] = await api('/dashboard/' + n);
        } else if (act === 'inv' || act === 'inv-refresh') {
          const sel = document.getElementById('an-entity');
          if (sel) st.entity = sel.value;
          if (act === 'inv-refresh') {
            await api('/inventory/' + st.entity + '/refresh', { method: 'POST' });
          }
          st.data.inv = await api('/inventory/' + st.entity + '?limit=200');
        } else if (act === 'tags') {
          st.data.tags = await api('/tags');
        }
      } catch (e) { st.error = e.message; }
      st.loading = false; paint();
    });
  }

  function boot() {
    const el = document.getElementById('analyst-root');
    if (!el) return;
    paint();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else { boot(); }
  window.analystConsole = { paint, state: st };
}());
