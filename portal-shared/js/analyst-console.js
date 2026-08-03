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

  /* Les vues sont regroupees selon les memes categories que la navigation
   * principale : visibilite, perimetre, detection. Une liste plate de 14
   * onglets oblige l'analyste a se rappeler OU se trouve chaque chose ; un
   * regroupement lui rappelle POURQUOI il y va. */
  const GROUPS = [
    ['g_visibility', [
      ['sources', 'an.v_sources'],
      ['intakes', 'an.v_intakes'],
      ['hostnames', 'an.v_hosts'],
      ['loss', 'an.v_loss'],
      ['anomalies', 'an.v_anom'],
      ['quality', 'an.v_quality'],
    ]],
    ['g_scope', [
      ['assets', 'an.v_assets'],
      ['fields', 'an.v_fields'],
      ['inventory', 'an.v_inv'],
    ]],
    ['g_detection', [
      ['rules', 'an.v_rules'],
      ['coverage', 'an.v_cov'],
      ['mitre', 'an.v_mitre'],
      ['taxonomies', 'an.v_taxo'],
      ['tags', 'an.v_tags'],
    ]],
  ];
  const VIEWS = GROUPS.flatMap(([, v]) => v);

  const st = { view: 'sources', data: {}, loading: false, error: null,
               entity: 'intakes',
               /* Paramètres d'échantillonnage, choisis par l'analyste. Les
                * élargir coûte du quota de recherche Sekoia : c'est un
                * arbitrage qui lui appartient, pas une valeur imposée. */
               window: '1h', sample: 2000, hours: 24,
               intake: '', relaysOnly: true,
               // Actions manuelles : ligne dépliée et résultats de simulation,
               // par clé « target:id ».
               bulkOpen: null, bulkPreview: {},
               // Numéro de génération des requêtes de tableau de bord/inventaire
               // — ignore une réponse arrivée après qu'une action plus récente
               // a déjà été lancée.
               reqGen: 0,
               // Chargement PAR ACTION (« dash:rules », « inv », « tags ») —
               // jamais un verrou de page entière, qui gèlerait la navigation
               // pendant qu'un tableau de bord calcule.
               busy: new Set(),
               // Pagination reelle de l'inventaire brut : le backend
               // porte offset/limit/has_more depuis ce correctif, mais
               // rien ne les exploitait cote ecran.
               invOffset: 0, invLimit: 200 };
  const WINDOWS = ['15m', '1h', '6h', '24h', '7d'];

  /* Repli des intitulés de groupe. La résolution i18n de ces trois clés échoue
   * alors que les clés voisines du même niveau fonctionnent — je n'ai pas
   * élucidé pourquoi, et afficher « an.g_visibility » à un analyste est pire
   * que tout. Le repli garantit un libellé correct dans les deux langues ; il
   * disparaîtra le jour où la cause sera trouvée. */
  const GROUP_LABELS = {
    fr: { g_visibility: 'Visibilité', g_scope: 'Périmètre', g_detection: 'Détection' },
    en: { g_visibility: 'Visibility', g_scope: 'Scope', g_detection: 'Detection' },
  };
  function groupLabel(g) {
    const out = T('an.' + g);
    if (out && out !== 'an.' + g) return out;
    const lang = (document.documentElement.lang || 'fr').slice(0, 2);
    return (GROUP_LABELS[lang] || GROUP_LABELS.fr)[g] || g;
  }

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

  /* ── Actions manuelles réelles ────────────────────────────────────────────
   * L'extension elle-même n'écrit jamais dans Sekoia (voir en-tête du module
   * back). Mais le moteur de lot (`bulkops.py`) EXISTE, est audité, simule
   * avant d'appliquer et journalise chaque écriture avec annulation possible
   * — il n'était câblé nulle part hors d'un onglet caché. Cette section
   * réutilise EXACTEMENT ce moteur, avec la même discipline : jamais
   * d'application sans simulation affichée d'abord.
   */
  const BULK_API = '/api/threat/sekoia';
  async function bulkApi(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    const r = await fetch(BULK_API + path, o);
    const d = await r.json().catch(() => ({}));
    if (!r.ok && d && d.error) throw new Error(d.error);
    return d;
  }

  // Cible du moteur de lot déduite de l'evidence d'un verdict, et rien d'autre
  // : on ne devine jamais un identifiant hors de ce que le back a fourni.
  function bulkSubject(v) {
    const ev = v.evidence || {};
    if (ev.rule_uuid) return { target: 'rules', id: ev.rule_uuid, taggable: true, toggle: true };
    if (ev.intake_uuid) return { target: 'intakes', id: ev.intake_uuid, taggable: false, toggle: true };
    if (ev.uuid) return { target: 'assets', id: ev.uuid, taggable: true, toggle: false };
    return null;
  }

  // Même détermination, mais depuis une ligne BRUTE de l'inventaire local
  // (pas un verdict) : le navigateur d'inventaire couvre les 12 entités, dont
  // trois seulement portent une action Sekoia réelle.
  function bulkSubjectFromRow(entity, row) {
    if (entity === 'rules' && row.rule_uuid) {
      return { target: 'rules', id: row.rule_uuid, taggable: true, toggle: true };
    }
    if ((entity === 'intakes' || entity === 'sources') && row.intake_uuid) {
      return { target: 'intakes', id: row.intake_uuid, taggable: false, toggle: true };
    }
    if (entity === 'assets' && row.uuid) {
      return { target: 'assets', id: row.uuid, taggable: true, toggle: false };
    }
    return null;
  }

  async function bulkDry(target, id, op, tags) {
    return bulkApi(`/bulk/${encodeURIComponent(target)}`, {
      method: 'POST',
      body: JSON.stringify({ action: op, ids: [id], tags: tags || [], dry_run: 1 }),
      headers: { 'Content-Type': 'application/json' },
    });
  }
  async function bulkApply(target, id, op, tags) {
    return bulkApi(`/bulk/${encodeURIComponent(target)}`, {
      method: 'POST',
      body: JSON.stringify({ action: op, ids: [id], tags: tags || [], dry_run: 0 }),
      headers: { 'Content-Type': 'application/json' },
    });
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

  function verdictRow(v, actionable) {
    const tone = v.severity === 'alerte' ? 'danger'
      : v.severity === 'attention' ? 'warn' : 'mute';
    const bs = actionable ? bulkSubject(v) : null;
    const rowKey = bs ? `${bs.target}:${bs.id}` : null;
    const open = rowKey && st.bulkOpen === rowKey;
    const link = v.sekoia && v.sekoia.url
      ? `<a href="${esc(v.sekoia.url)}" target="_blank" rel="noopener"
           class="fp-btn fp-btn-sm fp-btn-ghost" title="${T('an.open_sekoia')}">↗</a>` : '';
    const actBtn = bs ? `<button type="button" class="fp-btn fp-btn-sm"
        data-an-act="bulk-toggle" data-key="${esc(rowKey)}"
        data-target="${esc(bs.target)}" data-id="${esc(bs.id)}">${
        T(open ? 'an.act_close' : 'an.act_open')}</button>` : '';
    const panel = open ? bulkPanel(bs) : '';
    return `<tr>
      <td class="swb-truncate"><strong>${esc(v.subject)}</strong></td>
      <td>${esc(v.verdict)}</td>
      <td class="swb-hint swb-truncate" title="${esc(v.uncertainty)}">${
        esc(v.uncertainty)}</td>
      <td>${(v.tags || []).map((t) => `<span class="swb-pill swb-pill-${
        tone} swb-pill-flat">${esc(t)}</span>`).join(' ')}</td>
      <td class="swb-hint">${esc(((v.freshness) || {}).label || '')}</td>
      <td style="white-space:nowrap">${link} ${actBtn}</td>
    </tr>${panel ? `<tr><td colspan="6" style="padding:0">${panel}</td></tr>` : ''}`;
  }

  // Panneau d'action réel, sous la ligne dépliée. Jamais d'application sans
  // simulation affichée d'abord — c'est le moteur de lot qui l'impose.
  function bulkPanel(bs) {
    const key = `${bs.target}:${bs.id}`;
    const pv = st.bulkPreview[key];
    const ops = bs.toggle ? ['enable', 'disable'] : [];
    const opLabel = { enable: T('an.op_enable'), disable: T('an.op_disable'),
      tag_add: T('an.op_tag_add') };
    const inner = `<div class="swb-filters" style="align-items:center">
        ${ops.map((op) => `<button type="button" class="fp-btn fp-btn-sm"
          data-an-act="bulk-dry" data-target="${esc(bs.target)}" data-id="${esc(bs.id)}"
          data-op="${op}">${esc(opLabel[op])}</button>`).join('')}
        ${bs.taggable ? `<input class="swb-input" id="an-bulk-tag-${esc(bs.id)}"
            style="max-width:12rem" placeholder="${T('an.tag_ph')}">
          <button type="button" class="fp-btn fp-btn-sm" data-an-act="bulk-dry"
            data-target="${esc(bs.target)}" data-id="${esc(bs.id)}"
            data-op="tag_add">${esc(opLabel.tag_add)}</button>` : ''}
      </div>
      ${!pv ? `<p class="swb-hint" style="margin:.4rem 0 0">${T('an.bulk_hint')}</p>` : ''}
      ${pv && pv.dry && pv.result ? `<div class="swb-hint" style="margin:.5rem 0 0">
          <strong>${T('an.simulation')}</strong> — ${
            esc(JSON.stringify((pv.result.results || [{}])[0].before || {}))}
          ${pv.result.selected
            ? `<button type="button" class="fp-btn fp-btn-sm fp-btn-danger" style="margin-left:.5rem"
                data-an-act="bulk-apply" data-target="${esc(bs.target)}"
                data-id="${esc(bs.id)}" data-op="${esc(pv.op)}">${T('an.apply')}</button>`
            : `<span> — ${T('an.nothing_to_apply')}</span>`}
        </div>` : ''}
      ${pv && !pv.dry && pv.result ? `<p class="swb-hint" style="margin:.5rem 0 0">${
          pv.result.done ? T('an.applied') : T('an.apply_failed')}</p>` : ''}
      ${pv && pv.error ? `<p class="swb-hint" style="margin:.5rem 0 0">${esc(pv.error)}</p>` : ''}
      <p class="swb-hint" style="margin:.5rem 0 0">${T('an.write_note')}</p>`;
    return panel('', inner, 'accent');
  }

  function verdictTable(items, actionable) {
    if (!items || !items.length) {
      return `<p class="swb-hint" style="margin:0">${T('an.nothing')}</p>`;
    }
    return `<div class="swb-tablewrap" style="max-height:44vh"><table class="swb-table">
      <thead><tr><th>${T('an.c_subject')}</th><th>${T('an.c_verdict')}</th>
        <th>${T('an.c_uncertainty')}</th><th>${T('an.c_tags')}</th>
        <th>${T('an.c_fresh')}</th><th>${actionable ? T('an.c_actions') : ''}</th></tr></thead>
      <tbody>${items.map((v) => verdictRow(v, actionable)).join('')}</tbody></table></div>`;
  }

  function panelBlock(p) {
    const items = p.items || (p.inert ? [] : []);
    const head = `<p style="margin:0"><strong>${esc(p.headline || '')}</strong></p>
      <p style="margin:.3rem 0 0">${freshness(p)}</p>
      ${p.method ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(p.method)}</p>` : ''}
      ${p.why ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(p.why)}</p>` : ''}
      ${p.sampling_note ? `<p class="swb-hint" style="margin:.3rem 0 0">${
        esc(p.sampling_note)}</p>` : ''}`;
    /* Le tableau de bord des règles renvoie quatre familles nommées plutôt
     * qu'une liste plate : on les rend chacune avec son intitulé. */
    const families = ['inert', 'never_triggered', 'noisy', 'obsolete',
                      'dependency_break'];
    const hasFamilies = families.some((f) => p[f]);
    if (hasFamilies) {
      return panel('', head + families.filter((f) => p[f] && p[f].count).map((f) =>
        `<h4 class="swb-panel-title" style="margin-top:.8rem">${T('an.f_' + f)} — ${
          nf(p[f].count)}</h4>${verdictTable(p[f].items, true)}`).join(''), 'accent');
    }
    if (p.relay_summary && p.relay_summary.length) {
      return panel('', head + `<div class="swb-tablewrap" style="max-height:22vh;margin-top:.5rem">
        <table class="swb-table"><thead><tr><th>${T('an.c_intake')}</th>
          <th>${T('an.c_hosts')}</th><th>${T('an.c_family')}</th></tr></thead>
        <tbody>${p.relay_summary.map((r) => `<tr>
          <td class="swb-truncate">${esc(r.intake_name)}</td>
          <td class="swb-num"><strong>${nf(r.hosts)}</strong></td>
          <td class="swb-hint">${esc(r.family || '—')}</td></tr>`).join('')}
        </tbody></table></div>` + verdictTable(p.items, true), 'accent');
    }
    if (p.coverage_proven_pct !== undefined) {
      return panel('', head + `<div class="swb-stats">
        <div class="swb-stat"><span class="swb-stat-v">${nf(p.techniques_proven)}</span>
          <span class="swb-stat-k">${T('an.k_proven')}</span></div>
        <div class="swb-stat"><span class="swb-stat-v">${nf(p.techniques_declared)}</span>
          <span class="swb-stat-k">${T('an.k_declared')}</span></div>
        <div class="swb-stat"><span class="swb-stat-v">${nf(p.blind_spots.count)}</span>
          <span class="swb-stat-k">${T('an.k_blind')}</span></div></div>
        <p class="swb-hint" style="margin:.4rem 0 0">${esc(p.uncertainty || '')}</p>
        <div class="swb-tablewrap" style="max-height:34vh;margin-top:.5rem">
        <table class="swb-table"><tbody>${(p.items || []).slice(0, 150).map((t) =>
          `<tr><td class="swb-truncate swb-mono">${esc(t.technique)}</td>
           <td class="swb-num">${nf(t.rules_proven)}/${nf(t.rules_declared)}</td>
           <td><span class="swb-pill swb-pill-${t.status === 'prouvee' ? 'ok' : 'warn'
             } swb-pill-flat">${esc(t.status)}</span></td></tr>`).join('')}
        </tbody></table></div>`, 'accent');
    }
    if (p.debt_points !== undefined) {
      return panel('', head + `<div class="swb-tablewrap" style="margin-top:.5rem">
        <table class="swb-table"><tbody>${(p.lines || []).map((l) =>
          `<tr><td>${esc(l.item)}</td><td class="swb-num"><strong>${nf(l.count)}</strong></td>
           <td class="swb-hint">×${nf(l.weight)} — ${esc(l.action)}</td></tr>`).join('')}
        </tbody></table></div>
        <p class="swb-hint" style="margin:.4rem 0 0">${esc(p.uncertainty || '')}</p>`,
        'accent');
    }
    if (p.trends && p.trends.items) {
      return panel('', head + `<h4 class="swb-panel-title" style="margin-top:.8rem">${
        T('an.k_trends')} — ${nf(p.trends.count)}</h4>
        <p class="swb-hint" style="margin:0 0 .4rem">${esc(p.trends.meaning || '')}</p>
        <div class="swb-tablewrap" style="max-height:26vh"><table class="swb-table"><tbody>
          ${(p.trends.items || []).map((t) => `<tr>
            <td class="swb-truncate">${esc(t.intake_name)}</td>
            <td><span class="swb-pill swb-pill-warn swb-pill-flat">${esc(t.trend)}</span></td>
            <td class="swb-hint swb-truncate">${esc(t.meaning || '')}</td></tr>`).join('')}
        </tbody></table></div>` + verdictTable(p.items, true), 'accent');
    }
    if (p.coherence) {
      const fams = ['duplicates_id', 'duplicates_name', 'ghosts', 'orphans',
                    'unmapped', 'unused', 'obsolete', 'inert'];
      return panel('', head + `<div class="swb-tablewrap" style="max-height:40vh;margin-top:.5rem">
        <table class="swb-table"><thead><tr><th>${T('an.c_family')}</th>
          <th>${T('an.c_count')}</th><th>${T('an.c_meaning')}</th></tr></thead>
        <tbody>${fams.filter((f) => p.coherence[f]).map((f) => `<tr>
          <td>${T('an.k_' + f)}</td>
          <td class="swb-num"><strong>${nf(p.coherence[f].count)}</strong></td>
          <td class="swb-hint">${esc(p.coherence[f].meaning || '')}</td></tr>`).join('')}
        </tbody></table></div>
        <p class="swb-hint" style="margin:.4rem 0 0">${esc(p.coherence.note || '')}</p>`,
        'accent');
    }
    const lossFams = ['total_loss', 'partial_loss'];
    if (lossFams.some((f) => p[f])) {
      return panel('', head + lossFams.filter((f) => p[f] && p[f].count).map((f) =>
        `<h4 class="swb-panel-title" style="margin-top:.8rem">${T('an.k_' + f)} — ${
          nf(p[f].count)}</h4>${verdictTable(p[f].items, true)}`).join(''), 'accent');
    }
    const groups = ['without_logs', 'without_source', 'without_coverage',
                    'ghosts', 'orphans'];
    if (groups.some((g) => p[g])) {
      return panel('', head + groups.filter((g) => p[g] && p[g].count).map((g) =>
        `<h4 class="swb-panel-title" style="margin-top:.8rem">${T('an.g_' + g)} — ${
          nf(p[g].count)}</h4>${verdictTable(p[g].items, true)}`).join(''), 'accent');
    }
    return panel('', head + verdictTable(items, true), 'accent');
  }

  /* Réglages d'échantillonnage. Présents AVANT le calcul comme après, pour que
   * l'analyste puisse élargir sa fenêtre sans repartir de zéro. */
  function controls(name) {
    const hostView = (name === 'hostnames' || name === 'fortigate');
    const timeView = (name === 'sources' || name === 'intakes' || name === 'rules');
    return `<div class="swb-filters" style="margin-top:.5rem">
      ${!timeView ? `<label class="swb-hint">${T('an.f_window')}
        <select class="swb-input" id="an-window">${WINDOWS.map((w) =>
          `<option value="${w}"${w === st.window ? ' selected' : ''}>${w}</option>`
          ).join('')}</select></label>
        <label class="swb-hint">${T('an.f_sample')}
          <input class="swb-input" id="an-sample" type="number" min="200" max="10000"
            step="200" value="${st.sample}" style="width:7rem"></label>` : ''}
      ${timeView ? `<label class="swb-hint">${T('an.f_hours')}
        <input class="swb-input" id="an-hours" type="number" min="1" max="720"
          value="${st.hours}" style="width:6rem"></label>` : ''}
      ${hostView ? `<label class="swb-hint">${T('an.f_intake')}
          <input class="swb-input" id="an-intake" value="${esc(st.intake)}"
            placeholder="${T('an.f_intake_ph')}" style="width:14rem"></label>
        <label class="swb-hint"><input type="checkbox" id="an-relays"${
          st.relaysOnly ? ' checked' : ''}> ${T('an.f_relays')}</label>` : ''}
      <button type="button" class="fp-btn fp-btn-sm fp-btn-primary"
        data-an-act="dash:${name}"${st.busy.has('dash:' + name) ? ' disabled' : ''}>${
        st.busy.has('dash:' + name) ? T('an.computing') : T('an.compute')}</button>
    </div>`;
  }

  function viewDashboard(name) {
    const d = st.data['dash_' + name];
    if (!d) {
      return panel('', `<p class="swb-hint" style="margin:0">${T('an.idle')}</p>
        ${controls(name)}`);
    }
    if (d.ok === false) {
      return panel('', `<p style="margin:0">${esc(d.error)}</p>`, 'danger');
    }
    return `${panel('', `<p style="margin:0"><strong>${esc(d.headline || '')}</strong></p>
        <p style="margin:.3rem 0 0">${freshness(d)}</p>
        ${controls(name)}
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
                 'fields', 'formats', 'taxonomies', 'mitre',
                 'integration_types', 'groups', 'owners'];
    return `${panel(T('an.inv'), `
      <div class="swb-filters">
        <select class="swb-input" id="an-entity">${sel.map((e) =>
          `<option value="${e}"${e === st.entity ? ' selected' : ''}>${e}</option>`
          ).join('')}</select>
        <button type="button" class="fp-btn fp-btn-sm" data-an-act="inv"${
          st.busy.has('inv') ? ' disabled' : ''}>${
          st.busy.has('inv') ? T('an.computing') : T('an.read')}</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary"
          data-an-act="inv-refresh"${st.busy.has('inv') ? ' disabled' : ''}>${
          T('an.recollect')}</button>
      </div>
      <p class="swb-hint" style="margin:.4rem 0 0">${T('an.inv_sub')}</p>`)}
      ${!d ? '' : panel('', `<p style="margin:0"><strong>${nf(d.total)}</strong> ${
        T('an.objects')} · ${freshness(d)}
        ${d.total ? ` · ${T('an.inv_page', {
          a: nf((d.offset || 0) + 1), b: nf((d.offset || 0) + (d.returned || 0))
        })}` : ''}</p>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(d.note || '')}</p>
        <div class="swb-filters" style="margin:.5rem 0 0">
          <button type="button" class="fp-btn fp-btn-sm" data-an-act="inv-prev"${
            (d.offset || 0) <= 0 ? ' disabled' : ''}>${T('an.inv_prev')}</button>
          <button type="button" class="fp-btn fp-btn-sm" data-an-act="inv-next"${
            d.has_more ? '' : ' disabled'}>${T('an.inv_next')}</button>
        </div>
        <div class="swb-tablewrap" style="max-height:40vh;margin-top:.5rem">
        <table class="swb-table"><tbody>${(d.items || []).map((i) => {
          const bs = bulkSubjectFromRow(st.entity, i);
          const key = bs ? `${bs.target}:${bs.id}` : null;
          const openRow = key && st.bulkOpen === key;
          const label = esc(i.intake_name || i.rule_name || i.name || i.field
            || i.dialect_name || '—');
          const sub = esc(i.intake_status || i.connector_name || i.rule_enabled || '');
          const actBtn = bs ? `<button type="button" class="fp-btn fp-btn-sm"
              data-an-act="bulk-toggle" data-key="${esc(key)}"
              data-target="${esc(bs.target)}" data-id="${esc(bs.id)}">${
              T(openRow ? 'an.act_close' : 'an.act_open')}</button>` : '';
          return `<tr><td class="swb-truncate">${label}</td>
          <td class="swb-hint swb-truncate">${sub}</td>
          <td style="white-space:nowrap">${actBtn}</td></tr>${
            openRow ? `<tr><td colspan="3" style="padding:0">${bulkPanel(bs)}</td></tr>` : ''}`;
        }).join('')}
        </tbody></table></div>`, 'accent')}`;
  }

  function viewTags() {
    const d = st.data.tags;
    return `${panel(T('an.tags'), `<p class="swb-hint" style="margin:0 0 .5rem">${
        T('an.tags_sub')}</p>
      <button type="button" class="fp-btn fp-btn-sm fp-btn-primary"
        data-an-act="tags"${st.busy.has('tags') ? ' disabled' : ''}>${
        st.busy.has('tags') ? T('an.computing') : T('an.read')}</button>`)}
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
    return `<nav class="swb-nav">${GROUPS.map(([g, views]) =>
      `<span class="swb-nav-group"><span class="swb-nav-label">${esc(groupLabel(g))}</span>
        ${views.map(([id, key]) => `<button type="button"
          class="swb-tab" aria-selected="${st.view === id}" data-an-view="${id}">${
          T(key)}</button>`).join('')}</span>`).join(
      '<span class="swb-nav-sep"></span>')}</nav>`;
  }

  function paint() {
    const el = document.getElementById('analyst-root');
    if (!el) return;
    let body;
    // Le chargement est LOCAL a l'action (st.busy, un ensemble de cles), plus
    // jamais un verrou de PAGE ENTIERE : un tableau de bord peut demander
    // plusieurs dizaines de secondes, et geler toute la console pendant ce
    // temps empechait meme de changer d'onglet. Une erreur reste affichee
    // en plein ecran : elle interrompt reellement ce qu'on regardait.
    if (st.error) {
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
      // Les actions manuelles ne passent PAS par l'écran de chargement global :
      // il remplacerait toute la console et refermerait la ligne dépliée que
      // l'analyste est en train de regarder. Elles se traitent à part.
      if (act === 'bulk-toggle') {
        st.bulkOpen = st.bulkOpen === b.dataset.key ? null : b.dataset.key;
        paint(); return;
      }
      if (act === 'bulk-dry' || act === 'bulk-apply') {
        const { target, id, op } = b.dataset;
        const key = `${target}:${id}`;
        let tags = [];
        if (op === 'tag_add') {
          const raw = (document.getElementById(`an-bulk-tag-${id}`) || {}).value || '';
          tags = raw.split(',').map((x) => x.trim()).filter(Boolean);
          if (!tags.length) {
            st.bulkPreview[key] = { dry: true, op, error: T('an.need_tags') };
            paint(); return;
          }
        }
        try {
          const result = act === 'bulk-dry'
            ? await bulkDry(target, id, op, tags)
            : await bulkApply(target, id, op, tags);
          st.bulkPreview[key] = { dry: act === 'bulk-dry', op, result };
          // Une écriture reussie invalide les tableaux de bord deja calcules :
          // les rouvrir montrerait un etat perime sans le dire.
          if (act === 'bulk-apply' && result.done) {
            Object.keys(st.data).filter((k) => k.startsWith('dash_'))
              .forEach((k) => { delete st.data[k]; });
          }
        } catch (e) {
          st.bulkPreview[key] = { dry: act === 'bulk-dry', op, error: e.message };
        }
        paint(); return;
      }
      const g = (id) => document.getElementById(id);
      if (g('an-window')) st.window = g('an-window').value;
      if (g('an-sample')) st.sample = Math.max(200, Math.min(10000,
        parseInt(g('an-sample').value, 10) || 2000));
      if (g('an-hours')) st.hours = Math.max(1, Math.min(720,
        parseInt(g('an-hours').value, 10) || 24));
      if (g('an-intake')) st.intake = g('an-intake').value.trim();
      if (g('an-relays')) st.relaysOnly = g('an-relays').checked;
      if (g('an-entity')) st.entity = g('an-entity').value;
      // Numero de generation : un tableau de bord prend jusqu'a plusieurs
      // dizaines de secondes (il enchaine plusieurs mesures Sekoia). Si
      // l'analyste clique un second tableau avant que le premier ne reponde,
      // et que le PREMIER repond en dernier, il peindrait son contenu perime
      // par-dessus l'ecran deja a jour — exactement le defaut observe pendant
      // la validation de l'outil : ecrans qui semblent vides ou incoherents
      // lors d'un changement rapide, pris pour un incident reseau.
      const myGen = ++st.reqGen;
      const busyKey = act.startsWith('dash:') ? act
        : (act === 'inv' || act === 'inv-refresh' || act === 'inv-prev'
           || act === 'inv-next') ? 'inv' : act;
      st.busy.add(busyKey); st.error = null; paint();
      try {
        if (act.startsWith('dash:')) {
          const n = act.slice(5);
          const q = new URLSearchParams({
            window: st.window, sample: String(st.sample), hours: String(st.hours),
            relays_only: String(st.relaysOnly) });
          if (st.intake) q.set('intake', st.intake);
          const result = await api(`/dashboard/${n}?${q}`);
          if (myGen !== st.reqGen) return;   // supplantee par une action plus recente
          st.data['dash_' + n] = result;
        } else if (act === 'inv' || act === 'inv-refresh'
                   || act === 'inv-prev' || act === 'inv-next') {
          if (act === 'inv-refresh') {
            await api('/inventory/' + st.entity + '/refresh', { method: 'POST' });
            st.invOffset = 0;   // une recollecte repart de la premiere page
          } else if (act === 'inv') {
            st.invOffset = 0;   // changer d'entite ou relire repart au debut
          } else if (act === 'inv-prev') {
            st.invOffset = Math.max(0, st.invOffset - st.invLimit);
          } else if (act === 'inv-next') {
            const nxt = (st.data.inv || {}).next_offset;
            if (nxt != null) st.invOffset = nxt;
          }
          const result = await api('/inventory/' + st.entity
            + `?limit=${st.invLimit}&offset=${st.invOffset}`);
          if (myGen !== st.reqGen) return;
          st.data.inv = result;
        } else if (act === 'tags') {
          const result = await api('/tags');
          if (myGen !== st.reqGen) return;
          st.data.tags = result;
        }
      } catch (e) { if (myGen === st.reqGen) st.error = e.message; }
      finally { st.busy.delete(busyKey); }
      if (myGen !== st.reqGen) return;
      paint();
    });
  }

  function boot() {
    const el = document.getElementById('analyst-root');
    if (!el) return;
    paint();
    /* `i18n:language-changed` ne se declenche qu'au CHANGEMENT de langue, pas
     * au chargement initial : la console peignait donc avant que le
     * dictionnaire ne soit la, et affichait « an.v_sources » a l'analyste.
     * On repeint des que le dictionnaire repond, puis on s'arrete — une
     * scrutation qui ne se termine pas serait pire que le defaut qu'elle
     * corrige. */
    let tries = 0;
    const ready = setInterval(() => {
      tries += 1;
      if (T('an.v_sources') !== 'an.v_sources') {
        clearInterval(ready);
        paint();
      } else if (tries > 40) {          // 8 s : au-dela, le repli suffira
        clearInterval(ready);
      }
    }, 200);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else { boot(); }

  /* LA cause des libellés bruts. La console peignait AVANT que le dictionnaire
   * i18n ne soit charge — `t()` renvoyait alors la cle elle-meme, et rien ne
   * repeignait ensuite. La console SAGF ecoutait deja cet evenement ; celle-ci
   * ne l'ecoutait pas, et affichait donc « an.v_sources » a l'analyste.
   * Le meme abonnement couvre aussi le basculement FR/EN en cours de session. */
  window.addEventListener('i18n:language-changed', () => {
    if (document.getElementById('analyst-root')) paint();
  });
  window.analystConsole = { paint, state: st };
}());
