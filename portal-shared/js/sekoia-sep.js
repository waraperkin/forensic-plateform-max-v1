/* Sekoia Extended Platform — console des cas d'usage CERT.
 *
 * Un seul écran pour les 96 cas d'usage, organisés comme le CERT les pense :
 * cinq lentilles (inventaire, monitoring, détection, tableaux de bord, gestion)
 * traversant six entités (intakes, devices, assets natifs, groupes CERT, règles,
 * dépendances). La navigation suit cette grille et rien d'autre — pas
 * l'architecture interne, pas l'ordre d'implémentation.
 *
 * Trois partis pris d'affichage, tous issus de la QA du 04/08 :
 *   1. Aucun écran ne s'ouvre sur un formulaire vide. La vue d'accueil montre
 *      les déclenchements déjà collectés par le moteur, sans le moindre clic.
 *   2. Chaque résultat porte SON POURQUOI et SA REMÉDIATION. Une liste de noms
 *      sans explication oblige l'analyste à redemander « et alors ? ».
 *   3. Toute action de gestion affiche sa simulation avant de proposer
 *      d'appliquer. Sans exception.
 */
(function () {
  'use strict';
  const API = '/api/threat/sekoia/sep';

  const LENSES = [
    ['synthese', 'Synthèse'],
    ['inventaire', 'Inventaire'],
    ['monitoring', 'Monitoring'],
    ['detection', 'Détection'],
    ['dashboard', 'Dashboards'],
    ['gestion', 'Gestion'],
  ];

  const ENTITY_ORDER = ['intake', 'device', 'asset_native', 'asset_custom',
                        'rule', 'dependency'];
  const ENTITY_SHORT = {
    intake: 'Intakes', device: 'Devices', asset_native: 'Assets natifs',
    asset_custom: 'Groupes CERT', rule: 'Règles', dependency: 'Dépendances',
  };

  // Intitulés de colonne. Le back renvoie des noms de champ ; les afficher tels
  // quels (« parsing_ok_pct ») ferait lire une base de données à un analyste.
  const COL = {
    intake_name: 'Intake', device: 'Device', name: 'Nom', label: 'Objet',
    rule_name: 'Règle', dialect: 'Dialecte', dialects: 'Dialectes',
    criticality: 'Criticité', volume: 'Volume', devices_count: 'Devices',
    status: 'État', age_hours: 'Dernière obs.', evidence: 'Constat',
    intakes_count: 'Sources', kind: 'Nature', type: 'Type',
    rules_count: 'Règles', asset_type: 'Type d’asset', members_count: 'Membres',
    enabled: 'Active', rule_severity: 'Sévérité', alerts_count: 'Alertes',
    attack_count: 'MITRE', chain: 'Chaîne', broken_at: 'Rupture',
    slope_pct: 'Pente', flips: 'Bascules', parsing_ok_pct: 'Parsing',
    candidates_missing: 'Manquants', intruders_count: 'Intrus',
    age_days: 'Âge (j)', ratio: 'Ratio',
  };

  const SEV_TONE = { critique: 'danger', alerte: 'danger', attention: 'warn', info: 'mute' };

  const st = {
    lens: 'synthese', entity: 'intake', uc: null,
    catalog: null, result: null, findings: null, dash: null,
    manageOp: null, managePreview: null, groupDraft: null,
    hours: 24, days: 7,
    busy: new Set(), error: null, reqGen: 0,
  };

  /* i18n avec repli français explicite : la console ne doit JAMAIS afficher une
   * clé brute si le dictionnaire n'est pas encore chargé (défaut constaté sur
   * la console analystes). Le repli EST le texte de référence. */
  function T(key, fallback) {
    if (window.i18n && typeof i18n.t === 'function') {
      const out = i18n.t('sep.' + key);
      if (out && out !== 'sep.' + key) return out;
    }
    return fallback;
  }
  function esc(v) {
    return String(v === null || v === undefined ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
  function nf(n) {
    if (n === null || n === undefined || n === '' || isNaN(n)) return '—';
    return Number(n).toLocaleString('fr-FR');
  }
  function cell(key, v) {
    if (v === null || v === undefined || v === '') return '—';
    if (Array.isArray(v)) return v.length ? esc(v.slice(0, 4).join(', ')) : '—';
    if (typeof v === 'boolean') return v ? 'oui' : 'non';
    if (key === 'age_hours') return `${nf(v)} h`;
    if (key === 'slope_pct') return `${v > 0 ? '+' : ''}${nf(v)} %`;
    if (key === 'parsing_ok_pct') return `${nf(v)} %`;
    if (key === 'criticality' && typeof v === 'string') {
      const tone = v === 'critique' ? 'danger' : v === 'technique' ? 'warn' : 'mute';
      return `<span class="swb-pill swb-pill-${tone} swb-pill-flat">${esc(v)}</span>`;
    }
    if (typeof v === 'number') return nf(v);
    if (typeof v === 'object') return esc(JSON.stringify(v).slice(0, 80));
    return esc(String(v).slice(0, 160));
  }

  function withTimeout(o) {
    if (!o.signal && typeof AbortSignal !== 'undefined' && AbortSignal.timeout) {
      o.signal = AbortSignal.timeout(Number(window.THREAT_FETCH_TIMEOUT_MS || 180000));
    }
    return o;
  }
  async function api(path, opts) {
    const o = withTimeout(Object.assign(
      { credentials: 'include', cache: 'no-store' }, opts || {}));
    let r;
    try {
      r = await fetch(API + path, o);
    } catch (e) {
      if (e && (e.name === 'TimeoutError' || e.name === 'AbortError')) {
        throw new Error('Délai dépassé (3 min). Le calcul se poursuit côté '
          + 'serveur — réessayez dans un instant.');
      }
      throw e;
    }
    const d = await r.json().catch(() => ({}));
    if (!r.ok && d && d.error) throw new Error(d.error);
    if (d && d.ok === false && d.error) throw new Error(d.error);
    return d;
  }
  function post(path, body) {
    return api(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
  }

  function panel(title, inner, tone) {
    return `<div class="swb-panel"${tone ? ` style="border-left:3px solid var(--swb-${tone})"` : ''}>
      ${title ? `<h3 class="swb-panel-title">${esc(title)}</h3>` : ''}${inner}</div>`;
  }
  // « 1 Cycles » est le genre de détail qui fait douter du reste. L'accord se
  // fait sur la valeur, pas sur l'intitulé écrit en dur.
  function plural(n, one, many) {
    return Number(n) > 1 ? many : one;
  }
  function stat(value, label, tone) {
    return `<div class="swb-stat"><span class="swb-stat-v"${
      tone ? ` style="color:var(--swb-${tone})"` : ''}>${value}</span>
      <span class="swb-stat-k">${esc(label)}</span></div>`;
  }

  /* Bandeau moteur. La couverture du parcours d'actifs y figure parce qu'une
   * mesure partielle annoncée comme totale est un mensonge : tant que les
   * 106 000 actifs ne sont pas tous indexés, les groupes CERT ne voient qu'une
   * partie de la population, et l'analyste doit le savoir. */
  function engineBar(e) {
    if (!e) return '';
    const cov = e.assets_coverage_pct;
    const cycles = e.cycles || 0;
    const tone = e.last_error ? 'danger' : cycles ? 'ok' : 'warn';
    return `<div class="swb-stats" style="margin:0 0 .6rem">
      ${stat(cycles ? '● auto' : '○ démarrage', 'Moteur', tone)}
      ${stat(nf(cycles), plural(cycles, 'Cycle', 'Cycles'))}
      ${stat(e.last_cycle ? esc(String(e.last_cycle).slice(11, 16)) + ' UTC' : '—', 'Dernier cycle')}
      ${stat(cov === null || cov === undefined ? '—' : nf(cov) + ' %', 'Actifs indexés')}
      ${stat(nf(e.assets_indexed) + (e.assets_total ? ' / ' + nf(e.assets_total) : ''), 'Population')}
    </div>
    ${e.last_error ? `<p class="swb-hint" style="margin:0 0 .5rem;color:var(--swb-danger)">
      Dernier cycle en échec : ${esc(e.last_error)}</p>` : ''}
    <p class="swb-hint" style="margin:0 0 .8rem">${esc(e.history_note || '')}</p>`;
  }

  // ── Vue : synthèse (full-auto) ────────────────────────────────────────────
  function viewSynthese() {
    const f = st.findings;
    const cat = st.catalog;
    const counts = cat ? cat.counts : null;
    const head = panel('', `
      <p style="margin:0"><strong>${T('lead', 'Le moteur évalue les cas de détection '
        + 'en continu et conserve chaque déclenchement. Cette page montre ce qu\'il a '
        + 'trouvé sans qu\'on le lui demande.')}</strong></p>
      ${counts ? `<div class="swb-stats" style="margin-top:.6rem">
        ${stat(nf(counts.total), 'Cas d’usage')}
        ${stat(nf(counts.use_cases), plural(counts.use_cases, 'Analyse', 'Analyses'))}
        ${stat(nf(counts.dashboards), plural(counts.dashboards, 'Tableau de bord',
          'Tableaux de bord'))}
        ${stat(nf(counts.management), plural(counts.management, 'Opération', 'Opérations'))}</div>` : ''}
      ${engineBar((f && f.engine) || (cat && cat.engine))}
      ${st.findingsError ? `<p class="swb-hint" style="margin:0 0 .5rem;color:var(--swb-danger)">
        Flux des déclenchements indisponible : ${esc(st.findingsError)}</p>` : ''}
      <div class="swb-filters">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-sep-act="findings"${
          st.busy.has('findings') ? ' disabled' : ''}>${
          st.busy.has('findings') ? 'Chargement…' : 'Rafraîchir'}</button>
        <button type="button" class="fp-btn fp-btn-sm" data-sep-act="cycle"${
          st.busy.has('cycle') ? ' disabled' : ''}>${
          st.busy.has('cycle') ? 'Cycle en cours…' : 'Lancer un cycle maintenant'}</button>
      </div>
      <p class="swb-hint" style="margin:.5rem 0 0">${T('cycle_hint',
        'Un cycle prélève un échantillon d’événements, mesure le parsing, '
        + 'enrichit l’historique des atomes, indexe une tranche d’actifs puis '
        + 'réévalue les 24 cas de détection. Il tourne seul toutes les 15 minutes.')}</p>`,
      'accent');

    if (!f) return head;
    if (!f.items || !f.items.length) {
      return head + panel('', `<p style="margin:0">${T('no_findings',
        'Aucun déclenchement enregistré sur les dernières 24 heures. Soit le '
        + 'moteur vient de démarrer et son historique se constitue, soit rien '
        + 'ne va mal — les deux se distinguent au compteur de cycles ci-dessus.')}</p>`);
    }
    const bySev = f.by_severity || {};
    const byCase = Object.entries(f.by_case || {}).sort((a, b) => b[1] - a[1]);
    return head
      + panel('Déclenchements par sévérité', `<div class="swb-stats">
        ${['critique', 'alerte', 'attention', 'info'].map((s) =>
          stat(nf(bySev[s] || 0), s, SEV_TONE[s])).join('')}</div>`)
      + panel('Cas d’usage actifs', `<div class="swb-tablewrap" style="max-height:26vh">
        <table class="swb-table"><tbody>${byCase.map(([id, n]) => {
          const uc = ucById(id);
          return `<tr><td class="swb-truncate">
            <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost"
              data-sep-act="open-uc" data-uc="${esc(id)}">${esc(uc ? uc.title : id)}</button></td>
            <td class="swb-num"><strong>${nf(n)}</strong></td>
            <td class="swb-hint swb-truncate">${esc(uc ? uc.remediation : '')}</td></tr>`;
        }).join('')}</tbody></table></div>`)
      + panel('Derniers constats', `<div class="swb-tablewrap" style="max-height:40vh">
        <table class="swb-table"><thead><tr><th>Objet</th><th>Cas</th>
          <th>Constat</th><th>Sévérité</th><th>Quand</th></tr></thead>
        <tbody>${f.items.slice(0, 150).map((i) => `<tr>
          <td class="swb-truncate" title="${esc(i.subject)}"><strong>${esc(i.subject)}</strong></td>
          <td class="swb-hint swb-truncate">${esc(i.title)}</td>
          <td class="swb-hint swb-truncate" title="${esc(i.evidence)}">${esc(i.evidence)}</td>
          <td><span class="swb-pill swb-pill-${SEV_TONE[i.severity] || 'mute'} swb-pill-flat">${
            esc(i.severity)}</span></td>
          <td class="swb-hint">${esc(String(i['@timestamp'] || '').slice(5, 16).replace('T', ' '))}</td>
        </tr>`).join('')}</tbody></table></div>`);
  }

  function ucById(id) {
    if (!st.catalog) return null;
    const groups = st.catalog.use_cases || {};
    for (const lens of Object.keys(groups)) {
      for (const ent of Object.keys(groups[lens])) {
        const hit = groups[lens][ent].find((u) => u.id === id);
        if (hit) return hit;
      }
    }
    return null;
  }

  function casesFor(lens, entity) {
    const groups = (st.catalog && st.catalog.use_cases) || {};
    return ((groups[lens] || {})[entity]) || [];
  }

  // ── Vue : lentille d'analyse (inventaire / monitoring / détection) ────────
  function viewAnalysis() {
    const cases = casesFor(st.lens, st.entity);
    const list = panel('', `
      <div class="swb-filters" style="margin-bottom:.5rem">
        <label class="swb-hint">Fenêtre
          <select class="swb-input" id="sep-hours">${
            [6, 12, 24, 48, 72, 168].map((h) =>
              `<option value="${h}"${h === st.hours ? ' selected' : ''}>${h} h</option>`
            ).join('')}</select></label>
        <label class="swb-hint">Alertes sur
          <select class="swb-input" id="sep-days">${
            [1, 7, 14, 30].map((d) =>
              `<option value="${d}"${d === st.days ? ' selected' : ''}>${d} j</option>`
            ).join('')}</select></label>
      </div>
      <div class="sep-cards">${cases.map((u) => {
        const on = st.uc === u.id;
        const n = st.result && st.result.id === u.id ? st.result.count : null;
        return `<button type="button" class="sep-card${on ? ' sep-card-on' : ''}"
          data-sep-act="uc" data-uc="${esc(u.id)}">
          <span class="sep-card-t">${esc(u.title)}</span>
          <span class="sep-card-w">${esc(u.why)}</span>
          <span class="sep-card-f">
            <span class="swb-pill swb-pill-${SEV_TONE[u.severity] || 'mute'} swb-pill-flat">${
              esc(u.severity)}</span>
            ${u.signal ? `<span class="swb-pill swb-pill-mute swb-pill-flat">${
              esc(u.signal)}</span>` : ''}
            ${n !== null ? `<span class="sep-card-n">${nf(n)}</span>` : ''}
          </span></button>`;
      }).join('')}</div>`, 'accent');
    return list + resultPanel();
  }

  function resultPanel() {
    if (st.busy.has('uc')) {
      return panel('', `<p class="swb-hint" style="margin:0">Mesure en cours…</p>`);
    }
    const r = st.result;
    if (!r) {
      return panel('', `<p class="swb-hint" style="margin:0">${T('pick',
        'Choisissez un cas d’usage ci-dessus. Chaque carte indique ce que le cas '
        + 'mesure et pourquoi Sekoia ne peut pas le faire.')}</p>`);
    }
    const cols = r.columns || [];
    // « info : 4 » sous une carte marquée « alerte » se lit comme une
    // contradiction : la carte porte la gravité DU CAS, ces pastilles celle des
    // objets retenus. Le libellé lève l'ambiguïté au lieu de la commenter.
    const sevEntries = Object.entries(r.severities || {});
    const sevPills = sevEntries.length
      ? `<span class="swb-hint">Niveau des objets :</span> ` + sevEntries.map(([s, n]) =>
        `<span class="swb-pill swb-pill-${SEV_TONE[s] || 'mute'} swb-pill-flat">${
          nf(n)} en ${esc(s)}</span>`).join(' ')
      : '';
    const head = `<p style="margin:0"><strong>${esc(r.verdict)}</strong></p>
      <p class="swb-hint" style="margin:.3rem 0 0">${esc(r.why)}</p>
      <p style="margin:.5rem 0 0">${sevPills}
        <span class="swb-pill swb-pill-mute swb-pill-flat">mesuré en ${
          nf(r.duration_s)} s</span>
        <span class="swb-pill swb-pill-mute swb-pill-flat">${
          esc(String(r.measured_at || '').slice(11, 16))} UTC</span></p>
      <p class="swb-hint" style="margin:.4rem 0 0"><strong>Que faire :</strong> ${
        esc(r.remediation)}</p>
      ${r.truncated ? `<p class="swb-hint" style="margin:.3rem 0 0">Affichage limité à ${
        nf(r.returned)} lignes sur ${nf(r.count)}.</p>` : ''}
      <div class="swb-filters" style="margin-top:.5rem">
        <button type="button" class="fp-btn fp-btn-sm" data-sep-act="uc"
          data-uc="${esc(r.id)}">Recalculer</button>
        <button type="button" class="fp-btn fp-btn-sm" data-sep-act="export-uc"
          data-uc="${esc(r.id)}">Exporter (JSON)</button>
      </div>`;
    if (!r.items || !r.items.length) {
      return panel('', head + `<p class="swb-hint" style="margin:.6rem 0 0">${
        T('empty_case', 'Aucun objet ne remplit ce critère. C’est un résultat, '
          + 'pas une absence de mesure : ' + nf(r.total_measured)
          + ' objet(s) ont été examinés.')}</p>`, 'accent');
    }
    return panel('', head, 'accent') + panel('', `
      <div class="swb-tablewrap" style="max-height:52vh"><table class="swb-table">
        <thead><tr>${cols.map((c) => `<th>${esc(COL[c] || c)}</th>`).join('')}</tr></thead>
        <tbody>${r.items.map((it) => `<tr>${cols.map((c, i) =>
          `<td class="${i === 0 ? 'swb-truncate' : c === 'evidence' ? 'swb-hint swb-truncate' : ''}"
             title="${esc(typeof it[c] === 'object' ? '' : it[c])}">${
            i === 0 ? `<strong>${cell(c, it[c])}</strong>` : cell(c, it[c])}</td>`).join('')}
        </tr>`).join('')}</tbody></table></div>`);
  }

  // ── Vue : tableaux de bord ────────────────────────────────────────────────
  function viewDashboards() {
    const list = (st.catalog && st.catalog.dashboards) || {};
    const cards = panel('', `<div class="sep-cards">${Object.values(list).map((d) => {
      const on = st.dash && st.dash.id === d.id;
      return `<button type="button" class="sep-card${on ? ' sep-card-on' : ''}"
        data-sep-act="dash" data-dash="${esc(d.id)}">
        <span class="sep-card-t">${esc(d.title)}</span>
        <span class="sep-card-w">${esc(d.why)}</span></button>`;
    }).join('')}</div>`, 'accent');
    if (st.busy.has('dash')) {
      return cards + panel('', '<p class="swb-hint" style="margin:0">Calcul en cours…</p>');
    }
    const d = st.dash;
    if (!d) {
      return cards + panel('', `<p class="swb-hint" style="margin:0">${T('pick_dash',
        'Chaque tableau de bord compose plusieurs cas d’usage sur une même '
        + 'population, mesurée une seule fois.')}</p>`);
    }
    const agg = d.aggregate;
    return cards + panel('', `<p style="margin:0"><strong>${esc(d.title)}</strong> — ${
        nf(d.population)} ${esc(d.entity_label.toLowerCase())} mesuré(s)</p>
      <p class="swb-hint" style="margin:.3rem 0 0">${esc(d.why)}</p>`, 'accent')
      + (agg ? aggregatePanel(agg) : '')
      + panel('', `<div class="sep-tiles">${(d.tiles || []).map((t) => `
        <div class="sep-tile sep-tile-${SEV_TONE[t.severity] || 'mute'}">
          <button type="button" class="sep-tile-h" data-sep-act="open-uc" data-uc="${esc(t.id)}">
            <span class="sep-tile-n">${nf(t.count)}</span>
            <span class="sep-tile-t">${esc(t.title)}</span></button>
          <p class="sep-tile-w">${esc(t.why)}</p>
          ${t.top && t.top.length ? `<ul class="sep-tile-l">${t.top.map((x) =>
            `<li><span class="swb-truncate" title="${esc(x.name)}">${esc(x.name)}</span>
             <em>${cell('', x.value)}</em></li>`).join('')}</ul>`
            : '<p class="sep-tile-e">aucun cas</p>'}
          <p class="sep-tile-r">${esc(t.remediation)}</p>
        </div>`).join('')}</div>`);
  }

  function aggregatePanel(a) {
    if (a.kind === 'mitre') {
      return panel('Couverture MITRE', `<div class="swb-stats">
        ${stat(nf(a.techniques_declared), 'Techniques déclarées')}
        ${stat(nf(a.techniques_proven), 'Techniques prouvées', 'ok')}
        ${stat(nf(a.coverage_proven_pct) + ' %', 'Couverture prouvée',
          a.coverage_proven_pct < 50 ? 'danger' : 'ok')}
        ${stat(nf(a.blind_spots_count), 'Angles morts', 'warn')}</div>
        <p class="swb-hint" style="margin:.5rem 0 0">${esc(a.note)}</p>`, 'accent');
    }
    if (a.kind === 'parsing') {
      return panel('Qualité d’ingestion', `<div class="swb-stats">
        ${stat(nf(a.intakes_measured), 'Intakes mesurés')}
        ${stat(a.mean_ok_pct === null ? '—' : nf(a.mean_ok_pct) + ' %', 'Parsing moyen',
          (a.mean_ok_pct || 100) < 95 ? 'warn' : 'ok')}
        ${stat(nf(a.intakes_degraded), 'Parsing dégradé', 'danger')}
        ${stat(nf(a.dialect_mismatch), 'Dialecte incohérent', 'warn')}
        ${stat(nf(a.schema_drift), 'Dérive structurelle', 'warn')}
        ${stat(nf(a.intakes_unmeasured), 'Non mesurés')}</div>
        <p class="swb-hint" style="margin:.5rem 0 0">${esc(a.note)}</p>`, 'accent');
    }
    return '';
  }

  // ── Vue : gestion ─────────────────────────────────────────────────────────
  function viewGestion() {
    const ops = (st.catalog && st.catalog.management) || {};
    const cards = panel('', `<p class="swb-hint" style="margin:0 0 .6rem">${T('mgmt_lead',
        'Toute opération est simulée d’abord. Le bouton « Appliquer » n’apparaît '
        + 'qu’après une simulation, et jamais avant.')}</p>
      <div class="sep-cards">${Object.values(ops).map((o) => {
        const on = st.manageOp === o.id;
        return `<button type="button" class="sep-card${on ? ' sep-card-on' : ''}"
          data-sep-act="mgmt" data-op="${esc(o.id)}">
          <span class="sep-card-t">${esc(o.title)}</span>
          <span class="sep-card-w">${esc(o.why)}</span>
          <span class="sep-card-f">
            <span class="swb-pill swb-pill-${o.scope === 'sekoia' ? 'warn' : 'mute'} swb-pill-flat">${
              o.scope === 'sekoia' ? 'écrit dans Sekoia' : 'local à la plateforme'}</span>
          </span></button>`;
      }).join('')}</div>`, 'accent');
    if (!st.manageOp) {
      return cards + panel('', `<p class="swb-hint" style="margin:0">${T('pick_mgmt',
        'Choisissez une opération. Les groupes CERT se gèrent ici : ce sont les '
        + 'seuls objets que la plateforme possède en propre.')}</p>`);
    }
    const spec = ops[st.manageOp];
    const pv = st.managePreview;
    return cards + panel(spec.title, `
      <p class="swb-hint" style="margin:0 0 .5rem">${esc(spec.why)}</p>
      <div class="swb-filters">
        ${spec.operations.map((op) => `<button type="button" class="fp-btn fp-btn-sm"
          data-sep-act="mgmt-dry" data-op="${esc(st.manageOp)}" data-operation="${esc(op)}"${
          st.busy.has('mgmt') ? ' disabled' : ''}>${esc(op)}</button>`).join('')}
      </div>
      ${spec.entity === 'asset_custom' ? groupForm() : ''}
      ${spec.scope === 'sekoia' ? `<label class="swb-hint" style="display:block;margin-top:.5rem">
        Identifiants (un par ligne)
        <textarea class="swb-input" id="sep-ids" rows="3" style="width:100%"
          placeholder="uuid-1&#10;uuid-2"></textarea></label>
        <label class="swb-hint">Étiquettes (séparées par des virgules)
          <input class="swb-input" id="sep-tags" style="width:16rem"></label>` : ''}
      ${st.busy.has('mgmt') ? '<p class="swb-hint" style="margin:.6rem 0 0">En cours…</p>' : ''}
      ${pv ? previewBlock(pv) : `<p class="swb-hint" style="margin:.6rem 0 0">${
        T('mgmt_hint', 'Aucune simulation lancée. Rien n’a été écrit.')}</p>`}`, 'accent');
  }

  function groupForm() {
    const g = st.groupDraft || {};
    return `<details class="sep-form"${st.groupDraft ? ' open' : ''}>
      <summary>Définir un groupe</summary>
      <div class="swb-filters" style="margin-top:.5rem;flex-wrap:wrap">
        <label class="swb-hint">Identifiant
          <input class="swb-input" id="sep-g-id" value="${esc(g.id || '')}"
            placeholder="admins" style="width:10rem"></label>
        <label class="swb-hint">Nom
          <input class="swb-input" id="sep-g-name" value="${esc(g.name || '')}"
            style="width:12rem"></label>
        <label class="swb-hint">Nature
          <select class="swb-input" id="sep-g-kind">${
            ['critique', 'technique', 'metier'].map((k) =>
              `<option value="${k}"${k === g.kind ? ' selected' : ''}>${k}</option>`
            ).join('')}</select></label>
        <label class="swb-hint">Type d’asset
          <select class="swb-input" id="sep-g-type">${
            ['account', 'host', 'network', 'domain', 'email', 'hash', 'any'].map((k) =>
              `<option value="${k}"${k === g.asset_type ? ' selected' : ''}>${k}</option>`
            ).join('')}</select></label>
        <label class="swb-hint">Critère (expression régulière sur le nom)
          <input class="swb-input" id="sep-g-regex" value="${esc(
            (g.selector && g.selector.name_regex) || '')}"
            placeholder="(?i)^adm" style="width:18rem"></label>
      </div>
      <p class="swb-hint" style="margin:.4rem 0 0">${T('group_hint',
        'Un groupe défini par un critère ne vieillit pas : chaque nouvel actif '
        + 'qui le remplit y entre. Une liste figée, elle, se périme au premier '
        + 'mouvement de personnel.')}</p></details>`;
  }

  function previewBlock(pv) {
    if (pv.error) {
      return `<p style="margin:.6rem 0 0;color:var(--swb-danger)">${esc(pv.error)}</p>`;
    }
    const r = pv.result || {};
    const canApply = r.dry_run && !r.error
      && (r.selected || r.would_resolve || r.changes || r.accepted
          || (r.result && r.result.selected) || r.would_remove);
    return `<div class="swb-hint" style="margin:.6rem 0 0">
      <strong>${r.dry_run === false ? 'Appliqué' : 'Simulation'}</strong> — ${
        esc(r.note || '')}
      <pre class="sep-pre">${esc(JSON.stringify(stripNoise(r), null, 1).slice(0, 4000))}</pre>
      ${canApply ? `<button type="button" class="fp-btn fp-btn-sm fp-btn-danger"
        data-sep-act="mgmt-apply" data-op="${esc(st.manageOp)}"
        data-operation="${esc(pv.operation)}">Appliquer réellement</button>` : ''}
    </div>`;
  }
  function stripNoise(r) {
    const out = {};
    Object.keys(r || {}).forEach((k) => {
      if (k === 'groups' && Array.isArray(r[k])) { out[k] = `${r[k].length} groupe(s)`; return; }
      out[k] = r[k];
    });
    return out;
  }

  // ── Charpente ─────────────────────────────────────────────────────────────
  function nav() {
    const lenses = `<nav class="swb-nav">${LENSES.map(([id, label]) =>
      `<button type="button" class="swb-tab" aria-selected="${st.lens === id}"
        data-sep-lens="${id}">${esc(label)}</button>`).join('')}</nav>`;
    const analysis = ['inventaire', 'monitoring', 'detection'].includes(st.lens);
    if (!analysis) return lenses;
    const ents = (st.catalog && st.catalog.use_cases[st.lens]) || {};
    return lenses + `<nav class="swb-nav" style="margin-top:.3rem">${
      ENTITY_ORDER.filter((e) => ents[e]).map((e) =>
        `<button type="button" class="swb-tab" aria-selected="${st.entity === e}"
          data-sep-entity="${e}">${esc(ENTITY_SHORT[e])}
          <span class="sep-nav-n">${ents[e].length}</span></button>`).join('')}</nav>`;
  }

  function body() {
    if (st.error) {
      return panel('', `<p style="margin:0">${esc(st.error)}</p>
        <button type="button" class="fp-btn fp-btn-sm" style="margin-top:.5rem"
          data-sep-act="retry">Réessayer</button>`, 'danger');
    }
    if (!st.catalog) {
      return panel('', '<p class="swb-hint" style="margin:0">Chargement du catalogue…</p>');
    }
    if (st.lens === 'synthese') return viewSynthese();
    if (st.lens === 'dashboard') return viewDashboards();
    if (st.lens === 'gestion') return viewGestion();
    return viewAnalysis();
  }

  function paint() {
    const el = document.getElementById('sekoia-sep-root');
    if (!el) return;
    el.className = 'swb sep';
    el.innerHTML = `<div class="swb-head"><div>
        <h2 class="swb-title">${T('title', 'Cas d’usage CERT')}</h2>
        <p class="swb-sub">${T('sub', 'Inventaire, monitoring, détection, tableaux '
          + 'de bord et gestion — sur intakes, devices, assets natifs, groupes CERT, '
          + 'règles et dépendances. Ce que le SIEM ne restitue pas.')}</p>
      </div></div>${nav()}<div class="swb-body">${body()}</div>`;
    bind(el);
  }

  async function loadCatalog() {
    if (st.catalog || st.busy.has('catalog')) return;
    st.busy.add('catalog');
    try {
      st.catalog = await api('/catalog');
      st.error = null;
    } catch (e) { st.error = e.message; }
    finally { st.busy.delete('catalog'); }
    paint();
    if (st.lens === 'synthese') loadFindings();
  }

  /* L'échec du flux de déclenchements ne doit PAS masquer la console : le
   * catalogue, les tableaux de bord et la gestion restent utilisables sans lui.
   * Une erreur pleine page ici rendrait l'outil entier inaccessible pour une
   * panne de son écran d'accueil. */
  async function loadFindings() {
    if (st.busy.has('findings')) return;
    st.busy.add('findings'); paint();
    try {
      st.findings = await api('/findings?hours=24');
      st.findingsError = null;
    } catch (e) { st.findingsError = e.message; }
    finally { st.busy.delete('findings'); }
    paint();
  }

  async function runUC(id) {
    const gen = ++st.reqGen;
    st.uc = id; st.busy.add('uc'); st.error = null; paint();
    try {
      const r = await api(`/uc/${encodeURIComponent(id)}?hours=${st.hours}&days=${st.days}`);
      if (gen !== st.reqGen) return;
      st.result = r;
    } catch (e) { if (gen === st.reqGen) st.error = e.message; }
    finally { st.busy.delete('uc'); }
    if (gen === st.reqGen) paint();
  }

  async function runDash(id) {
    const gen = ++st.reqGen;
    st.busy.add('dash'); st.error = null; paint();
    try {
      const r = await api(`/dashboard/${encodeURIComponent(id)}?hours=${st.hours}&days=${st.days}`);
      if (gen !== st.reqGen) return;
      st.dash = r;
    } catch (e) { if (gen === st.reqGen) st.error = e.message; }
    finally { st.busy.delete('dash'); }
    if (gen === st.reqGen) paint();
  }

  function readGroupDraft() {
    const g = (id) => (document.getElementById(id) || {}).value || '';
    const id = g('sep-g-id').trim();
    if (!id) return null;
    return {
      id, name: g('sep-g-name').trim() || id, kind: g('sep-g-kind') || 'metier',
      asset_type: g('sep-g-type') || 'any',
      selector: g('sep-g-regex').trim()
        ? { name_regex: g('sep-g-regex').trim(), type: g('sep-g-type') || 'any' }
        : {},
    };
  }

  async function runManage(opId, operation, dry) {
    const spec = (st.catalog.management || {})[opId] || {};
    const body = { operation, dry_run: dry ? 1 : 0 };
    if (spec.entity === 'asset_custom') {
      const draft = readGroupDraft();
      if (draft) { body.group = draft; body.group_id = draft.id; st.groupDraft = draft; }
      const sel = document.getElementById('sep-g-id');
      if (sel && sel.value.trim()) body.group_id = sel.value.trim();
    }
    const ids = (document.getElementById('sep-ids') || {}).value || '';
    if (ids.trim()) body.ids = ids.split('\n').map((s) => s.trim()).filter(Boolean);
    const tags = (document.getElementById('sep-tags') || {}).value || '';
    if (tags.trim()) body.tags = tags.split(',').map((s) => s.trim()).filter(Boolean);

    st.busy.add('mgmt'); paint();
    try {
      const result = await post(`/manage/${encodeURIComponent(opId)}`, body);
      st.managePreview = { operation, result };
    } catch (e) {
      st.managePreview = { operation, error: e.message };
    } finally { st.busy.delete('mgmt'); }
    paint();
  }

  function bind(el) {
    if (el.dataset.sepBound) return;
    el.dataset.sepBound = '1';
    el.addEventListener('click', async (ev) => {
      const lens = ev.target.closest('[data-sep-lens]');
      if (lens) {
        st.lens = lens.dataset.sepLens; st.error = null;
        const ents = (st.catalog && st.catalog.use_cases[st.lens]) || {};
        if (!ents[st.entity]) st.entity = ENTITY_ORDER.find((e) => ents[e]) || st.entity;
        paint();
        if (st.lens === 'synthese' && !st.findings) loadFindings();
        return;
      }
      const ent = ev.target.closest('[data-sep-entity]');
      if (ent) { st.entity = ent.dataset.sepEntity; st.result = null; paint(); return; }
      const b = ev.target.closest('[data-sep-act]');
      if (!b) return;
      const act = b.dataset.sepAct;
      const g = (id) => document.getElementById(id);
      if (g('sep-hours')) st.hours = parseInt(g('sep-hours').value, 10) || 24;
      if (g('sep-days')) st.days = parseInt(g('sep-days').value, 10) || 7;

      if (act === 'uc') { runUC(b.dataset.uc); return; }
      if (act === 'open-uc') {
        // Ouvrir un cas depuis la synthèse ou un tableau de bord : on bascule
        // sur SA lentille et SON entité, sinon la navigation mentirait sur
        // l'endroit où l'analyste se trouve.
        const uc = ucById(b.dataset.uc);
        if (uc) { st.lens = uc.lens; st.entity = uc.entity; }
        runUC(b.dataset.uc);
        return;
      }
      if (act === 'dash') { runDash(b.dataset.dash); return; }
      if (act === 'findings') { loadFindings(); return; }
      if (act === 'retry') { st.error = null; st.catalog = null; paint(); loadCatalog(); return; }
      if (act === 'export-uc') {
        window.open(`${API}/uc/${encodeURIComponent(b.dataset.uc)}?hours=${st.hours}`
          + `&days=${st.days}&limit=2000`, '_blank', 'noopener');
        return;
      }
      if (act === 'cycle') {
        st.busy.add('cycle'); paint();
        try { await post('/cycle', {}); st.findings = null; } catch (e) { st.error = e.message; }
        finally { st.busy.delete('cycle'); }
        loadFindings();
        return;
      }
      if (act === 'mgmt') {
        st.manageOp = b.dataset.op; st.managePreview = null; paint(); return;
      }
      if (act === 'mgmt-dry') { runManage(b.dataset.op, b.dataset.operation, true); return; }
      if (act === 'mgmt-apply') { runManage(b.dataset.op, b.dataset.operation, false); return; }
    });
  }

  /* Amorçage à l'OUVERTURE de l'onglet, pas au chargement de la page (appelé
   * par cert-app.js). Charger le catalogue à chaque visite du portail
   * coûterait une requête pour un écran que l'analyste n'ouvre pas toujours. */
  function boot() {
    if (!document.getElementById('sekoia-sep-root')) return;
    paint();
    loadCatalog();
  }

  window.addEventListener('i18n:language-changed', () => {
    if (document.getElementById('sekoia-sep-root')) paint();
  });
  window.SekoiaSEP = { boot, paint, state: st };
}());
