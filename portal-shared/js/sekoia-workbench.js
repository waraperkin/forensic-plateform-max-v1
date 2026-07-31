/* ═══════════════════════════════════════════════════════════════════════════
   SEKOIA WORKBENCH — console unifiée de la couche Sekoia.
   Remplace neuf écrans hétérogènes par une seule surface de travail :
   Vue d'ensemble · Sources · Détections · Télémétrie · Alerting ·
   Opérations · Clés API · Audit · Configuration.

   Parti pris produit :
   - navigation par MISSION, pas par objet technique ;
   - le tableau est l'écran principal, le détail arrive en volet latéral —
     on ne perd jamais sa position dans la liste ;
   - recherche et tri instantanés côté client sur les jeux déjà chargés,
     pagination côté serveur pour les gros volumes (1180 règles) ;
   - raccourcis clavier ( / recherche, Échap ferme, g+lettre navigue ) ;
   - aucune donnée fabriquée : « non mesuré » n'est jamais rendu comme 0 ;
   - aucun message technique brut : états dégradés dessinés avec relance.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  const TC = window.ThreatCommon || null;
  const esc = (s) => (TC && TC.esc ? TC.esc(s) : String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));
  const toast = (m, c) => { if (TC && TC.toast) TC.toast(m, c); };
  const API = '/api/threat/sekoia';

  const VIEWS = [
    { id: 'overview', label: "Vue d'ensemble", key: 'o', group: 1 },
    { id: 'sources', label: 'Sources', key: 's', group: 1 },
    { id: 'detections', label: 'Détections', key: 'd', group: 1 },
    { id: 'inventory', label: 'Inventaire', key: 'i', group: 1 },
    { id: 'telemetry', label: 'Télémétrie', key: 't', group: 1 },
    { id: 'alerting', label: 'Alerting', key: 'a', group: 2 },
    { id: 'operations', label: 'Opérations', key: 'p', group: 2 },
    { id: 'apikeys', label: 'Clés API', key: 'k', group: 3 },
    { id: 'audit', label: 'Audit', key: 'u', group: 3 },
    { id: 'config', label: 'Configuration', key: 'c', group: 3 },
  ];

  const st = {
    view: 'overview', range: 24, loading: false, error: null,
    q: '', filters: {}, sort: null, sortDir: -1,
    drawer: null, data: {}, badges: {},
  };

  // ── Utilitaires ───────────────────────────────────────────────────────────
  const lang = () => ((window.i18n && i18n.getLanguage && i18n.getLanguage() === 'en') ? 'en-US' : 'fr-FR');
  function nf(n) {
    if (n === null || n === undefined || n === '') return '—';
    const v = Number(n);
    return Number.isFinite(v) ? v.toLocaleString(lang()) : String(n);
  }
  function compact(n) {
    const v = Number(n) || 0;
    if (v >= 1e9) return (v / 1e9).toFixed(1) + ' G';
    if (v >= 1e6) return (v / 1e6).toFixed(1) + ' M';
    if (v >= 1e3) return (v / 1e3).toFixed(1) + ' k';
    return String(v);
  }
  function dt(s) {
    if (!s) return '—';
    return String(s).replace('T', ' ').replace(/\.\d+Z?$/, '').slice(0, 16);
  }
  function ago(s) {
    if (!s) return '—';
    const ms = Date.now() - new Date(s).getTime();
    if (!Number.isFinite(ms)) return '—';
    const m = Math.round(ms / 60000);
    if (m < 1) return "à l'instant";
    if (m < 60) return `il y a ${m} min`;
    const h = Math.round(m / 60);
    if (h < 48) return `il y a ${h} h`;
    return `il y a ${Math.round(h / 24)} j`;
  }

  async function api(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    if (o.body && typeof o.body !== 'string') {
      o.body = JSON.stringify(o.body);
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
    }
    const r = await fetch(API + path, o);
    const d = await r.json().catch(() => ({}));
    if (d && d.controlplane_unavailable) {
      throw new Error(d.error || 'Control-plane momentanément indisponible.');
    }
    if (!r.ok && d && d.error) throw new Error(d.error);
    return d;
  }
  async function portalApi(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    const r = await fetch('/api/threat' + path, o);
    const d = await r.json().catch(() => ({}));
    if (!r.ok && d && d.error) throw new Error(d.error);
    return d;
  }

  // Les onglets Sekoia sont des panneaux exclusifs : un seul est visible a la
  // fois. Un socle unique se remonte donc dans le conteneur de l'onglet actif,
  // plutot que neuf instances concurrentes.
  const MOUNTS = [
    { el: 'sekoia-extended-root', view: null, nav: true },
    { el: 'sekoia-cc-root', view: 'overview', nav: false },
    { el: 'sekoia-ingest-root', view: 'ingestion', nav: false },
    { el: 'sekoia-assets-root', view: 'sources', nav: false },
    { el: 'sekoia-rules-root', view: 'detections', nav: false },
    { el: 'sekoia-fetch-root', view: 'telemetry', nav: false },
    { el: 'sekoia-apikeys-root', view: 'apikeys', nav: false },
    { el: 'audit-center-root', view: 'audit', nav: false },
    { el: 'tp-config-root', view: 'config', nav: false },
  ];
  st.mount = 'sekoia-extended-root';
  st.nav = true;
  function root() { return document.getElementById(st.mount); }

  // ── Briques d'interface ───────────────────────────────────────────────────
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
  function spark(points) {
    if (!points || points.length < 2) return '<span class="swb-hint">—</span>';
    // Une serie entierement nulle tracee comme une ligne plate se confond avec
    // une courbe reelle : on affiche explicitement l'absence de volume.
    if (!points.some((v) => v > 0)) return '<span class="swb-hint">aucun volume</span>';
    const w = 92; const h = 22;
    const max = Math.max.apply(null, points) || 1;
    const dx = w / (points.length - 1);
    const xy = points.map((v, i) => [i * dx, h - (v / max) * (h - 3) - 1.5]);
    const line = xy.map((c, i) => (i ? 'L' : 'M') + c[0].toFixed(1) + ' ' + c[1].toFixed(1)).join(' ');
    return `<svg class="swb-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
      <path d="${line} L${w} ${h} L0 ${h} Z" class="swb-spark-area"/>
      <path d="${line}" class="swb-spark-line"/></svg>`;
  }
  function stateBox(title, msg, action) {
    return `<div class="swb-state"><p class="swb-state-title">${esc(title)}</p>
      <p class="swb-state-msg">${esc(msg)}</p>
      ${action || ''}</div>`;
  }
  function degraded(msg) {
    return `<div class="swb-state swb-state-degraded" role="status">
      <p class="swb-state-title">Donnée momentanément indisponible</p>
      <p class="swb-state-msg">${esc(msg)}</p>
      <button type="button" class="fp-btn fp-btn-sm" data-swb-act="reload">Réessayer</button></div>`;
  }
  function skeleton(rows) {
    let s = '<div class="swb-panel">';
    for (let i = 0; i < (rows || 6); i += 1) {
      s += `<div class="swb-skel" style="width:${88 - i * 7}%"></div>`;
    }
    return s + '</div>';
  }
  function toolbar(placeholder, extra, count) {
    return `<div class="swb-filters">
      <input type="search" class="swb-input swb-search" id="swb-q" placeholder="${esc(placeholder)}"
             value="${esc(st.q)}" aria-label="${esc(placeholder)}">
      ${extra || ''}
      ${count !== undefined ? `<span class="swb-count">${esc(count)}</span>` : ''}
      <span class="swb-nav-spacer"></span>
      <span class="swb-hint"><span class="swb-kbd">/</span> rechercher · <span class="swb-kbd">Échap</span> fermer</span>
    </div>`;
  }
  function th(label, key, cls) {
    const on = st.sort === key;
    const arrow = on ? (st.sortDir < 0 ? ' ↓' : ' ↑') : '';
    return `<th class="${cls || ''}${key ? ' swb-sortable' : ''}"${key ? ` data-swb-sort="${key}"` : ''}>${esc(label)}${arrow}</th>`;
  }
  function sorted(rows, def) {
    const key = st.sort || def;
    if (!key) return rows;
    const dir = st.sort ? st.sortDir : -1;
    return rows.slice().sort((a, b) => {
      const x = a[key]; const y = b[key];
      const nx = Number(x); const ny = Number(y);
      if (Number.isFinite(nx) && Number.isFinite(ny)) return (nx - ny) * dir;
      return String(x ?? '').localeCompare(String(y ?? ''), lang()) * dir;
    });
  }
  function match(row, fields) {
    if (!st.q) return true;
    const q = st.q.toLowerCase();
    return fields.some((f) => String(row[f] ?? '').toLowerCase().includes(q));
  }

  // ── Volet de détail ───────────────────────────────────────────────────────
  function kv(pairs) {
    return '<dl class="swb-kv">' + pairs.filter((p) => p)
      .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v === undefined || v === null || v === '' ? '—' : v}</dd>`)
      .join('') + '</dl>';
  }
  // Barre d'actions du volet : un ecran d'exploitation doit permettre d'AGIR,
  // pas seulement de consulter.
  function actionsBar(actions) {
    const btns = actions.filter(Boolean).map((a) => `<button type="button"
      class="fp-btn fp-btn-sm${a.tone === 'danger' ? ' fp-btn-danger' : a.tone === 'primary' ? ' fp-btn-primary' : ' fp-btn-ghost'}"
      data-swb-act="${esc(a.act)}" data-id="${esc(a.id)}" data-to="${esc(a.to || '')}">${esc(a.label)}</button>`).join(' ');
    return `<div class="swb-filters" style="margin:0 0 .8rem">${btns}</div>`;
  }

  function drawer() {
    if (!st.drawer) return '';
    const d = st.drawer;
    return `<div class="swb-scrim" data-swb-act="close-drawer"></div>
      <aside class="swb-drawer" role="dialog" aria-label="${esc(d.title)}">
        <div class="swb-drawer-head">
          <div><h3 class="swb-title">${esc(d.title)}</h3>
            ${d.subtitle ? `<p class="swb-sub">${esc(d.subtitle)}</p>` : ''}</div>
          <button type="button" class="swb-drawer-close" data-swb-act="close-drawer" aria-label="Fermer">✕</button>
        </div>
        <div class="swb-drawer-body">${d.body}</div>
      </aside>`;
  }

  // ═══ VUES ═════════════════════════════════════════════════════════════════

  // ── Vue d'ensemble ────────────────────────────────────────────────────────
  function viewOverview() {
    const d = st.data.dashboard;
    if (!d || !d.available) return degraded((d && d.errors && d.errors[0]) || 'Aucune télémétrie agrégée.');
    const k = d.kpi || {};
    const sev = (d.alerts && d.alerts.by_severity) || {};
    const ranges = [[6, '6 h'], [24, '24 h'], [168, '7 j'], [720, '30 j']];
    const picker = ranges.map(([h, l]) => `<button type="button" class="swb-tab"
      aria-selected="${st.range === h}" data-swb-act="range" data-hours="${h}">${esc(l)}</button>`).join('');

    const tl = d.timeline || [];
    const chart = tl.length < 2
      ? stateBox('Série en cours de constitution',
        `Deux points de collecte au minimum sont nécessaires pour tracer une tendance. `
        + `Le collecteur écrit un point toutes les 5 minutes.`)
      : tl.length < 4 ? (function () {
        // Avec deux ou trois releves, une aire produit un aplat qui ne dit rien.
        // Des barres restituent honnetement la mesure ponctuelle.
        const max = Math.max.apply(null, tl.map((p) => p.count)) || 1;
        const cells = tl.map((p) => `<div style="flex:1 1 0;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:.35rem">
            <span style="font-size:.74rem;color:var(--swb-muted)">${esc(nf(p.count))}</span>
            <span style="width:min(72px,80%);height:${Math.max(6, Math.round((p.count / max) * 130))}px;
              background:linear-gradient(180deg,var(--swb-accent),color-mix(in srgb,var(--swb-accent) 45%,transparent));
              border-radius:5px 5px 0 0" title="${esc(dt(p.ts))} — ${esc(nf(p.count))}"></span>
            <span style="font-size:.7rem;color:var(--swb-muted)">${esc(dt(p.ts).slice(11))}</span>
          </div>`).join('');
        return `<div style="display:flex;align-items:flex-end;gap:1rem;height:190px;padding:0 .5rem">${cells}</div>
          <p class="swb-hint" style="margin-top:.5rem">Série en constitution : ${tl.length} relevés. La courbe se dessine au-delà de quatre points.</p>`;
      }()) : (function () {
        const w = 1000; const h = 190;
        const max = Math.max.apply(null, tl.map((p) => p.count)) || 1;
        const dx = w / (tl.length - 1);
        const xy = tl.map((p, i) => [i * dx, h - (p.count / max) * (h - 26) - 14]);
        const line = xy.map((c, i) => (i ? 'L' : 'M') + c[0].toFixed(1) + ' ' + c[1].toFixed(1)).join(' ');
        const dots = xy.map((c, i) => `<circle cx="${c[0].toFixed(1)}" cy="${c[1].toFixed(1)}" r="2.5"
          class="swb-spark-line" style="fill:var(--swb-accent)"><title>${esc(dt(tl[i].ts))} — ${esc(nf(tl[i].count))}</title></circle>`).join('');
        const grid = [0.25, 0.5, 0.75].map((f) => `<line x1="0" x2="${w}" y1="${(h * f).toFixed(0)}" y2="${(h * f).toFixed(0)}"
          stroke="currentColor" stroke-opacity="0.07"/>`).join('');
        return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:190px;display:block"
            role="img" aria-label="Volumétrie d'ingestion, maximum ${esc(nf(max))} par heure">
            ${grid}<path d="${line} L${w} ${h} L0 ${h} Z" class="swb-spark-area"/>
            <path d="${line}" class="swb-spark-line" style="stroke-width:2"/>${dots}</svg>
          <div class="swb-filters" style="margin:0.4rem 0 0"><span class="swb-hint">${esc(dt(tl[0].ts))}</span>
            <span class="swb-nav-spacer"></span><span class="swb-hint">pic ${esc(nf(max))}/h</span>
            <span class="swb-nav-spacer"></span><span class="swb-hint">${esc(dt(tl[tl.length - 1].ts))}</span></div>`;
      }());

    const top = (d.top_sources || []);
    const maxTop = Math.max.apply(null, top.map((s) => s.count || 0).concat([1]));
    const topRows = top.map((s) => `<tr>
      <td class="swb-truncate" title="${esc(s.name)}">${esc(s.name)}</td>
      <td>${meter(((s.count || 0) / maxTop) * 100, s.count ? 'ok' : 'danger')}</td>
      <td class="swb-num">${esc(nf(s.count))}</td></tr>`).join('');

    const hm = d.heatmap || {};
    const heatRows = (hm.rows || []).map((r) => {
      const cells = r.values.map((v, i) => {
        const lvl = v <= 0 ? 0 : Math.min(5, Math.ceil((Math.log10(v + 1) / Math.log10((hm.max || 1) + 1)) * 5));
        return `<span class="sep-heat-cell sep-heat-${lvl}" title="${esc(dt(hm.slots[i]))} — ${esc(nf(v))}"></span>`;
      }).join('');
      return `<div class="sep-heat-row"><span class="sep-heat-label swb-truncate" title="${esc(r.label)}">${esc(r.label)}</span>
        <span class="sep-heat-cells">${cells}</span></div>`;
    }).join('');

    return `<div class="swb-head">
        <div><h2 class="swb-title">Ingestion — ${esc(d.hours)} h</h2>
          <p class="swb-sub">Volumétrie mesurée source par source. Granularité ${esc(d.interval)}.</p></div>
        <div class="swb-actions">${picker}</div></div>
      <div class="swb-kpis">
        ${kpi('Débit courant', compact(k.events_per_hour) + '/h', 'ok', 'dernier créneau mesuré')}
        ${kpi('Pic sur la fenêtre', compact(k.events_peak) + '/h', 'warn')}
        ${kpi('Sources actives', nf(k.sources_active), k.sources_active ? 'ok' : 'danger', `sur ${nf(k.sources_total)}`)}
        ${kpi('Sources silencieuses', nf(k.sources_silent), k.sources_silent ? 'danger' : 'ok', 'aucun événement')}
        ${kpi('Alertes critiques', nf(sev.critical || 0), sev.critical ? 'danger' : 'ok', `${nf(sev.high || 0)} élevées`)}
      </div>
      <div class="swb-panel"><div class="swb-panel-head"><h3 class="swb-panel-title">Volumétrie d'ingestion</h3></div>${chart}</div>
      <div class="swb-grid2">
        <div class="swb-panel"><div class="swb-panel-head"><h3 class="swb-panel-title">Sources les plus volumineuses</h3></div>
          <div class="swb-tablewrap"><table class="swb-table"><tbody>${topRows || '<tr><td class="swb-hint">Aucune source mesurée.</td></tr>'}</tbody></table></div></div>
        <div class="swb-panel"><div class="swb-panel-head"><h3 class="swb-panel-title">Activité par source</h3></div>
          <p class="swb-hint" style="margin-bottom:.5rem">Échelle logarithmique : sans elle une source à 1 M/h écraserait les autres.</p>
          <div class="sep-heat">${heatRows || '<span class="swb-hint">Carte indisponible.</span>'}</div></div>
      </div>`;
  }

  // ── Ingestion : volumétrie détaillée par source ───────────────────────────
  function viewIngestion() {
    const d = st.data.dashboard;
    const h = st.data.health;
    if (!d || !d.available) return degraded((d && d.errors && d.errors[0]) || 'Aucune télémétrie agrégée.');
    const k = d.kpi || {};
    const series = d.series || [];
    const ranges = [[6, '6 h'], [24, '24 h'], [168, '7 j'], [720, '30 j']];
    const picker = ranges.map(([hh, l]) => `<button type="button" class="swb-tab"
      aria-selected="${st.range === hh}" data-swb-act="range" data-hours="${hh}">${esc(l)}</button>`).join('');

    // Table par source : volume, part du total, tendance, écart à la baseline.
    const total = series.reduce((a, x) => a + (x.total || 0), 0) || 1;
    const byName = {};
    ((h && h.items) || []).forEach((i) => { byName[i.intake_name] = i; });
    let rows = series.filter((x) => match({ n: x.intake_name }, ['n']));
    rows = rows.map((x) => {
      const st2 = byName[x.intake_name] || {};
      const base = Math.round(st2.baseline_avg || 0);
      const cur = st2.current_count;
      const delta = (base > 0 && cur !== undefined && cur !== null) ? ((cur - base) / base) * 100 : null;
      return Object.assign({}, x, { base, cur, delta, share: (x.total / total) * 100 });
    });
    const key = st.sort || 'total';
    const dir = st.sort ? st.sortDir : -1;
    rows.sort((a, b) => ((Number(a[key]) || 0) - (Number(b[key]) || 0)) * dir);

    const body = rows.map((x) => {
      const pts = (x.points || []).map((p) => p.count);
      const stopped = x.cur === 0 && x.base > 0;
      const dTone = x.delta === null ? 'mute' : (x.delta < -50 ? 'danger' : x.delta > 100 ? 'warn' : 'ok');
      const dTxt = x.delta === null ? '—' : (stopped ? 'arrêtée' : `${x.delta > 0 ? '+' : ''}${x.delta.toFixed(0)} %`);
      return `<tr>
        <td class="swb-truncate" title="${esc(x.intake_name)}">${esc(x.intake_name)}</td>
        <td>${spark(pts)}</td>
        <td class="swb-num">${esc(nf(x.total))}</td>
        <td>${meter(x.share, x.share > 40 ? 'warn' : 'ok')}</td>
        <td class="swb-num">${esc(x.share.toFixed(1))} %</td>
        <td class="swb-num">${esc(nf(x.base))}</td>
        <td class="swb-num">${pill(dTxt, dTone, true)}</td></tr>`;
    }).join('');

    // Le drapeau `silent` porte sur le DERNIER releve, alors que le volume porte
    // sur toute la fenetre. Une source peut donc avoir emis 1 M d'evenements ce
    // matin et etre muette a l'instant : afficher les deux faits cote a cote
    // sans le dire serait contradictoire.
    const volByName = {};
    series.forEach((x) => { volByName[x.intake_name] = x.total || 0; });
    const silentAll = ((h && h.items) || []).filter((i) => i.silent);
    const silentDropped = silentAll.filter((i) => (volByName[i.intake_name] || 0) > 0);
    const silentAlways = silentAll.filter((i) => !(volByName[i.intake_name] || 0));
    const liOf = (i, withVol) => `<li>${esc(i.intake_name)}
      <span class="swb-hint">· ${esc(i.entity_name || '—')}${
  withVol ? ` · ${nf(volByName[i.intake_name])} sur la fenêtre` : ''}</span></li>`;
    const silentList = silentAlways.slice(0, 12).map((i) => liOf(i, false)).join('');
    const droppedList = silentDropped.slice(0, 8).map((i) => liOf(i, true)).join('');

    return `<div class="swb-head">
        <div><h2 class="swb-title">Ingestion des logs — volumétrie</h2>
          <p class="swb-sub">Volume, part du total, tendance et écart à la baseline, source par source. Le SIEM n'expose aucune de ces mesures.</p></div>
        <div class="swb-actions">${picker}</div></div>
      <div class="swb-kpis">
        ${kpi('Débit courant', compact(k.events_per_hour) + '/h', 'ok', `granularité ${esc(d.interval)}`)}
        ${kpi('Pic sur la fenêtre', compact(k.events_peak) + '/h', 'warn')}
        ${kpi('Sources émettrices', nf(k.sources_active), k.sources_active ? 'ok' : 'danger', `sur ${nf(k.sources_total)}`)}
        ${kpi('Sources muettes', nf(k.sources_silent), k.sources_silent ? 'danger' : 'ok')}
        ${kpi('Concentration', `${((series[0] ? series[0].total : 0) / total * 100).toFixed(0)} %`,
    ((series[0] ? series[0].total : 0) / total) > 0.6 ? 'warn' : 'ok', 'part de la 1re source')}
      </div>
      ${toolbar('Filtrer une source…', '', `${nf(rows.length)} sources mesurées`)}
      <div class="swb-panel" style="padding:0">
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          ${th('Source', 'intake_name')}<th>Tendance</th>${th('Volume', 'total', 'swb-num')}
          <th>Part</th>${th('%', 'share', 'swb-num')}${th('Baseline', 'base', 'swb-num')}${th('Écart', 'delta', 'swb-num')}
        </tr></thead><tbody>${body || '<tr><td colspan="7"><p class="swb-hint" style="padding:1rem">Aucune source mesurée sur la fenêtre.</p></td></tr>'}</tbody></table></div></div>
      ${qualityLatencyPanels()}
      ${silentDropped.length ? `<div class="swb-panel" style="border-left:3px solid var(--swb-danger)">
        <div class="swb-panel-head"><h3 class="swb-panel-title">Collecte interrompue — ${nf(silentDropped.length)}</h3></div>
        <p class="swb-hint" style="margin-bottom:.5rem">Ces sources ont émis sur la fenêtre mais ne remontent plus rien au dernier relevé. C'est le signal le plus urgent : une source qui produisait vient de se taire.</p>
        <ul style="margin:0;padding-left:1.1rem;font-size:.82rem;columns:2;column-gap:2rem">${droppedList}</ul></div>` : ''}
      ${silentAlways.length ? `<div class="swb-panel"><div class="swb-panel-head">
        <h3 class="swb-panel-title">Sources sans aucun volume — ${nf(silentAlways.length)}</h3></div>
        <p class="swb-hint" style="margin-bottom:.5rem">Aucun événement sur toute la fenêtre. Intake configuré mais jamais alimenté, ou source arrêtée de longue date.</p>
        <ul style="margin:0;padding-left:1.1rem;font-size:.82rem;columns:2;column-gap:2rem">${silentList}</ul>
        ${silentAlways.length > 12 ? `<p class="swb-hint" style="margin-top:.5rem">…et ${nf(silentAlways.length - 12)} autres. Voir l'écran Sources pour la liste complète.</p>` : ''}</div>` : ''}`;
  }

  /**
   * Qualité de parsing et latence de livraison. Ces deux mesures répondent à ce
   * que la volumétrie ne dit pas : ce qui entre est-il correctement interprété,
   * et arrive-t-il assez tôt pour être exploitable.
   */
  function qualityLatencyPanels() {
    const q = st.data.quality;
    const l = st.data.latency;
    if (!q && !l) return '';

    const qBlock = !q || !q.available
      ? `<div class="swb-panel"><div class="swb-panel-head">
          <h3 class="swb-panel-title">Qualité d'ingestion</h3></div>
          <p class="swb-hint">${esc((q && q.reason) || 'Mesure indisponible.')}</p></div>`
      : `<div class="swb-panel"><div class="swb-panel-head">
          <h3 class="swb-panel-title">Qualité d'ingestion</h3>
          <span class="swb-hint">échantillon de ${esc(nf(q.sampled))} événements</span></div>
        <div class="swb-kpis" style="margin-bottom:.6rem">
          ${kpi('Parsing réussi', `${q.parsing_ok_pct} %`, q.parsing_ok_pct >= 99 ? 'ok' : q.parsing_ok_pct >= 90 ? 'warn' : 'danger')}
          ${kpi('Sources en échec', nf(q.intakes_with_failures), q.intakes_with_failures ? 'danger' : 'ok')}
          ${kpi('Dialectes mélangés', nf(q.intakes_mixed_dialects), q.intakes_mixed_dialects ? 'warn' : 'ok',
    'plusieurs formats sur une même source')}
        </div>
        <div class="swb-tablewrap" style="max-height:26vh"><table class="swb-table"><thead><tr>
          <th>Source</th><th class="swb-num">Parsing</th><th class="swb-num">Échecs</th>
          <th>Dialecte</th><th class="swb-num">Champs</th></tr></thead><tbody>
          ${(q.items || []).slice(0, 30).map((i) => `<tr>
            <td class="swb-truncate" title="${esc(i.intake_name)}">${esc(i.intake_name)}</td>
            <td class="swb-num">${pill(`${i.parsing_ok_pct} %`, i.parsing_ok_pct >= 99 ? 'ok' : 'danger', true)}</td>
            <td class="swb-num">${esc(nf(i.parsing_failures))}</td>
            <td class="swb-truncate">${esc(i.dialects.join(', '))}${i.mixed_dialects ? ' ' + pill('mélange', 'warn', true) : ''}</td>
            <td class="swb-num">${esc(i.fields_count)}</td></tr>`).join('')}
        </tbody></table></div>
        <p class="swb-hint" style="margin-top:.4rem">${esc(q.sampling_note)}</p></div>`;

    const lBlock = !l || !l.available
      ? `<div class="swb-panel"><div class="swb-panel-head">
          <h3 class="swb-panel-title">Latence de livraison</h3></div>
          <p class="swb-hint">${esc((l && l.reason) || 'Mesure indisponible.')}</p></div>`
      : `<div class="swb-panel"><div class="swb-panel-head">
          <h3 class="swb-panel-title">Latence de livraison</h3>
          <span class="swb-hint">${esc(nf(l.measured))} mesures</span></div>
        <div class="swb-kpis" style="margin-bottom:.6rem">
          ${kpi('Médiane', `${l.global.p50_s} s`, 'ok')}
          ${kpi('p90', `${l.global.p90_s} s`, (l.global.p90_s || 0) > 300 ? 'danger' : 'ok')}
          ${kpi('p99', `${l.global.p99_s} s`, (l.global.p99_s || 0) > 300 ? 'warn' : 'ok')}
          ${kpi('Hors seuil', nf(l.intakes_above_threshold), l.intakes_above_threshold ? 'danger' : 'ok',
    `> ${l.freshness_threshold_s} s au p90`)}
        </div>
        <p class="swb-hint" style="margin-bottom:.5rem">${esc(l.threshold_note)}</p>
        ${l.clock_skew_note ? `<p class="swb-hint">${esc(nf(l.clock_skew_events))} événement(s) — ${esc(l.clock_skew_note)}</p>` : ''}
        <div class="swb-tablewrap" style="max-height:22vh"><table class="swb-table"><thead><tr>
          <th>Source</th><th class="swb-num">p50</th><th class="swb-num">p90</th>
          <th class="swb-num">max</th><th class="swb-num">Mesures</th></tr></thead><tbody>
          ${(l.items || []).slice(0, 30).map((i) => `<tr>
            <td class="swb-truncate" title="${esc(i.intake_name)}">${esc(i.intake_name)}</td>
            <td class="swb-num">${esc(i.p50_s)} s</td>
            <td class="swb-num">${pill(`${i.p90_s} s`, (i.p90_s || 0) > 300 ? 'danger' : 'ok', true)}</td>
            <td class="swb-num">${esc(i.max_s)} s</td>
            <td class="swb-num">${esc(nf(i.samples))}</td></tr>`).join('')}
        </tbody></table></div></div>`;

    return `<div class="swb-grid2">${qBlock}${lBlock}</div>`;
  }

  // ── Sources ───────────────────────────────────────────────────────────────
  function viewSources() {
    const h = st.data.health;
    if (!h || !h.available) {
      return degraded((h && h.error) || "Aucun état de source collecté. La première collecte suit le redémarrage de quelques minutes.");
    }
    let rows = (h.items || []).filter((r) => match(r, ['intake_name', 'entity_name', 'intake_uuid']));
    const f = st.filters;
    if (f.state === 'silent') rows = rows.filter((r) => r.silent);
    if (f.state === 'active') rows = rows.filter((r) => (r.current_count || 0) > 0);
    if (f.state === 'unmeasured') rows = rows.filter((r) => !r.volume_available);
    if (f.entity) rows = rows.filter((r) => r.entity_name === f.entity);
    rows = sorted(rows, 'score');

    const entities = Array.from(new Set((h.items || []).map((r) => r.entity_name).filter(Boolean))).sort();
    const extra = `<select class="swb-select" data-swb-filter="state" aria-label="État">
        <option value="">Tous les états</option>
        <option value="active"${f.state === 'active' ? ' selected' : ''}>Actives</option>
        <option value="silent"${f.state === 'silent' ? ' selected' : ''}>Silencieuses</option>
        <option value="unmeasured"${f.state === 'unmeasured' ? ' selected' : ''}>Non mesurées</option>
      </select>
      <select class="swb-select" data-swb-filter="entity" aria-label="Entité">
        <option value="">Toutes les entités</option>
        ${entities.map((e) => `<option value="${esc(e)}"${f.entity === e ? ' selected' : ''}>${esc(e)}</option>`).join('')}
      </select>`;

    const body = rows.map((r) => {
      const measured = r.volume_available;
      const count = measured ? nf(r.current_count)
        : '<span class="swb-hint" title="Non mesuré — jamais assimilé à zéro">non mesuré</span>';
      return `<tr class="swb-clickable" data-swb-act="open-source" data-id="${esc(r.intake_uuid)}">
        <td><span class="swb-grade swb-grade-${esc(r.grade)}">${esc(r.grade)}</span></td>
        <td class="swb-num">${esc(r.score)}</td>
        <td class="swb-truncate" title="${esc(r.intake_name)}">${esc(r.intake_name || r.intake_uuid)}</td>
        <td class="swb-truncate">${esc(r.entity_name || '—')}</td>
        <td class="swb-num">${count}</td>
        <td class="swb-num">${measured ? nf(Math.round(r.baseline_avg || 0)) : '—'}</td>
        <td>${r.silent ? pill('silencieuse', 'danger') : (measured ? pill('active', 'ok') : pill('non mesurée', 'warn'))}</td>
      </tr>`;
    }).join('');

    return `${assetsPanel()}
      <div class="swb-head">
        <div><h2 class="swb-title">Sources d'ingestion</h2>
          <p class="swb-sub">Inventaire complet avec volumétrie, baseline et note de santé — aucune de ces valeurs n'est exposée par le SIEM.</p></div>
        <div class="swb-actions">${kpiInline(h)}</div></div>
      ${toolbar('Rechercher une source, une entité, un identifiant…', extra, `${nf(rows.length)} / ${nf((h.items || []).length)}`)}
      <div class="swb-panel" style="padding:0">
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          ${th('Note', 'grade')}${th('Score', 'score', 'swb-num')}${th('Source', 'intake_name')}
          ${th('Entité', 'entity_name')}${th('Événements/h', 'current_count', 'swb-num')}
          ${th('Baseline', 'baseline_avg', 'swb-num')}${th('État', 'silent')}
        </tr></thead><tbody>${body || '<tr><td colspan="7"><p class="swb-hint" style="padding:1rem">Aucune source ne correspond aux filtres.</p></td></tr>'}</tbody></table></div>
      </div>`;
  }
  /**
   * Couverture d'actifs : les hôtes qui parlent et que Sekoia ne connaît pas.
   * C'est l'angle mort le plus coûteux — un actif non référencé n'est ni
   * corrélé, ni rattaché à une entité, ni couvert par les règles de périmètre.
   */
  function assetsPanel() {
    const a = st.data.assets;
    if (!a) return '';
    if (!a.available) {
      return `<div class="swb-panel"><div class="swb-panel-head">
        <h3 class="swb-panel-title">Couverture d'actifs</h3></div>
        <p class="swb-hint">${esc(a.reason || 'Mesure indisponible.')}</p></div>`;
    }
    const rows = (a.hosts || []).slice(0, 40).map((h) => `<tr>
      <td class="swb-truncate" title="${esc(h.host)}">${esc(h.host)}</td>
      <td class="swb-num">${esc(nf(h.events))}</td>
      <td>${h.is_relay ? pill('relais', 'warn', true)
    : h.known_asset ? pill('référencé', 'ok', true) : pill('non référencé', 'danger')}</td>
      <td class="swb-truncate">${esc(h.intakes.join(', '))}</td>
      <td class="swb-truncate swb-hint">${esc(h.dialects.join(', '))}</td>
      <td class="swb-hint">${esc((h.ips || []).join(', ') || '—')}</td></tr>`).join('');

    const relays = (a.relays || []).map((r) => `<li><span class="swb-mono">${esc(r.relay)}</span>
      — ${esc(nf(r.hosts_behind))} hôtes derrière lui</li>`).join('');

    return `<div class="swb-panel"><div class="swb-panel-head">
        <h3 class="swb-panel-title">Couverture d'actifs</h3>
        <span class="swb-hint">échantillon de ${esc(nf(a.sampled))} événements</span></div>
      <div class="swb-kpis" style="margin-bottom:.6rem">
        ${kpi('Hôtes observés', nf(a.hosts_total), 'ok')}
        ${kpi('Référencés', `${a.coverage_pct} %`, a.coverage_pct >= 90 ? 'ok' : 'warn',
    `${nf(a.hosts_known)} sur ${nf(a.machines_total)} machines`)}
        ${kpi('NON référencés', nf(a.hosts_unmanaged), a.hosts_unmanaged ? 'danger' : 'ok',
    'émettent sans exister dans l\'inventaire')}
        ${kpi('Relais de collecte', nf(a.relays_count), a.relays_count ? 'warn' : 'ok')}
        ${kpi('Comptes observés', nf(a.users_total), 'ok')}
      </div>
      ${a.hosts_unmanaged ? `<div class="swb-state" style="border-left:3px solid var(--swb-danger);text-align:left">
        <p class="swb-state-title">${esc(nf(a.hosts_unmanaged))} hôte(s) non référencé(s)</p>
        <p class="swb-state-msg">${esc(a.coverage_note)}</p>
        <p class="swb-mono" style="font-size:.76rem">${esc((a.unmanaged || []).slice(0, 12).join(' · '))}</p></div>` : ''}
      ${relays ? `<p class="swb-hint" style="margin:.6rem 0 .2rem">${esc(a.relay_note)}</p>
        <ul style="margin:0 0 .6rem;padding-left:1.1rem;font-size:.82rem">${relays}</ul>` : ''}
      <div class="swb-tablewrap" style="max-height:30vh"><table class="swb-table"><thead><tr>
        <th>Hôte</th><th class="swb-num">Événements</th><th>Inventaire</th>
        <th>Source</th><th>Dialecte</th><th>IP</th></tr></thead><tbody>${rows}</tbody></table></div>
      <p class="swb-hint" style="margin-top:.4rem">${esc(a.sampling_note)}
        ${a.snapshots_compared ? ` · ${esc(nf(a.first_seen_hosts.length))} première(s) apparition(s), ${esc(nf(a.absent_hosts.length))} absent(s) sur ${esc(a.snapshots_compared)} relevés.` : ''}</p></div>`;
  }

  function kpiInline(h) {
    const items = h.items || [];
    const silent = items.filter((i) => i.silent).length;
    return `${pill(`${nf(items.length)} sources`, 'mute', true)} ${pill(`${nf(silent)} silencieuses`, silent ? 'danger' : 'ok')}`;
  }

  function openSource(id) {
    const r = (st.data.health.items || []).find((x) => x.intake_uuid === id);
    if (!r) return;
    const c = r.components || {};
    st.drawer = {
      title: r.intake_name || id,
      subtitle: `Score de santé ${r.score}/100 · note ${r.grade}`,
      body: kv([
        ['Identifiant', `<span class="swb-mono">${esc(r.intake_uuid)}</span>`],
        ['Entité', esc(r.entity_name)],
        ['Statut', esc(r.intake_status)],
        ['Événements / h', r.volume_available ? nf(r.current_count)
          : '<span class="swb-hint">non mesuré</span>'],
        ['Baseline 7 j', r.volume_available ? nf(Math.round(r.baseline_avg || 0)) : '—'],
        ['Ratio / baseline', r.drop_ratio === null || r.drop_ratio === undefined ? '—' : r.drop_ratio],
        ['Hôtes distincts', nf(r.hostnames_count)],
        ['Dernier événement', r.last_event_age_min === null || r.last_event_age_min === undefined
          ? '—' : `il y a ${nf(Math.round(r.last_event_age_min))} min`],
        ['Silencieuse', r.silent ? pill('oui', 'danger') : pill('non', 'ok')],
      ]) + actionsBar([
        r.intake_status && String(r.intake_status).toLowerCase() === 'running'
          ? { act: 'intake-toggle', id: r.intake_uuid, to: 'disable', label: 'Désactiver la source', tone: 'danger' }
          : { act: 'intake-toggle', id: r.intake_uuid, to: 'enable', label: 'Activer la source', tone: 'primary' },
      ]) + `<h4 class="swb-panel-title" style="margin:1rem 0 .5rem">Décomposition du score</h4>`
        + kv([
          ['Fraîcheur', `${meter((c.freshness / 40) * 100, 'ok')} ${nf(c.freshness)}/40`],
          ['Stabilité', `${meter((c.stability / 30) * 100, 'ok')} ${nf(c.stability)}/30`],
          ['Baseline', `${meter((c.baseline / 15) * 100, 'ok')} ${nf(c.baseline)}/15`],
          ['Diversité', `${meter((c.diversity / 15) * 100, 'ok')} ${nf(c.diversity)}/15`],
        ]),
    };
    paint();
  }

  // ── Détections ────────────────────────────────────────────────────────────
  function viewDetections() {
    const d = st.data.rules;
    const mc = st.data.mitre;
    if (!d) return degraded('Catalogue de règles injoignable.');
    const items = d.items || [];
    const f = st.filters;
    let rows = items.filter((r) => match(r, ['rule_name', 'rule_tags', 'rule_uuid', 'rule_datasources']));
    if (f.severity) {
      const lo = { low: [0, 40], medium: [40, 60], high: [60, 80], critical: [80, 101] }[f.severity];
      if (lo) rows = rows.filter((r) => Number(r.rule_severity) >= lo[0] && Number(r.rule_severity) < lo[1]);
    }
    if (f.enabled === 'yes') rows = rows.filter((r) => r.rule_enabled);
    if (f.enabled === 'no') rows = rows.filter((r) => !r.rule_enabled);
    if (f.attack === 'yes') rows = rows.filter((r) => (r.rule_attack_refs_count || 0) > 0);
    if (f.attack === 'no') rows = rows.filter((r) => !(r.rule_attack_refs_count || 0));
    rows = sorted(rows, 'rule_severity');

    const ap = (mc && mc.attack_patterns) || {};
    const extra = `<select class="swb-select" data-swb-filter="severity" aria-label="Sévérité">
        <option value="">Toutes sévérités</option>
        ${['critical', 'high', 'medium', 'low'].map((s) => `<option value="${s}"${f.severity === s ? ' selected' : ''}>${s}</option>`).join('')}
      </select>
      <select class="swb-select" data-swb-filter="enabled" aria-label="Activation">
        <option value="">Activées et désactivées</option>
        <option value="yes"${f.enabled === 'yes' ? ' selected' : ''}>Activées</option>
        <option value="no"${f.enabled === 'no' ? ' selected' : ''}>Désactivées</option>
      </select>
      <select class="swb-select" data-swb-filter="attack" aria-label="Couverture ATT&CK">
        <option value="">Toute couverture</option>
        <option value="yes"${f.attack === 'yes' ? ' selected' : ''}>Avec attack-pattern</option>
        <option value="no"${f.attack === 'no' ? ' selected' : ''}>Sans attack-pattern</option>
      </select>`;

    // Rendu borné : 300 lignes suffisent à l'œil, le filtre fait le reste.
    // Charger 1180 <tr> d'un coup dégraderait le défilement sans rien apporter.
    const shown = rows.slice(0, 300);
    const body = shown.map((r) => {
      const sev = Number(r.rule_severity) || 0;
      const tone = sev >= 80 ? 'danger' : sev >= 60 ? 'warn' : sev >= 40 ? 'mute' : 'mute';
      return `<tr class="swb-clickable" data-swb-act="open-rule" data-id="${esc(r.rule_uuid)}">
        <td>${r.rule_enabled ? pill('active', 'ok') : pill('inactive', 'mute')}</td>
        <td class="swb-truncate" title="${esc(r.rule_name)}">${esc(r.rule_name)}</td>
        <td class="swb-num">${pill(String(sev), tone, true)}</td>
        <td class="swb-truncate">${esc(r.rule_datasources || '—')}</td>
        <td class="swb-num">${r.rule_attack_refs_count ? esc(r.rule_attack_refs_count) : '<span class="swb-hint">0</span>'}</td>
        <td class="swb-truncate">${esc(r.rule_tags || '—')}</td>
      </tr>`;
    }).join('');

    const coverage = ap.coverage_pct !== undefined ? `
      <div class="swb-kpis">
        ${kpi('Règles au catalogue', nf(d.total), 'ok')}
        ${kpi('Couverture ATT&CK', `${ap.coverage_pct} %`, ap.coverage_pct > 70 ? 'ok' : 'warn',
    `${nf(ap.rules_with_attack_patterns)} règles rattachées`)}
        ${kpi('Attack-patterns', nf(ap.distinct_attack_patterns), 'ok', `${nf(ap.named_attack_patterns)} nommés`)}
        ${kpi('Sans couverture', nf(ap.rules_without), ap.rules_without ? 'warn' : 'ok')}
      </div>` : '';

    const topPatterns = (ap.top_patterns || []).filter((p) => p.name).slice(0, 12);
    const maxP = Math.max.apply(null, topPatterns.map((p) => p.rules).concat([1]));
    const patternRows = topPatterns.map((p) => `<tr>
      <td class="swb-truncate" title="${esc(p.name)}">${esc(p.name)}</td>
      <td>${meter((p.rules / maxP) * 100, 'ok')}</td>
      <td class="swb-num">${esc(nf(p.rules))}</td></tr>`).join('');

    return `<div class="swb-head">
        <div><h2 class="swb-title">Règles de détection</h2>
          <p class="swb-sub">Catalogue du tenant avec couverture offensive réelle. Le SIEM n'expose aucun identifiant ATT&CK : la couverture provient des attack-patterns rattachés.</p></div></div>
      ${coverage}
      ${toolbar('Rechercher une règle, un tag, une source de données…', extra,
    `${nf(rows.length)} / ${nf(items.length)}${rows.length > 300 ? ' · 300 affichées' : ''}`)}
      <div class="swb-panel" style="padding:0">
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          ${th('État', 'rule_enabled')}${th('Règle', 'rule_name')}${th('Sévérité', 'rule_severity', 'swb-num')}
          ${th('Sources de données', 'rule_datasources')}${th('ATT&CK', 'rule_attack_refs_count', 'swb-num')}${th('Tags', 'rule_tags')}
        </tr></thead><tbody>${body || '<tr><td colspan="6"><p class="swb-hint" style="padding:1rem">Aucune règle ne correspond aux filtres.</p></td></tr>'}</tbody></table></div>
      </div>
      ${patternRows ? `<div class="swb-panel"><div class="swb-panel-head">
        <h3 class="swb-panel-title">Techniques les plus couvertes</h3></div>
        <div class="swb-tablewrap" style="max-height:320px"><table class="swb-table"><tbody>${patternRows}</tbody></table></div></div>` : ''}`;
  }

  async function openRule(id) {
    const r = (st.data.rules.items || []).find((x) => x.rule_uuid === id);
    st.drawer = { title: (r && r.rule_name) || id, subtitle: 'Chargement du détail…', body: skeleton(5) };
    paint();
    let full = null;
    try { full = await api('/rules/' + encodeURIComponent(id)); } catch (e) { /* détail optionnel */ }
    const rule = (full && full.rule) || {};
    const names = (st.data.mitre && st.data.mitre.attack_patterns
      && st.data.mitre.attack_patterns.top_patterns) || [];
    const nameOf = {};
    names.forEach((p) => { if (p.id) nameOf[p.id] = p.name; });
    const refs = String((r && r.rule_attack_refs) || '').split(',').filter(Boolean);
    st.drawer = {
      title: (r && r.rule_name) || id,
      subtitle: `Sévérité ${(r && r.rule_severity) || '—'} · ${(r && r.rule_enabled) ? 'active' : 'inactive'}`,
      body: actionsBar([
        (r && r.rule_enabled)
          ? { act: 'rule-toggle', id: id, to: 'disable', label: 'Désactiver la règle', tone: 'danger' }
          : { act: 'rule-toggle', id: id, to: 'enable', label: 'Activer la règle', tone: 'primary' },
      ]) + kv([
        ['Identifiant', `<span class="swb-mono">${esc(id)}</span>`],
        ['Type', esc((r && r.rule_type) || rule.type)],
        ['Description', esc((r && r.rule_description) || rule.description || '—')],
        ['Sources de données', esc((r && r.rule_datasources) || '—')],
        ['Tags', esc((r && r.rule_tags) || '—')],
        ['Catégorie', esc((r && r.rule_alert_category_name) || '—')],
        ['Cycle de vie', esc((r && r.rule_lifecycle) || rule.lifecycle || '—')],
        ['Vérifiée', (r && r.rule_verified) ? pill('oui', 'ok') : pill('non', 'mute')],
      ]) + (refs.length ? `<h4 class="swb-panel-title" style="margin:1rem 0 .5rem">Attack-patterns (${refs.length})</h4>
        <ul style="margin:0;padding-left:1.1rem;font-size:.8rem">${refs.map((x) => (nameOf[x]
          ? `<li>${esc(nameOf[x])}</li>`
          // Sekoia n'expose pas de referentiel resolvable : on le dit au lieu
          // d'afficher un UUID brut qui ne renseigne personne.
          : `<li><span class="swb-hint">libellé non résolu</span> <span class="swb-mono">${esc(x.replace('attack-pattern--', '').slice(0, 8))}…</span></li>`)).join('')}</ul>` : '')
        + (rule.payload ? `<h4 class="swb-panel-title" style="margin:1rem 0 .5rem">Requête de détection</h4>
          <pre class="swb-mono" style="white-space:pre-wrap;background:var(--swb-surface-2);padding:.6rem;border-radius:7px">${esc(rule.payload)}</pre>` : ''),
    };
    paint();
  }

  // ── Inventaire : dérive et incohérences ───────────────────────────────────
  function viewInventory() {
    const c = st.data.consistency;
    const d = st.data.drift;
    const tl = st.data.invTimeline;
    const snaps = st.data.snapshots;
    if (!c) return degraded('Moteur d\'inventaire injoignable.');

    const sevTone = { high: 'danger', medium: 'warn', low: 'mute' };
    const issues = (c.issues || []).map((i) => `<tr class="swb-clickable"
      data-swb-act="open-issue" data-kind="${esc(i.kind)}">
      <td>${pill(i.severity, sevTone[i.severity] || 'mute')}</td>
      <td>${esc(i.title)}</td>
      <td class="swb-num">${esc(nf(i.count))}</td>
      <td class="swb-hint swb-truncate" title="${esc(i.action)}">${esc(i.action)}</td></tr>`).join('');

    const drift = (!d || !d.available)
      ? stateBox('Dérive non mesurable', (d && d.reason)
        || 'Au moins deux instantanés sont nécessaires. Le premier est pris automatiquement au démarrage.')
      : `<div class="swb-kpis">
          ${kpi('Changements', nf(d.total_changes), d.total_changes ? 'warn' : 'ok',
    `sur ${esc(Math.abs(d.span_hours))} h`)}
          ${kpi('Sources ajoutées', nf(d.intakes.added.length), d.intakes.added.length ? 'warn' : 'ok')}
          ${kpi('Sources retirées', nf(d.intakes.removed.length), d.intakes.removed.length ? 'danger' : 'ok')}
          ${kpi('Règles modifiées', nf(d.rules.changed.length), d.rules.changed.length ? 'warn' : 'ok')}
        </div>
        <div class="swb-panel" style="padding:0"><div class="swb-tablewrap" style="max-height:34vh">
          <table class="swb-table"><thead><tr><th>Objet</th><th>Nature</th><th>Détail</th></tr></thead><tbody>
          ${[...d.intakes.removed.map((x) => ['source', 'retirée', x.name, 'danger']),
    ...d.intakes.added.map((x) => ['source', 'ajoutée', x.name, 'warn']),
    ...d.intakes.changed.map((x) => ['source', 'modifiée', `${x.name} — ${fieldsOf(x.fields)}`, 'warn']),
    ...d.rules.removed.map((x) => ['règle', 'retirée', x.name, 'danger']),
    ...d.rules.added.map((x) => ['règle', 'ajoutée', x.name, 'warn']),
    ...d.rules.changed.map((x) => ['règle', 'modifiée', `${x.name} — ${fieldsOf(x.fields)}`, 'warn'])]
    .slice(0, 200).map(([o, n, det, tone]) => `<tr><td>${esc(o)}</td>
      <td>${pill(n, tone, true)}</td><td class="swb-truncate" title="${esc(det)}">${esc(det)}</td></tr>`).join('')
    || '<tr><td colspan="3"><p class="swb-hint" style="padding:1rem">Aucun changement sur la période.</p></td></tr>'}
          </tbody></table></div></div>`;

    const tlRows = ((tl && tl.points) || []).slice().reverse().map((p) => `<tr>
      <td class="swb-hint">${esc(dt(p.ts))}</td>
      <td>${p.auto ? pill('automatique', 'mute', true) : pill('manuel', 'mute', true)}</td>
      <td class="swb-num">${esc(p.intakes_changed)}</td>
      <td class="swb-num">${esc(p.rules_changed)}</td>
      <td class="swb-num">${pill(String(p.total), p.total ? 'warn' : 'ok', true)}</td></tr>`).join('');

    return `<div class="swb-head">
        <div><h2 class="swb-title">Inventaire — dérive et cohérence</h2>
          <p class="swb-sub">Ce qui a changé depuis le dernier point de référence, et ce qui ne tient pas debout
            dans la configuration courante. Le SIEM n'historise ni l'un ni l'autre.</p></div>
        <div class="swb-actions">
          <span class="swb-hint">${esc(nf((snaps && snaps.count) || 0))} instantané(s)</span>
          <button type="button" class="fp-btn fp-btn-sm" data-swb-act="snapshot">Prendre un instantané</button></div></div>
      <div class="swb-kpis">
        ${kpi('Incohérences', nf(c.issues_total), c.issues_total ? 'danger' : 'ok',
    `${nf(c.checked_intakes)} sources analysées`)}
        ${kpi('Gravité haute', nf((c.by_severity || {}).high), (c.by_severity || {}).high ? 'danger' : 'ok')}
        ${kpi('Gravité moyenne', nf((c.by_severity || {}).medium), (c.by_severity || {}).medium ? 'warn' : 'ok')}
        ${kpi('Règles analysées', nf(c.checked_rules), 'ok')}
      </div>
      <div class="swb-panel" style="padding:0"><div class="swb-panel-head" style="padding:.8rem .9rem 0">
          <h3 class="swb-panel-title">Incohérences de configuration</h3></div>
        <div class="swb-tablewrap" style="max-height:36vh"><table class="swb-table"><thead><tr>
          <th>Gravité</th><th>Constat</th><th class="swb-num">Objets</th><th>Action attendue</th>
        </tr></thead><tbody>${issues || '<tr><td colspan="4"><p class="swb-hint" style="padding:1rem">Aucune incohérence détectée.</p></td></tr>'}</tbody></table></div></div>
      <h3 class="swb-panel-title" style="margin-top:.5rem">Dérive de configuration</h3>
      ${drift}
      ${tlRows ? `<div class="swb-panel" style="padding:0"><div class="swb-panel-head" style="padding:.8rem .9rem 0">
        <h3 class="swb-panel-title">Chronologie des changements</h3></div>
        <div class="swb-tablewrap" style="max-height:28vh"><table class="swb-table"><thead><tr>
          <th>Date</th><th>Origine</th><th class="swb-num">Sources</th><th class="swb-num">Règles</th><th class="swb-num">Total</th>
        </tr></thead><tbody>${tlRows}</tbody></table></div></div>` : ''}`;
  }
  function fieldsOf(f) {
    return Object.entries(f || {}).map(([k, v]) => `${k} : ${v.avant} → ${v.apres}`).join(', ');
  }

  // ── Télémétrie à la demande ───────────────────────────────────────────────
  function viewTelemetry() {
    const res = st.data.events;
    const form = `<div class="swb-panel"><div class="swb-panel-head">
        <h3 class="swb-panel-title">Collecte ciblée</h3></div>
      <p class="swb-hint" style="margin-bottom:.6rem">Interroge directement le SIEM. La collecte est bornée : le job Sekoia est plafonné et aucun événement au-delà de la limite n'est rapatrié.</p>
      <div class="swb-filters">
        <input class="swb-input swb-search" id="swb-tq" placeholder="Requête (ex. source.ip:&quot;10.0.0.1&quot;)" value="${esc(st.filters.tq || '*')}">
        <select class="swb-select" id="swb-trange">
          ${[['1h', '1 heure'], ['6h', '6 heures'], ['24h', '24 heures'], ['7d', '7 jours']]
    .map(([v, l]) => `<option value="${v}"${(st.filters.trange || '24h') === v ? ' selected' : ''}>${esc(l)}</option>`).join('')}
        </select>
        <select class="swb-select" id="swb-tmax">
          ${[100, 500, 1000, 5000].map((n) => `<option value="${n}"${Number(st.filters.tmax || 500) === n ? ' selected' : ''}>${n} événements</option>`).join('')}
        </select>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-swb-act="run-search">Collecter</button>
        ${res && res.items && res.items.length ? '<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="export-os">Indexer dans OpenSearch</button>' : ''}
      </div></div>`;

    if (st.data.eventsLoading) return form + skeleton(8);
    if (!res) {
      return form + stateBox('Aucune collecte lancée',
        'Saisissez une requête puis lancez la collecte. Le résultat peut être indexé dans OpenSearch pour être corrélé avec les autres sources de la plateforme.');
    }
    if (res.error) return form + degraded(res.error);
    const items = res.items || [];
    if (!items.length) {
      return form + stateBox('Aucun événement', `La requête n'a retourné aucun résultat sur la fenêtre demandée.`);
    }
    const cols = ['@timestamp', 'log.hostname', 'source.ip', 'destination.ip', 'event.category', 'message'];
    const get = (o, p) => p.split('.').reduce((a, k) => (a == null ? a : a[k]), o);
    const rows = items.slice(0, 200).map((e) => `<tr>${cols.map((c) => {
      const v = get(e, c) ?? e[c];
      return `<td class="${c === 'message' ? 'swb-truncate' : ''}" title="${esc(v || '')}">${esc(v === undefined || v === null ? '—' : String(v).slice(0, 160))}</td>`;
    }).join('')}</tr>`).join('');
    return form + `<div class="swb-panel" style="padding:0">
      <div class="swb-filters" style="padding:.6rem .8rem 0">
        <span class="swb-count">${nf(res.collected || items.length)} collectés${res.total ? ` sur ${nf(res.total)}` : ''}${res.truncated ? ' · tronqué' : ''}</span></div>
      <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
        ${cols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead>
        <tbody>${rows}</tbody></table></div></div>`;
  }

  // ── Alerting ──────────────────────────────────────────────────────────────
  function viewAlerting() {
    const rules = st.data.arules; const alerts = st.data.alerts;
    if (!rules) return degraded('Moteur de règles injoignable.');
    const bySev = (alerts && alerts.by_severity) || {};
    const ruleRows = (rules.items || []).map((r) => `<tr>
      <td>${r.enabled ? pill('active', 'ok') : pill('inactive', 'mute')}</td>
      <td>${esc(r.name)}</td>
      <td><span class="swb-mono">${esc(r.type)}</span></td>
      <td>${pill(r.severity, r.severity === 'critical' ? 'danger' : r.severity === 'high' ? 'warn' : 'mute')}</td>
      <td class="swb-hint swb-truncate">${esc(JSON.stringify(r.params || {}))}</td>
      <td class="swb-num">${esc(r.cooldown_s)} s</td>
      <td><button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="toggle-rule"
        data-id="${esc(r.id)}" data-enabled="${r.enabled}">${r.enabled ? 'Désactiver' : 'Activer'}</button></td>
    </tr>`).join('');

    let aRows = (alerts && alerts.items) || [];
    aRows = aRows.filter((a) => match(a, ['intake_name', 'message', 'rule_type', 'rule']));
    const body = aRows.slice(0, 200).map((a) => `<tr>
      <td>${pill(a.severity, a.severity === 'critical' ? 'danger' : a.severity === 'high' ? 'warn' : 'mute')}</td>
      <td><span class="swb-mono">${esc(a.rule_type || '—')}</span></td>
      <td class="swb-truncate">${esc(a.intake_name || '—')}</td>
      <td class="swb-truncate" title="${esc(a.message)}">${esc(a.message || '')}</td>
      <td>${a.group_size > 1 ? pill(`×${a.group_size}`, 'warn', true) : ''}</td>
      <td class="swb-hint">${esc(ago(a['@timestamp']))}</td></tr>`).join('');

    return `<div class="swb-head">
        <div><h2 class="swb-title">Alerting d'ingestion</h2>
          <p class="swb-sub">Seuils dynamiques adossés à la baseline et à l'écart-type. Les alertes simultanées partageant une cause forment un incident unique.</p></div>
        <div class="swb-actions">
          <button type="button" class="fp-btn fp-btn-sm" data-swb-act="evaluate">Évaluer (simulation)</button></div></div>
      <div class="swb-kpis">
        ${kpi('Alertes 24 h', nf((alerts && alerts.total) || 0), (alerts && alerts.total) ? 'warn' : 'ok')}
        ${kpi('Critiques', nf(bySev.critical || 0), bySev.critical ? 'danger' : 'ok')}
        ${kpi('Élevées', nf(bySev.high || 0), bySev.high ? 'warn' : 'ok')}
        ${kpi('Règles actives', nf(rules.enabled || 0), 'ok', `${nf(rules.count)} définies`)}
      </div>
      <div class="swb-panel" style="padding:0"><div class="swb-panel-head" style="padding:.8rem .9rem 0">
          <h3 class="swb-panel-title">Règles</h3></div>
        <div class="swb-tablewrap" style="max-height:34vh"><table class="swb-table"><thead><tr>
          <th>État</th><th>Nom</th><th>Type</th><th>Sévérité</th><th>Paramètres</th><th>Cooldown</th><th></th>
        </tr></thead><tbody>${ruleRows}</tbody></table></div></div>
      ${toolbar('Filtrer les alertes…', '', `${nf(aRows.length)} alertes`)}
      <div class="swb-panel" style="padding:0">
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          <th>Sévérité</th><th>Type</th><th>Source</th><th>Message</th><th>Groupe</th><th>Quand</th>
        </tr></thead><tbody>${body || '<tr><td colspan="6"><p class="swb-hint" style="padding:1rem">Aucune alerte sur la période.</p></td></tr>'}</tbody></table></div></div>`;
  }

  // ── Opérations en lot ─────────────────────────────────────────────────────
  function viewOperations() {
    const t = st.data.targets; const hist = st.data.history; const prev = st.data.preview;
    if (!t) return degraded("Moteur d'opérations en lot injoignable.");
    const cur = (t.items || []).find((x) => x.target === (st.filters.target || 'intakes')) || (t.items || [])[0] || {};
    const previewBlock = !prev ? '' : `<div class="swb-panel" style="border-left:3px solid var(--swb-warn)">
      <div class="swb-panel-head"><h3 class="swb-panel-title">${prev.dry_run ? 'Simulation' : 'Exécution'} — ${nf(prev.selected || 0)} objet(s)</h3>
        ${prev.dry_run && prev.selected ? `<button type="button" class="fp-btn fp-btn-sm fp-btn-danger" data-swb-act="bulk-apply">Appliquer à ${nf(prev.selected)} objet(s)</button>` : ''}</div>
      ${prev.error ? `<p class="swb-hint">${esc(prev.error)}</p>` : ''}
      <div class="swb-tablewrap" style="max-height:32vh"><table class="swb-table"><thead><tr><th>Objet</th><th>${prev.dry_run ? 'État avant' : 'Résultat'}</th></tr></thead>
        <tbody>${(prev.results || []).slice(0, 100).map((r) => `<tr><td class="swb-truncate">${esc(r.name || r.id)}</td>
          <td class="swb-hint">${esc(prev.dry_run ? JSON.stringify(r.before || {}) : (r.ok ? 'appliqué' : (r.error || 'échec')))}</td></tr>`).join('')}</tbody></table></div></div>`;

    const histRows = ((hist && hist.items) || []).slice(0, 25).map((b) => `<tr>
      <td class="swb-hint">${esc(dt(b.ts))}</td><td><span class="swb-mono">${esc(b.target)}</span></td>
      <td>${esc(b.action)}</td><td class="swb-num">${esc(b.done)}/${esc(b.selected)}</td>
      <td>${b.rolled_back ? pill('annulé', 'mute')
    : `<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="rollback" data-id="${esc(b.batch_id)}">Annuler</button>`}</td></tr>`).join('');

    return `<div class="swb-head">
        <div><h2 class="swb-title">Opérations en lot</h2>
          <p class="swb-sub">Sélection par filtre plutôt que par liste d'identifiants. Toute opération est simulée avant exécution, et chaque lot peut être annulé.</p></div></div>
      <div class="swb-panel"><div class="swb-filters">
        <select class="swb-select" data-swb-filter="target" aria-label="Cible">
          ${(t.items || []).map((x) => `<option value="${esc(x.target)}"${x.target === st.filters.target ? ' selected' : ''}>${esc(x.target)}</option>`).join('')}
        </select>
        <select class="swb-select" id="swb-action" aria-label="Action">
          ${(cur.actions || []).filter((a) => a !== 'patch').map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join('')}
        </select>
        <input class="swb-input swb-search" id="swb-bulkq" placeholder="Filtrer les objets (nom ou identifiant)">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-swb-act="bulk-dry">Simuler</button>
        <a class="fp-btn fp-btn-sm fp-btn-ghost" href="/api/threat/sekoia/bulk/export/${esc(st.filters.target || 'intakes')}?fmt=yaml"
           target="_blank" rel="noopener">Exporter en YAML</a>
      </div></div>
      ${previewBlock}
      <div class="swb-panel" style="padding:0"><div class="swb-panel-head" style="padding:.8rem .9rem 0">
          <h3 class="swb-panel-title">Historique des lots</h3></div>
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          <th>Date</th><th>Cible</th><th>Action</th><th>Appliqué</th><th></th></tr></thead>
          <tbody>${histRows || '<tr><td colspan="5"><p class="swb-hint" style="padding:1rem">Aucun lot exécuté.</p></td></tr>'}</tbody></table></div></div>`;
  }

  // ── Clés API ──────────────────────────────────────────────────────────────
  function viewApiKeys() {
    const d = st.data.apikeys;
    if (!d) return degraded('Gestion des clés API injoignable.');
    if (d.error && !(d.items || []).length) return degraded(d.error);
    const m = d.monitoring || {};
    let rows = (d.items || []).filter((r) => match(r, ['name', 'description', 'permissions']));
    rows = sorted(rows, 'expires_in_days');
    const body = rows.map((r) => {
      const days = r.expires_in_days;
      const tone = !r.enabled ? 'mute' : (days !== null && days !== undefined && days <= 30 ? 'warn' : 'ok');
      return `<tr>
        <td>${r.enabled ? pill('active', 'ok') : pill(r.state || 'inactive', 'mute')}</td>
        <td class="swb-truncate" title="${esc(r.name)}">${esc(r.name)}</td>
        <td class="swb-hint">${esc(dt(r.created_at))}</td>
        <td>${r.expires_at ? `${esc(dt(r.expires_at))} ${days !== null && days !== undefined ? pill(`${days} j`, tone, true) : ''}` : '<span class="swb-hint">sans expiration</span>'}</td>
        <td class="swb-num">${esc(r.permissions_count || 0)}</td>
        <td class="swb-truncate swb-hint" title="${esc(r.permissions)}">${esc(r.permissions || '—')}</td></tr>`;
    }).join('');
    return `<div class="swb-head"><div><h2 class="swb-title">Clés API Sekoia</h2>
        <p class="swb-sub">Surveillance du parc de clés : expiration proche, clés révoquées, périmètre de permissions.</p></div></div>
      <div class="swb-kpis">
        ${kpi('Clés totales', nf(m.total), 'ok')}
        ${kpi('Actives', nf(m.active), 'ok')}
        ${kpi('Expirent sous 30 j', nf(m.near_expiry), m.near_expiry ? 'warn' : 'ok')}
        ${kpi('Inactives', nf(m.inactive), m.inactive ? 'warn' : 'ok')}
      </div>
      ${toolbar('Rechercher une clé…', '', `${nf(rows.length)} / ${nf((d.items || []).length)}`)}
      <div class="swb-panel" style="padding:0"><div class="swb-tablewrap"><table class="swb-table"><thead><tr>
        ${th('État', 'enabled')}${th('Nom', 'name')}${th('Créée', 'created_at')}${th('Expiration', 'expires_in_days')}
        ${th('Perms', 'permissions_count', 'swb-num')}<th>Permissions</th></tr></thead>
        <tbody>${body || '<tr><td colspan="6"><p class="swb-hint" style="padding:1rem">Aucune clé.</p></td></tr>'}</tbody></table></div></div>`;
  }

  // ── Audit ─────────────────────────────────────────────────────────────────
  function viewAudit() {
    const d = st.data.audit;
    if (!d) return degraded('Journal d’audit injoignable.');
    let rows = (d.items || []).filter((r) => match(r, ['type', 'action', 'user', 'summary', 'target_id']));
    const body = rows.slice(0, 300).map((r) => `<tr>
      <td class="swb-hint">${esc(dt(r.ts))}</td>
      <td>${r.status === 'ok' ? pill('ok', 'ok') : pill(`${r.http || 'erreur'}`, 'danger')}</td>
      <td><span class="swb-mono">${esc(r.type)}</span></td>
      <td>${esc(r.action)}</td>
      <td class="swb-truncate swb-mono">${esc(r.target_id || '—')}</td>
      <td>${esc(r.user || '—')}${r.role ? ` <span class="swb-hint">(${esc(r.role)})</span>` : ''}</td>
      <td class="swb-truncate swb-hint" title="${esc(r.summary)}">${esc(r.summary || '—')}</td></tr>`).join('');
    return `<div class="swb-head"><div><h2 class="swb-title">Centre d'audit</h2>
        <p class="swb-sub">Toute écriture relayée vers Sekoia est journalisée : qui, quoi, quand, avec quel résultat. Les secrets ne sont jamais consignés.</p></div></div>
      ${toolbar('Rechercher dans le journal…', '', `${nf(rows.length)} entrées`)}
      <div class="swb-panel" style="padding:0"><div class="swb-tablewrap"><table class="swb-table"><thead><tr>
        <th>Date</th><th>Résultat</th><th>Objet</th><th>Action</th><th>Cible</th><th>Utilisateur</th><th>Résumé</th>
      </tr></thead><tbody>${body || '<tr><td colspan="7"><p class="swb-hint" style="padding:1rem">Aucune écriture journalisée.</p></td></tr>'}</tbody></table></div></div>`;
  }

  // ── Configuration ─────────────────────────────────────────────────────────
  function viewConfig() {
    const c = st.data.config; const hEng = st.data.cphealth;
    if (!c) return degraded('Configuration injoignable.');
    const data = c.data || {};
    const counts = data.counts || {};
    return `<div class="swb-head"><div><h2 class="swb-title">Configuration de la plateforme</h2>
        <p class="swb-sub">Connexion au tenant Sekoia et état du stockage chiffré. La clé API se saisit ici et n'est jamais renvoyée au navigateur.</p></div></div>
      <div class="swb-kpis">
        ${kpi('Connexion', c.configured ? 'configurée' : 'absente', c.configured ? 'ok' : 'danger', esc(c.base_url))}
        ${kpi('Store de secrets', (hEng && hEng.secrets_store) || c.secrets_store, 'ok', 'chiffrement Fernet')}
        ${kpi('Jeton', c.token_expired ? 'expiré' : 'valide', c.token_expired ? 'danger' : 'ok',
    c.has_api_key ? 'clé API' : (c.has_ui_token ? 'UI token' : '—'))}
        ${kpi('Données persistées', data.persisted ? 'oui' : 'non', data.persisted ? 'ok' : 'warn', ago(data.refreshed_at))}
      </div>
      <div class="swb-grid2">
        <div class="swb-panel"><div class="swb-panel-head"><h3 class="swb-panel-title">Inventaire persisté</h3></div>
          ${kv([
    ['Intakes', nf(counts.intakes)], ['Règles', nf(counts.rules)],
    ['Playbooks', nf(counts.playbooks)], ['Connecteurs', nf(counts.connectors)],
    ['Modules', nf(counts.modules)], ['Formats', nf(counts.formats)],
    ['Dernier rafraîchissement', `${esc(dt(data.refreshed_at))} <span class="swb-hint">(${esc(ago(data.refreshed_at))})</span>`],
    data.refresh_error ? ['Erreur de rafraîchissement', `<span style="color:var(--swb-danger)">${esc(data.refresh_error)}</span>`] : null,
  ])}</div>
        <div class="swb-panel"><div class="swb-panel-head"><h3 class="swb-panel-title">Connexion au tenant</h3></div>
          <p class="swb-hint" style="margin-bottom:.6rem">La clé est stockée chiffrée sur le volume du control-plane. Sa suppression purge l'intégralité des données collectées.</p>
          <div class="swb-filters">
            <input class="swb-input swb-search" id="swb-apikey" type="password" placeholder="Nouvelle clé API Sekoia" autocomplete="off">
            <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-swb-act="save-key">Enregistrer</button>
          </div>
          <p class="swb-hint">Réservé aux administrateurs. Le champ n'est jamais pré-rempli : une clé enregistrée n'est plus jamais restituée.</p>
        </div>
      </div>`;
  }

  // ── Assemblage ────────────────────────────────────────────────────────────
  function nav() {
    let html = '<nav class="swb-nav" role="tablist">';
    let group = null;
    VIEWS.forEach((v) => {
      if (group !== null && v.group !== group) html += '<span class="swb-nav-sep"></span>';
      group = v.group;
      const b = st.badges[v.id];
      html += `<button type="button" role="tab" class="swb-tab" aria-selected="${st.view === v.id}"
        data-swb-view="${v.id}" title="Aller à ${esc(v.label)} (g puis ${esc(v.key)})">${esc(v.label)}${
  b ? `<span class="swb-tab-badge${b.tone === 'danger' ? ' swb-tab-badge-danger' : ''}">${esc(b.text)}</span>` : ''}</button>`;
    });
    return html + `<span class="swb-nav-spacer"></span>
      <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="reload">↻ Rafraîchir</button></nav>`;
  }

  function paint() {
    const el = root();
    if (!el) return;
    let body;
    if (st.loading) body = skeleton(8);
    else if (st.error) body = degraded(st.error);
    else if (st.view === 'overview') body = viewOverview();
    else if (st.view === 'ingestion') body = viewIngestion();
    else if (st.view === 'sources') body = viewSources();
    else if (st.view === 'detections') body = viewDetections();
    else if (st.view === 'inventory') body = viewInventory();
    else if (st.view === 'telemetry') body = viewTelemetry();
    else if (st.view === 'alerting') body = viewAlerting();
    else if (st.view === 'operations') body = viewOperations();
    else if (st.view === 'apikeys') body = viewApiKeys();
    else if (st.view === 'audit') body = viewAudit();
    else body = viewConfig();
    el.className = 'swb';
    el.innerHTML = (st.nav ? nav() : '') + `<div class="swb-body">${body}</div>` + drawer();
  }

  async function load() {
    st.loading = true; st.error = null; st.drawer = null; paint();
    try {
      if (st.view === 'overview' || st.view === 'ingestion') {
        st.data.dashboard = await api(`/dashboard?hours=${st.range}&top=${st.view === 'ingestion' ? 25 : 10}`);
        if (st.view === 'ingestion') {
          // UN SEUL prélèvement pour les deux mesures : deux jobs Sekoia
          // concurrents sur la même fenêtre doublaient le coût et l'un des
          // deux pouvait revenir vide.
          const extra = await Promise.all([
            api('/intakes/health').catch(() => null),
            api('/telemetry/sample?window=1h&sample=500').catch(() => null),
          ]);
          st.data.health = extra[0];
          const smp = extra[1];
          st.data.quality = (smp && smp.available) ? smp.quality
            : { available: false, reason: (smp && smp.reason) || 'Prélèvement indisponible.' };
          st.data.latency = (smp && smp.available) ? smp.latency
            : { available: false, reason: (smp && smp.reason) || 'Prélèvement indisponible.' };
        }
        const k = st.data.dashboard.kpi || {};
        if (k.sources_silent) st.badges.sources = { text: String(k.sources_silent), tone: 'danger' };
      } else if (st.view === 'sources') {
        const r = await Promise.all([
          api('/intakes/health'),
          api('/assets/intelligence?window=1h&sample=1000&persist=1').catch(() => null),
        ]);
        st.data.health = r[0];
        st.data.assets = r[1];
        if (r[1] && r[1].hosts_unmanaged) {
          st.badges.sources = { text: String(r[1].hosts_unmanaged), tone: 'danger' };
        }
      } else if (st.view === 'detections') {
        const r = await Promise.all([
          api('/rules?limit=1200'),
          api('/mitre-coverage').catch(() => null),
        ]);
        st.data.rules = r[0]; st.data.mitre = r[1];
      } else if (st.view === 'inventory') {
        const r = await Promise.all([
          api('/inventory/consistency'),
          api('/inventory/drift').catch(() => null),
          api('/inventory/timeline').catch(() => null),
          api('/inventory/snapshots').catch(() => null),
        ]);
        st.data.consistency = r[0]; st.data.drift = r[1];
        st.data.invTimeline = r[2]; st.data.snapshots = r[3];
        if (r[0] && r[0].issues_total) {
          st.badges.inventory = { text: String(r[0].issues_total), tone: 'danger' };
        }
      } else if (st.view === 'alerting') {
        const r = await Promise.all([
          api('/alerting/rules'), api('/alerting/alerts?hours=24').catch(() => null),
        ]);
        st.data.arules = r[0]; st.data.alerts = r[1];
        if (r[1] && r[1].total) st.badges.alerting = { text: String(r[1].total), tone: 'danger' };
      } else if (st.view === 'operations') {
        const r = await Promise.all([api('/bulk/targets'), api('/bulk/history').catch(() => null)]);
        st.data.targets = r[0]; st.data.history = r[1];
        if (!st.filters.target) st.filters.target = 'intakes';
      } else if (st.view === 'apikeys') {
        st.data.apikeys = await api('/apikeys');
      } else if (st.view === 'audit') {
        st.data.audit = await portalApi('/audit');
      } else if (st.view === 'config') {
        const r = await Promise.all([api('/config'), api('/health').catch(() => null)]);
        st.data.config = r[0]; st.data.cphealth = r[1] && r[1].sekoia ? r[1].sekoia : r[1];
      }
    } catch (e) { st.error = e.message; }
    st.loading = false; paint();
  }

  async function runSearch() {
    st.filters.tq = (document.getElementById('swb-tq') || {}).value || '*';
    st.filters.trange = (document.getElementById('swb-trange') || {}).value || '24h';
    st.filters.tmax = (document.getElementById('swb-tmax') || {}).value || 500;
    st.data.eventsLoading = true; paint();
    try {
      st.data.events = await api('/events/search', {
        method: 'POST',
        body: { q: st.filters.tq, timeRange: st.filters.trange, maxEvents: Number(st.filters.tmax) },
      });
    } catch (e) { st.data.events = { error: e.message }; }
    st.data.eventsLoading = false; paint();
  }

  async function bulk(dry) {
    const action = (document.getElementById('swb-action') || {}).value || 'disable';
    const search = (document.getElementById('swb-bulkq') || {}).value || '';
    try {
      st.data.preview = await api(`/bulk/${encodeURIComponent(st.filters.target || 'intakes')}`, {
        method: 'POST', body: { action, search, dry_run: dry ? 1 : 0 },
      });
      if (!dry) {
        toast(`Lot appliqué : ${st.data.preview.done}/${st.data.preview.selected}`, 'ok');
        st.data.history = await api('/bulk/history').catch(() => st.data.history);
      }
      paint();
    } catch (e) { toast(e.message, 'err'); }
  }

  // ── Interactions ──────────────────────────────────────────────────────────
  function bind(el) {
    if (el.dataset.swbBound) return;
    el.dataset.swbBound = '1';

    el.addEventListener('input', (ev) => {
      const t = ev.target;
      if (t.id === 'swb-q') {
        st.q = t.value;
        // Re-rendu ciblé : on repeint puis on redonne le focus et la position
        // du curseur, sinon la saisie « saute » à chaque frappe.
        const pos = t.selectionStart;
        paint();
        const again = document.getElementById('swb-q');
        if (again) { again.focus(); again.setSelectionRange(pos, pos); }
      }
    });

    el.addEventListener('change', (ev) => {
      const f = ev.target.closest('[data-swb-filter]');
      if (!f) return;
      st.filters[f.dataset.swbFilter] = f.value;
      if (f.dataset.swbFilter === 'target') { st.data.preview = null; }
      paint();
    });

    el.addEventListener('click', async (ev) => {
      const v = ev.target.closest('[data-swb-view]');
      if (v) { st.view = v.dataset.swbView; st.q = ''; st.filters = {}; st.sort = null; load(); return; }
      const sortEl = ev.target.closest('[data-swb-sort]');
      if (sortEl) {
        const k = sortEl.dataset.swbSort;
        st.sortDir = (st.sort === k) ? -st.sortDir : -1;
        st.sort = k; paint(); return;
      }
      const b = ev.target.closest('[data-swb-act]');
      if (!b) return;
      const act = b.dataset.swbAct;
      try {
        if (act === 'reload') { load(); return; }
        if (act === 'close-drawer') { st.drawer = null; paint(); return; }
        if (act === 'range') { st.range = Number(b.dataset.hours) || 24; load(); return; }
        if (act === 'snapshot') {
          b.disabled = true;
          const r = await api('/inventory/snapshots?label=manuel', { method: 'POST' });
          toast(`Instantané pris : ${r.intakes} sources, ${r.rules} règles`, 'ok');
          load(); return;
        }
        if (act === 'open-issue') {
          const issue = (st.data.consistency.issues || []).find((x) => x.kind === b.dataset.kind);
          if (!issue) return;
          st.drawer = {
            title: issue.title,
            subtitle: `${issue.count} objet(s) · gravité ${issue.severity}`,
            body: `<p class="swb-sub">${esc(issue.detail)}</p>`
              + `<div class="swb-state" style="border-left:3px solid var(--swb-warn);text-align:left">
                   <p class="swb-state-title">Action attendue</p>
                   <p class="swb-state-msg">${esc(issue.action)}</p></div>`
              + `<h4 class="swb-panel-title" style="margin:1rem 0 .5rem">Objets concernés</h4>`
              + `<ul style="margin:0;padding-left:1.1rem;font-size:.82rem">${
  issue.items.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`
              + (issue.count > issue.items.length
                ? `<p class="swb-hint" style="margin-top:.5rem">…et ${nf(issue.count - issue.items.length)} autres.</p>` : ''),
          };
          paint(); return;
        }
        if (act === 'open-source') { openSource(b.dataset.id); return; }
        if (act === 'open-rule') { openRule(b.dataset.id); return; }
        if (act === 'intake-toggle' || act === 'rule-toggle') {
          const kind = act === 'intake-toggle' ? 'intakes' : 'rules';
          const to = b.dataset.to === 'enable' ? 'enable' : 'disable';
          b.disabled = true;
          const r = await api(`/${kind}/${encodeURIComponent(b.dataset.id)}/${to}`, { method: 'POST' });
          if (r.ok) {
            toast(to === 'enable' ? 'Activation appliquée' : 'Désactivation appliquée', 'ok');
            st.drawer = null;
            load();
          } else {
            b.disabled = false;
            toast(r.error || 'Sekoia a refusé la modification', 'err');
          }
          return;
        }
        if (act === 'run-search') { runSearch(); return; }
        if (act === 'bulk-dry') { bulk(true); return; }
        if (act === 'bulk-apply') { bulk(false); return; }
        if (act === 'evaluate') {
          const r = await api('/alerting/evaluate?dry_run=1', { method: 'POST' });
          toast(`${r.alerts_new} alerte(s) → ${r.incidents} incident(s)`, 'ok'); return;
        }
        if (act === 'toggle-rule') {
          await api(`/alerting/rules/${encodeURIComponent(b.dataset.id)}`, {
            method: 'PATCH', body: { enabled: b.dataset.enabled !== 'true' },
          });
          load(); return;
        }
        if (act === 'rollback') {
          const r = await api(`/bulk/rollback/${encodeURIComponent(b.dataset.id)}?dry_run=0`, { method: 'POST' });
          toast(r.ok ? `Lot annulé : ${r.restored} restauré(s)` : (r.error || 'échec'), r.ok ? 'ok' : 'err');
          load(); return;
        }
        if (act === 'export-os') {
          const items = (st.data.events && st.data.events.items) || [];
          const r = await fetch('/api/threat/export/opensearch', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ events: items, name: 'workbench' }),
          }).then((x) => x.json());
          toast(r.ok ? `${r.count} événement(s) indexé(s)` : (r.error || 'échec'), r.ok ? 'ok' : 'err');
          return;
        }
        if (act === 'save-key') {
          const input = document.getElementById('swb-apikey');
          const val = (input && input.value || '').trim();
          if (!val) { toast('Saisissez une clé', 'err'); return; }
          const r = await api('/config', { method: 'PUT', body: { SEKOIA_API_KEY: val } });
          if (input) input.value = '';
          toast(r.ok ? 'Clé enregistrée' : (r.error || 'échec'), r.ok ? 'ok' : 'err');
          load(); return;
        }
      } catch (e) { toast(e.message, 'err'); }
    });
  }

  // Raccourcis clavier : « / » focalise la recherche, Échap ferme le volet,
  // « g » puis une lettre navigue entre les missions.
  let chord = false;
  function keys(ev) {
    const el = root();
    if (!el || !el.offsetParent) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((ev.target.tagName || ''));
    if (ev.key === 'Escape') { if (st.drawer) { st.drawer = null; paint(); } chord = false; return; }
    if (typing) return;
    if (ev.key === '/') {
      const q = document.getElementById('swb-q');
      if (q) { ev.preventDefault(); q.focus(); }
      return;
    }
    if (ev.key === 'g') { chord = true; setTimeout(() => { chord = false; }, 1200); return; }
    if (chord) {
      const v = VIEWS.find((x) => x.key === ev.key);
      chord = false;
      if (v) { st.view = v.id; st.q = ''; st.filters = {}; st.sort = null; load(); }
    }
  }

  function init() {
    const el = root();
    if (!el) return;
    bind(el);
    if (!window.__swbKeys) { document.addEventListener('keydown', keys); window.__swbKeys = true; }
    load();
  }

  function mountAt(elId, view, withNav) {
    st.mount = elId;
    st.nav = withNav !== false;
    if (view) st.view = view;
    st.q = ''; st.filters = {}; st.sort = null; st.drawer = null;
    const el = root();
    if (!el) return;
    bind(el);
    if (!window.__swbKeys) { document.addEventListener('keydown', keys); window.__swbKeys = true; }
    load();
  }

  window.SekoiaWorkbench = { init, load, mountAt };
  document.addEventListener('DOMContentLoaded', () => {
    // Chaque entree de la barre laterale ouvre le socle sur SA mission :
    // huit ecrans heterogenes deviennent huit vues d'un meme produit.
    const TABS = {
      'sekoia-extended': ['sekoia-extended-root', null, true],
      'sekoia-cc': ['sekoia-cc-root', 'overview', false],
      'sekoia-ingest': ['sekoia-ingest-root', 'ingestion', false],
      'sekoia-assets': ['sekoia-assets-root', 'sources', false],
      'sekoia-rules': ['sekoia-rules-root', 'detections', false],
      'sekoia-fetch': ['sekoia-fetch-root', 'telemetry', false],
      'sekoia-apikeys': ['sekoia-apikeys-root', 'apikeys', false],
      'audit-center': ['audit-center-root', 'audit', false],
      'tp-config': ['tp-config-root', 'config', false],
    };
    Object.keys(TABS).forEach((tab) => {
      const btn = document.querySelector(`[data-tab-btn="${tab}"]`);
      if (!btn) return;
      const [elId, view, withNav] = TABS[tab];
      btn.addEventListener('click', () => setTimeout(() => mountAt(elId, view, withNav), 60));
    });
  });
}());
