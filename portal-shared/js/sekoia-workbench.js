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
    { id: 'overview', key: 'o', group: 1 },
    { id: 'sources', key: 's', group: 1 },
    { id: 'detections', key: 'd', group: 1 },
    { id: 'inventory', key: 'i', group: 1 },
    { id: 'telemetry', key: 't', group: 1 },
    { id: 'hosts', key: 'h', group: 1 },
    { id: 'value', key: 'v', group: 1 },
    { id: 'alerting', key: 'a', group: 2 },
    { id: 'operations', key: 'p', group: 2 },
    { id: 'apikeys', key: 'k', group: 3 },
    { id: 'audit', key: 'u', group: 3 },
    { id: 'config', key: 'c', group: 3 },
  ];

  // Mode SEP (/sekoia) : l'entrée sidebar « Alerting & drops » ne doit PAS
  // ressortir le workbench 12 onglets (Inventaire, Clés API, Audit…) déjà
  // couverts ailleurs. Deux missions seulement.
  const SEP_VIEWS = [
    { id: 'drops', key: 'd', group: 1 },
    { id: 'alerting', key: 'a', group: 2 },
  ];

  function isSepTool() {
    return document.body.classList.contains('cc-mode-sekoia');
  }
  function activeViews() {
    return isSepTool() ? SEP_VIEWS : VIEWS;
  }

  const st = {
    view: 'overview', range: 24, loading: false, error: null,
    q: '', filters: {}, sort: null, sortDir: -1,
    drawer: null, data: {}, badges: {},
    // Sélection courante, par vue : changer d'onglet ne doit jamais conserver
    // une sélection invisible qu'une action appliquerait ensuite à l'aveugle.
    sel: {}, selView: null, act: null,
  };

  // Cible du moteur de lot pour chaque vue actionnable.
  const SEL_TARGET = { sources: 'intakes', detections: 'rules' };

  function selSet() {
    if (st.selView !== st.view) { st.sel = {}; st.selView = st.view; }
    return st.sel;
  }
  function selIds() { return Object.keys(selSet()); }

  // ── Utilitaires ───────────────────────────────────────────────────────────
  const lang = () => ((window.i18n && i18n.getLanguage && i18n.getLanguage() === 'en') ? 'en-US' : 'fr-FR');

  // Traduction. Le workbench était intégralement écrit en français dans le
  // code : basculer en anglais laissait donc tout le texte en français. Chaque
  // libellé passe désormais par le dictionnaire partagé.
  //
  // Le repli renvoie la clé plutôt qu'une chaîne vide : une clé manquante doit
  // se voir en recette, pas disparaître silencieusement de l'écran.
  // Correspondance exacte français → anglais, pour le texte que le workbench
  // fabrique lui-même (titres, sous-titres, libellés de KPI, filtres). Le
  // moteur i18n du portail ne sait traduire que des attributs `data-i18n`, ce
  // qui ne s'applique pas à du HTML généré.
  //
  // La correspondance est EXACTE : une chaîne absente de la table est laissée
  // telle quelle. C'est ce qui garantit qu'aucune donnée du tenant — un nom de
  // source, un hôte, une entité — ne sera jamais réécrite par erreur.
  let TXMAP = null;
  async function loadTx() {
    if (TXMAP || lang() !== 'en-US') return;
    try {
      // Même base que le moteur i18n du portail : coder l'URL en dur ailleurs
      // reviendrait à en maintenir deux, et j'ai commencé par me tromper.
      const r = await fetch('/shared/i18n/en.json', { credentials: 'same-origin' });
      TXMAP = ((await r.json()) || {}).swbtx || {};
    } catch (_) { TXMAP = {}; }
  }
  function TX(fr) {
    if (lang() !== 'en-US' || !TXMAP) return fr;
    return Object.prototype.hasOwnProperty.call(TXMAP, fr) ? TXMAP[fr] : fr;
  }

  // Passe de traduction limitée aux éléments de CHROME. On ne descend jamais
  // dans les cellules de données : un tableau contient des noms de machines et
  // d'entités, qui ne doivent pas être touchés.
  const CHROME = '.swb-title, .swb-sub, .swb-panel-title, .swb-kpi-label, .swb-kpi-hint,'
    + ' .swb-hint, .swb-table thead th, .swb-select option, button[data-swb-act]';
  function translateChrome(root) {
    if (lang() !== 'en-US' || !TXMAP || !root) return;
    root.querySelectorAll(CHROME).forEach((el) => {
      if (el.children.length) return;          // sous-arbre : on ne réécrit pas
      const raw = (el.textContent || '').trim();
      if (raw && Object.prototype.hasOwnProperty.call(TXMAP, raw)) el.textContent = TXMAP[raw];
    });
    root.querySelectorAll('input[placeholder]').forEach((el) => {
      const raw = el.getAttribute('placeholder');
      if (raw && Object.prototype.hasOwnProperty.call(TXMAP, raw)) el.placeholder = TXMAP[raw];
    });
  }

  function T(key, vars) {
    if (window.i18n && typeof i18n.t === 'function') {
      const out = i18n.t(key, vars);
      if (out && out !== key) return out;
    }
    return key;
  }
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

  // Délai navigateur partagé : un appel qui pend ne doit JAMAIS laisser un
  // squelette éternel — il expire, la vue affiche l'erreur et « Réessayer »,
  // et le calcul serveur (single-flight) alimente le cache pour l'essai suivant.
  function withTimeout(o) {
    if (!o.signal && typeof AbortSignal !== 'undefined' && AbortSignal.timeout) {
      o.signal = AbortSignal.timeout(Number(window.THREAT_FETCH_TIMEOUT_MS || 180000));
    }
    return o;
  }
  function timeoutError(e) {
    if (e && (e.name === 'TimeoutError' || e.name === 'AbortError')) {
      return new Error('Délai dépassé (3 min). Le calcul se poursuit côté serveur — réessayez dans un instant pour lire le résultat.');
    }
    return e;
  }

  async function api(path, opts) {
    const o = withTimeout(Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {}));
    if (o.body && typeof o.body !== 'string') {
      o.body = JSON.stringify(o.body);
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
    }
    let r;
    try { r = await fetch(API + path, o); } catch (e) { throw timeoutError(e); }
    const d = await r.json().catch(() => ({}));
    if (d && d.controlplane_unavailable) {
      throw new Error(d.error || 'Control-plane momentanément indisponible.');
    }
    if (d && d.timed_out) throw new Error(d.error || 'Délai dépassé côté serveur — réessayez.');
    if (!r.ok && d && d.error) throw new Error(d.error);
    return d;
  }
  // SAGF vit sous un prefixe distinct : le confondre avec /sekoia ferait croire
  // qu'il fait partie du SIEM, ce que l'adossement interdit (L8).
  async function sagfApi(path, opts) {
    const o = withTimeout(Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {}));
    if (o.body && typeof o.body !== 'string') {
      o.body = JSON.stringify(o.body);
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
    }
    let r;
    try { r = await fetch('/api/threat/sagf' + path, o); } catch (e) { throw timeoutError(e); }
    const d = await r.json().catch(() => ({}));
    if (!r.ok && d && d.error) throw new Error(d.error);
    return d;
  }

  async function portalApi(path, opts) {
    const o = withTimeout(Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {}));
    let r;
    try { r = await fetch('/api/threat' + path, o); } catch (e) { throw timeoutError(e); }
    const d = await r.json().catch(() => ({}));
    if (!r.ok && d && d.error) throw new Error(d.error);
    return d;
  }

  // QA 04/08/2026 — le workbench n'occupe plus QUE « Synthèse & alertes »
  // (sekoia-extended), avec sa navigation interne à 12 vues. Les autres onglets
  // Sekoia ont chacun leur rendeur dédié : les monter aussi ici créait deux
  // rendeurs concurrents sur le même nœud DOM (sous-nav du Pilotage effacée,
  // double chargement, écrans figés). Un seul montage, une seule vérité.
  const MOUNTS = [
    { el: 'sekoia-extended-root', view: null, nav: true },
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
  function selectionBar() {
    const target = SEL_TARGET[st.view];
    const ids = selIds();
    if (!target || !ids.length) return '';
    const act = st.act;
    // La simulation est montrée AVANT l'application : c'est le moteur de lot
    // qui l'impose, l'interface ne fait que la rendre visible.
    const preview = act && act.preview ? `<div class="swb-panel" style="margin:.5rem 0 0;border-left:3px solid var(--swb-warn)">
        <div class="swb-panel-head"><h3 class="swb-panel-title">${T('swb.sel.simulation', {
          n: nf(act.preview.selected || 0) })}</h3>
          ${act.preview.changing ? `<button type="button" class="fp-btn fp-btn-sm fp-btn-danger"
            data-swb-act="sel-apply">${T('swb.sel.apply', { n: nf(act.preview.changing) })}</button>` : ''}</div>
        ${act.preview.error ? `<p class="swb-hint">${esc(act.preview.error)}</p>` : ''}
        ${act.preview.unchanged ? `<p class="swb-hint">${T('swb.sel.unchanged', {
          n: nf(act.preview.unchanged) })}</p>` : ''}
        <div class="swb-tablewrap" style="max-height:24vh"><table class="swb-table"><tbody>
          ${(act.preview.results || []).slice(0, 60).map((r) => `<tr>
            <td class="swb-truncate" title="${esc(r.name || r.id)}">${esc(r.name || r.id)}</td>
            <td class="swb-hint">${esc(JSON.stringify(r.before || {}))} → ${esc(JSON.stringify(r.would_apply || {}))}</td>
          </tr>`).join('')}</tbody></table></div></div>` : '';

    const bb = st.batch;
    const batchBlock = !bb ? '' : (bb.error
      ? `<div class="swb-panel" style="margin:.5rem 0 0"><p class="swb-hint" style="margin:0">${esc(bb.error)}</p></div>`
      : `<div class="swb-panel" style="margin:.5rem 0 0;border-left:3px solid ${
          bb.rules_ingerables ? 'var(--swb-danger)' : 'var(--swb-ok)'}">
          <div class="swb-panel-head"><h3 class="swb-panel-title">${esc(bb.headline)}</h3>
            <span class="swb-pill swb-pill-flat">${nf(bb.replayed)}/${nf(bb.rules_requested)} ${T('swb.bt.replayed')}</span></div>
          <p class="swb-hint" style="margin:.3rem 0 0">${esc(bb.caution)}</p>
          ${bb.refused ? `<p class="swb-hint" style="margin:.2rem 0 0">${
            T('swb.bt.refused', { n: nf(bb.refused) })}</p>` : ''}
          <div class="swb-tablewrap" style="max-height:26vh;margin-top:.5rem">
            <table class="swb-table"><thead><tr><th>${T('swb.col.rule')}</th>
              <th class="swb-num">${T('swb.v.events')}</th><th>${T('swb.v.verdict')}</th>
            </tr></thead><tbody>${(bb.top || []).map((r) => `<tr>
              <td class="swb-truncate" title="${esc(r.rule_name)}">${esc(r.rule_name)}</td>
              <td class="swb-num">${nf(r.matches)}</td>
              <td class="swb-hint swb-truncate">${esc((r.verdict || {}).text || '')}</td>
            </tr>`).join('')}</tbody></table></div></div>`);

    return `<div class="swb-panel" style="border-left:3px solid var(--swb-accent)">
      <div class="swb-filters" style="align-items:center">
        <strong>${T('swb.sel.count', { n: nf(ids.length) })}</strong>
        <button type="button" class="fp-btn fp-btn-sm" data-swb-act="sel-do" data-op="enable">${T('swb.sel.enable')}</button>
        <button type="button" class="fp-btn fp-btn-sm" data-swb-act="sel-do" data-op="disable">${T('swb.sel.disable')}</button>
        <input class="swb-input" id="swb-seltags" style="max-width:14rem" placeholder="${T('swb.sel.tags_ph')}">
        <button type="button" class="fp-btn fp-btn-sm" data-swb-act="sel-do" data-op="tag_add">${T('swb.sel.tag_add')}</button>
        <button type="button" class="fp-btn fp-btn-sm" data-swb-act="sel-do" data-op="tag_remove">${T('swb.sel.tag_remove')}</button>
        ${target === 'rules' ? `<button type="button" class="fp-btn fp-btn-sm"
          data-swb-act="sel-backtest">${T('swb.bt.batch')}</button>` : ''}
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="sel-clear">${T('swb.sel.clear')}</button>
      </div>${batchBlock}${preview}</div>`;
  }

  function selHead() {
    return `<th style="width:2rem"><input type="checkbox" class="swb-selbox" data-swb-selall="1"
      aria-label="${T('swb.sel.all')}"></th>`;
  }

  function selCell(id) {
    const on = selSet()[id] ? ' checked' : '';
    return `<td><input type="checkbox" class="swb-selbox" data-swb-sel="${esc(id)}"${on}
      aria-label="${T('swb.sel.pick')}"></td>`;
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
    let d = st.drawer;
    if (d.kind === 'remediation') d = remediationDrawer(d);
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

  // Rejeu d'une regle : le VERDICT en premier, le chiffre ensuite, et la reserve
  // avec — un nombre d'evenements lu comme un nombre d'alertes ferait renoncer a
  // une regle qui n'en aurait produit qu'une poignee.
  function backtestPanel(bt) {
    if (bt.loading) {
      return `<div class="swb-panel"><p class="swb-hint" style="margin:0">${T('swb.bt.running')}</p></div>`;
    }
    if (bt.error || bt.reason) {
      return `<div class="swb-panel" style="border-left:3px solid var(--swb-muted)">
        <h3 class="swb-panel-title">${T('swb.bt.not_replayable')}</h3>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(bt.reason || bt.error)}</p>
        ${bt.note ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(bt.note)}</p>` : ''}</div>`;
    }
    const v = bt.verdict || {};
    const tone = v.level === 'ingérable' ? 'var(--swb-danger)'
      : v.level === 'a_surveiller' ? 'var(--swb-warn)'
        : v.level === 'silencieuse' ? 'var(--swb-muted)' : 'var(--swb-ok)';
    return `<div class="swb-panel" style="border-left:3px solid ${tone}">
      <div class="swb-panel-head"><h3 class="swb-panel-title">${T('swb.bt.title')}</h3>
        <span class="swb-pill swb-pill-flat">${nf(bt.matches)} ${T('swb.bt.events')}</span></div>
      <p style="margin:.3rem 0 0"><strong>${esc(v.text || '')}</strong></p>
      <p class="swb-hint" style="margin:.4rem 0 0">${esc(bt.upper_bound_note || '')}</p>
      <p class="swb-hint" style="margin:.3rem 0 0">${esc(bt.vs_satisfiability || '')}</p>
      <p class="swb-hint swb-mono" style="margin:.4rem 0 0;word-break:break-all">${esc(bt.query || '')}</p>
    </div>`;
  }

  // Volet de remédiation : la simulation intégrale AVANT l'écriture, et la
  // réserve du module affichée à côté du bouton — pas dans une infobulle qu'on
  // ne lit qu'après coup.
  function remediationDrawer(d) {
    const rem = (d.issue || {}).remediation || {};
    const p = d.preview || {};
    const rows = (p.results || []).slice(0, 200).map((r) => `<tr>
      <td class="swb-truncate" title="${esc(r.name || r.id)}">${esc(r.name || r.id)}</td>
      <td class="swb-hint">${esc(JSON.stringify(r.before || {}))} → ${esc(JSON.stringify(r.would_apply || {}))}</td>
    </tr>`).join('');
    return {
      title: rem.label || T('swb.inv.remediate'),
      subtitle: d.issue.title,
      body: `${rem.caveat ? `<div class="swb-panel" style="border-left:3px solid var(--swb-warn)">
          <p class="swb-hint" style="margin:0">${esc(rem.caveat)}</p></div>` : ''}
        <div class="swb-panel">
          <p class="swb-hint" style="margin:0 0 .5rem">${T('swb.sel.simulation', { n: nf(p.selected || 0) })}</p>
          ${p.error ? `<p class="swb-hint">${esc(p.error)}</p>` : ''}
          <button type="button" class="fp-btn fp-btn-sm fp-btn-danger"
            data-swb-act="remediate-apply"${p.selected ? '' : ' disabled'}>
            ${T('swb.sel.apply', { n: nf(p.changing !== undefined ? p.changing : p.selected || 0) })}</button>
        </div>
        <div class="swb-panel" style="padding:0"><div class="swb-tablewrap">
          <table class="swb-table"><tbody>${rows}</tbody></table></div></div>`,
    };
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
          <p class="swb-sub">${T('swb.v.ingest_sub', { interval: esc(d.interval) })}</p></div>
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
          ${th(T('swb.col.source'), 'intake_name')}<th>Tendance</th>${th('Volume', 'total', 'swb-num')}
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
            <td class="swb-truncate" title="${esc(i.dialects.join(', '))}">${esc(i.dialects.join(', '))}${i.mixed_dialects ? ' ' + pill('mélange', 'warn', true) : ''}</td>
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
        ${selCell(r.intake_uuid)}
        <td><span class="swb-grade swb-grade-${esc(r.grade)}">${esc(r.grade)}</span></td>
        <td class="swb-num">${esc(r.score)}</td>
        <td class="swb-truncate" title="${esc(r.intake_name)}">${esc(r.intake_name || r.intake_uuid)}</td>
        <td class="swb-truncate" title="${esc(r.entity_name || '—')}">${esc(r.entity_name || '—')}</td>
        <td class="swb-num">${count}</td>
        <td class="swb-num">${measured ? nf(Math.round(r.baseline_avg || 0)) : '—'}</td>
        <td>${r.silent ? pill(T('swb.pill.silent'), 'danger') : (measured ? pill(T('swb.pill.active'), 'ok') : pill(T('swb.pill.unmeasured'), 'warn'))}</td>
      </tr>`;
    }).join('');

    return `${assetsPanel()}
      <div class="swb-head">
        <div><h2 class="swb-title">Sources d'ingestion</h2>
          <p class="swb-sub">Inventaire complet avec volumétrie, baseline et note de santé — aucune de ces valeurs n'est exposée par le SIEM.</p></div>
        <div class="swb-actions">${kpiInline(h)}</div></div>
      ${toolbar('Rechercher une source, une entité, un identifiant…', extra, `${nf(rows.length)} / ${nf((h.items || []).length)}`)}
      ${selectionBar()}
      <div class="swb-panel" style="padding:0">
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          ${selHead()}${th(T('swb.col.grade'), 'grade')}${th(T('swb.col.score'), 'score', 'swb-num')}${th(T('swb.col.source'), 'intake_name')}
          ${th(T('swb.col.entity'), 'entity_name')}${th(T('swb.col.events_h'), 'current_count', 'swb-num')}
          ${th(T('swb.col.baseline'), 'baseline_avg', 'swb-num')}${th(T('swb.col.state'), 'silent')}
        </tr></thead><tbody>${body || '<tr><td colspan="8"><p class="swb-hint" style="padding:1rem">Aucune source ne correspond aux filtres.</p></td></tr>'}</tbody></table></div>
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
      <td class="swb-truncate" title="${esc(h.intakes.join(', '))}">${esc(h.intakes.join(', '))}</td>
      <td class="swb-truncate swb-hint" title="${esc(h.dialects.join(', '))}">${esc(h.dialects.join(', '))}</td>
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
        ${selCell(r.rule_uuid)}
        <td>${r.rule_enabled ? pill(T('swb.pill.active'), 'ok') : pill(T('swb.pill.inactive'), 'mute')}</td>
        <td class="swb-truncate" title="${esc(r.rule_name)}">${esc(r.rule_name)}</td>
        <td class="swb-num">${pill(String(sev), tone, true)}</td>
        <td class="swb-truncate" title="${esc(r.rule_datasources || '—')}">${esc(r.rule_datasources || '—')}</td>
        <td class="swb-num">${r.rule_attack_refs_count ? esc(r.rule_attack_refs_count) : '<span class="swb-hint">0</span>'}</td>
        <td class="swb-truncate" title="${esc(r.rule_tags || '—')}">${esc(r.rule_tags || '—')}</td>
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

    return `${coveragePanel()}
      <div class="swb-head">
        <div><h2 class="swb-title">Règles de détection</h2>
          <p class="swb-sub">Catalogue du tenant avec couverture offensive réelle. Le SIEM n'expose aucun identifiant ATT&CK : la couverture provient des attack-patterns rattachés.</p></div></div>
      ${coverage}
      ${toolbar('Rechercher une règle, un tag, une source de données…', extra,
    `${nf(rows.length)} / ${nf(items.length)}${rows.length > 300 ? ' · 300 affichées' : ''}`)}
      ${selectionBar()}
      <div class="swb-panel" style="padding:0">
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          ${selHead()}${th(T('swb.col.state'), 'rule_enabled')}${th(T('swb.col.rule'), 'rule_name')}${th(T('swb.col.severity'), 'rule_severity', 'swb-num')}
          ${th(T('swb.col.datasources'), 'rule_datasources')}${th(T('swb.col.attack'), 'rule_attack_refs_count', 'swb-num')}${th(T('swb.col.tags'), 'rule_tags')}
        </tr></thead><tbody>${body || '<tr><td colspan="7"><p class="swb-hint" style="padding:1rem">Aucune règle ne correspond aux filtres.</p></td></tr>'}</tbody></table></div>
      </div>
      ${patternRows ? `<div class="swb-panel"><div class="swb-panel-head">
        <h3 class="swb-panel-title">Techniques les plus couvertes</h3></div>
        <div class="swb-tablewrap" style="max-height:320px"><table class="swb-table"><tbody>${patternRows}</tbody></table></div></div>` : ''}`;
  }

  /**
   * Recommandations de couverture et topologie. Le moteur ne constate pas, il
   * dit quoi faire — chaque recommandation porte sa priorité, son motif et son
   * action.
   */
  function coveragePanel() {
    const c = st.data.coverageEngine;
    const g = st.data.graph;
    if (!c || !c.available) return '';
    const tone = { haute: 'danger', moyenne: 'warn', basse: 'mute' };
    const recos = (c.recommendations || []).map((r) => `<div class="swb-panel"
        style="border-left:3px solid var(--swb-${r.priority === 'haute' ? 'danger' : r.priority === 'moyenne' ? 'warn' : 'line'})">
      <div class="swb-panel-head"><h4 class="swb-panel-title">${esc(r.title)}</h4>
        ${pill(r.priority, tone[r.priority] || 'mute')}</div>
      <p class="swb-hint" style="margin:0 0 .4rem">${esc(r.why)}</p>
      <p style="margin:0 0 .4rem;font-size:.84rem"><strong>À faire :</strong> ${esc(r.action)}</p>
      <p class="swb-mono swb-hint" style="font-size:.74rem;margin:0">${
  esc((r.items || []).slice(0, 8).map((i) => i.format || i.intake || '').filter(Boolean).join(' · '))}</p>
    </div>`).join('');

    return `<div class="swb-panel"><div class="swb-panel-head">
        <h3 class="swb-panel-title">Couverture de détection — recommandations</h3>
        ${g ? `<span class="swb-hint">graphe : ${esc(nf(g.nodes_total))} nœuds, ${esc(nf(g.edges_total))} liens</span>` : ''}</div>
      <div class="swb-kpis" style="margin-bottom:.6rem">
        ${kpi('Formats couverts', `${c.coverage_pct} %`, c.coverage_pct >= 60 ? 'ok' : 'warn',
    `${nf(c.formats_covered)} sur ${nf(c.formats_ingested_active)} · ${esc(c.coverage_scope)}`)}
        ${kpi('Règles liées à un format', nf(c.rules_format_specific), 'ok')}
        ${kpi('Règles agnostiques', nf(c.rules_format_agnostic_enabled), 'ok',
    'activées, applicables à toute source')}
        ${kpi('Recommandations', nf(c.recommendations_count), c.recommendations_count ? 'warn' : 'ok')}
      </div>
      <div class="swb-state" style="text-align:left;border-style:solid;border-left:3px solid var(--swb-accent)">
        <p class="swb-state-msg" style="margin:0">${esc(c.coverage_caveat)}</p></div>
      ${recos}</div>`;
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
      ]) + `<div class="swb-filters" style="margin:0 0 .8rem">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="simulate"
          data-kind="rule" data-id="${esc(id)}"
          data-to="${(r && r.rule_enabled) ? 'disable' : 'enable'}">Simuler l'impact</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-swb-act="backtest"
          data-id="${esc(r && r.rule_uuid)}">${T('swb.bt.run')}</button>
        ${st.backtest && st.backtest.rule_uuid === (r && r.rule_uuid) ? backtestPanel(st.backtest) : ''}
        ${st.simulation && st.simulation.target && st.simulation.target.id === id
    ? `<span class="swb-hint">${esc(st.simulation.verdict)}</span>` : ''}
      </div>` + kv([
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
      <td class="swb-hint swb-truncate" title="${esc(i.action)}">${esc(i.action)}</td>
      <td>${i.remediation ? `<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost"
        data-swb-act="remediate" data-kind="${esc(i.kind)}"
        title="${esc(i.remediation.caveat || '')}">${esc(i.remediation.label)}</button>`
        : `<span class="swb-hint">${T('swb.inv.manual')}</span>`}</td></tr>`).join('');

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
          <th>Gravité</th><th>Constat</th><th class="swb-num">Objets</th><th>Action attendue</th><th></th>
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
        <span class="swb-count">${nf(res.collected || items.length)} collectés${res.total ? ` sur ${nf(res.total)}` : ''}${res.truncated ? ' · tronqué' : ''}${
  items.length > 200 ? ` · 200 lignes affichées (tableau borné, tous les événements collectés restent exportables)` : ''}</span></div>
      <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
        ${cols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead>
        <tbody>${rows}</tbody></table></div></div>`;
  }

  // ── Baisses & silencieux (mission SEP « Alerting & drops ») ───────────────
  function viewDrops() {
    const h = st.data.health;
    if (!h || !Array.isArray(h.items)) return degraded('État des intakes injoignable.');
    const items = h.items;
    const silent = items.filter((i) => i.silent);
    const drops = items.filter((i) => {
      const base = Number(i.baseline_avg) || 0;
      const ratio = i.drop_ratio;
      return base > 0 && ratio != null && Number(ratio) < 0.5 && !i.silent;
    });
    const interrupted = silent.filter((i) => (Number(i.baseline_avg) || 0) > 0);
    const never = silent.filter((i) => !(Number(i.baseline_avg) || 0));
    const byType = (st.data.alerts && st.data.alerts.by_type) || {};

    const q = (st.q || '').trim().toLowerCase();
    const filt = (row) => !q || [row.intake_name, row.entity_name, row.intake_uuid]
      .some((x) => String(x || '').toLowerCase().includes(q));

    const silentRows = silent.filter(filt).slice(0, 250).map((i) => `<tr>
      <td class="swb-truncate" title="${esc(i.intake_name)}">${esc(i.intake_name || '—')}</td>
      <td class="swb-truncate" title="${esc(i.entity_name || '')}">${esc(i.entity_name || '—')}</td>
      <td class="swb-num">${esc(nf(i.baseline_avg))}</td>
      <td class="swb-num">${esc(i.last_event_age_min != null ? `${nf(i.last_event_age_min)} min` : '—')}</td>
      <td>${(Number(i.baseline_avg) || 0) > 0
        ? pill('interrompue', 'danger') : pill('jamais alimentée', 'mute')}</td>
      <td><button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-swb-act="intake-enable"
        data-id="${esc(i.intake_uuid)}">Enable</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" data-swb-act="intake-disable"
        data-id="${esc(i.intake_uuid)}">Disable</button>
        <button type="button" class="fp-btn fp-btn-danger-ghost fp-btn-sm" data-swb-act="intake-escalate"
        data-id="${esc(i.intake_uuid)}" data-name="${esc(i.intake_name || '')}"
        data-entity="${esc(i.entity_name || '')}">Escalader</button></td>
    </tr>`).join('');

    const dropRows = drops.filter(filt).slice(0, 100).map((i) => {
      const pct = Math.round((1 - Number(i.drop_ratio)) * 100);
      return `<tr>
        <td class="swb-truncate" title="${esc(i.intake_name)}">${esc(i.intake_name || '—')}</td>
        <td class="swb-num">${esc(nf(i.current_count))}</td>
        <td class="swb-num">${esc(nf(i.baseline_avg))}</td>
        <td>${pill(`−${pct} %`, pct >= 50 ? 'danger' : 'warn', true)}</td>
        <td class="swb-hint">${esc(i.grade || '—')}</td>
      </tr>`;
    }).join('');

    return `<div class="swb-head">
        <div><h2 class="swb-title">Baisses &amp; silencieux</h2>
          <p class="swb-sub">Intakes qui se taisent ou chutent ≥ 50 % vs baseline — pas la volumétrie globale ni l'inventaire.</p></div>
        <div class="swb-actions">
          <button type="button" class="fp-btn fp-btn-sm" data-swb-act="reload">↻ ${esc(T('swb.act.refresh'))}</button></div></div>
      <div class="swb-kpis">
        ${kpi('Intakes', nf(items.length), 'ok')}
        ${kpi('Silencieux', nf(silent.length), silent.length ? 'danger' : 'ok',
          `${nf(interrupted.length)} interrompus · ${nf(never.length)} jamais alimentés`)}
        ${kpi('Baisses ≥ 50 %', nf(drops.length), drops.length ? 'warn' : 'ok', 'émetteurs encore actifs')}
        ${kpi('Alertes silent 24 h', nf(byType.intake_silent || 0), byType.intake_silent ? 'danger' : 'ok',
          'événements (polls répétés)')}
        ${kpi('Alertes drop 24 h', nf((byType.volume_drop || 0) + (byType.host_drop || 0)),
          (byType.volume_drop || byType.host_drop) ? 'warn' : 'ok')}
      </div>
      ${toolbar('Filtrer un intake…', '', `${nf(silent.length)} silencieux · ${nf(drops.length)} baisses`)}
      ${(() => {
        const alerts = (st.data.alerts && st.data.alerts.items) || [];
        const hostvol = (st.data.hostvol && st.data.hostvol.items) || [];
        const silentIds = new Set(silent.map((i) => i.intake_uuid).filter(Boolean));
        const silentNames = new Set(silent.map((i) => String(i.intake_name || '').toLowerCase()).filter(Boolean));
        const linkedAlerts = alerts.filter((a) =>
          silentIds.has(a.intake_uuid) || silentNames.has(String(a.intake_name || '').toLowerCase())
          || ['intake_silent', 'volume_drop', 'host_drop'].includes(a.rule_type)).slice(0, 12);
        const linkedHosts = hostvol.filter((h) => h.silent || h.gone || !h.known_asset).slice(0, 8);
        if (!linkedAlerts.length && !linkedHosts.length) return '';
        return `<div class="swb-panel" style="border-left:3px solid var(--swb-accent)">
          <div class="swb-panel-head"><h3 class="swb-panel-title">Corrélation silence ↔ drop ↔ hôte</h3></div>
          <p class="swb-hint" style="margin:0 0 .5rem">Alertes d'ingestion liées aux silencieux / baisses, et hôtes suspects (non inventoriés ou absents).</p>
          <ul style="margin:0;padding-left:1.1rem;font-size:.82rem;columns:2;column-gap:1.5rem">
            ${linkedAlerts.map((a) => `<li><strong>${esc(a.rule_type || 'alerte')}</strong> —
              ${esc(a.intake_name || a.host || '—')} · ${esc(ago(a['@timestamp']))}</li>`).join('')}
            ${linkedHosts.map((h) => `<li><strong>host</strong> — ${esc(h.host)}
              ${h.known_asset ? '' : ' · hors inventaire'}${h.intake_name ? ` · ${esc(h.intake_name)}` : ''}</li>`).join('')}
          </ul></div>`;
      })()}
      <div class="swb-panel" style="padding:0">
        <div class="swb-panel-head" style="padding:.8rem .9rem 0">
          <h3 class="swb-panel-title">Sources silencieuses</h3></div>
        <div class="swb-tablewrap" style="max-height:36vh"><table class="swb-table"><thead><tr>
          <th>Intake</th><th>Entité</th><th class="swb-num">Baseline</th><th class="swb-num">Âge signal</th><th>État</th><th>Action</th>
        </tr></thead><tbody>${silentRows
          || '<tr><td colspan="6"><p class="swb-hint" style="padding:1rem">Aucun intake silencieux.</p></td></tr>'}</tbody></table></div></div>
      <div class="swb-panel" style="padding:0;margin-top:.7rem">
        <div class="swb-panel-head" style="padding:.8rem .9rem 0">
          <h3 class="swb-panel-title">Baisses de collecte ≥ 50 %</h3></div>
        <div class="swb-tablewrap" style="max-height:28vh"><table class="swb-table"><thead><tr>
          <th>Intake</th><th class="swb-num">Courant</th><th class="swb-num">Baseline</th><th>Chute</th><th>Grade</th>
        </tr></thead><tbody>${dropRows
          || '<tr><td colspan="5"><p class="swb-hint" style="padding:1rem">Aucune baisse ≥ 50 % sur les émetteurs actifs.</p></td></tr>'}</tbody></table></div></div>`;
  }

  // ── Alerting ──────────────────────────────────────────────────────────────
  function viewAlerting() {
    const rules = st.data.arules; const alerts = st.data.alerts;
    if (!rules) return degraded('Moteur de règles injoignable.');
    const bySev = (alerts && alerts.by_severity) || {};
    const byType = (alerts && alerts.by_type) || {};
    const typeHint = Object.entries(byType)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([k, n]) => `${k}: ${nf(n)}`)
      .join(' · ');
    const ruleRows = (rules.items || []).map((r) => `<tr>
      <td>${r.enabled ? pill(T('swb.pill.active'), 'ok') : pill(T('swb.pill.inactive'), 'mute')}</td>
      <td>${esc(r.name)}</td>
      <td><span class="swb-mono">${esc(r.type)}</span></td>
      <td>${pill(r.severity, r.severity === 'critical' ? 'danger' : r.severity === 'high' ? 'warn' : 'mute')}</td>
      <td class="swb-hint swb-truncate">${esc(JSON.stringify(r.params || {}))}</td>
      <td class="swb-num">${esc(r.cooldown_s)} s</td>
      <td><button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="toggle-rule"
        data-id="${esc(r.id)}" data-enabled="${r.enabled}">${r.enabled ? T('swb.sel.disable') : T('swb.sel.enable')}</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="arule-del"
        data-id="${esc(r.id)}" data-name="${esc(r.name)}">${T('swb.al.delete')}</button></td>
    </tr>`).join('');

    let aRows = (alerts && alerts.items) || [];
    aRows = aRows.filter((a) => match(a, ['intake_name', 'message', 'rule_type', 'rule', 'host']));
    const body = aRows.slice(0, 200).map((a) => `<tr>
      <td>${pill(a.severity, a.severity === 'critical' ? 'danger' : a.severity === 'high' ? 'warn' : 'mute')}</td>
      <td><span class="swb-mono">${esc(a.rule_type || '—')}</span></td>
      <td class="swb-truncate" title="${esc(a.intake_name || a.host || '—')}">${esc(a.intake_name || a.host || '—')}</td>
      <td class="swb-truncate" title="${esc(a.message)}">${esc(a.message || '')}</td>
      <td>${a.group_size > 1 ? pill(`×${a.group_size}`, 'warn', true) : ''}</td>
      <td class="swb-hint">${esc(ago(a['@timestamp']))}</td></tr>`).join('');

    return `<div class="swb-head">
        <div><h2 class="swb-title">Alerting d'ingestion</h2>
          <p class="swb-sub">Règles, seuils et flux d'alertes. Les volumes bruts (ex. intake_silent × chaque poll) ne sont pas des intakes distincts.</p></div>
        <div class="swb-actions">
          <button type="button" class="fp-btn fp-btn-sm" data-swb-act="evaluate">${T('swb.act.evaluate')}</button></div></div>
      <div class="swb-kpis">
        ${kpi('Alertes uniques 24 h', nf((alerts && alerts.total) || 0), (alerts && alerts.total) ? 'warn' : 'ok',
          alerts && alerts.raw_total != null
            ? `${nf(alerts.raw_total)} événements bruts${alerts.deduped ? ' · dédupliqués' : ''}`
            : (typeHint || undefined))}
        ${kpi('Critiques', nf(bySev.critical || 0), bySev.critical ? 'danger' : 'ok',
          byType.intake_silent ? `${nf(byType.intake_silent)} silent` : undefined)}
        ${kpi('Élevées', nf(bySev.high || 0), bySev.high ? 'warn' : 'ok',
          (byType.host_drop || byType.volume_drop)
            ? `${nf(byType.host_drop || 0)} host_drop · ${nf(byType.volume_drop || 0)} volume_drop` : undefined)}
        ${kpi('Règles actives', nf(rules.enabled || 0), 'ok', `${nf(rules.count)} définies`)}
      </div>
      ${alerts && alerts.truncated ? `<p class="swb-hint" style="margin:0 0 .6rem;color:var(--swb-warn)">Échantillon tronqué côté index — total estimé via cardinalité fingerprint.</p>` : ''}
      <div class="swb-panel">
        <div class="swb-panel-head"><h3 class="swb-panel-title">${T('swb.al.new')}</h3></div>
        <div class="swb-filters">
          <input class="swb-input" id="swb-arname" style="max-width:16rem" placeholder="${T('swb.al.name_ph')}">
          <select class="swb-select" id="swb-artype" aria-label="${T('swb.col.type')}">
            ${((st.data.artypes && st.data.artypes.items) || []).map((v) =>
              `<option value="${esc(v.type)}">${esc(v.label || v.type)}</option>`).join('')}
          </select>
          <select class="swb-select" id="swb-arsev" aria-label="${T('swb.col.severity')}">
            ${(((st.data.artypes && st.data.artypes.severities) || ['critical', 'high', 'medium', 'low', 'info'])).map((x) =>
              `<option value="${esc(x)}">${esc(x)}</option>`).join('')}
          </select>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-swb-act="arule-new">${T('swb.al.create')}</button>
        </div>
        <p class="swb-hint" style="margin:.4rem 0 0">${T('swb.al.new_hint')}</p></div>
      <div class="swb-panel" style="padding:0"><div class="swb-panel-head" style="padding:.8rem .9rem 0">
          <h3 class="swb-panel-title">Règles</h3></div>
        <div class="swb-tablewrap" style="max-height:34vh"><table class="swb-table"><thead><tr>
          <th>État</th><th>Nom</th><th>Type</th><th>Sévérité</th><th>Paramètres</th><th>Cooldown</th><th></th>
        </tr></thead><tbody>${ruleRows}</tbody></table></div></div>
      ${toolbar('Filtrer les alertes…', '', `${nf(aRows.length)} alertes`)}
      <div class="swb-panel" style="padding:0">
        <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
          <th>Sévérité</th><th>Type</th><th>Source</th><th>Message</th><th>Groupe</th><th>Quand</th>
        </tr></thead><tbody>${body || '<tr><td colspan="6"><p class="swb-hint" style="padding:1rem">Aucune alerte sur la période.</p></td></tr>'}</tbody></table></div></div>
      ${mailNotifyPanel(st.data.mailNotify)}`;
  }

  function mailNotifyPanel(mail) {
    const m = mail || {};
    const recs = m.recipients || [];
    const ev = m.events || {};
    const smtp = m.smtp || {};
    const rows = recs.map((e) => `<tr>
      <td><code>${esc(e)}</code></td>
      <td><button type="button" class="fp-btn fp-btn-sm fp-btn-danger-ghost" data-swb-act="mail-del"
        data-email="${esc(e)}">Retirer</button></td>
    </tr>`).join('');
    const chk = (key, label) => `<label class="swb-hint" style="display:inline-flex;align-items:center;gap:.35rem;margin-right:1rem">
      <input type="checkbox" data-mail-ev="${esc(key)}"${ev[key] !== false ? ' checked' : ''}> ${esc(label)}</label>`;
    const srcLabel = smtp.source === 'encrypted'
      ? 'chiffré Fernet (UI SEP)'
      : 'non configuré — saisir dans l’UI (jamais dans .env)';
    return `<div class="swb-panel" style="margin-top:.75rem">
      <div class="swb-panel-head">
        <h3 class="swb-panel-title">Notifications e-mail</h3>
        <span class="swb-hint">${smtp.configured
          ? `SMTP ${esc(smtp.host || '')}:${esc(String(smtp.port || ''))} · ${esc(srcLabel)}`
          : 'SMTP non configuré — saisir le serveur ci-dessous'}</span>
      </div>
      <p class="swb-hint" style="margin:0 0 .6rem">Identifiants SMTP chiffrés comme la clé API Sekoia (<code>SEKOIA_SECRETS_KEY</code>). Destinataires et événements ci-dessous.</p>
      <div class="swb-filters" style="margin-bottom:.55rem;flex-wrap:wrap;gap:.4rem">
        <input class="swb-input" id="swb-smtp-host" style="max-width:14rem" placeholder="smtp.example.com"
          value="${esc(smtp.host || '')}">
        <input class="swb-input" id="swb-smtp-port" style="max-width:5rem" placeholder="587"
          value="${esc(String(smtp.port != null ? smtp.port : 587))}">
        <input class="swb-input" id="swb-smtp-user" style="max-width:12rem"
          placeholder="${smtp.user ? 'utilisateur (inchangé si vide)' : 'utilisateur'}"
          value="" autocomplete="off">
        <input class="swb-input" id="swb-smtp-pass" type="password" style="max-width:12rem"
          placeholder="${smtp.has_password ? '•••••••• (inchangé si vide)' : 'mot de passe'}"
          value="" autocomplete="new-password">
        <input class="swb-input" id="swb-smtp-from" style="max-width:16rem" placeholder="noreply@example.com"
          value="${esc(smtp.from || '')}">
        <label class="swb-hint" style="display:inline-flex;align-items:center;gap:.3rem">
          <input type="checkbox" id="swb-smtp-tls"${smtp.tls !== false ? ' checked' : ''}> STARTTLS</label>
        <label class="swb-hint" style="display:inline-flex;align-items:center;gap:.3rem">
          <input type="checkbox" id="swb-smtp-ssl"${smtp.ssl ? ' checked' : ''}> SSL</label>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-swb-act="mail-save-smtp">Enregistrer SMTP</button>
      </div>
      ${smtp.has_password || smtp.user
        ? `<p class="swb-hint" style="margin:0 0 .55rem">Auth : ${esc(smtp.user || '—')}${smtp.has_password ? ' · mot de passe enregistré' : ''}</p>`
        : ''}
      <div style="margin-bottom:.55rem">
        ${chk('intake_silent', 'Intake silencieux')}
        ${chk('volume_drop', 'Baisse de volume')}
        ${chk('api_key_created', 'Clé API créée')}
        ${chk('user_created', 'Compte utilisateur')}
      </div>
      <div class="swb-filters" style="margin-bottom:.55rem">
        <input class="swb-input" id="swb-mail-email" style="max-width:22rem" placeholder="admin@cyberdefense.ml"
          value="">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-swb-act="mail-add">Ajouter destinataire</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="mail-save-ev">Enregistrer événements</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="mail-test">Envoyer un test</button>
      </div>
      <div class="swb-tablewrap" style="max-height:16vh"><table class="swb-table"><thead><tr>
        <th>Destinataire</th><th></th>
      </tr></thead><tbody>${rows
        || '<tr><td colspan="2"><p class="swb-hint" style="padding:.6rem">Aucun destinataire — ajoutez admin@cyberdefense.ml</p></td></tr>'}</tbody></table></div>
      ${(m.last_sent && m.last_sent.length) ? `<p class="swb-hint" style="margin:.5rem 0 0">Dernier envoi : ${esc(m.last_sent[0].ts || '')} — ${esc(m.last_sent[0].subject || '')}</p>` : ''}
    </div>
    ${channelsNotifyPanel(st.data.notifyChannels)}`;
  }

  function channelsNotifyPanel(ch) {
    const data = ch || {};
    const items = data.items || [];
    const rows = items.map((c) => `<tr>
      <td><strong>${esc(c.name || c.id)}</strong><br><span class="swb-hint">${esc(c.type)} · ${c.enabled === false ? 'off' : 'on'}</span></td>
      <td><code class="swb-hint">${esc(c.url_preview || '—')}</code></td>
      <td>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="ch-test" data-id="${esc(c.id)}">Test</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-danger-ghost" data-swb-act="ch-del" data-id="${esc(c.id)}">Retirer</button>
      </td>
    </tr>`).join('');
    return `<div class="swb-panel" style="margin-top:.75rem">
      <div class="swb-panel-head">
        <h3 class="swb-panel-title">Canaux (webhook · Slack · Mattermost · Teams · Discord)</h3>
        <span class="swb-hint">${items.length} canal(aux) · URLs chiffrées Fernet</span>
      </div>
      <p class="swb-hint" style="margin:0 0 .6rem">Mêmes événements que l’e-mail. Collez l’URL Incoming Webhook du canal ; le secret reste chiffré.</p>
      <div class="swb-filters" style="margin-bottom:.55rem;flex-wrap:wrap;gap:.4rem">
        <input class="swb-input" id="swb-ch-name" style="max-width:10rem" placeholder="Nom (SOC Slack)">
        <select class="swb-input" id="swb-ch-type" style="max-width:10rem">
          <option value="slack">Slack</option>
          <option value="mattermost">Mattermost</option>
          <option value="teams">Microsoft Teams</option>
          <option value="discord">Discord</option>
          <option value="webhook">Webhook JSON</option>
        </select>
        <input class="swb-input" id="swb-ch-url" style="max-width:28rem" placeholder="https://hooks.slack.com/services/…">
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-swb-act="ch-add">Ajouter canal</button>
      </div>
      <div class="swb-tablewrap" style="max-height:18vh"><table class="swb-table"><thead><tr>
        <th>Canal</th><th>URL</th><th></th>
      </tr></thead><tbody>${rows
        || '<tr><td colspan="3"><p class="swb-hint" style="padding:.6rem">Aucun canal — ajoutez un webhook Slack/Teams/Mattermost</p></td></tr>'}</tbody></table></div>
    </div>`;
  }


  // ── Surveillance par hôte ─────────────────────────────────────────────────
  function viewHosts() {
    const v = st.data.hostvol; const ev = st.data.hostEval;
    if (!v) return degraded('Surveillance par hôte injoignable.');
    if (v.available === false) return degraded(v.reason || v.error || 'Aucun hôte observable.');

    const items = (v.items || []).filter((h) => match(h, ['host', 'intake_name']));
    const unmanaged = (v.items || []).filter((h) => !h.known_asset).length;
    const alerts = (ev && ev.alerts) || [];

    // L'estimation est annoncée AVANT les chiffres : un volume par machine que
    // Sekoia ne mesure pas doit être lu comme un ordre de grandeur.
    const note = `<div class="swb-panel" style="border-left:3px solid var(--swb-accent)">
      <p class="swb-hint" style="margin:0">${esc(v.estimation_note || '')}</p></div>`;

    let evBlock;
    if (!ev) {
      evBlock = '';
    } else if (!ev.ok || (ev.reason && !alerts.length)) {
      // Refus de conclure : on l'affiche comme une information, pas comme une panne.
      evBlock = `<div class="swb-panel" style="border-left:3px solid var(--swb-muted)">
        <h3 class="swb-panel-title">Pas encore de verdict</h3>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(ev.reason || ev.error || '')}</p></div>`;
    } else if (!alerts.length) {
      evBlock = `<div class="swb-panel" style="border-left:3px solid var(--swb-ok)">
        <h3 class="swb-panel-title">Aucune anomalie sur ${esc(ev.hosts_measured || 0)} machine(s)</h3>
        <p class="swb-hint" style="margin:.3rem 0 0">Comparé aux ${esc(ev.snapshots_seen || 0)} relevés de même fenêtre.</p></div>`;
    } else {
      evBlock = alerts.slice(0, 25).map((a) => `<div class="swb-panel" style="border-left:3px solid ${
        a.severity === 'critical' ? 'var(--swb-danger)' : 'var(--swb-warn)'}">
        <div class="swb-panel-head"><h3 class="swb-panel-title">${esc(a.host)}</h3>
          ${pill(a.severity, a.severity === 'critical' ? 'danger' : 'warn', true)}</div>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(a.message)}</p>
        ${a.noise_floor_pct !== undefined ? `<p class="swb-hint" style="margin:.2rem 0 0">
          Concluant : ${esc(a.drop_pct)} % de chute pour un bruit d'échantillonnage de
          ${esc(a.noise_floor_pct)} % (${nf(a.baseline_sampled)} tirages habituels).</p>` : ''}
        ${a.group_size > 1 ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(a.group_label)} — traitez la source, pas chaque machine.</p>` : ''}
      </div>`).join('');
    }

    // Maturité du profil horaire. Affichée AVANT les anomalies : tant qu'elle
    // est faible, les verdicts se fondent sur une médiane globale et un poste
    // qui dort la nuit ressemble à une panne.
    const prof = st.data.hostProf;
    let profBlock = '';
    if (prof && prof.items && prof.items.length) {
      const ready = prof.items.filter((p) => p.coverage && p.coverage.ready).length;
      // Deux mesures distinctes, et les confondre induit en erreur : « complet »
      // = la moitié des 48 créneaux renseignés ; « exploitable » = une normale de
      // créneau utilisable MAINTENANT. La seconde arrive bien avant la première.
      const usable = prof.items.filter((p) => p.expected_now && p.expected_now.seasonal).length;
      const best = prof.items.slice(0, 6);
      profBlock = `<div class="swb-panel">
        <div class="swb-panel-head"><h3 class="swb-panel-title">Normale par créneau horaire</h3>
          ${pill(`${usable}/${prof.items.length} normales de créneau exploitables`, usable ? 'ok' : 'warn', true)}
          ${pill(`${ready} profil(s) complet(s)`, ready ? 'ok' : 'mute', true)}</div>
        <p class="swb-hint" style="margin:.2rem 0 .6rem">${esc(prof.method || '')}</p>
        <div class="swb-tablewrap" style="max-height:22vh"><table class="swb-table"><thead><tr>
          <th>Machine</th><th>Relevés</th><th>Créneaux</th><th>Attendu maintenant</th><th>Référence</th>
        </tr></thead><tbody>${best.map((p) => `<tr>
          <td class="swb-truncate" title="${esc(p.host)}">${esc(p.host)}</td>
          <td class="swb-num swb-hint">${nf(p.points)}</td>
          <td class="swb-num">${nf(p.coverage.cells_filled)}/48</td>
          <td class="swb-num">${nf(p.expected_now.median)}</td>
          <td>${p.expected_now.seasonal ? pill(esc(p.expected_now.reference_label), 'ok')
            : `<span class="swb-hint">${esc(p.expected_now.reference_label)}</span>`}</td>
        </tr>`).join('')}</tbody></table></div></div>`;
    }

    // Corrélation avec les détections. Le diagnostic de joignabilité est
    // indispensable : « 0 corrélation » ne veut pas dire « machines tranquilles ».
    const corr = st.data.hostCorr;
    let corrBlock = '';
    if (corr && corr.ok) {
      const j = corr.joinability || {};
      const forts = (corr.items || []).filter((i) => i.correlation === 'detection_prealable');
      corrBlock = `<div class="swb-panel" style="border-left:3px solid ${
        corr.escalated ? 'var(--swb-danger)' : 'var(--swb-accent)'}">
        <div class="swb-panel-head"><h3 class="swb-panel-title">Corrélation avec les détections</h3>
          ${corr.escalated ? pill(`${corr.escalated} escaladée(s)`, 'danger', true) : ''}</div>
        ${forts.length ? forts.slice(0, 6).map((i) => `<p class="swb-hint" style="margin:.3rem 0">
            <strong>${esc(i.host)}</strong> — ${esc(i.correlation_verdict)}</p>`).join('')
          : `<p class="swb-hint" style="margin:.3rem 0">${esc(corr.reason
              || 'Aucune extinction suivie d\'une détection préalable.')}</p>`}
        <p class="swb-hint" style="margin:.5rem 0 0">${esc(j.note || '')}</p>
        ${j.assets_watched !== undefined ? `<p class="swb-hint" style="margin:.2rem 0 0">
          ${nf(j.assets_watched)} actif(s) surveillé(s) · ${nf(j.assets_cited_by_alerts)} cité(s) par les détections ·
          ${nf(j.assets_in_common)} en commun · ${nf(corr.not_correlatable || 0)} machine(s) non corrélable(s)</p>` : ''}
      </div>`;
    }

    const rows = items.slice(0, 250).map((h) => `<tr>
      <td class="swb-truncate" title="${esc(h.host)}">${esc(h.host)}</td>
      <td class="swb-truncate" title="${esc(h.intake_name || '—')}">${esc(h.intake_name || '—')}</td>
      <td class="swb-num">${nf(h.estimated_events)}</td>
      <td class="swb-num swb-hint">${esc(h.share_pct)} %</td>
      <td class="swb-num swb-hint">${nf(h.sampled)}</td>
      <td>${h.known_asset ? pill(T('swb.pill.known'), 'ok') : pill(T('swb.pill.unknown'), 'warn')}</td>
    </tr>`).join('');

    return `<div class="swb-head">
        <div><h2 class="swb-title">Surveillance par hôte</h2>
          <p class="swb-sub">Une machine qui se tait derrière un relais ne fait pas bouger le total de sa source : l'alerting par intake ne la voit pas. Ce niveau-ci la voit.</p></div>
        <div class="swb-actions">
          <button type="button" class="fp-btn fp-btn-sm" data-swb-act="host-eval">${T('swb.act.host_eval')}</button></div></div>
      <div class="swb-kpis">
        ${kpi('Machines observées', nf(v.hosts), 'ok', `échantillon de ${nf(v.sample_total)} événements`)}
        ${kpi('Hors inventaire', nf(unmanaged), unmanaged ? 'warn' : 'ok', 'émettent sans exister comme actif')}
        ${kpi('Anomalies', nf(alerts.length), alerts.length ? 'danger' : 'ok')}
        ${kpi('Relevés comparés', nf((ev && ev.snapshots_seen) || 0), 'ok', `${nf((ev && ev.rules_active) || 0)} règles hôte`)}
      </div>
      ${note}
      ${corrBlock}
      ${evBlock}
      ${profBlock}
      ${toolbar('Filtrer par machine ou source…', '', `${nf(items.length)} machines`)}
      <div class="swb-panel" style="padding:0"><div class="swb-tablewrap"><table class="swb-table"><thead><tr>
        <th>Machine</th><th>Source</th><th>Volume estimé</th><th>Part</th><th>Échantillonné</th><th>Actif</th>
      </tr></thead><tbody>${rows || '<tr><td colspan="6"><p class="swb-hint" style="padding:1rem">Aucune machine.</p></td></tr>'}</tbody></table></div></div>`;
  }


  // ── Satisfiabilité et valeur ──────────────────────────────────────────────
  function viewValue() {
    const sat = st.data.sat; const val = st.data.val;
    if (!sat && !val) return degraded(T('swb.v.value_down'));

    let satBlock = '';
    if (sat && sat.available) {
      const v = sat.by_verdict || {};
      const inert = sat.rules_enabled_inert || 0;
      const spots = (sat.blind_spots || []).filter((b) => b.rules_enabled_blocked > 0);
      satBlock = `<div class="swb-head"><div>
          <h2 class="swb-title">${T('swb.v.sat_title')}</h2>
          <p class="swb-sub">${T('swb.v.sat_sub')}</p></div></div>
        <div class="swb-panel" style="border-left:3px solid ${inert ? 'var(--swb-danger)' : 'var(--swb-ok)'}">
          <h3 class="swb-panel-title">${esc(sat.headline)}</h3>
          <p class="swb-hint" style="margin:.4rem 0 0">${esc(sat.method_note)}</p></div>
        <div class="swb-kpis">
          ${kpi(T('swb.v.k_inert'), nf(inert), inert ? 'danger' : 'ok', T('swb.v.k_inert_h'))}
          ${kpi(T('swb.v.k_ok'), nf(v.satisfiable || 0), 'ok', T('swb.v.k_ok_h'))}
          ${kpi(T('swb.v.k_noingest'), nf(v.non_ingere || 0), (v.non_ingere ? 'warn' : 'ok'), T('swb.v.k_noingest_h'))}
          ${kpi(T('swb.v.k_conclusive'), `${esc(sat.conclusive_pct)} %`, 'ok',
            `${nf(sat.events_sampled)} · ${nf(sat.fields_observed)} ${T('swb.v.fields')}`)}
        </div>
        ${spots.length ? `<div class="swb-panel" style="padding:0">
          <div class="swb-panel-head" style="padding:.8rem .9rem 0">
            <h3 class="swb-panel-title">${T('swb.v.spots')}</h3></div>
          <p class="swb-hint" style="padding:0 .9rem">${T('swb.v.spots_sub')}</p>
          <div class="swb-tablewrap" style="max-height:32vh"><table class="swb-table"><thead><tr>
            <th>${T('swb.v.field')}</th><th class="swb-num">${T('swb.v.blocked')}</th>
            <th class="swb-num">${T('swb.v.blocked_on')}</th><th class="swb-num">${T('swb.col.severity')}</th>
            <th>${T('swb.v.examples')}</th></tr></thead><tbody>
            ${spots.slice(0, 25).map((b) => `<tr>
              <td><span class="swb-mono">${esc(b.field)}</span></td>
              <td class="swb-num">${nf(b.rules_blocked)}</td>
              <td class="swb-num"><strong>${nf(b.rules_enabled_blocked)}</strong></td>
              <td class="swb-num">${pill(String(b.max_severity), b.max_severity >= 80 ? 'danger' : 'warn', true)}</td>
              <td class="swb-truncate swb-hint" title="${esc((b.examples || []).slice(0, 2).join(' · '))}">${esc((b.examples || []).slice(0, 2).join(' · '))}</td>
            </tr>`).join('')}</tbody></table></div></div>` : ''}
        <div class="swb-panel" style="padding:0">
          <div class="swb-panel-head" style="padding:.8rem .9rem 0">
            <h3 class="swb-panel-title">${T('swb.v.inert_rules')}</h3></div>
          <div class="swb-tablewrap" style="max-height:34vh"><table class="swb-table"><thead><tr>
            <th>${T('swb.col.state')}</th><th>${T('swb.col.rule')}</th>
            <th>${T('swb.v.verdict')}</th><th>${T('swb.v.why')}</th></tr></thead><tbody>
            ${(sat.items || []).filter((i) => i.verdict === 'jamais_satisfiable' || i.verdict === 'non_ingere')
              .slice(0, 60).map((i) => `<tr>
              <td>${i.enabled ? pill(T('swb.pill.active'), 'danger') : pill(T('swb.pill.inactive'), 'mute')}</td>
              <td class="swb-truncate" title="${esc(i.rule_name)}">${esc(i.rule_name)}</td>
              <td>${pill(T('swb.verdict.' + i.verdict), i.verdict === 'jamais_satisfiable' ? 'danger' : 'warn', true)}</td>
              <td class="swb-truncate swb-hint" title="${esc(i.reason)}">${esc(i.reason)}</td>
            </tr>`).join('') || `<tr><td colspan="4"><p class="swb-hint" style="padding:1rem">${T('swb.v.none_inert')}</p></td></tr>`}
          </tbody></table></div></div>`;
    } else if (sat) {
      satBlock = degraded(sat.reason || sat.error || '');
    }

    // Dérive de schéma : la panne qui ne prévient jamais. Placée AVANT la
    // valorisation car une règle morte silencieusement est plus urgente qu'un
    // classement de rendement.
    const dr = st.data.drift;
    let driftBlock = '';
    if (dr && dr.available) {
      const dead = dr.rules_silently_dead || 0;
      driftBlock = `<div class="swb-head" style="margin-top:1rem"><div>
          <h2 class="swb-title">${T('swb.sd.title')}</h2>
          <p class="swb-sub">${T('swb.sd.sub')}</p></div></div>
        <div class="swb-panel" style="border-left:3px solid ${dead ? 'var(--swb-danger)' : 'var(--swb-ok)'}">
          <h3 class="swb-panel-title">${esc(dr.headline)}</h3>
          <p class="swb-hint" style="margin:.4rem 0 0">${esc(dr.reason || dr.method_note || '')}</p></div>
        <div class="swb-kpis">
          ${kpi(T('swb.sd.k_dead'), nf(dead), dead ? 'danger' : 'ok')}
          ${kpi(T('swb.sd.k_lost'), nf(dr.fields_lost), dr.fields_lost ? 'danger' : 'ok')}
          ${kpi(T('swb.sd.k_degraded'), nf(dr.fields_degraded), dr.fields_degraded ? 'warn' : 'ok')}
          ${kpi(T('swb.sd.k_profiled'), nf(dr.fields_profiled), 'ok',
            `${nf(dr.formats_profiled)} ${T('swb.sd.formats')} · ${nf(dr.snapshots_seen)} ${T('swb.sd.snapshots')}`)}
        </div>
        ${[...(dr.disappeared || []), ...(dr.degraded || [])].slice(0, 12).map((d) => `
          <div class="swb-panel" style="border-left:3px solid ${
            d.rules_enabled_impacted ? 'var(--swb-danger)' : 'var(--swb-warn)'}">
            <div class="swb-panel-head">
              <h3 class="swb-panel-title"><span class="swb-mono">${esc(d.field)}</span></h3>
              ${d.rules_enabled_impacted ? pill(`${nf(d.rules_enabled_impacted)} ${T('swb.sd.rules')}`, 'danger', true) : ''}</div>
            <p class="swb-hint" style="margin:.3rem 0 0">${esc(d.message)}</p>
            ${(d.examples || []).length ? `<p class="swb-hint" style="margin:.2rem 0 0">${
              esc(d.examples.slice(0, 3).join(' · '))}</p>` : ''}</div>`).join('')}`;
    } else if (dr) {
      driftBlock = `<div class="swb-panel" style="border-left:3px solid var(--swb-muted)">
        <h3 class="swb-panel-title">${T('swb.sd.title')}</h3>
        <p class="swb-hint" style="margin:.3rem 0 0">${esc(dr.reason || dr.error || '')}</p></div>`;
    }

    let valBlock = '';
    if (val && val.available) {
      const r = val.rules || {};
      valBlock = `<div class="swb-head" style="margin-top:1rem"><div>
          <h2 class="swb-title">${T('swb.v.val_title')}</h2>
          <p class="swb-sub">${T('swb.v.val_sub')}</p></div></div>
        <div class="swb-panel" style="border-left:3px solid ${val.sources_without_alert ? 'var(--swb-warn)' : 'var(--swb-ok)'}">
          <h3 class="swb-panel-title">${esc(val.headline)}</h3>
          <p class="swb-hint" style="margin:.4rem 0 0">${esc(val.caution)}</p>
          ${val.alerts_truncated ? `<p class="swb-hint" style="margin:.3rem 0 0">${esc(val.truncation_note)}</p>` : ''}</div>
        <div class="swb-kpis">
          ${kpi(T('swb.v.k_mute'), nf(val.sources_without_alert), val.sources_without_alert ? 'warn' : 'ok',
            `${esc(val.events_without_alert_pct)} % ${T('swb.v.of_volume')}`)}
          ${kpi(T('swb.v.k_fired'), nf(r.rules_fired), 'ok', `${nf(r.rules_enabled)} ${T('swb.v.enabled')}`)}
          ${kpi(T('swb.v.k_silent'), nf(r.rules_silent), r.rules_silent ? 'warn' : 'ok')}
          ${kpi(T('swb.v.k_conc'), `${esc(r.concentration_top5_pct)} %`,
            r.concentration_top5_pct >= 60 ? 'danger' : 'ok', T('swb.v.k_conc_h'))}
        </div>
        <div class="swb-panel"><p class="swb-hint" style="margin:0">${esc(r.concentration_note)}</p></div>
        <div class="swb-panel" style="padding:0">
          <div class="swb-panel-head" style="padding:.8rem .9rem 0">
            <h3 class="swb-panel-title">${T('swb.v.per_source')}</h3></div>
          <div class="swb-tablewrap" style="max-height:34vh"><table class="swb-table"><thead><tr>
            <th>${T('swb.col.source')}</th><th class="swb-num">${T('swb.v.events')}</th>
            <th class="swb-num">${T('swb.v.alerts')}</th><th class="swb-num">${T('swb.v.per_alert')}</th>
            <th>${T('swb.col.state')}</th></tr></thead><tbody>
            ${(val.items || []).slice(0, 60).map((i) => `<tr>
              <td class="swb-truncate" title="${esc(i.intake_name)}">${esc(i.intake_name)}</td>
              <td class="swb-num">${nf(i.events_period)}</td>
              <td class="swb-num">${nf(i.alerts)}</td>
              <td class="swb-num">${i.events_per_alert === null ? '<span class="swb-hint">—</span>' : nf(i.events_per_alert)}</td>
              <td>${i.silent_value ? pill(T('swb.v.no_alert'), 'warn') : pill(T('swb.v.contributes'), 'ok')}</td>
            </tr>`).join('')}</tbody></table></div></div>
        ${(r.top_noisy || []).length ? `<div class="swb-panel" style="padding:0">
          <div class="swb-panel-head" style="padding:.8rem .9rem 0">
            <h3 class="swb-panel-title">${T('swb.v.noisy')}</h3></div>
          <div class="swb-tablewrap" style="max-height:24vh"><table class="swb-table"><tbody>
            ${r.top_noisy.slice(0, 12).map((n) => `<tr><td class="swb-truncate" title="${esc(n.rule_name)}">${esc(n.rule_name)}</td>
              <td class="swb-num">${nf(n.alerts)}</td></tr>`).join('')}</tbody></table></div></div>` : ''}`;
    } else if (val) {
      valBlock = degraded(val.reason || val.error || '');
    }
    return satBlock + driftBlock + valBlock;
  }


  // ── SAGF — gouvernance adossée ────────────────────────────────────────────
  function viewSagf() {
    const laws = st.data.sagfLaws; const mech = st.data.sagfMech;
    const rep = st.data.sagfReport; const comp = st.data.sagfComp;
    if (!laws && !rep) return degraded(T('swb.sg.down'));

    // La conformité EXÉCUTÉE, pas récitée : c'est ce qui distingue une
    // promesse d'une vérification.
    const c = comp || {};
    const checks = [
      ['L3', T('swb.sg.l3'), c.L3 && c.L3.reversible],
      ['L8', T('swb.sg.l8'), c.L8 && c.L8.faithful],
      ['L11', T('swb.sg.l11'), c.L11 && c.L11.aligned],
      ['I11', T('swb.sg.i11'), c.I11 && c.I11.separated],
    ];
    const compBlock = `<div class="swb-panel">
      <div class="swb-panel-head"><h3 class="swb-panel-title">${T('swb.sg.compliance')}</h3></div>
      <p class="swb-hint" style="margin:.2rem 0 .6rem">${T('swb.sg.compliance_sub')}</p>
      <div class="swb-tablewrap"><table class="swb-table"><tbody>
        ${checks.map(([id, label, ok]) => `<tr>
          <td style="width:4rem"><span class="swb-mono">${esc(id)}</span></td>
          <td>${esc(label)}</td>
          <td style="width:8rem">${ok === undefined ? '<span class="swb-hint">—</span>'
            : ok ? pill(T('swb.sg.verified'), 'ok') : pill(T('swb.sg.violated'), 'danger')}</td>
        </tr>`).join('')}</tbody></table></div></div>`;

    const r = rep || {};
    const kpis = `<div class="swb-kpis">
      ${kpi(T('swb.sg.k_mech'), `${nf(r.mechanisms_implemented)}/${nf(r.mechanisms_total)}`,
        (r.mechanisms_missing || []).length ? 'warn' : 'ok')}
      ${kpi(T('swb.sg.k_laws'), `${nf(12 - (r.laws_not_code_enforced || []).length)}/12`,
        (r.laws_not_code_enforced || []).length ? 'warn' : 'ok', T('swb.sg.k_laws_h'))}
      ${kpi(T('swb.sg.k_inv'), `${nf(13 - (r.invariants_not_fully_enforced || []).length)}/13`,
        (r.invariants_not_fully_enforced || []).length ? 'warn' : 'ok', T('swb.sg.k_inv_h'))}
      ${kpi(T('swb.sg.k_budget'), `${nf((r.budget || {}).remaining)}/${nf((r.budget || {}).per_hour)}`,
        'ok', T('swb.sg.k_budget_h'))}
    </div>`;

    // Les limites permanentes sont affichées AVANT les mécanismes : un écran
    // qui montre « 20/20 » sans elles se lit comme une promesse de perfection.
    const lim = (r.always_limited || {});
    const limBlock = `<div class="swb-panel" style="border-left:3px solid var(--swb-warn)">
      <div class="swb-panel-head"><h3 class="swb-panel-title">${T('swb.sg.limits')}</h3></div>
      <p class="swb-hint" style="margin:.2rem 0 .5rem">${T('swb.sg.limits_sub')}</p>
      <ul style="margin:0;padding-left:1.1rem">
        ${Object.entries(lim).map(([k, v]) => `<li class="swb-hint">
          <span class="swb-mono">${esc(k)}</span> — ${esc(Array.isArray(v) ? v.join(', ') : v)}</li>`).join('')}
      </ul></div>`;

    const own = laws || {};
    const ownBlock = `<div class="swb-panel">
      <div class="swb-panel-head"><h3 class="swb-panel-title">${T('swb.sg.sovereignty')}</h3></div>
      <div class="swb-tablewrap"><table class="swb-table"><thead><tr>
        <th>${T('swb.sg.sekoia_owns')}</th><th>${T('swb.sg.sagf_owns')}</th>
      </tr></thead><tbody><tr>
        <td class="swb-hint">${(own.sekoia_owned || []).map(esc).join(' · ')}</td>
        <td class="swb-hint">${(own.sagf_owned || []).map(esc).join(' · ')}</td>
      </tr></tbody></table></div></div>`;

    const mechBlock = `<div class="swb-panel" style="padding:0">
      <div class="swb-panel-head" style="padding:.8rem .9rem 0">
        <h3 class="swb-panel-title">${T('swb.sg.mechanisms')}</h3></div>
      <p class="swb-hint" style="padding:0 .9rem">${T('swb.sg.mechanisms_sub')}</p>
      <div class="swb-tablewrap" style="max-height:34vh"><table class="swb-table"><thead><tr>
        <th>${T('swb.col.state')}</th><th>#</th><th>${T('swb.sg.name')}</th>
        <th>${T('swb.sg.delegates')}</th><th>${T('swb.sg.refutation')}</th>
      </tr></thead><tbody>${((mech || {}).implemented || []).map((m) => `<tr>
        <td>${m.implemented ? pill(T('swb.sg.on'), 'ok') : pill(T('swb.sg.off'), 'mute')}</td>
        <td><span class="swb-mono">${esc(m.code)}</span></td>
        <td class="swb-truncate" title="${esc(m.name)}">${esc(m.name)}</td>
        <td class="swb-hint swb-truncate">${esc(m.delegates_to || '—')}</td>
        <td class="swb-hint swb-truncate" title="${esc(m.refutation)}">${esc(m.refutation)}</td>
      </tr>`).join('')}</tbody></table></div></div>`;

    // Console SAGQL : le langage est le seul point d'entrée du filtrage.
    const q = st.data.sagfQuery;
    const qBlock = `<div class="swb-panel">
      <div class="swb-panel-head"><h3 class="swb-panel-title">${T('swb.sg.console')}</h3></div>
      <div class="swb-filters">
        <input class="swb-input swb-search" id="swb-sagql" style="flex:1"
          placeholder="${T('swb.sg.ph')}" value="${esc(st.filters.sagql || 'SELECT Rule WHERE verdict = "jamais_satisfiable"')}">
        <button type="button" class="fp-btn fp-btn-sm" data-swb-act="sagql-explain">${T('swb.sg.explain')}</button>
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-swb-act="sagql-run">${T('swb.sg.run')}</button>
      </div>
      <p class="swb-hint" style="margin:.4rem 0 0">${T('swb.sg.console_sub')}</p>
      ${!q ? '' : q.ok === false ? `<div class="swb-panel" style="margin:.5rem 0 0;border-left:3px solid var(--swb-danger)">
          <p class="swb-hint" style="margin:0"><strong>${T('swb.sg.refused')}</strong> ${esc(q.error)}</p>
          ${q.hint ? `<p class="swb-hint swb-mono" style="margin:.3rem 0 0">${esc(q.hint)}</p>` : ''}</div>`
        : `<div class="swb-panel" style="margin:.5rem 0 0;border-left:3px solid var(--swb-accent)">
          ${q.explain ? `<p class="swb-hint" style="margin:0">${T('swb.sg.cost', {
            n: nf(q.explain.cost_units), b: nf(q.explain.budget_remaining) })}</p>` : ''}
          ${q.executed ? `<p style="margin:.3rem 0 0"><strong>${nf(q.matched)}</strong> ${T('swb.sg.matched', { n: nf(q.scanned) })}</p>
            <p class="swb-hint swb-mono" style="margin:.2rem 0 0">${esc((q.provenance || {}).chain ? q.provenance.chain.join(' ← ') : '')}</p>
            <div class="swb-tablewrap" style="max-height:24vh;margin-top:.4rem"><table class="swb-table"><tbody>
              ${(q.items || []).slice(0, 40).map((it) => `<tr>
                <td class="swb-truncate" title="${esc(it.rule_name || it.intake_name || it.field || it.dialect_uuid || '—')}">${esc(it.rule_name || it.intake_name || it.field || it.dialect_uuid || '—')}</td>
                <td class="swb-hint swb-truncate">${esc(it.verdict || it.intake_status || '')}</td></tr>`).join('')}
            </tbody></table></div>` : `<p class="swb-hint" style="margin:.3rem 0 0">${T('swb.sg.not_executed')}</p>`}
        </div>`}</div>`;

    return `<div class="swb-head">
        <div><h2 class="swb-title">${T('swb.sg.title')}</h2>
          <p class="swb-sub">${T('swb.sg.sub')}</p></div>
        <div class="swb-actions">
          <button type="button" class="fp-btn fp-btn-sm" data-swb-act="sagf-snapshot">${T('swb.sg.snapshot')}</button></div></div>
      ${kpis}${compBlock}${limBlock}${qBlock}${ownBlock}${mechBlock}`;
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
        <tbody>${(prev.results || []).slice(0, 100).map((r) => `<tr><td class="swb-truncate" title="${esc(r.name || r.id)}">${esc(r.name || r.id)}</td>
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
        ${cur.taggable ? `<input class="swb-input" id="swb-tags" style="max-width:16rem"
           placeholder="Étiquettes, séparées par des virgules">` : ''}
        <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-swb-act="bulk-dry">Simuler</button>
        <a class="fp-btn fp-btn-sm fp-btn-ghost" href="/api/threat/sekoia/bulk/export/${esc(st.filters.target || 'intakes')}?fmt=yaml"
           target="_blank" rel="noopener">${T('swb.act.export_yaml')}</a>
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
        <td>${r.enabled ? pill(T('swb.pill.active'), 'ok') : pill(r.state || 'inactive', 'mute')}</td>
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
      <td class="swb-truncate swb-mono" title="${esc(r.target_id || '—')}">${esc(r.target_id || '—')}</td>
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
    activeViews().forEach((v) => {
      if (group !== null && v.group !== group) html += '<span class="swb-nav-sep"></span>';
      group = v.group;
      const b = st.badges[v.id];
      html += `<button type="button" role="tab" class="swb-tab" aria-selected="${st.view === v.id}"
        data-swb-view="${v.id}" title="${esc(T('swb.nav.' + v.id))} (g · ${esc(v.key)})">${esc(T('swb.nav.' + v.id))}${
  b ? `<span class="swb-tab-badge${b.tone === 'danger' ? ' swb-tab-badge-danger' : ''}">${esc(b.text)}</span>` : ''}</button>`;
    });
    return html + `<span class="swb-nav-spacer"></span>
      <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-swb-act="reload">↻ ${esc(T('swb.act.refresh'))}</button></nav>`;
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
    else if (st.view === 'hosts') body = viewHosts();
    else if (st.view === 'value') body = viewValue();
    else if (st.view === 'drops') body = viewDrops();
    else if (st.view === 'alerting') body = viewAlerting();
    else if (st.view === 'operations') body = viewOperations();
    else if (st.view === 'apikeys') body = viewApiKeys();
    else if (st.view === 'audit') body = viewAudit();
    else body = viewConfig();
    el.className = 'swb';
    el.innerHTML = (st.nav ? nav() : '') + `<div class="swb-body">${body}</div>` + drawer();
    translateChrome(el);
  }

  // Numéro de génération : incrémenté à chaque `load()`. Sans lui, changer
  // d'onglet vite lance une requête, puis une seconde AVANT que la première
  // n'ait répondu — et si la première répond APRÈS la seconde, elle peint son
  // contenu périmé par-dessus l'écran déjà à jour. C'est exactement le défaut
  // observé pendant la validation de l'outil Sekoia : des écrans vides ou
  // obsolètes lors d'un changement d'onglet rapide, pris pour un défaut
  // réseau alors qu'il venait de l'absence de cette garde.
  let loadGen = 0;
  async function load() {
    const myGen = ++loadGen;
    await loadTx();
    if (myGen !== loadGen) return;   // un onglet plus récent a déjà pris le relais
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
          api('/coverage/engine').catch(() => null),
          api('/graph').catch(() => null),
        ]);
        st.data.rules = r[0]; st.data.mitre = r[1];
        st.data.coverageEngine = r[2]; st.data.graph = r[3];
        if (r[2] && r[2].recommendations_count) {
          st.badges.detections = { text: String(r[2].recommendations_count), tone: 'danger' };
        }
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
      } else if (st.view === 'drops') {
        const r = await Promise.all([
          api('/intakes/health'),
          api('/alerting/alerts?hours=24&dedupe=1&size=200').catch(() => null),
          api('/hosts/volumetry?window=1h&sample=800').catch(() => null),
        ]);
        st.data.health = r[0];
        st.data.alerts = r[1];
        st.data.hostvol = r[2];
        const silentN = ((r[0] && r[0].items) || []).filter((i) => i.silent).length;
        if (silentN) st.badges.drops = { text: String(silentN), tone: 'danger' };
      } else if (st.view === 'alerting') {
        const r = await Promise.all([
          api('/alerting/rules'),
          api('/alerting/alerts?hours=24&dedupe=1&size=200').catch(() => null),
          api('/notify/mail').catch(() => null),
          api('/notify/channels').catch(() => null),
        ]);
        st.data.arules = r[0]; st.data.alerts = r[1];
        st.data.mailNotify = r[2];
        st.data.notifyChannels = r[3];
        st.data.artypes = await api('/alerting/rule-types').catch(() => null);
        if (r[1] && r[1].total) st.badges.alerting = { text: String(r[1].total), tone: 'danger' };
      } else if (st.view === 'hosts') {
        // Le relevé est persisté à chaque consultation : c'est ce qui construit
        // l'historique sans lequel aucune anomalie n'est jugeable.
        const r = await Promise.all([
          api('/hosts/volumetry?window=1h&sample=1500&persist=1'),
          api('/hosts/evaluate?window=1h&sample=1500&dry_run=1', { method: 'POST' }).catch(() => null),
          api('/hosts/profile?hours=336').catch(() => null),
          api('/hosts/correlate?window=1h&hours=24').catch(() => null),
        ]);
        st.data.hostvol = r[0]; st.data.hostEval = r[1];
        st.data.hostProf = r[2]; st.data.hostCorr = r[3];
        const n = (r[1] && r[1].alerts_new) || 0;
        if (n) st.badges.hosts = { text: String(n), tone: 'danger' };
      } else if (st.view === 'value') {
        // Deux moteurs lourds : la satisfiabilité prélève des événements, la
        // valorisation pagine les alertes. On les lance en parallèle et on
        // tolère l'échec de l'un sans perdre l'autre.
        const r = await Promise.all([
          api('/satisfiability?window=24h&sample=1500').catch(() => null),
          api('/valuation?hours=24').catch(() => null),
          // Réutilise l'inventaire déjà en cache : aucun job de recherche
          // supplémentaire n'est lancé si la satisfiabilité vient de tourner.
          api('/schema-drift?window=24h&sample=1200').catch(() => null),
        ]);
        st.data.sat = r[0]; st.data.val = r[1]; st.data.drift = r[2];
        const inert = (r[0] && r[0].rules_enabled_inert) || 0;
        if (inert) st.badges.value = { text: String(inert), tone: 'danger' };
      } else if (st.view === 'sagf') {
        const r = await Promise.all([
          sagfApi('/laws').catch(() => null),
          sagfApi('/mechanisms').catch(() => null),
          sagfApi('/self-report').catch(() => null),
          sagfApi('/compliance').catch(() => null),
        ]);
        st.data.sagfLaws = r[0]; st.data.sagfMech = r[1];
        st.data.sagfReport = r[2]; st.data.sagfComp = r[3];
        const miss = ((r[2] || {}).mechanisms_missing || []).length;
        if (miss) st.badges.sagf = { text: String(miss), tone: 'warn' };
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
    } catch (e) { if (myGen === loadGen) st.error = e.message; }
    if (myGen !== loadGen) return;   // superseded pendant les requêtes ci-dessus
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

  // Action de lot depuis une vue, sur la selection courante. Elle passe par le
  // MEME moteur que l'onglet Operations : simulation obligatoire, historique,
  // rollback. Une action lancee depuis un tableau ne doit pas etre moins sure
  // parce qu'elle est plus rapide d'acces.
  async function selRun(op, dry) {
    const target = SEL_TARGET[st.view];
    const ids = selIds();
    if (!target || !op || !ids.length) return;
    const raw = (document.getElementById('swb-seltags') || {}).value || '';
    const tags = raw.split(',').map((t) => t.trim()).filter(Boolean);
    if (op.indexOf('tag_') === 0 && !tags.length) {
      toast(T('swb.sel.need_tags'), 'err'); return;
    }
    try {
      const r = await api(`/bulk/${encodeURIComponent(target)}`, {
        method: 'POST', body: { action: op, ids, tags, dry_run: dry ? 1 : 0 },
      });
      if (dry) {
        st.act = { op, preview: r };
        if (!r.selected) toast(T('swb.sel.none'), 'err');
        paint(); return;
      }
      st.act = null; st.sel = {};
      toast(T('swb.sel.done', {
        done: nf(r.done || 0), total: nf(r.selected || 0),
        skipped: r.skipped ? T('swb.sel.skipped', { n: nf(r.skipped) }) : '',
      }), r.failed ? 'err' : 'ok');
      load();
    } catch (e) { toast(e.message, 'err'); }
  }

  async function bulk(dry) {
    const action = (document.getElementById('swb-action') || {}).value || 'disable';
    const search = (document.getElementById('swb-bulkq') || {}).value || '';
    const raw = (document.getElementById('swb-tags') || {}).value || '';
    const tags = raw.split(',').map((t) => t.trim()).filter(Boolean);
    if (action.indexOf('tag_') === 0 && !tags.length && action !== 'tag_set') {
      toast('Indiquez au moins une étiquette.', 'err'); return;
    }
    try {
      st.data.preview = await api(`/bulk/${encodeURIComponent(st.filters.target || 'intakes')}`, {
        method: 'POST', body: { action, search, tags, dry_run: dry ? 1 : 0 },
      });
      if (!dry) {
        const p = st.data.preview;
        toast(`Lot appliqué : ${p.done}/${p.selected}${p.skipped ? ` — ${p.skipped} sans changement` : ''}`,
          p.failed ? 'err' : 'ok');
        st.data.history = await api('/bulk/history').catch(() => st.data.history);
      }
      paint();
    } catch (e) { toast(e.message, 'err'); }
  }

  // ── Interactions ──────────────────────────────────────────────────────────
  function bind(el) {
    if (el.dataset.swbBound) return;
    el.dataset.swbBound = '1';

    window.addEventListener('i18n:language-changed', async () => {
      // Seul le rendu est refait : recharger les donnees ferait repartir des
      // jobs de recherche Sekoia pour un simple changement de langue.
      await loadTx();
      try { paint(); } catch (_) { /* la vue n'est pas encore montee */ }
    });

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
      if (v) {
        st.view = v.dataset.swbView; st.q = ''; st.filters = {}; st.sort = null;
        try {
          const u = new URL(location.href);
          u.searchParams.set('tab', 'sekoia-extended');
          u.searchParams.set('view', st.view);
          history.replaceState({}, '', u);
        } catch (_) { /* noop */ }
        load(); return;
      }
      const sortEl = ev.target.closest('[data-swb-sort]');
      if (sortEl) {
        const k = sortEl.dataset.swbSort;
        st.sortDir = (st.sort === k) ? -st.sortDir : -1;
        st.sort = k; paint(); return;
      }
      // Cases a cocher : traitees AVANT les actions de ligne, sinon cocher une
      // case ouvrirait aussi le volet de l'objet.
      const box = ev.target.closest('[data-swb-sel]');
      if (box) {
        ev.stopPropagation();
        const id = box.dataset.swbSel;
        const set = selSet();
        if (set[id]) delete set[id]; else set[id] = 1;
        st.act = null; paint(); return;
      }
      const all = ev.target.closest('[data-swb-selall]');
      if (all) {
        ev.stopPropagation();
        const set = selSet();
        const ids = Array.from(el.querySelectorAll('[data-swb-sel]')).map((n) => n.dataset.swbSel);
        // Tout decocher si tout est deja coche, sinon tout cocher : le meme
        // controle sert dans les deux sens, comme partout ailleurs.
        const every = ids.length && ids.every((i) => set[i]);
        ids.forEach((i) => { if (every) delete set[i]; else set[i] = 1; });
        st.act = null; paint(); return;
      }

      const b = ev.target.closest('[data-swb-act]');
      if (!b) return;
      const act = b.dataset.swbAct;
      try {
        if (act === 'reload') { load(); return; }
        if (act === 'sel-clear') { st.sel = {}; st.act = null; st.batch = null; paint(); return; }
        if (act === 'sagql-run' || act === 'sagql-explain') {
          const raw = (document.getElementById('swb-sagql') || {}).value || '';
          st.filters.sagql = raw;
          const text = act === 'sagql-explain' ? `${raw} EXPLAIN` : raw;
          try {
            st.data.sagfQuery = await sagfApi('/query', { method: 'POST', body: { q: text } });
          } catch (e) { st.data.sagfQuery = { ok: false, error: e.message }; }
          paint(); return;
        }
        if (act === 'sagf-snapshot') {
          const r = await sagfApi('/config/snapshot?entity=Rule&author=ui&reason=releve%20manuel',
            { method: 'POST' }).catch((e) => ({ ok: false, error: e.message }));
          toast(r.ok ? T('swb.sg.snapshot_done', { w: nf(r.written), u: nf(r.unchanged) })
            : (r.error || 'échec'), r.ok ? 'ok' : 'err');
          return;
        }
        if (act === 'sel-backtest') {
          const ids = selIds();
          if (!ids.length) return;
          // Chaque rejeu est un job de recherche : on previent, sinon
          // l'operateur croit que rien ne se passe pendant une minute.
          toast(T('swb.bt.batch_running', { n: nf(ids.length) }), 'ok');
          st.batch = null; paint();
          try {
            st.batch = await api('/backtest-batch?window=7d',
              { method: 'POST', body: { ids } });
          } catch (e) { st.batch = { error: e.message }; }
          paint(); return;
        }
        if (act === 'arule-new') {
          const name = (document.getElementById('swb-arname') || {}).value || '';
          if (!name.trim()) { toast(T('swb.al.need_name'), 'err'); return; }
          const type = (document.getElementById('swb-artype') || {}).value;
          // Envoyer un type vide produit un 400 opaque cote serveur. On le dit
          // ici, ou le catalogue de types n'a pas pu etre charge.
          if (!type) { toast(T('swb.al.no_types'), 'err'); return; }
          const body = {
            name: name.trim(),
            type,
            severity: (document.getElementById('swb-arsev') || {}).value,
            enabled: true,
          };
          const r = await api('/alerting/rules', { method: 'POST', body });
          if (r && r.error) { toast(r.error, 'err'); return; }
          // La regle creee est prise depuis la REPONSE, qui fait autorite, et non
          // depuis une relecture de la liste. J'ai observe que la relecture
          // immediate pouvait renvoyer un etat anterieur d'un cran, sans avoir pu
          // en isoler la cause : le fichier et l'API directe concordent pourtant.
          // Afficher ce que le serveur vient de confirmer evite de faire croire a
          // l'operateur que sa creation a echoue alors qu'elle a reussi.
          if (r && r.rule && st.data.arules) {
            const items = (st.data.arules.items || []).filter((x) => x.id !== r.rule.id);
            items.push(r.rule);
            st.data.arules = { ...st.data.arules, items, count: items.length,
              enabled: items.filter((x) => x.enabled).length };
          }
          toast(T('swb.al.created', { name: body.name }), 'ok');
          // On ne recharge PAS derriere : la relecture immediate renvoie un etat
          // anterieur et ecraserait la ligne qu'on vient de confirmer. L'etat
          // affiche vient de la reponse du serveur, qui fait autorite ; le
          // prochain rafraichissement volontaire reconcilie le reste.
          paint(); return;
        }
        if (act === 'arule-del') {
          // Suppression definitive : on demande confirmation en NOMMANT la
          // regle, plutot qu'un « etes-vous sur ? » qu'on clique sans lire.
          if (!window.confirm(T('swb.al.confirm_del', { name: b.dataset.name }))) return;
          await api(`/alerting/rules/${encodeURIComponent(b.dataset.id)}`, { method: 'DELETE' });
          // Meme raison qu'a la creation : on retire la ligne tout de suite.
          if (st.data.arules) {
            const items = (st.data.arules.items || []).filter((x) => x.id !== b.dataset.id);
            st.data.arules = { ...st.data.arules, items, count: items.length,
              enabled: items.filter((x) => x.enabled).length };
          }
          toast(T('swb.al.deleted'), 'ok');
          paint(); return;
        }
        if (act === 'remediate') {
          // La remediation passe par le moteur de lot, en SIMULATION d'abord.
          // Un constat d'inventaire ne doit pas etre un raccourci vers une
          // ecriture non simulee.
          const issue = ((st.data.consistency || {}).issues || [])
            .find((x) => x.kind === b.dataset.kind);
          if (!issue || !issue.remediation) return;
          const rem = issue.remediation;
          const r = await api(`/bulk/${encodeURIComponent(rem.target)}`, {
            method: 'POST', body: { action: rem.action, ids: rem.ids, dry_run: 1 },
          });
          st.drawer = { kind: 'remediation', issue, preview: r };
          paint(); return;
        }
        if (act === 'remediate-apply') {
          const d = st.drawer || {};
          const rem = (d.issue || {}).remediation || {};
          const r = await api(`/bulk/${encodeURIComponent(rem.target)}`, {
            method: 'POST', body: { action: rem.action, ids: rem.ids, dry_run: 0 },
          });
          st.drawer = null;
          toast(T('swb.sel.done', { done: nf(r.done || 0), total: nf(r.selected || 0),
            skipped: r.skipped ? T('swb.sel.skipped', { n: nf(r.skipped) }) : '' }),
            r.failed ? 'err' : 'ok');
          load(); return;
        }
        if (act === 'sel-do') { await selRun(b.dataset.op, true); return; }
        if (act === 'sel-apply') { await selRun(st.act && st.act.op, false); return; }
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
        if (act === 'backtest') {
          // Le rejeu lance un job de recherche Sekoia : on le signale, sans quoi
          // l'operateur croit que rien ne se passe pendant une minute.
          toast(T('swb.bt.running'), 'ok');
          st.backtest = { rule_uuid: b.dataset.id, loading: true };
          paint();
          try {
            st.backtest = await api(`/backtest/${encodeURIComponent(b.dataset.id)}?window=7d`);
          } catch (e) {
            st.backtest = { rule_uuid: b.dataset.id, error: e.message };
          }
          await openRule(b.dataset.id);
          return;
        }
        if (act === 'simulate') {
          const r = await api(`/simulate?kind=${encodeURIComponent(b.dataset.kind)}`
            + `&id=${encodeURIComponent(b.dataset.id)}&action=${encodeURIComponent(b.dataset.to)}`);
          if (!r.ok) { toast(r.error || 'Simulation impossible', 'err'); return; }
          st.simulation = r;
          // Le verdict est la valeur du simulateur : on le met en avant plutôt
          // que de laisser l'analyste lire un objet JSON.
          toast(r.verdict, r.impact && r.impact.creates_blind_spot ? 'err' : 'ok');
          paint(); return;
        }
        if (act === 'intake-escalate') {
          const name = b.dataset.name || b.dataset.id || 'intake';
          if (!confirm(`Escalader « ${name} » en alerte critique ?`)) return;
          b.disabled = true;
          const preview = await api('/alerting/escalate?dry_run=1', {
            method: 'POST',
            body: {
              intake_uuid: b.dataset.id,
              intake_name: b.dataset.name,
              entity_name: b.dataset.entity,
              reason: `Escalade manuelle — intake silencieux (${name})`,
              severity: 'critical',
            },
          });
          if (!preview || preview.ok === false) {
            b.disabled = false;
            toast((preview && preview.error) || 'Échec simulation escalade', 'err');
            return;
          }
          const r = await api('/alerting/escalate?dry_run=0', {
            method: 'POST',
            body: {
              intake_uuid: b.dataset.id,
              intake_name: b.dataset.name,
              entity_name: b.dataset.entity,
              reason: `Escalade manuelle — intake silencieux (${name})`,
              severity: 'critical',
            },
          });
          b.disabled = false;
          if (r && r.ok) {
            toast('Escalade écrite (alerte critique)', 'ok');
            load();
          } else {
            toast((r && r.error) || 'Échec escalade', 'err');
          }
          return;
        }
        if (act === 'intake-enable' || act === 'intake-disable'
            || act === 'intake-toggle' || act === 'rule-toggle') {
          const kind = act === 'rule-toggle' ? 'rules' : 'intakes';
          const op = act === 'intake-enable' ? 'enable'
            : act === 'intake-disable' ? 'disable'
              : (b.dataset.to === 'enable' ? 'enable' : 'disable');
          b.disabled = true;
          const r = await api(`/${kind}/${encodeURIComponent(b.dataset.id)}/${op}`, { method: 'POST' });
          if (r.ok) {
            toast(op === 'enable' ? 'Activation appliquée' : 'Désactivation appliquée', 'ok');
            st.drawer = null;
            load();
          } else {
            b.disabled = false;
            toast(r.error || 'Sekoia a refusé la modification', 'err');
          }
          return;
        }
        if (act === 'run-search') { runSearch(); return; }
        if (act === 'host-eval') {
          const r = await api('/hosts/evaluate?window=1h&sample=1500&dry_run=1', { method: 'POST' });
          st.data.hostEval = r;
          toast(r.reason ? r.reason : `${r.alerts_new || 0} anomalie(s) sur ${r.hosts_measured || 0} machine(s)`,
            (r.alerts_new || 0) ? 'err' : 'ok');
          paint(); return;
        }
        if (act === 'bulk-dry') { bulk(true); return; }
        if (act === 'bulk-apply') { bulk(false); return; }
        if (act === 'evaluate') {
          const r = await api('/alerting/evaluate?dry_run=1', { method: 'POST' });
          toast(`${r.alerts_new} alerte(s) → ${r.incidents} incident(s)`, 'ok'); return;
        }
        if (act === 'mail-add') {
          const inp = document.getElementById('swb-mail-email');
          const email = ((inp && inp.value) || '').trim().toLowerCase();
          if (!email || email.indexOf('@') < 1) { toast('Adresse e-mail invalide', 'err'); return; }
          const r = await api('/notify/mail/recipients', { method: 'POST', body: { email } });
          if (r && r.ok) { toast(`Ajouté : ${email}`, 'ok'); load(); }
          else toast((r && r.error) || 'Échec ajout', 'err');
          return;
        }
        if (act === 'mail-del') {
          const email = b.dataset.email;
          if (!confirm(`Retirer ${email} ?`)) return;
          const r = await api(`/notify/mail/recipients?email=${encodeURIComponent(email)}`, { method: 'DELETE' });
          if (r && r.ok) { toast('Destinataire retiré', 'ok'); load(); }
          else toast((r && r.error) || 'Échec', 'err');
          return;
        }
        if (act === 'mail-save-ev') {
          const events = {};
          document.querySelectorAll('[data-mail-ev]').forEach((el) => {
            events[el.dataset.mailEv] = !!el.checked;
          });
          const r = await api('/notify/mail', { method: 'PUT', body: { events } });
          if (r && r.ok) { toast('Événements enregistrés', 'ok'); load(); }
          else toast((r && r.error) || 'Échec', 'err');
          return;
        }
        if (act === 'mail-save-smtp') {
          const host = (document.getElementById('swb-smtp-host') || {}).value || '';
          const port = (document.getElementById('swb-smtp-port') || {}).value || '587';
          const user = (document.getElementById('swb-smtp-user') || {}).value || '';
          const password = (document.getElementById('swb-smtp-pass') || {}).value || '';
          const from = (document.getElementById('swb-smtp-from') || {}).value || '';
          const tls = !!(document.getElementById('swb-smtp-tls') || {}).checked;
          const ssl = !!(document.getElementById('swb-smtp-ssl') || {}).checked;
          if (!host.trim()) { toast('Hôte SMTP requis', 'err'); return; }
          const body = { host: host.trim(), port: parseInt(port, 10) || 587, from: from.trim(), tls, ssl };
          if (user.trim()) body.user = user.trim();
          if (password) body.password = password;
          const r = await api('/notify/mail/smtp', { method: 'PUT', body });
          if (r && r.ok) { toast('SMTP enregistré (chiffré)', 'ok'); load(); }
          else toast((r && r.error) || 'Échec enregistrement SMTP', 'err');
          return;
        }
        if (act === 'mail-test') {
          const inp = document.getElementById('swb-mail-email');
          const email = ((inp && inp.value) || '').trim();
          const r = await api('/notify/mail/test', { method: 'POST', body: email ? { email } : {} });
          if (r && r.ok) toast(`Test envoyé → ${(r.recipients || []).join(', ')}`, 'ok');
          else toast((r && r.error) || 'Échec envoi (configurer SMTP dans SEP)', 'err');
          return;
        }
        if (act === 'ch-add') {
          const name = ((document.getElementById('swb-ch-name') || {}).value || '').trim();
          const type = ((document.getElementById('swb-ch-type') || {}).value || 'webhook').trim();
          const url = ((document.getElementById('swb-ch-url') || {}).value || '').trim();
          if (!url || url.indexOf('http') !== 0) { toast('URL http(s) requise', 'err'); return; }
          const r = await api('/notify/channels', {
            method: 'POST',
            body: { name: name || type, type, url, events: [] },
          });
          if (r && r.ok) { toast(`Canal ${type} ajouté`, 'ok'); load(); }
          else toast((r && r.error) || 'Échec ajout canal', 'err');
          return;
        }
        if (act === 'ch-del') {
          if (!confirm('Retirer ce canal ?')) return;
          const r = await api(`/notify/channels/${encodeURIComponent(b.dataset.id)}`, { method: 'DELETE' });
          if (r && r.ok) { toast('Canal retiré', 'ok'); load(); }
          else toast((r && r.error) || 'Échec', 'err');
          return;
        }
        if (act === 'ch-test') {
          const r = await api(`/notify/channels/${encodeURIComponent(b.dataset.id)}/test`, { method: 'POST' });
          if (r && r.ok) toast('Test canal envoyé', 'ok');
          else toast((r && r.error) || 'Échec test canal', 'err');
          return;
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
      const v = activeViews().find((x) => x.key === ev.key);
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
    const pendingView = window.__pendingSwbView
      || new URLSearchParams(location.search).get('view');
    window.__pendingSwbView = null;
    // Vue demandée > ?view= > défaut SEP (alerting) > défaut CERT (overview).
    if (view) st.view = view;
    else if (pendingView) st.view = pendingView;
    else if (isSepTool()) st.view = 'alerting';
    if (isSepTool() && !SEP_VIEWS.some((v) => v.id === st.view)) st.view = 'alerting';
    try {
      const u = new URL(location.href);
      u.searchParams.set('tab', 'sekoia-extended');
      u.searchParams.set('view', st.view);
      history.replaceState({}, '', u);
    } catch (_) { /* noop */ }
    st.q = ''; st.filters = {}; st.sort = null; st.drawer = null;
    const el = root();
    if (!el) return;
    bind(el);
    if (!window.__swbKeys) { document.addEventListener('keydown', keys); window.__swbKeys = true; }
    load();
  }

  // L'activation des 9 ecrans (clic ET lien profond ?tab=) est centralisee
  // dans cert-app.js:tab() via window.SekoiaWorkbench.mountAt — c'est le
  // dispatcher unique deja utilise par tous les autres modules du portail.
  // Un ecouteur de clic propre a ce module, comme avant, faisait DOUBLE
  // emploi avec celui que cert-app.js attache deja a tout [data-tab-btn]
  // (deux appels a mountAt() par clic) et surtout ne couvrait PAS le lien
  // profond, le rafraichissement de page ni le retour arriere du navigateur
  // — ces neuf panneaux restaient alors bloques sur « Chargement... »
  // indefiniment, sans erreur, alors meme que le backend repondait en 0,5 s.
  window.SekoiaWorkbench = { init, load, mountAt };
}());
