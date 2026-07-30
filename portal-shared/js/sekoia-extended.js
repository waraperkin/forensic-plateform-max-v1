/* SEKOIA EXTENDED PLATFORM — console analyste.
 *
 * Expose les moteurs que le SIEM Sekoia ne fournit pas : volumétrie réelle par
 * intake, alerting configurable, opérations en lot. Navigation par mission
 * (Supervision / Alerting / Opérations) plutôt que par objet technique.
 *
 * Principes tenus :
 * - aucune donnée fabriquée : « non mesuré » ne s'affiche jamais comme 0 ;
 * - aucun message technique brut (ENOTFOUND…) : état dégradé + relance ;
 * - toute opération d'écriture est simulée avant d'être proposée à l'exécution.
 */
(function () {
  'use strict';

  const TC = window.ThreatCommon || null;
  const esc = (s) => (TC && TC.esc ? TC.esc(s) : String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));
  const toast = (m, c) => { if (TC && TC.toast) TC.toast(m, c); };

  const API = '/api/threat/sekoia';
  const st = { view: 'dashboard', range: 24, data: {}, loading: false, error: null };

  function nf(n) {
    if (n === null || n === undefined) return '—';
    return Number(n).toLocaleString(
      (window.i18n && i18n.getLanguage && i18n.getLanguage() === 'en') ? 'en-US' : 'fr-FR');
  }

  async function api(path, opts) {
    const o = Object.assign({ credentials: 'include', cache: 'no-store' }, opts || {});
    if (o.body && typeof o.body !== 'string') {
      o.body = JSON.stringify(o.body);
      o.headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {});
    }
    const r = await fetch(API + path, o);
    const d = await r.json().catch(() => ({}));
    // Le proxy renvoie 200 + controlplane_unavailable quand le service redémarre.
    if (d && d.controlplane_unavailable) {
      throw new Error(d.error || 'Control-plane momentanément indisponible.');
    }
    if (!r.ok && d && d.error) throw new Error(d.error);
    return d;
  }

  function root() { return document.getElementById('sekoia-extended-root'); }

  function shell(body) {
    const tabs = [
      ['dashboard', 'Tableau de bord'],
      ['supervision', 'Supervision'],
      ['alerting', 'Alerting'],
      ['operations', 'Opérations en lot'],
    ];
    const nav = tabs.map(function (t) {
      const on = st.view === t[0];
      return '<button type="button" role="tab" class="fp-btn fp-btn-sm'
        + (on ? ' fp-btn-primary' : ' fp-btn-ghost') + '" data-sep-view="' + t[0]
        + '" aria-selected="' + on + '">' + esc(t[1]) + '</button>';
    }).join('');
    return '<div class="sep-console"><nav class="sep-tabs" role="tablist">' + nav
      + '<span class="sep-tabs-spacer"></span>'
      + '<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-sep-act="refresh">&#8635; Rafraîchir</button>'
      + '</nav><div class="sep-body">' + body + '</div></div>';
  }

  function degraded(message) {
    return '<div class="fp-card sep-degraded" role="status">'
      + '<p class="sep-degraded-title">Données momentanément indisponibles</p>'
      + '<p class="fp-muted">' + esc(message) + '</p>'
      + '<button type="button" class="fp-btn fp-btn-sm" data-sep-act="refresh">Réessayer</button></div>';
  }

  function stat(label, value, tone, hint) {
    return '<div class="sep-stat' + (tone ? ' sep-stat-' + tone : '') + '">'
      + '<div class="sep-stat-value">' + esc(value) + '</div>'
      + '<div class="sep-stat-label">' + esc(label) + '</div>'
      + (hint ? '<div class="sep-stat-hint">' + esc(hint) + '</div>' : '')
      + '</div>';
  }

  // ── Graphiques SVG en ligne ────────────────────────────────────────────────
  // Tracés à la main plutôt qu'avec une librairie : aucune dépendance externe,
  // rien à charger, et un rendu net dans les deux thèmes.
  function sparkArea(points, w, h) {
    if (!points || points.length < 2) {
      return '<p class="fp-muted">Série insuffisante — au moins deux points de collecte sont nécessaires.</p>';
    }
    const max = Math.max.apply(null, points.map(function (p) { return p.count; })) || 1;
    const dx = w / (points.length - 1);
    const xy = points.map(function (p, i) {
      return [i * dx, h - (p.count / max) * (h - 12) - 6];
    });
    const line = xy.map(function (c, i) { return (i ? 'L' : 'M') + c[0].toFixed(1) + ' ' + c[1].toFixed(1); }).join(' ');
    const area = line + ' L' + w + ' ' + h + ' L0 ' + h + ' Z';
    const dots = xy.map(function (c, i) {
      return '<circle cx="' + c[0].toFixed(1) + '" cy="' + c[1].toFixed(1) + '" r="2.5" class="sep-dot">'
        + '<title>' + esc(points[i].ts) + ' \u2014 ' + esc(nf(points[i].count)) + '</title></circle>';
    }).join('');
    return '<svg class="sep-chart" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none" role="img" '
      + 'aria-label="Volumétrie d’ingestion, maximum ' + esc(nf(max)) + ' événements par heure">'
      + '<path d="' + area + '" class="sep-area"/><path d="' + line + '" class="sep-line"/>' + dots + '</svg>'
      + '<div class="sep-axis"><span>' + esc(points[0].ts.slice(5, 16).replace('T', ' ')) + '</span>'
      + '<span>max ' + esc(nf(max)) + '/h</span>'
      + '<span>' + esc(points[points.length - 1].ts.slice(5, 16).replace('T', ' ')) + '</span></div>';
  }

  function bars(rows, valueKey, labelKey) {
    if (!rows || !rows.length) return '<p class="fp-muted">Aucune donnée.</p>';
    const max = Math.max.apply(null, rows.map(function (r) { return r[valueKey] || 0; })) || 1;
    return '<div class="sep-bars">' + rows.map(function (r) {
      const pct = Math.max(1, Math.round(((r[valueKey] || 0) / max) * 100));
      return '<div class="sep-bar-row"><span class="sep-bar-label" title="' + esc(r[labelKey]) + '">'
        + esc(r[labelKey]) + '</span>'
        + '<span class="sep-bar-track"><span class="sep-bar-fill" style="width:' + pct + '%"></span></span>'
        + '<span class="sep-bar-value">' + esc(nf(r[valueKey])) + '</span></div>';
    }).join('') + '</div>';
  }

  function heat(hm) {
    if (!hm || !hm.rows || !hm.rows.length) return '<p class="fp-muted">Carte de chaleur indisponible.</p>';
    const max = hm.max || 1;
    return '<div class="sep-heat">' + hm.rows.map(function (r) {
      const cells = r.values.map(function (v, i) {
        // Échelle logarithmique : sans elle une source à 1 M écrase toutes les
        // autres et la carte ne montre plus rien.
        const lvl = v <= 0 ? 0 : Math.min(5, Math.ceil((Math.log10(v + 1) / Math.log10(max + 1)) * 5));
        return '<span class="sep-heat-cell sep-heat-' + lvl + '" title="' + esc(hm.slots[i] || '')
          + ' \u2014 ' + esc(nf(v)) + '"></span>';
      }).join('');
      return '<div class="sep-heat-row"><span class="sep-heat-label" title="' + esc(r.label) + '">'
        + esc(r.label) + '</span><span class="sep-heat-cells">' + cells + '</span></div>';
    }).join('') + '<div class="sep-heat-legend"><span>moins</span>'
      + [0, 1, 2, 3, 4, 5].map(function (l) { return '<span class="sep-heat-cell sep-heat-' + l + '"></span>'; }).join('')
      + '<span>plus</span></div></div>';
  }

  // ── Tableau de bord ────────────────────────────────────────────────────────
  function renderDashboard() {
    const d = st.data.dashboard;
    if (!d || !d.available) {
      return degraded((d && d.errors && d.errors[0]) || "Aucune télémétrie agrégée pour l’instant.");
    }
    const k = d.kpi || {};
    const sev = (d.alerts && d.alerts.by_severity) || {};
    const byType = (d.alerts && d.alerts.by_type) || {};
    const types = Object.keys(byType).map(function (t) {
      return { type: t, count: byType[t] };
    }).sort(function (a, b) { return b.count - a.count; });

    const ranges = [[6, '6 h'], [24, '24 h'], [168, '7 j'], [720, '30 j']];
    const picker = '<div class="sep-range">' + ranges.map(function (r) {
      const on = (st.range || 24) === r[0];
      return '<button type="button" class="fp-btn fp-btn-sm' + (on ? ' fp-btn-primary' : ' fp-btn-ghost')
        + '" data-sep-act="range" data-hours="' + r[0] + '">' + esc(r[1]) + '</button>';
    }).join('') + '</div>';

    return '<div class="sep-row-between"><h3 class="fp-section-title">Ingestion \u2014 '
      + esc(d.hours) + ' h (granularité ' + esc(d.interval) + ')</h3>' + picker + '</div>'
      + '<div class="sep-stats">'
      + stat('Débit courant', nf(k.events_per_hour) + '/h', 'ok', 'dernier créneau mesuré')
      + stat('Pic sur la fenêtre', nf(k.events_peak) + '/h', 'warn')
      + stat('Sources actives', nf(k.sources_active), k.sources_active ? 'ok' : 'danger')
      + stat('Sources silencieuses', nf(k.sources_silent), k.sources_silent ? 'danger' : 'ok')
      + stat('Alertes critiques', nf(sev.critical || 0), sev.critical ? 'danger' : 'ok')
      + '</div>'
      + '<div class="fp-card"><h3 class="fp-section-title">Volumétrie d’ingestion</h3>'
      + sparkArea(d.timeline, 900, 170) + '</div>'
      + '<div class="sep-grid2">'
      + '<div class="fp-card"><h3 class="fp-section-title">Sources les plus volumineuses</h3>'
      + bars(d.top_sources, 'count', 'name') + '</div>'
      + '<div class="fp-card"><h3 class="fp-section-title">Alertes par type</h3>'
      + bars(types, 'count', 'type') + '</div>'
      + '</div>'
      + '<div class="fp-card"><h3 class="fp-section-title">Carte de chaleur \u2014 activité par source</h3>'
      + '<p class="fp-muted">Échelle logarithmique : sans elle, une source à 1 M/h écraserait toutes les autres.</p>'
      + heat(d.heatmap) + '</div>';
  }

  // ── Supervision : volumétrie réelle ────────────────────────────────────────
  function renderSupervision() {
    const h = st.data.health;
    if (!h || !h.available) {
      return degraded((h && h.error)
        || "Aucun état d'intake collecté pour l'instant. La première collecte peut prendre quelques minutes après un redémarrage.");
    }
    const items = h.items || [];
    const silent = items.filter(function (i) { return i.silent; });
    const active = items.filter(function (i) { return (i.current_count || 0) > 0; });
    const unmeasured = items.filter(function (i) { return !i.volume_available; });
    const total = items.reduce(function (a, i) { return a + (i.current_count || 0); }, 0);

    const rows = items.slice(0, 300).map(function (i) {
      const measured = i.volume_available;
      const count = measured ? nf(i.current_count)
        : '<span class="fp-muted" title="Non mesuré — jamais assimilé à zéro">non mesuré</span>';
      const tone = i.silent ? 'danger' : (i.score >= 70 ? 'ok' : 'warn');
      return '<tr data-intake="' + esc(i.intake_uuid) + '">'
        + '<td><span class="fp-tag fp-tag-' + tone + '">' + esc(i.grade) + '</span></td>'
        + '<td class="sep-num">' + esc(i.score) + '</td>'
        + '<td>' + esc(i.intake_name || i.intake_uuid) + '</td>'
        + '<td>' + esc(i.entity_name || '—') + '</td>'
        + '<td class="sep-num">' + count + '</td>'
        + '<td class="sep-num">' + (measured ? nf(Math.round(i.baseline_avg || 0)) : '—') + '</td>'
        + '<td>' + (i.silent ? '<span class="fp-tag fp-tag-danger">silencieux</span>' : '') + '</td>'
        + '</tr>';
    }).join('');

    const score = (h.global_score === null || h.global_score === undefined) ? '—' : h.global_score;
    return '<div class="sep-stats">'
      + stat('Événements / heure', nf(total), 'ok', 'mesuré source par source')
      + stat('Sources actives', nf(active.length), active.length ? 'ok' : 'danger')
      + stat('Sources silencieuses', nf(silent.length), silent.length ? 'danger' : 'ok', 'aucun événement sur la fenêtre')
      + stat('Non mesurées', nf(unmeasured.length), unmeasured.length ? 'warn' : 'ok')
      + stat('Score de santé', score + '/100', (h.global_score || 0) >= 70 ? 'ok' : 'warn')
      + '</div>'
      + '<div class="fp-card sep-table-wrap">'
      + '<h3 class="fp-section-title">Inventaire des sources — ' + esc(nf(items.length)) + ' intakes</h3>'
      + '<p class="fp-muted">Volumétrie mesurée source par source. Le SIEM n\'expose aucune de ces valeurs.</p>'
      + '<div class="sep-scroll"><table class="fp-table sep-table"><thead><tr>'
      + '<th>Note</th><th>Score</th><th>Intake</th><th>Entité</th>'
      + '<th>Événements/h</th><th>Baseline</th><th>État</th>'
      + '</tr></thead><tbody>' + rows + '</tbody></table></div></div>';
  }

  // ── Alerting ───────────────────────────────────────────────────────────────
  function renderAlerting() {
    const rules = st.data.rules;
    const alerts = st.data.alerts;
    if (!rules) return degraded('Moteur de règles injoignable.');

    const ruleRows = (rules.items || []).map(function (r) {
      const sevTone = r.severity === 'critical' ? 'danger' : (r.severity === 'high' ? 'warn' : '');
      return '<tr data-rule="' + esc(r.id) + '">'
        + '<td><span class="fp-tag ' + (r.enabled ? 'fp-tag-ok' : '') + '">' + (r.enabled ? 'actif' : 'inactif') + '</span></td>'
        + '<td>' + esc(r.name) + '</td>'
        + '<td><code>' + esc(r.type) + '</code></td>'
        + '<td><span class="fp-tag fp-tag-' + sevTone + '">' + esc(r.severity) + '</span></td>'
        + '<td class="fp-muted">' + esc(JSON.stringify(r.params || {})) + '</td>'
        + '<td class="sep-num">' + esc(r.cooldown_s) + ' s</td>'
        + '<td><button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-sep-act="toggle-rule" data-id="'
        + esc(r.id) + '" data-enabled="' + r.enabled + '">' + (r.enabled ? 'Désactiver' : 'Activer') + '</button></td>'
        + '</tr>';
    }).join('');

    const bySev = (alerts && alerts.by_severity) || {};
    const alertRows = ((alerts && alerts.items) || []).slice(0, 100).map(function (a) {
      const sevTone = a.severity === 'critical' ? 'danger' : (a.severity === 'high' ? 'warn' : '');
      const grp = a.group_size > 1
        ? '<span class="fp-tag" title="Incident groupé : ' + esc(a.group_label || '') + '">&times;' + esc(a.group_size) + '</span>'
        : '';
      return '<tr><td><span class="fp-tag fp-tag-' + sevTone + '">' + esc(a.severity) + '</span></td>'
        + '<td><code>' + esc(a.rule_type || '—') + '</code></td>'
        + '<td>' + esc(a.intake_name || '—') + '</td>'
        + '<td>' + esc(a.message || '') + '</td>'
        + '<td>' + grp + '</td>'
        + '<td class="fp-muted">' + esc(a['@timestamp'] || '') + '</td></tr>';
    }).join('');

    return '<div class="sep-stats">'
      + stat('Alertes 24 h', nf(alerts ? alerts.total : 0), (alerts && alerts.total) ? 'warn' : 'ok')
      + stat('Critiques', nf(bySev.critical || 0), bySev.critical ? 'danger' : 'ok')
      + stat('Élevées', nf(bySev.high || 0), bySev.high ? 'warn' : 'ok')
      + stat('Règles actives', nf(rules.enabled || 0), 'ok', nf(rules.count) + ' définies')
      + '</div>'
      + '<div class="fp-card sep-table-wrap"><div class="sep-row-between">'
      + '<h3 class="fp-section-title">Règles d\'alerte</h3>'
      + '<button type="button" class="fp-btn fp-btn-sm" data-sep-act="evaluate">Évaluer maintenant (simulation)</button></div>'
      + '<p class="fp-muted">Seuils dynamiques adossés à la baseline et à l\'écart-type : un intake à 10 événements/h et un autre à 1 M/h ne partagent pas le même seuil.</p>'
      + '<div class="sep-scroll"><table class="fp-table sep-table"><thead><tr>'
      + '<th>État</th><th>Nom</th><th>Type</th><th>Sévérité</th><th>Paramètres</th><th>Cooldown</th><th></th>'
      + '</tr></thead><tbody>' + ruleRows + '</tbody></table></div></div>'
      + '<div class="fp-card sep-table-wrap">'
      + '<h3 class="fp-section-title">Alertes — 24 dernières heures</h3>'
      + '<p class="fp-muted">Les alertes simultanées partageant un connecteur ou une entité sont regroupées en un incident unique.</p>'
      + '<div class="sep-scroll"><table class="fp-table sep-table"><thead><tr>'
      + '<th>Sévérité</th><th>Type</th><th>Source</th><th>Message</th><th>Groupe</th><th>Horodatage</th>'
      + '</tr></thead><tbody>'
      + (alertRows || '<tr><td colspan="6" class="fp-muted">Aucune alerte sur la période.</td></tr>')
      + '</tbody></table></div></div>';
  }

  // ── Opérations en lot ──────────────────────────────────────────────────────
  function renderOperations() {
    const t = st.data.targets;
    const hist = st.data.history;
    if (!t) return degraded("Moteur d'opérations en lot injoignable.");
    const preview = st.data.bulkPreview;

    const targetOpts = (t.items || []).map(function (x) {
      return '<option value="' + esc(x.target) + '"'
        + (x.target === st.data.bulkTarget ? ' selected' : '') + '>' + esc(x.target) + '</option>';
    }).join('');
    const cur = (t.items || []).filter(function (x) {
      return x.target === (st.data.bulkTarget || 'intakes');
    })[0] || (t.items || [])[0] || {};
    const actionOpts = (cur.actions || []).filter(function (a) { return a !== 'patch'; })
      .map(function (a) { return '<option value="' + esc(a) + '">' + esc(a) + '</option>'; }).join('');

    let previewBlock = '';
    if (preview) {
      const prows = (preview.results || []).slice(0, 50).map(function (r) {
        const right = preview.dry_run ? JSON.stringify(r.before || {})
          : (r.ok ? 'appliqué' : (r.error || 'échec'));
        return '<tr><td>' + esc(r.name || r.id) + '</td><td class="fp-muted">' + esc(right) + '</td></tr>';
      }).join('');
      previewBlock = '<div class="fp-card sep-preview"><h4>'
        + (preview.dry_run ? 'Simulation' : 'Exécution') + ' — ' + esc(nf(preview.selected || 0)) + ' objet(s)</h4>'
        + (preview.error ? '<p class="fp-muted">' + esc(preview.error) + '</p>' : '')
        + '<div class="sep-scroll sep-scroll-sm"><table class="fp-table sep-table"><thead><tr><th>Objet</th><th>'
        + (preview.dry_run ? 'Avant' : 'Résultat') + '</th></tr></thead><tbody>' + prows + '</tbody></table></div>'
        + ((preview.dry_run && preview.selected)
          ? '<button type="button" class="fp-btn fp-btn-sm fp-btn-danger" data-sep-act="bulk-apply">Appliquer réellement à '
            + esc(nf(preview.selected)) + ' objet(s)</button>' : '')
        + '</div>';
    }

    const histRows = ((hist && hist.items) || []).slice(0, 20).map(function (b) {
      return '<tr><td class="fp-muted">' + esc(b.ts) + '</td>'
        + '<td><code>' + esc(b.target) + '</code></td>'
        + '<td>' + esc(b.action) + '</td>'
        + '<td class="sep-num">' + esc(b.done) + '/' + esc(b.selected) + '</td>'
        + '<td>' + (b.rolled_back ? '<span class="fp-tag">annulé</span>'
          : '<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-sep-act="rollback" data-id="'
            + esc(b.batch_id) + '">Annuler ce lot</button>') + '</td></tr>';
    }).join('');

    return '<div class="fp-card"><h3 class="fp-section-title">Opération en lot</h3>'
      + '<p class="fp-muted">Sélection par filtre — on agit sur « tous les intakes Windows », pas sur une liste d\'identifiants copiés à la main. Toute opération est simulée avant exécution.</p>'
      + '<div class="sep-form">'
      + '<label>Cible<select id="sep-target">' + targetOpts + '</select></label>'
      + '<label>Action<select id="sep-action">' + actionOpts + '</select></label>'
      + '<label>Recherche<input id="sep-search" type="text" placeholder="nom ou identifiant"></label>'
      + '<button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-sep-act="bulk-dryrun">Simuler</button>'
      + '</div>' + previewBlock + '</div>'
      + '<div class="fp-card sep-table-wrap"><h3 class="fp-section-title">Historique des lots</h3>'
      + '<p class="fp-muted">L\'état antérieur de chaque objet est capturé avant écriture : un lot peut être annulé.</p>'
      + '<div class="sep-scroll"><table class="fp-table sep-table"><thead><tr>'
      + '<th>Date</th><th>Cible</th><th>Action</th><th>Appliqué</th><th></th></tr></thead><tbody>'
      + (histRows || '<tr><td colspan="5" class="fp-muted">Aucun lot exécuté.</td></tr>')
      + '</tbody></table></div></div>';
  }

  // ── Chargement ─────────────────────────────────────────────────────────────
  async function load() {
    st.loading = true; st.error = null; paint();
    try {
      if (st.view === 'dashboard') {
        st.data.dashboard = await api('/dashboard?hours=' + (st.range || 24) + '&top=10');
      } else if (st.view === 'supervision') {
        st.data.health = await api('/intakes/health');
      } else if (st.view === 'alerting') {
        const res = await Promise.all([
          api('/alerting/rules'),
          api('/alerting/alerts?hours=24').catch(function () { return null; }),
        ]);
        st.data.rules = res[0]; st.data.alerts = res[1];
      } else {
        const res2 = await Promise.all([
          api('/bulk/targets'),
          api('/bulk/history').catch(function () { return null; }),
        ]);
        st.data.targets = res2[0]; st.data.history = res2[1];
      }
    } catch (e) {
      st.error = e.message;
    } finally {
      st.loading = false; paint();
    }
  }

  function paint() {
    const el = root();
    if (!el) return;
    let body;
    if (st.loading) body = '<p class="fp-muted">Chargement…</p>';
    else if (st.error) body = degraded(st.error);
    else if (st.view === 'dashboard') body = renderDashboard();
    else if (st.view === 'supervision') body = renderSupervision();
    else if (st.view === 'alerting') body = renderAlerting();
    else body = renderOperations();
    el.innerHTML = shell(body);
  }

  async function bulkRun(dryRun) {
    const target = (document.getElementById('sep-target') || {}).value || 'intakes';
    const action = (document.getElementById('sep-action') || {}).value || 'disable';
    const search = (document.getElementById('sep-search') || {}).value || '';
    st.data.bulkTarget = target;
    try {
      const r = await api('/bulk/' + encodeURIComponent(target), {
        method: 'POST', body: { action: action, search: search, dry_run: dryRun ? 1 : 0 },
      });
      st.data.bulkPreview = r;
      if (!dryRun) {
        toast('Lot appliqué : ' + r.done + '/' + r.selected, 'ok');
        st.data.history = await api('/bulk/history').catch(function () { return st.data.history; });
      }
      paint();
    } catch (e) { toast(e.message, 'err'); }
  }

  function bind(el) {
    if (el.dataset.sepBound) return;
    el.dataset.sepBound = '1';
    el.addEventListener('click', async function (ev) {
      const view = ev.target.closest('[data-sep-view]');
      if (view) { st.view = view.dataset.sepView; st.data.bulkPreview = null; load(); return; }
      const btn = ev.target.closest('[data-sep-act]');
      if (!btn) return;
      const act = btn.dataset.sepAct;
      try {
        if (act === 'refresh') { load(); return; }
        if (act === 'range') { st.range = Number(btn.dataset.hours) || 24; load(); return; }
        if (act === 'evaluate') {
          const r = await api('/alerting/evaluate?dry_run=1', { method: 'POST' });
          toast(r.alerts_new + ' alerte(s) → ' + r.incidents + ' incident(s)', 'ok');
          return;
        }
        if (act === 'toggle-rule') {
          await api('/alerting/rules/' + encodeURIComponent(btn.dataset.id), {
            method: 'PATCH', body: { enabled: btn.dataset.enabled !== 'true' },
          });
          load(); return;
        }
        if (act === 'bulk-dryrun') { bulkRun(true); return; }
        if (act === 'bulk-apply') { bulkRun(false); return; }
        if (act === 'rollback') {
          const r2 = await api('/bulk/rollback/' + encodeURIComponent(btn.dataset.id) + '?dry_run=0',
            { method: 'POST' });
          toast(r2.ok ? 'Lot annulé : ' + r2.restored + ' objet(s) restauré(s)' : (r2.error || 'échec'),
            r2.ok ? 'ok' : 'err');
          load(); return;
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

  window.SekoiaExtended = { init: init, load: load };
  document.addEventListener('DOMContentLoaded', function () {
    const btn = document.querySelector('[data-tab-btn="sekoia-extended"]');
    if (btn) btn.addEventListener('click', function () { setTimeout(init, 50); });
  });
}());
