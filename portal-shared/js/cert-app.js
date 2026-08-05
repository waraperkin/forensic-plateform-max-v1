/* global ForensicAPI, ForensicUI, ForensicUtils, ForensicComponents, FileValidator */
'use strict';

const api = new ForensicAPI({ base: '' });
let validator = new FileValidator();
let files = [];
let activeTab = 'overview';

function svcDotMap() {
  return {
    OpenSearch: 'd-osd',
    Timesketch: 'd-ts',
    OpenCTI: 'd-cti',
    TheHive: 'd-th',
    Cortex: 'd-cx',
    MISP: 'd-misp',
    MinIO: 'd-minio',
    Grafana: 'd-gf',
    Logstash: 'd-ls',
    [i18n.t('health.portal_it')]: 'd-it',
    Dashboards: 'd-osd',
  };
}

function log(m, c = '') {
  ForensicUI.consoleLog('con', m, c);
}

const TAB_ALIASES = {
  overview: 'overview',
  'overview-cert': 'overview',
  health: 'health',
  'overview-health': 'health',
  'threat-intel': 'threat-intel',
  'ingest-evidence': 'ingest-evidence',
  'cert-ops': 'cert-ops',
  'it-ops': 'it-ops',
  cases: 'cases',
  incidents: 'cases',
  'hist-legacy': 'hist-legacy',
};

function resolveTab(raw) {
  return TAB_ALIASES[raw] || raw;
}

// Les 9 ecrans de sekoia-workbench.js (SekoiaWorkbench.mountAt) ne
// s'activent aujourd'hui QUE sur un clic direct dans la barre laterale — le
// module attache son propre ecouteur en DOMContentLoaded, mais rien
// n'appelle mountAt() pour un lien profond (?tab=), un rafraichissement de
// page ou un retour arriere du navigateur. Constate en session : ces neuf
// panneaux restent bloques sur « Chargement... » indefiniment, sans erreur,
// des qu'on y arrive autrement que par un clic — le backend repond pourtant
// en 0,5 s. SekoiaWorkbench est charge en differe (portal-lazy.js) : au
// moment ou tab() tourne pendant boot(), le module peut ne pas encore
// exister, d'ou le sondage plutot qu'un appel direct (meme discipline que
// loadDoc() pour PortalDoc un peu plus haut dans ce fichier).
// QA 04/08/2026 — un seul rendeur par onglet. Le workbench n'occupe que
// sekoia-extended ; les autres onglets ont leur rendeur dédié. En mode SEP,
// la nav workbench est réduite à Baisses & Alerting (voir SEP_VIEWS).
const SEKOIA_WORKBENCH_TABS = {
  // SEP « Alerting & drops » : atterrir sur l'alerting, pas la vue d'ensemble
  // fourre-tout (12 onglets qui doublaient Inventaire / API keys / Settings).
  'sekoia-extended': ['sekoia-extended-root', 'alerting', true],
};
function mountSekoiaWorkbenchDeepLink(t, n = 0) {
  const cfg = SEKOIA_WORKBENCH_TABS[t];
  if (!cfg) return;
  if (window.SekoiaWorkbench && typeof window.SekoiaWorkbench.mountAt === 'function') {
    const [elId, view, withNav] = cfg;
    window.SekoiaWorkbench.mountAt(elId, view, withNav);
    return;
  }
  if (n < 60) { setTimeout(() => mountSekoiaWorkbenchDeepLink(t, n + 1), 50); return; }
  // 3 s sans que le module ne se charge : ne pas laisser le « Chargement… »
  // fige indefiniment sans explication.
  const root = document.getElementById(cfg[0]);
  if (root && /Chargement/i.test(root.textContent || '')) {
    root.innerHTML = '<p class="fp-alert fp-alert-err">Module indisponible — rechargez la page.</p>';
  }
}

function tab(raw) {
  const t = resolveTab(raw);
  activeTab = t;
  document.querySelectorAll('[data-tab-btn]').forEach((el) => {
    const btnPanel = resolveTab(el.dataset.tabBtn);
    let on = btnPanel === t;
    // Plusieurs entrées sidebar partagent sekoia-cc (overview / sol / hosts)
    if (on && t === 'sekoia-cc' && el.dataset.ccSub) {
      on = el.dataset.ccSub === (window.__activeCcSub || window.__pendingCcSub || 'overview');
    }
    el.classList.toggle('active', on);
  });
  document.querySelectorAll('.fp-panel').forEach((el) => {
    const isActive = el.id === `tab-${t}`;
    el.classList.toggle('active', isActive);
    el.setAttribute('aria-hidden', isActive ? 'false' : 'true');
  });
  const sidebar = document.getElementById('fp-sidebar');
  if (sidebar) sidebar.classList.remove('open');
  document.body.classList.remove('cc-sidebar-open');
  if (t === 'upload') {
    loadConfig();
    if (window.HelkIntegration) HelkIntegration.refreshHelkBadges();
    if (window.VelociraptorIntegration) VelociraptorIntegration.refreshVelociraptorBadges();
  }
  if (t === 'tokens') loadTokens();
  if (t === 'cert') loadCertUploads();
  if (t === 'it') loadItUploads();
  if (t === 'hist' && window.PortalActivityLog) PortalActivityLog.loadActivityLog();
  if (t === 'hist-legacy') loadHistory();
  if (t === 'svcs') {
    checkSvcs();
    loadSslFp();
    loadCredentials();
  }
  if (t === 'users' && window.PortalUsers) PortalUsers.loadPortalUsers();
  if (t === 'soc-tools' && window.SocTools) {
    SocTools.loadSocToolsPage();
  }
  if (t === 'helk-hunting' && window.HelkIntegration) {
    HelkIntegration.loadHelkHuntingPage();
  }
  if (t === 'velociraptor-dfir' && window.VelociraptorIntegration) {
    VelociraptorIntegration.loadVelociraptorPage();
  }
  if (t === 'access-center' && window.AccessCenter) {
    AccessCenter.loadAccessCenter();
  }
  if (t === 'portal-documentation') {
    const loadDoc = (n = 0) => {
      if (window.PortalDoc?.renderDocumentationRoot) {
        window.PortalDoc.renderDocumentationRoot();
        return;
      }
      if (n < 40) {
        setTimeout(() => loadDoc(n + 1), 50);
        return;
      }
      // Module PortalDoc indisponible : ne pas laisser le « Chargement… » figé
      const root = document.getElementById('portal-documentation-root');
      if (root) {
        root.__docBound = false;
        root.innerHTML = '<p class="fp-alert fp-alert-err">Documentation indisponible — '
          + '<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" id="portal-doc-retry">Réessayer</button></p>';
        document.getElementById('portal-doc-retry')?.addEventListener('click', () => {
          root.innerHTML = '<p class="fp-muted">Chargement…</p>';
          loadDoc(0);
        });
      }
    };
    loadDoc();
  }
  const masterZone = t === 'cases' ? 'incidents' : t === 'master-users' ? 'users' : t;
  const skipMasterZone = new Set(['kb']);
  if (window.PortalMasterZones && PortalMasterZones.MASTER_TABS.has(masterZone) && t !== 'users' && !skipMasterZone.has(masterZone)) {
    PortalMasterZones.loadMasterZone(api, masterZone);
  }
  if (t === 'settings-admin' && window.PortalSettings) PortalSettings.loadSettingsAdmin();
  if ((t === 'overview' || t === 'overview-cert') && window.PortalOverview) PortalOverview.loadOverviewCert();
  if ((t === 'health' || t === 'overview-health') && window.PortalOverview) PortalOverview.loadOverviewHealth();
  if (t === 'overview-ingest' && window.PortalOverview) PortalOverview.loadOverviewIngest();
  if (t === 'overview-ti' && window.PortalOverview) PortalOverview.loadOverviewTi();
  if (t === 'threat-intel' && window.PortalHub) PortalHub.loadThreatIntelHub();
  if (t === 'ingest-evidence' && window.PortalHub) PortalHub.loadIngestEvidenceHub();
  if (t === 'cert-ops' && window.PortalHub) PortalHub.loadCertOpsHub();
  if (t === 'it-ops' && window.PortalHub) PortalHub.loadItOpsHub();
  if (t === 'references' && window.PortalHub) PortalHub.loadReferencesHub();
  if (t === 'cases' && window.PortalHub) PortalHub.loadCasesHub();
  if (t === 'kb' && window.PortalHub) PortalHub.loadKbHub();
  if (t === 'sekoia-cc' && window.PortalHub) PortalHub.loadSekoiaHub();
  // La console des cas d'usage ne charge son catalogue qu'à l'ouverture : le
  // faire au chargement de la page coûterait une requête à chaque visite du
  // portail, pour un onglet que l'analyste n'ouvre pas toujours.
  if (t === 'sekoia-sep' && window.SekoiaSEP) SekoiaSEP.boot();
  if (t === 'sekoia-volume-detail' && window.SekoiaVolume) {
    SekoiaVolume.loadDetail(window.PanelDetailCore?.getSlice() || 'volume');
  }
  if (t === 'sekoia-ingest' && window.SekoiaVolume) {
    const slice = window.PanelDetailCore?.getSlice() || 'global';
    const section = window.PanelDetailCore?.getSection?.();
    SekoiaVolume.loadIngest(slice).then(() => {
      if (window.SekoiaIngest) {
        SekoiaIngest.afterPanelOpen({
          section: section || window.PanelDetailCore?.sliceToSection?.('sekoia-ingest', slice),
        });
      }
    }).catch(() => {});
  }
  if (t === 'cti-detail' && window.PanelCtiDetail) {
    PanelCtiDetail.load(window.PanelDetailCore?.getSlice() || 'summary');
  }
  if (t === 'ingest-detail' && window.PanelIngestDetail) {
    PanelIngestDetail.load(window.PanelDetailCore?.getSlice() || 'volume');
  }
  if (t === 'certops-detail' && window.PanelCertopsDetail) {
    PanelCertopsDetail.load(window.PanelDetailCore?.getSlice() || 'dashboard-cert');
  }
  if (t === 'itops-detail' && window.PanelItopsDetail) {
    PanelItopsDetail.load(window.PanelDetailCore?.getSlice() || 'dashboard-it');
  }
  if (t === 'forensic-reports' && window.ForensicReport) {
    ForensicReport.loadPanel(document.getElementById('fp-report-root'));
  }
  if (t === 'incidents-detail' && window.PanelIncidentsDetail) {
    PanelIncidentsDetail.load(window.PanelDetailCore?.getSlice() || 'list');
  }
  if (t === 'kb-detail' && window.PanelKbDetail) {
    PanelKbDetail.load(window.PanelDetailCore?.getSlice() || 'list');
  }
  if (t === 'ti-overview' && window.PortalOverview) PortalOverview.loadTiOverview();
  if (t === 'ti-ioc' && window.PortalOverview) PortalOverview.loadTiIocList();
  if (t === 'ti-heatmap' && window.PortalOverview) PortalOverview.loadTiHeatmap();
  if (SEKOIA_WORKBENCH_TABS[t]) mountSekoiaWorkbenchDeepLink(t);
  if (window.CybercorpUltra) CybercorpUltra.bindClickableCards();
}

const STAT_TAB_NAV = { su: 'cert', si: 'it', st: 'tokens' };
const STAT_DISCOVER_IDX = {
  'ps-win': i18n.t('msg.forensic_windows'),
  'ps-lin': i18n.t('msg.forensic_linux'),
  'ps-web': i18n.t('msg.forensic_web'),
  'ps-net': i18n.t('msg.forensic_network'),
  'ps-cld': i18n.t('msg.forensic_cloud'),
  'ps-ep': i18n.t('msg.forensic_endpoint'),
};

function discoverIndexUrl(index) {
  const idx = String(index || 'fp-events').replace(/'/g, "\\'");
  return `/dashboards/app/discover#/?_a=(columns:!(),filters:!(),index:'${idx}',interval:auto,query:(language:kuery,query:'*'),sort:!())`;
}

function bindClickableStats() {
  Object.entries(STAT_TAB_NAV).forEach(([id, tabName]) => {
    const el = document.getElementById(id);
    if (!el) return;
    const card = el.closest('.fp-stat') || el.parentElement;
    if (!card) return;
    card.classList.add('fp-stat-clickable');
    card.title = `Voir ${tabName}`;
    card.addEventListener('click', () => tab(tabName));
  });
  Object.entries(STAT_DISCOVER_IDX).forEach(([id, index]) => {
    const el = document.getElementById(id);
    if (!el) return;
    const card = el.closest('.fp-stat') || el.parentElement;
    if (!card) return;
    card.classList.add('fp-stat-clickable');
    card.title = `${i18n.t('msg.ouvrir_discover')} — ${index}`;
    card.addEventListener('click', () => {
      window.open(discoverIndexUrl(index), '_blank', 'noopener');
    });
  });
}

function renderQ() {
  ForensicComponents.renderFileQueue('q', files, validator, (i) => {
    files.splice(i, 1);
    renderQ();
  });
  const check = validator.validateQueue(files);
  document.getElementById('ubtn').disabled = !files.length || !check.valid;
}

function addF(nf) {
  for (const f of nf) {
    if (!files.find((x) => x.name === f.name && x.size === f.size)) files.push(f);
  }
  renderQ();
  log(i18n.t('msg.fichiers_pret', { n: nf.length }), 'info');
}

async function loadConfig() {
  try {
    validator = await FileValidator.loadFromAPI(api, '/api/config');
    const hint = document.getElementById('upload-limits-hint');
    if (hint) {
      hint.textContent = i18n.t('upload.limits_hint', {
        max: validator.maxFiles,
        size: ForensicUtils.sz(validator.maxSizeBytes),
        ext: [...validator.allowedExtensions].slice(0, 8).join(', '),
      });
    }
  } catch (_) {
    validator = new FileValidator();
  }
}

async function loadStats() {
  try {
    const d = await api.get('/api/stats');
    document.getElementById('su').textContent = d.uploads ?? '—';
    document.getElementById('si').textContent = d.it_uploads ?? '—';
    document.getElementById('st').textContent = d.active_tokens ?? '—';
  } catch (e) {
    console.warn('stats:', e.message);
  }
  try {
    const p = await api.get('/api/stats/parsing');
    const map = {
      'ps-win': 'windows',
      'ps-lin': 'linux',
      'ps-web': 'web',
      'ps-net': 'network',
      'ps-cld': 'cloud',
      'ps-ep': 'endpoint',
    };
    const linuxTotal = (Number(p.linux) || 0) + (Number(p.macos) || 0);
    for (const id in map) {
      const el = document.getElementById(id);
      if (!el) continue;
      if (id === 'ps-lin') {
        el.textContent = linuxTotal.toLocaleString('fr-FR');
      } else {
        el.textContent = (p[map[id]] ?? 0).toLocaleString('fr-FR');
      }
    }
  } catch (e) {
    console.warn(i18n.t('msg.stats_parsing'), e.message);
  }
}

async function doUpload() {
  if (!files.length) return;
  const check = validator.validateQueue(files);
  if (!check.valid) {
    ForensicUI.toast(check.globalError || i18n.t('msg.fichiers_invalides'), 'error');
    return;
  }

  document.getElementById('ubtn').disabled = true;
  const fd = new FormData();
  fd.append('case_id', document.getElementById('cid').value || 'CASE-001');
  fd.append('analyst', document.getElementById('ana').value || 'cert');
  fd.append('os_type', document.getElementById('ost').value);
  fd.append('priority', document.getElementById('prio').value);
  if (document.getElementById('helk-send')?.checked) fd.append('helk_hunt', 'true');
  files.forEach((f) => fd.append('files', f));

  log(i18n.t('upload.uploading', { n: files.length }), 'info');
  ForensicComponents.resetUploadProgress('pf', 'pf-meta');

  try {
    const { data: d } = await api.uploadWithProgress('/api/upload', fd, (p) => {
      ForensicComponents.updateUploadProgress({
        barId: 'pf',
        metaId: 'pf-meta',
        percent: p.percent,
        speed: p.speed,
        remaining: p.remaining,
      });
    });
    (d.results || []).forEach((r) => {
      if (r.ok) {
        const helkNote = r.helk?.ok ? ' + HELK' : (r.helk?.skipped ? '' : r.helk?.error ? ` (HELK: ${r.helk.error})` : '');
        log(`✓ ${r.file} → ${r.bucket}${helkNote}`, 'ok');
      }
      else log(`✗ ${r.file}: ${r.error}`, 'err');
    });
    const okCount = (d.results || []).filter((r) => r.ok).length;
    if (okCount) ForensicUI.toast(i18n.t('upload.files_sent', { n: okCount }), 'success');
    files = [];
    renderQ();
    loadStats();
    if (activeTab === 'hist') loadHistory();
    if (activeTab === 'cert') loadCertUploads();
  } catch (e) {
    log(`${i18n.t('ui.error_prefix')} ${e.message}`, 'err');
    ForensicUI.toast(e.message || i18n.t('toast.upload_failed'), 'error');
  }

  setTimeout(() => ForensicComponents.resetUploadProgress('pf', 'pf-meta'), 1500);
  document.getElementById('ubtn').disabled = files.length === 0;
}

async function genToken() {
  const caseId = document.getElementById('tk-case').value.trim();
  if (!caseId) {
    ForensicUI.toast(i18n.t('upload.case_id_required'), 'warn');
    return;
  }
  try {
    const d = await api.post('/api/tokens/generate', {
      case_id: caseId,
      description: document.getElementById('tk-desc').value,
      expires_in_hours: parseInt(document.getElementById('tk-exp').value, 10),
      max_uses: parseInt(document.getElementById('tk-uses').value, 10),
      analyst: document.getElementById('tk-analyst').value || 'cert',
    });
    if (!d.success) throw new Error(d.error);

    const res = document.getElementById('tok-result');
    res.style.display = 'block';
    res.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    res.innerHTML = `
      <div class="fp-alert fp-alert-ok">
        <p>${i18n.t('upload.token_generated', { date: new Date(d.expires_at).toLocaleString() })}</p>
        <p style="font-size:0.75rem;color:var(--text-muted);margin:0.5rem 0 0.25rem">${i18n.t('upload.url_for_it')}</p>
        <div class="fp-tok-url" id="gen-url">${ForensicUtils.escapeHtml(d.it_portal_url)}</div>
        ${d.ssl_fingerprint ? `<div class="fp-tok-url" style="border-color:var(--accent-2);color:var(--accent-2)">🔒 ${ForensicUtils.escapeHtml(d.ssl_fingerprint)}</div>` : ''}
        <div style="display:flex;gap:0.5rem;margin-top:0.5rem;flex-wrap:wrap">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" onclick="navigator.clipboard.writeText(document.getElementById('gen-url').textContent);ForensicUI.toast(i18n.t('toast.url_copied'),'success')">${i18n.t('upload.copy_url_btn')}</button>
        </div>
      </div>`;
    log(i18n.t('upload.token_log_case', { case: caseId }), 'ok');
    ForensicUI.toast(i18n.t('toast.token_created'), 'success');
    loadTokens();
    loadStats();
  } catch (e) {
    log(`${i18n.t('ui.error_prefix')} ${e.message}`, 'err');
    ForensicUI.toast(e.message, 'error');
  }
}

async function loadTokens() {
  const el = document.getElementById('tok-list');
  el.innerHTML = ForensicComponents.tableSkeleton(1, 3);
  try {
    const tokens = await api.get('/api/tokens');
    if (!tokens.length) {
      el.innerHTML = `<p style="color:var(--text-muted);font-size:0.85rem">${i18n.t('msg.aucun_token')}</p>`;
      return;
    }
    el.innerHTML = tokens
      .map(
        (t) => `
      <div class="fp-tok-card">
        <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.35rem;flex-wrap:wrap">
          <strong style="color:var(--accent)">${ForensicUtils.escapeHtml(t.case_id)}</strong>
          <span class="fp-tag fp-tag-${t.status}">${t.status}</span>
          <span style="color:var(--text-muted);font-size:0.72rem;margin-left:auto">${t.uses_count}/${t.max_uses} util.</span>
        </div>
        <div style="font-size:0.8rem;margin-bottom:0.25rem">${ForensicUtils.escapeHtml(t.description || '—')}</div>
        <div style="font-size:0.72rem;color:var(--text-muted)">Expire: ${ForensicUtils.fmtDate(t.expires_at)} · Par: ${ForensicUtils.escapeHtml(t.created_by || '—')}</div>
        <div class="fp-tok-url">${ForensicUtils.escapeHtml(t.it_portal_url || '—')}</div>
        <div style="display:flex;gap:0.35rem;margin-top:0.5rem;flex-wrap:wrap">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" onclick="navigator.clipboard.writeText('${(t.it_portal_url || '').replace(/'/g, "\\'")}');ForensicUI.toast(i18n.t('ui.copied'),'success')">${i18n.t('ui.copy_clipboard')}</button>
          <button type="button" class="fp-btn fp-btn-danger fp-btn-sm" onclick="deleteToken('${ForensicUtils.escapeHtml(String(t.token_id || t.doc_id || t.id || ''))}')">🗑 ${i18n.t('ui.delete')}</button>
        </div>
      </div>`,
      )
      .join('');
  } catch {
    el.innerHTML = `<p style="color:var(--danger)">${i18n.t('msg.erreur_de_chargement')}</p>`;
    ForensicUI.toast(i18n.t('msg.impossible_de_charger_les_tokens'), 'error');
  }
}

async function deleteToken(id) {
  const ref = String(id || '').trim();
  if (!ref) {
    ForensicUI.toast(i18n.t('msg.identifiant_token_invalide'), 'error');
    return;
  }
  if (!confirm(i18n.t('confirm.delete_token'))) return;
  try {
    await api.delete(`/api/tokens/${encodeURIComponent(ref)}`);
    log(`Token ${ref} ${i18n.t('msg.supprime')}`, 'warn');
    ForensicUI.toast(i18n.t('toast.token_deleted'), 'success');
    loadTokens();
    loadStats();
  } catch (e) {
    ForensicUI.toast(e.message || i18n.t('toast.token_delete_failed'), 'error');
  }
}

function renderUploadRow(u, cols) {
  const id = u.id || u.upload_id || u.doc_id;
  const safeId = ForensicUtils.escapeHtml(String(id || ''));
  const name = (u.file?.name || '—').slice(0, 30);
  const ingest = cols.ingest
    ? `<td><span class="fp-tag fp-tag-${u.ingest_status === 'completed' ? 'active' : ''}">${u.ingest_status || '—'}</span></td>`
    : '';
  return `<tr>
    <td>${ForensicUtils.fmtDate(u['@timestamp'])}</td>
    <td title="${ForensicUtils.escapeHtml(u.file?.name || '')}">${ForensicUtils.escapeHtml(name)}</td>
    <td><code style="font-size:0.72rem">${ForensicUtils.escapeHtml(u.case_id || '—')}</code></td>
    <td>${ForensicUtils.escapeHtml(u.analyst || '—')}</td>
    ${cols.extra || ''}
    <td><span class="fp-tag">${ForensicUtils.escapeHtml(u.storage?.bucket || '—')}</span></td>
    <td>${u.file?.size ? ForensicUtils.sz(u.file.size) : '—'}</td>
    ${ingest}
    <td><button type="button" class="fp-btn fp-btn-danger fp-btn-sm" onclick="deleteUpload('${safeId}','${ForensicUtils.escapeHtml(u.file?.name || i18n.t('upload.default_file')).replace(/'/g, "\\'")}')">🗑</button></td>
  </tr>`;
}

async function loadCertUploads() {
  const tb = document.getElementById('cert-recus-tbl');
  tb.innerHTML = ForensicComponents.tableSkeleton(9, 5);
  try {
    const data = await api.get('/api/uploads');
    if (!data.length) {
      tb.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:1rem">${i18n.t('msg.aucun_upload_cert')}</td></tr>`;
      return;
    }
    tb.innerHTML = data
      .map((u) =>
        renderUploadRow(u, {
          ingest: true,
          extra: `<td><span style="color:${ForensicUtils.prioColor(u.priority)}">${u.priority || '—'}</span></td>`,
        }),
      )
      .join('');
  } catch (e) {
    tb.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--danger)">${ForensicUtils.escapeHtml(e.message)}</td></tr>`;
  }
}

async function loadItUploads() {
  const tb = document.getElementById('it-tbl');
  tb.innerHTML = ForensicComponents.tableSkeleton(8, 5);
  try {
    const data = await api.get('/api/it-uploads');
    if (!data.length) {
      tb.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:1rem">${i18n.t('msg.aucun_upload_it')}</td></tr>`;
      return;
    }
    tb.innerHTML = data
      .map((u) =>
        renderUploadRow(u, {
          extra: `<td style="font-size:0.72rem">${ForensicUtils.escapeHtml(u.submitter_email || '—')}</td>`,
        }),
      )
      .join('');
  } catch (e) {
    tb.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--danger)">${ForensicUtils.escapeHtml(e.message)}</td></tr>`;
  }
}

async function loadHistory() {
  const tb = document.getElementById('cert-tbl');
  tb.innerHTML = ForensicComponents.tableSkeleton(8, 5);
  try {
    const data = await api.get('/api/uploads');
    if (!data.length) {
      tb.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:1rem">${i18n.t('msg.aucun_upload')}</td></tr>`;
      return;
    }
    tb.innerHTML = data
      .map((u) =>
        renderUploadRow(u, {
          extra: `<td><span style="color:${ForensicUtils.prioColor(u.priority)}">${u.priority || '—'}</span></td>`,
        }),
      )
      .join('');
  } catch (e) {
    tb.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--danger)">${ForensicUtils.escapeHtml(e.message)}</td></tr>`;
  }
}

async function deleteUpload(id, name) {
  const ref = String(id || '').trim();
  if (!ref) {
    ForensicUI.toast(i18n.t('msg.identifiant_upload_invalide'), 'error');
    return;
  }
  if (!confirm(i18n.t('confirm.delete_upload', { name }))) return;
  try {
    const d = await api.delete(`/api/uploads/${encodeURIComponent(ref)}`);
    if (d.success) {
      log(`✓ ${name} ${i18n.t('msg.supprime')}`, 'ok');
      ForensicUI.toast(i18n.t('toast.upload_deleted'), 'success');
      loadHistory();
      loadItUploads();
      loadCertUploads();
      loadStats();
    } else {
      log(`✗ ${d.error || i18n.t('msg.echec')}`, 'err');
      ForensicUI.toast(d.error || i18n.t('msg.echec_suppression'), 'error');
    }
  } catch (e) {
    log(`${i18n.t('ui.error_prefix')} ${e.message}`, 'err');
    ForensicUI.toast(e.message || i18n.t('toast.upload_delete_failed'), 'error');
  }
}

async function checkSvcs() {
  document.querySelectorAll('.fp-dot').forEach((d) => {
    d.className = 'fp-dot loading';
  });
  try {
    const data = await api.get('/api/services');
    data.forEach((svc) => {
      const dotId = svcDotMap()[svc.name];
      if (dotId) {
        const dot = document.getElementById(dotId);
        if (dot) dot.className = `fp-dot ${svc.status}`;
      }
    });
    document.getElementById('svc-tbl').innerHTML = data
      .map(
        (s) => `<tr>
        <td>${ForensicUtils.escapeHtml(s.name)}</td>
        <td><span class="fp-tag fp-tag-${s.status}">${s.status}</span></td>
        <td style="color:var(--text-muted)">${(window.formatServiceDetail ? formatServiceDetail(s) : (s.code || s.error || '—'))}</td>
      </tr>`,
      )
      .join('');
  } catch {
    document.querySelectorAll('.fp-dot').forEach((d) => {
      d.className = 'fp-dot down';
    });
    ForensicUI.toast(i18n.t('toast.services_check_failed'), 'warn');
  }
}

async function loadCredentials() {
  const tb = document.getElementById('cred-tbl');
  const hint = document.getElementById('cred-hint');
  if (!tb) return;
  try {
    const data = await api.get('/api/credentials');
    if (hint) {
      hint.textContent = data.note || i18n.t('msg.reference_interne_mots_de_passe_en_clair');
    }
    const rows = data.credentials || [];
    if (!rows.length) {
      tb.innerHTML =
        `<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">${i18n.t('ui.entry_empty')}</td></tr>`;
      return;
    }
    const escAttr = (s) =>
      String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;');
    tb.innerHTML = rows
      .map(
        (c, i) => {
          const pwId = `cred-pw-${i}`;
          const loginId = `cred-login-${i}`;
          return `<tr>
        <td>${ForensicUtils.escapeHtml(c.service)}</td>
        <td><a href="${ForensicUtils.escapeHtml(c.url)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:0.72rem">${ForensicUtils.escapeHtml(c.url)}</a></td>
        <td class="fp-cred-pw-cell">
          <code id="${loginId}">${ForensicUtils.escapeHtml(c.login)}</code>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm fp-cred-copy" data-copy-target="${loginId}" title="${i18n.t('msg.copier_le_login')}">${i18n.t('msg.copier_le_login')}</button>
        </td>
        <td class="fp-cred-pw-cell">
          <span class="fp-cred-pw-plain" id="${pwId}">${ForensicUtils.escapeHtml(c.password)}</span>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm fp-cred-copy" data-copy-target="${pwId}" title="${i18n.t('msg.copier_le_mot_de_passe')}">${i18n.t('ui.copy')}</button>
        </td>
        <td style="color:var(--text-muted);font-size:0.75rem">${ForensicUtils.escapeHtml(c.role || '—')}</td>
      </tr>`;
        },
      )
      .join('');
    tb.querySelectorAll('.fp-cred-copy').forEach((btn) => {
      btn.addEventListener('click', () => {
        const el = document.getElementById(btn.getAttribute('data-copy-target') || '');
        const text = el?.textContent || '';
        if (navigator.clipboard?.writeText) {
          navigator.clipboard.writeText(text).then(
            () => ForensicUI.toast(btn.title?.includes('login') ? i18n.t('toast.login_copied') : i18n.t('toast.password_copied'), 'ok'),
            () => ForensicUI.toast(i18n.t('msg.copie_impossible'), 'warn'),
          );
        } else {
          ForensicUI.toast(text, 'info');
        }
      });
    });
  } catch (e) {
    tb.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--danger)">${ForensicUtils.escapeHtml(e.message)}</td></tr>`;
    if (hint) hint.textContent = i18n.t('msg.impossible_de_charger_api_credentials');
  }
}

async function loadSslFp() {
  const fpEl = document.getElementById('ssl-fp');
  const dlEl = document.getElementById('dl-cert');
  if (dlEl) {
    dlEl.href = '/api/ssl-cert';
    dlEl.setAttribute('download', 'forensic-platform.crt');
  }
  if (!fpEl) return;
  try {
    const d = await api.get('/api/ssl-fingerprint');
    fpEl.textContent = d.fingerprint ? `SHA-256: ${d.fingerprint}` : i18n.t('msg.fingerprint_indisponible');
  } catch {
    fpEl.textContent = '—';
  }
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws/logs`);
  ws.onmessage = (e) => {
    const d = JSON.parse(e.data);
    if (d.type === 'upload') log(`⬆ ${d.file} → ${d.bucket}`, 'ok');
  };
  ws.onclose = () => setTimeout(connectWS, 5000);
  ws.onerror = () => ws.close();
}

function initCertApp() {
  ForensicUI.initTheme('cert');
  ForensicUI.initErrorBoundary();
  const theme = document.documentElement.getAttribute('data-theme');
  const tbtn = document.getElementById('theme-toggle');
  if (tbtn) tbtn.textContent = theme === 'dark' ? '☀️' : '🌙';

  document.querySelectorAll('[data-tab-btn]').forEach((btn) => {
    btn.addEventListener('click', () => {
      // Sous-vue Control Center (Queries → SOL, Synthèse → overview, Hosts)
      window.__pendingCcSub = btn.dataset.ccSub || null;
      if (btn.dataset.ccSub) window.__activeCcSub = btn.dataset.ccSub;
      tab(btn.dataset.tabBtn);
    });
  });

  document.getElementById('menu-toggle')?.addEventListener('click', () => {
    const sb = document.getElementById('fp-sidebar');
    if (!sb) return;
    sb.classList.toggle('open');
    document.body.classList.toggle('cc-sidebar-open', sb.classList.contains('open'));
  });
  document.body.addEventListener('click', (e) => {
    if (!document.body.classList.contains('cc-sidebar-open')) return;
    if (e.target.closest('#fp-sidebar') || e.target.closest('#menu-toggle')) return;
    document.getElementById('fp-sidebar')?.classList.remove('open');
    document.body.classList.remove('cc-sidebar-open');
  });

  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    ForensicUI.toggleTheme('cert');
  });

  ForensicComponents.bindCaseAutocomplete('cid', 'case-ac-list', api);
  ForensicComponents.bindCaseAutocomplete('tk-case', 'tk-case-ac-list', api);

  loadConfig().then(() => {
    ForensicComponents.bindUploadZone({
      zoneId: 'dz',
      inputId: 'fi',
      onFiles: addF,
      validator,
    });
    renderQ();
  });
  loadStats();
  bindClickableStats();
  connectWS();
  setInterval(loadStats, 15000);
  if (window.GlobalHealthService) GlobalHealthService.startPolling();
  if (window.HelkIntegration) HelkIntegration.refreshHelkBadges();
  if (window.VelociraptorIntegration) VelociraptorIntegration.refreshVelociraptorBadges();
  setInterval(() => { if (window.HelkIntegration) HelkIntegration.refreshHelkBadges(); }, 60000);
  setInterval(() => { if (window.VelociraptorIntegration) VelociraptorIntegration.refreshVelociraptorBadges(); }, 60000);

  window.tab = tab;
  window.loadStats = loadStats;
  window.doUpload = doUpload;
  window.genToken = genToken;
  window.loadTokens = loadTokens;
  window.deleteToken = deleteToken;
  window.loadCertUploads = loadCertUploads;
  window.loadItUploads = loadItUploads;
  window.loadHistory = loadHistory;
  window.deleteUpload = deleteUpload;
  window.checkSvcs = checkSvcs;
  window.loadSslFp = loadSslFp;
  window.loadCredentials = loadCredentials;

  document.addEventListener('i18n:language-changed', () => {
    if (!window.i18n) return;
    i18n.translateDOM(document);
    tab(activeTab);
  });

  // P17 — le bouton langue n'était jamais bindé (PortalV6.init() jamais appelé)
  // : le toggle FR/EN était totalement mort. Binding direct et idempotent.
  const langBtn = document.getElementById('lang-switch');
  if (langBtn && !langBtn.dataset.fpLangBound) {
    langBtn.dataset.fpLangBound = '1';
    langBtn.addEventListener('click', () => { if (window.i18n) i18n.toggleLanguage(); });
  }
}

async function boot() {
  const ok = await bootstrapPortalSession();
  if (!ok) return;
  if (window.i18n?.whenReady) {
    await new Promise((resolve) => i18n.whenReady(resolve));
  }
  initCertApp();
  if (window.initCybercorpShell) initCybercorpShell();
  // Deep-link autoritatif : activer l'onglet même si PortalLazy n'a pas encore wrappé tab()
  const tabParam = new URLSearchParams(location.search).get('tab');
  if (tabParam && typeof window.tab === 'function') {
    window.tab(tabParam);
  } else if (tabParam && window.applyInitialTabFromUrl) {
    applyInitialTabFromUrl();
  } else if (window.PortalOverview) {
    PortalOverview.loadOverviewCert();
  }
  if (window.CybercorpUltra) CybercorpUltra.initSocClock();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
