/* global ForensicAPI, ForensicUI, ForensicUtils, ForensicComponents, FileValidator */
'use strict';

const api = new ForensicAPI({
  base: '',
  getHeaders: () => (tokenValue ? { 'x-it-token': tokenValue } : {}),
});
let validator = new FileValidator();
let tokenValue = null;
let tokenData = null;
let files = [];

function getToken() {
  return new URLSearchParams(window.location.search).get('token');
}

function log(m, c = '') {
  ForensicUI.consoleLog('con', m, c);
}

async function loadConfig() {
  try {
    validator = await FileValidator.loadFromAPI(api, 'api/config');
    const hint = document.getElementById('upload-limits-hint');
    if (hint) {
      hint.textContent = i18n.t('it.upload_limits_hint', {
        max: validator.maxFiles,
        size: ForensicUtils.sz(validator.maxSizeBytes),
      });
    }
  } catch (_) {
    validator = new FileValidator({ maxSizeBytes: 500 * 1024 * 1024 });
  }
}

function renderQ() {
  ForensicComponents.renderFileQueue('queue', files, validator, (i) => {
    files.splice(i, 1);
    renderQ();
  });
  const check = validator.validateQueue(files);
  const valid = files.filter((f) => validator.validateFile(f).valid);
  document.getElementById('ubtn').disabled = valid.length === 0 || !tokenValue;
}

function addF(nf) {
  if (!tokenValue) {
    ForensicUI.toast(i18n.t('it.no_token_message'), 'warn');
  }
  for (const f of nf) {
    if (!files.find((x) => x.name === f.name && x.size === f.size)) files.push(f);
  }
  renderQ();
  log(i18n.t('upload.uploading', { n: nf.length }).replace('Upload de', '').trim() || `${nf.length} fichier(s) ajouté(s)`, 'info');
}

function bindItUploadZone() {
  ForensicComponents.bindUploadZone({
    zoneId: 'dz',
    inputId: 'fi',
    onFiles: addF,
    validator: null,
  });
}

function renderTokenBox(d) {
  document.getElementById('token-box').innerHTML = `
    <div class="case-id">🔍 ${i18n.t('it.token_case')}: <strong>${ForensicUtils.escapeHtml(d.case_id)}</strong></div>
    <div class="desc">${ForensicUtils.escapeHtml(d.description || i18n.t('it.upload_title'))}</div>
    <div class="meta">${i18n.t('it.token_expires')}: ${new Date(d.expires_at).toLocaleString()}
      · ${i18n.t('it.token_uses')}: ${d.uses_count}/${d.max_uses}
      · ${i18n.t('it.token_remaining')}: ~${d.hours_remaining}h</div>`;
}

function scrollItAnchor() {
  const id = (location.hash || '').slice(1);
  if (!id || !id.startsWith('it-')) return;
  const el = document.getElementById(id);
  if (!el) return;
  requestAnimationFrame(() => {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    document.querySelectorAll('#fp-sidebar-it a[href^="#"]').forEach((a) => {
      a.classList.toggle('active', a.getAttribute('href') === `#${id}`);
    });
  });
}

function ensureUploadLockedNotice() {
  const upload = document.getElementById('it-upload');
  if (!upload) return;
  let notice = document.getElementById('it-upload-locked-notice');
  if (!notice) {
    notice = document.createElement('div');
    notice.id = 'it-upload-locked-notice';
    notice.className = 'fp-alert fp-alert-warn fp-ds-animate-in';
    notice.setAttribute('role', 'alert');
    upload.prepend(notice);
  }
  notice.textContent = i18n.t('it.no_token_message');
  notice.style.display = 'block';
}

function showItSections(locked) {
  const main = document.getElementById('main');
  if (!main) return;
  main.style.display = 'block';
  main.classList.toggle('it-locked', Boolean(locked));
  const notice = document.getElementById('it-upload-locked-notice');
  if (locked) ensureUploadLockedNotice();
  else if (notice) notice.style.display = 'none';
  scrollItAnchor();
}

async function refreshItUi() {
  if (window.ItDashboard) await ItDashboard.loadItDashboard(tokenData);
  if (window.ItOperations) await ItOperations.loadItOperations(tokenValue);
}

async function init() {
  if (window.i18n) await i18n.init();
  ForensicUI.initTheme('it');
  ForensicUI.initErrorBoundary();
  const tbtn = document.getElementById('theme-toggle');
  if (tbtn) {
    tbtn.textContent = document.documentElement.getAttribute('data-theme') === 'dark' ? '☀️' : '🌙';
    tbtn.addEventListener('click', () => ForensicUI.toggleTheme('it'));
  }

  document.getElementById('menu-toggle')?.addEventListener('click', () => {
    const sb = document.getElementById('fp-sidebar-it');
    if (!sb) return;
    sb.classList.toggle('open');
    document.body.classList.toggle('cc-sidebar-open', sb.classList.contains('open'));
  });
  document.body.addEventListener('click', (e) => {
    if (!document.body.classList.contains('cc-sidebar-open')) return;
    if (e.target.closest('#fp-sidebar-it') || e.target.closest('#menu-toggle')) return;
    document.getElementById('fp-sidebar-it')?.classList.remove('open');
    document.body.classList.remove('cc-sidebar-open');
  });
  document.querySelectorAll('#fp-sidebar-it a[href^="#"]').forEach((a) => {
    a.addEventListener('click', () => {
      if (window.matchMedia('(max-width:900px)').matches) {
        document.getElementById('fp-sidebar-it')?.classList.remove('open');
        document.body.classList.remove('cc-sidebar-open');
      }
      const id = a.getAttribute('href')?.slice(1);
      if (id) {
        requestAnimationFrame(() => {
          document.querySelectorAll('#fp-sidebar-it a[href^="#"]').forEach((link) => {
            link.classList.toggle('active', link.getAttribute('href') === `#${id}`);
          });
        });
      }
    });
  });
  window.addEventListener('hashchange', scrollItAnchor);

  await loadConfig();

  const token = getToken();
  document.getElementById('loading').style.display = 'none';

  if (!token) {
    const banner = document.getElementById('it-no-token-banner');
    if (banner) {
      banner.style.display = 'block';
      banner.textContent = i18n.t('it.no_token_message');
    }
    const invalidEl = document.getElementById('invalid');
    if (invalidEl) invalidEl.style.display = 'none';
    showItSections(true);
    await refreshItUi();
    bindItUploadZone();
    return;
  }
  tokenValue = token;

  try {
    const d = await api.get(`api/token/verify?token=${encodeURIComponent(token)}`);
    if (!d.valid) {
      if (d.code === 'TOKEN_EXHAUSTED') {
        document.getElementById('exhausted').style.display = 'block';
        document.getElementById('exhausted').innerHTML = `⚠️ ${i18n.t('it.token_exhausted', { detail: ForensicUtils.escapeHtml(d.error || '') })}`;
      } else {
        document.getElementById('invalid').style.display = 'block';
        document.getElementById('invalid').textContent = `❌ ${d.error || i18n.t('it.token_invalid')}`;
      }
      showItSections(true);
      await refreshItUi();
      bindItUploadZone();
      return;
    }

    tokenData = d;
    renderTokenBox(d);
    showItSections(false);
    await refreshItUi();
    renderQ();
  } catch (e) {
    document.getElementById('invalid').style.display = 'block';
    document.getElementById('invalid').innerHTML = `❌ ${i18n.t('it.token_connection_error', { detail: ForensicUtils.escapeHtml(e.message || i18n.t('msg.reseau')) })}`;
    showItSections(true);
    await refreshItUi();
  }

  bindItUploadZone();
  await refreshItHelkBadge();
  await refreshItVelociraptorBadge();
  setInterval(refreshItHelkBadge, 60000);
  setInterval(refreshItVelociraptorBadge, 60000);
}

async function doUpload() {
  const validFiles = files.filter((f) => validator.validateFile(f).valid);
  if (!validFiles.length || !tokenValue) return;

  document.getElementById('ubtn').disabled = true;
  document.getElementById('success').style.display = 'none';

  const fd = new FormData();
  fd.append('token', tokenValue);
  fd.append('submitter_name', document.getElementById('submitter').value || 'IT Team');
  fd.append('submitter_email', document.getElementById('email').value || '');
  fd.append('notes', document.getElementById('notes').value || '');
  validFiles.forEach((f) => fd.append('files', f));
  if (document.getElementById('helk-sync-it')?.checked) fd.append('helk_sync', 'true');

  if (files.length > validFiles.length) {
    log(`⚠️ ${files.length - validFiles.length} fichier(s) ignoré(s) (invalides)`, 'warn');
    ForensicUI.toast(`${files.length - validFiles.length} fichier(s) ignoré(s)`, 'warn');
  }

  log(i18n.t('upload.uploading', { n: validFiles.length }), 'info');
  ForensicComponents.resetUploadProgress('pf', 'pf-meta');

  try {
    const { status, data: d } = await api.uploadWithProgress(
      'api/upload',
      fd,
      (p) => {
        ForensicComponents.updateUploadProgress({
          barId: 'pf',
          metaId: 'pf-meta',
          percent: p.percent,
          speed: p.speed,
          remaining: p.remaining,
        });
      },
    );

    if (status === 401) {
      log(`❌ ${d.error || i18n.t('msg.acces_refuse')}`, 'err');
      document.getElementById('invalid').style.display = 'block';
      document.getElementById('invalid').textContent = `❌ ${d.error || i18n.t('it.token_invalid')}`;
      ForensicUI.toast(i18n.t('msg.acces_refuse'), 'error');
      return;
    }

    if (status === 413) {
      log(i18n.t('msg.fichiers_trop_volumineux'), 'err');
      ForensicUI.toast(i18n.t('msg.fichiers_trop_volumineux'), 'error');
      return;
    }

    (d.results || []).forEach((res) => {
      if (res.ok) log(`✓ ${res.file} → ${res.bucket}`, 'ok');
      else log(`✗ ${res.file}: ${res.error}`, 'err');
    });

    if (d.results && d.results.some((r) => r.ok)) {
      document.getElementById('success').style.display = 'block';
      document.getElementById('success').innerHTML =
        `✅ ${i18n.t('upload.files_sent', { n: validFiles.length })} — <strong>${ForensicUtils.escapeHtml(d.case_id)}</strong>`;
      ForensicUI.toast(i18n.t('msg.fichiers_transmis_au_cert'), 'success');
      files = [];
      renderQ();

      if (tokenData?.max_uses === 1) {
        document.getElementById('ubtn').textContent = i18n.t('msg.token_usage_unique_epuise');
        log(i18n.t('msg.token_usage_unique_upload_desactive'), 'warn');
      }

      if (window.ItOperations) await ItOperations.loadItOperations(tokenValue);
    }
  } catch (e) {
    log(`❌ ${e.message || e}`, 'err');
    ForensicUI.toast(e.message || i18n.t('msg.erreur_reseau'), 'error');
    document.getElementById('ubtn').disabled = false;
  }

  setTimeout(() => ForensicComponents.resetUploadProgress('pf', 'pf-meta'), 1500);
  if (tokenData?.max_uses > 1) document.getElementById('ubtn').disabled = files.length === 0;
}

async function refreshItHelkBadge() {
  const el = document.getElementById('helk-it-badge');
  if (!el) return;
  try {
    const data = await api.get('api/helk/status');
    const ok = data?.helk?.ok;
    el.className = `cc-badge ${ok ? 'cc-badge-ok' : 'cc-badge-warn'}`;
    el.textContent = ok ? i18n.t('helk.badge_active') : i18n.t('helk.badge_offline');
  } catch (_) {
    el.className = 'cc-badge cc-badge-warn';
    el.textContent = i18n.t('helk.badge_offline');
  }
}

async function refreshItVelociraptorBadge() {
  const el = document.getElementById('vr-it-badge');
  if (!el) return;
  try {
    const data = await api.get('api/velociraptor/status');
    const ok = data?.velociraptor?.ok;
    el.className = `cc-badge ${ok ? 'cc-badge-ok' : 'cc-badge-warn'}`;
    el.textContent = ok ? i18n.t('velociraptor.badge_managed') : i18n.t('velociraptor.badge_offline');
  } catch (_) {
    el.className = 'cc-badge cc-badge-warn';
    el.textContent = i18n.t('velociraptor.badge_offline');
  }
}

window.doUpload = doUpload;

document.addEventListener('i18n:language-changed', () => {
  if (!window.i18n) return;
  i18n.translateDOM(document);
  loadConfig();
  if (tokenData) renderTokenBox(tokenData);
  refreshItUi();
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
