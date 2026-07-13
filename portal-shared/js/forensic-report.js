/* global ForensicAPI, ForensicUI, ThreatCommon */
'use strict';

/**
 * Générateur de rapports d'investigation forensic — collecte preuves, édition, IA locale.
 */
(function () {
  const esc = (s) => (window.ThreatCommon?.esc || ((x) => String(x ?? '')))(s);

  const state = {
    caseId: null,
    incidentId: null,
    incident: null,
    evidence: null,
    report: null,
    templates: [],
    llmStatus: null,
  };

  async function api(method, path, body) {
    const apiClient = new ForensicAPI({ base: '' });
    if (method === 'GET') return apiClient.get(path);
    if (method === 'DELETE') return apiClient.delete(path);
    if (method === 'PUT') return apiClient.put(path, body);
    return apiClient.post(path, body);
  }

  function t(key, vars) {
    return (window.i18n && window.i18n.t) ? window.i18n.t(key, vars) : key;
  }

  function sectionEditor(key, sec) {
    return `
      <div class="fp-report-editor-block" data-section-key="${esc(key)}">
        <div class="fp-report-editor-head">
          <h4>${esc(sec.title || key)}</h4>
          <span class="fp-report-source fp-report-source-${esc(sec.source || 'auto')}">${esc(sec.source || 'auto')}</span>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-xs fp-report-enrich-btn" data-enrich="${esc(key)}">${t('report.enrich_ai')}</button>
        </div>
        <textarea class="fp-textarea fp-report-textarea" data-section-input="${esc(key)}" rows="8">${esc(sec.content || '')}</textarea>
      </div>`;
  }

  function customBlockEditor(block, idx) {
    return `
      <div class="fp-report-custom-block" data-custom-idx="${idx}">
        <input type="text" class="fp-input fp-report-custom-title" data-custom-title="${idx}" value="${esc(block.title || '')}" placeholder="${t('report.custom_title_ph')}"/>
        <textarea class="fp-textarea fp-report-textarea" data-custom-content="${idx}" rows="5">${esc(block.content || '')}</textarea>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-xs fp-report-remove-custom" data-remove-custom="${idx}">${t('ui.delete')}</button>
      </div>`;
  }

  function renderBuilder(root) {
    const llmLabel = state.llmStatus?.available
      ? `${t('report.llm_ok')} (${esc(state.llmStatus.model || 'ollama')})`
      : t('report.llm_heuristic');

    root.innerHTML = `
      <div class="fp-report-builder">
        <header class="fp-report-builder-head">
          <div>
            <h3 class="fp-section-sub">${t('report.builder_title')}</h3>
            <p class="fp-muted">${t('report.builder_lead')}</p>
          </div>
          <div class="fp-report-llm-badge ${state.llmStatus?.available ? 'is-live' : ''}">${llmLabel}</div>
        </header>
        <div class="fp-report-form-grid">
          <label>${t('report.case_id')}
            <input type="text" class="fp-input" id="fp-report-case-id" value="${esc(state.caseId || '')}"/>
          </label>
          <label>${t('report.template')}
            <select class="fp-input" id="fp-report-template">
              ${(state.templates || []).map((tpl) =>
    `<option value="${esc(tpl.id)}" ${tpl.id === 'standard-ir' ? 'selected' : ''}>${esc(tpl.name)}</option>`,
  ).join('')}
            </select>
          </label>
          <label class="fp-report-span2">${t('report.title_field')}
            <input type="text" class="fp-input" id="fp-report-title" placeholder="${t('report.title_ph')}"/>
          </label>
        </div>
        <div class="fp-report-actions">
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="fp-report-collect">${t('report.collect_evidences')}</button>
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" id="fp-report-generate">${t('report.generate')}</button>
          <label class="fp-checkbox-inline"><input type="checkbox" id="fp-report-enrich-ai"/> ${t('report.enrich_on_generate')}</label>
        </div>
        <div id="fp-report-evidence-stats" class="fp-report-stats"></div>
        <div id="fp-report-editor" class="fp-report-editor" hidden></div>
        <div id="fp-report-saved-list" class="fp-report-saved"></div>
      </div>`;

    root.querySelector('#fp-report-collect')?.addEventListener('click', onCollect);
    root.querySelector('#fp-report-generate')?.addEventListener('click', onGenerate);
    loadSavedReports(root);
  }

  function renderEvidenceStats(el, evidence) {
    if (!el || !evidence) return;
    const st = evidence.stats || {};
    el.innerHTML = `
      <div class="fp-report-kpis">
        <div class="fp-report-kpi"><span>${t('report.kpi_events')}</span><strong>${st.events_total || 0}</strong></div>
        <div class="fp-report-kpi"><span>${t('report.kpi_uploads')}</span><strong>${st.uploads_count || 0}</strong></div>
        <div class="fp-report-kpi"><span>${t('report.kpi_iocs')}</span><strong>${st.iocs_count || 0}</strong></div>
        <div class="fp-report-kpi"><span>${t('report.kpi_alerts')}</span><strong>${st.alerts_count || 0}</strong></div>
      </div>`;
  }

  function renderEditor(root, report) {
    const editor = root.querySelector('#fp-report-editor');
    if (!editor) return;
    editor.hidden = false;
    const sections = report.sections || {};
    const blocks = report.custom_blocks || [];
    editor.innerHTML = `
      <h4 class="fp-section-sub">${t('report.edit_sections')}</h4>
      ${Object.entries(sections).map(([k, s]) => sectionEditor(k, s)).join('')}
      <div class="fp-report-custom-zone">
        <h4 class="fp-section-sub">${t('report.custom_blocks')}</h4>
        <div id="fp-report-custom-blocks">${blocks.map((b, i) => customBlockEditor(b, i)).join('')}</div>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="fp-report-add-custom">+ ${t('report.add_block')}</button>
      </div>
      <div class="fp-report-actions fp-report-actions-bottom">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" id="fp-report-save">${t('report.save')}</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="fp-report-preview">${t('report.preview')}</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="fp-report-export-html">${t('report.export_html')}</button>
        <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="fp-report-export-md">${t('report.export_md')}</button>
        <select class="fp-input fp-report-status-select" id="fp-report-status">
          <option value="draft" ${report.status === 'draft' ? 'selected' : ''}>${t('report.status_draft')}</option>
          <option value="review" ${report.status === 'review' ? 'selected' : ''}>${t('report.status_review')}</option>
          <option value="final" ${report.status === 'final' ? 'selected' : ''}>${t('report.status_final')}</option>
        </select>
      </div>`;

    editor.querySelectorAll('.fp-report-enrich-btn').forEach((btn) => {
      btn.addEventListener('click', () => onEnrichSection(root, btn.dataset.enrich));
    });
    editor.querySelector('#fp-report-save')?.addEventListener('click', () => onSave(root));
    editor.querySelector('#fp-report-preview')?.addEventListener('click', () => onPreview());
    editor.querySelector('#fp-report-export-html')?.addEventListener('click', () => onExport('html'));
    editor.querySelector('#fp-report-export-md')?.addEventListener('click', () => onExport('md'));
    editor.querySelector('#fp-report-add-custom')?.addEventListener('click', () => {
      const host = editor.querySelector('#fp-report-custom-blocks');
      const idx = host?.children.length || 0;
      host?.insertAdjacentHTML('beforeend', customBlockEditor({ title: '', content: '' }, idx));
      bindCustomRemove(editor);
    });
    bindCustomRemove(editor);
  }

  function bindCustomRemove(editor) {
    editor.querySelectorAll('.fp-report-remove-custom').forEach((btn) => {
      btn.onclick = () => btn.closest('.fp-report-custom-block')?.remove();
    });
  }

  function readSectionsFromEditor(root) {
    const sections = {};
    root.querySelectorAll('[data-section-input]').forEach((ta) => {
      const key = ta.dataset.sectionInput;
      if (key && state.report?.sections?.[key]) {
        sections[key] = {
          ...state.report.sections[key],
          content: ta.value,
          source: 'manual',
        };
      }
    });
    return sections;
  }

  function readCustomBlocks(root) {
    const blocks = [];
    root.querySelectorAll('.fp-report-custom-block').forEach((el) => {
      const title = el.querySelector('[data-custom-title]')?.value || '';
      const content = el.querySelector('[data-custom-content]')?.value || '';
      if (title || content) blocks.push({ title, content });
    });
    return blocks;
  }

  async function onCollect() {
    const root = document.getElementById('fp-report-root') || document.getElementById('fp-report-modal-root');
    if (!root) return;
    const caseId = root.querySelector('#fp-report-case-id')?.value?.trim();
    if (!caseId && !state.incidentId) {
      ForensicUI.toast(t('report.err_case'), 'warn');
      return;
    }
    try {
      ForensicUI.toast(t('report.collecting'), 'info');
      const r = await api('POST', '/api/reports/collect', {
        case_id: caseId,
        incident_id: state.incidentId,
      });
      state.evidence = r.evidence;
      state.caseId = r.evidence?.case_id || caseId;
      renderEvidenceStats(root.querySelector('#fp-report-evidence-stats'), state.evidence);
      ForensicUI.toast(t('report.collect_ok'), 'success');
    } catch (e) {
      ForensicUI.toast(e.message, 'error');
    }
  }

  async function onGenerate() {
    const root = document.getElementById('fp-report-root') || document.getElementById('fp-report-modal-root');
    if (!root) return;
    const caseId = root.querySelector('#fp-report-case-id')?.value?.trim();
    const templateId = root.querySelector('#fp-report-template')?.value;
    const title = root.querySelector('#fp-report-title')?.value?.trim();
    const enrichAi = root.querySelector('#fp-report-enrich-ai')?.checked;
    if (!caseId && !state.incidentId) {
      ForensicUI.toast(t('report.err_case'), 'warn');
      return;
    }
    try {
      ForensicUI.toast(t('report.generating'), 'info');
      const r = await api('POST', '/api/reports/generate', {
        case_id: caseId,
        incident_id: state.incidentId,
        template_id: templateId,
        title: title || undefined,
        enrich_ai: enrichAi,
        language: (window.i18n?.getLang?.() || 'fr').startsWith('en') ? 'en' : 'fr',
      });
      state.report = r.report;
      state.caseId = r.report?.case_id;
      renderEvidenceStats(root.querySelector('#fp-report-evidence-stats'), r.report?.evidence_snapshot);
      renderEditor(root, state.report);
      showDownloadBanner(root);
      loadSavedReports(root);
      root.querySelector('#fp-report-editor')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      ForensicUI.toast(t('report.generate_ok'), 'success');
    } catch (e) {
      ForensicUI.toast(e.message, 'error');
    }
  }

  async function onEnrichSection(root, sectionKey) {
    if (!state.report?.id) return;
    try {
      ForensicUI.toast(t('report.enriching'), 'info');
      const r = await api('POST', `/api/reports/${encodeURIComponent(state.report.id)}/enrich`, {
        section_key: sectionKey,
        language: (window.i18n?.getLang?.() || 'fr').startsWith('en') ? 'en' : 'fr',
      });
      const ta = root.querySelector(`[data-section-input="${sectionKey}"]`);
      if (ta) ta.value = r.section?.content || '';
      if (state.report.sections?.[sectionKey]) {
        state.report.sections[sectionKey] = r.section;
      }
      ForensicUI.toast(t('report.enrich_ok'), 'success');
    } catch (e) {
      ForensicUI.toast(e.message, 'error');
    }
  }

  async function onSave(root) {
    if (!state.report?.id) return;
    try {
      const sections = readSectionsFromEditor(root);
      const custom_blocks = readCustomBlocks(root);
      const status = root.querySelector('#fp-report-status')?.value || 'draft';
      const title = root.querySelector('#fp-report-title')?.value?.trim() || state.report.title;
      const r = await api('PUT', `/api/reports/${encodeURIComponent(state.report.id)}`, {
        title,
        status,
        sections,
        custom_blocks,
      });
      state.report = r.report;
      loadSavedReports(root);
      ForensicUI.toast(t('report.save_ok'), 'success');
    } catch (e) {
      ForensicUI.toast(e.message, 'error');
    }
  }

  function downloadReport(fmt) {
    if (!state.report?.id) {
      ForensicUI.toast(t('report.err_no_report'), 'warn');
      return;
    }
    const url = `/api/reports/${encodeURIComponent(state.report.id)}/export?format=${fmt}`;
    const ext = fmt === 'md' ? 'md' : 'html';
    const safeName = String(state.report.case_id || state.report.id).replace(/[^\w.-]+/g, '_');
    ForensicUI.toast(t('report.downloading'), 'info');
    fetch(url, { credentials: 'same-origin' })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.blob();
      })
      .then((blob) => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `rapport-${safeName}.${ext}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 5000);
        ForensicUI.toast(t('report.download_ok'), 'success');
      })
      .catch((e) => ForensicUI.toast(e.message, 'error'));
  }

  function onPreview() {
    if (!state.report?.id) {
      ForensicUI.toast(t('report.err_no_report'), 'warn');
      return;
    }
    window.open(`/api/reports/${encodeURIComponent(state.report.id)}/export?format=html`, '_blank', 'noopener');
  }

  function onExport(fmt) {
    downloadReport(fmt);
  }

  function showDownloadBanner(root) {
    if (!state.report?.id) return;
    let banner = root.querySelector('#fp-report-download-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'fp-report-download-banner';
      banner.className = 'fp-report-download-banner';
      const stats = root.querySelector('#fp-report-evidence-stats');
      if (stats?.nextSibling) stats.parentNode.insertBefore(banner, stats.nextSibling);
      else root.querySelector('.fp-report-builder')?.appendChild(banner);
    }
    banner.innerHTML = `
      <div class="fp-report-download-inner">
        <strong>${t('report.ready_title')}</strong>
        <span class="fp-muted">${esc(state.report.title || state.report.case_id || '')}</span>
        <div class="fp-report-download-actions">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" id="fp-report-dl-preview">${t('report.preview')}</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="fp-report-dl-html">${t('report.download_html')}</button>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="fp-report-dl-md">${t('report.download_md')}</button>
        </div>
      </div>`;
    banner.querySelector('#fp-report-dl-preview')?.addEventListener('click', () => onPreview());
    banner.querySelector('#fp-report-dl-html')?.addEventListener('click', () => downloadReport('html'));
    banner.querySelector('#fp-report-dl-md')?.addEventListener('click', () => downloadReport('md'));
    banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function loadSavedReports(root) {
    const host = root.querySelector('#fp-report-saved-list');
    if (!host) return;
    const caseId = state.caseId || root.querySelector('#fp-report-case-id')?.value?.trim();
    if (!caseId) {
      host.innerHTML = '';
      return;
    }
    try {
      const list = await api('GET', `/api/reports?case_id=${encodeURIComponent(caseId)}`);
      if (!list.length) {
        host.innerHTML = `<p class="fp-muted">${t('report.no_saved')}</p>`;
        return;
      }
      host.innerHTML = `
        <h4 class="fp-section-sub">${t('report.saved_list')}</h4>
        <ul class="fp-report-saved-ul">
          ${list.map((r) => `
            <li>
              <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm fp-report-open" data-id="${esc(r.id)}">
                ${esc(r.title)} <span class="fp-muted">(${esc(r.status)}) — ${esc(r.generated_at?.slice(0, 10) || '')}</span>
              </button>
              <button type="button" class="fp-btn fp-btn-ghost fp-btn-xs fp-report-dl-saved" data-id="${esc(r.id)}" data-fmt="html">HTML</button>
              <button type="button" class="fp-btn fp-btn-ghost fp-btn-xs fp-report-dl-saved" data-id="${esc(r.id)}" data-fmt="md">MD</button>
            </li>`).join('')}
        </ul>`;
      host.querySelectorAll('.fp-report-open').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const rep = await api('GET', `/api/reports/${encodeURIComponent(btn.dataset.id)}`);
          state.report = rep;
          const titleEl = root.querySelector('#fp-report-title');
          if (titleEl) titleEl.value = rep.title || '';
          renderEvidenceStats(root.querySelector('#fp-report-evidence-stats'), rep.evidence_snapshot);
          renderEditor(root, rep);
          showDownloadBanner(root);
        });
      });
      host.querySelectorAll('.fp-report-dl-saved').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const prev = state.report?.id;
          try {
            if (btn.dataset.id !== state.report?.id) {
              state.report = await api('GET', `/api/reports/${encodeURIComponent(btn.dataset.id)}`);
            }
            downloadReport(btn.dataset.fmt || 'html');
          } finally {
            if (prev && prev !== btn.dataset.id) state.report = prev;
          }
        });
      });
    } catch {
      host.innerHTML = '';
    }
  }

  async function init(root, options = {}) {
    if (!root) return;
    state.caseId = options.caseId || null;
    state.incidentId = options.incidentId || null;
    state.incident = options.incident || null;
    state.report = null;
    state.evidence = null;

    try {
      const [tplR, llmR] = await Promise.all([
        api('GET', '/api/reports/templates'),
        api('GET', '/api/reports/llm/status'),
      ]);
      state.templates = tplR.templates || [];
      state.llmStatus = llmR;
    } catch {
      state.templates = [];
    }

    renderBuilder(root);
    if (state.caseId) {
      const titleEl = root.querySelector('#fp-report-title');
      if (titleEl && state.incident?.title) {
        titleEl.value = `${t('report.title_prefix')} — ${state.incident.title}`;
      }
    }
  }

  function openModalForIncident(incident) {
    const caseId = incident?.case_id || incident?.id;
    const overlay = document.createElement('div');
    overlay.className = 'fp-report-modal-overlay';
    overlay.innerHTML = `
      <div class="fp-report-modal" role="dialog" aria-labelledby="fp-report-modal-title">
        <header class="fp-report-modal-head">
          <h3 id="fp-report-modal-title">${t('report.modal_title')}</h3>
          <button type="button" class="fp-btn fp-btn-ghost fp-btn-sm" id="fp-report-modal-close">✕</button>
        </header>
        <div id="fp-report-modal-root" class="fp-report-modal-body"></div>
      </div>`;
    document.body.appendChild(overlay);
    overlay.querySelector('#fp-report-modal-close')?.addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
    init(overlay.querySelector('#fp-report-modal-root'), {
      caseId,
      incidentId: incident?.id,
      incident,
    });
  }

  async function loadPanel(root) {
    await init(root, {});
  }

  window.ForensicReport = {
    init,
    loadPanel,
    openModalForIncident,
  };
})();
