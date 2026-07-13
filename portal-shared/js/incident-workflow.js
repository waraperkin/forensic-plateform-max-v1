/* global i18n, ForensicUI */
'use strict';

/**
 * Workflow incident type SOAR — statuts, sévérités, actions rapides, journal.
 */
(function () {
  const STATUSES = ['new', 'open', 'investigating', 'contained', 'remediating', 'closed', 'false_positive'];
  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

  const QUICK_ACTIONS = [
    { key: 'investigating', status: 'investigating', icon: '▶' },
    { key: 'contained', status: 'contained', icon: '⛔' },
    { key: 'remediating', status: 'remediating', icon: '🔧' },
    { key: 'closed', status: 'closed', icon: '✓', needsResolution: true },
    { key: 'false_positive', status: 'false_positive', icon: '✕' },
  ];

  function t(key, fb) {
    return (typeof i18n !== 'undefined' && i18n.t) ? i18n.t(key) : (fb || key);
  }

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function statusLabel(code) {
    return t(`incidents.workflow.status.${code}`, code);
  }

  function severityLabel(code) {
    return t(`incidents.workflow.severity.${code}`, code);
  }

  function actionLabel(code) {
    return t(`incidents.workflow.action.${code}`, code);
  }

  function renderWorkflowBar(inc) {
    const curStatus = String(inc.status || 'open').toLowerCase();
    const curSev = String(inc.severity || 'medium').toLowerCase();
    const statusOpts = STATUSES.map((s) =>
      `<option value="${esc(s)}"${s === curStatus ? ' selected' : ''}>${esc(statusLabel(s))}</option>`,
    ).join('');
    const sevOpts = SEVERITIES.map((s) =>
      `<option value="${esc(s)}"${s === curSev ? ' selected' : ''}>${esc(severityLabel(s))}</option>`,
    ).join('');
    const quickBtns = QUICK_ACTIONS.map((a) =>
      `<button type="button" class="fp-btn fp-btn-sm fp-btn-ghost fp-wf-quick" data-wf-quick="${esc(a.status)}"${curStatus === a.status ? ' disabled' : ''}>${a.icon} ${esc(actionLabel(a.key))}</button>`,
    ).join('');

    const log = Array.isArray(inc.workflow_log) ? inc.workflow_log : [];
    const logHtml = log.length
      ? `<ul class="fp-wf-log-list">${log.slice(0, 12).map((e) => {
        const label = e.action === 'status_change'
          ? `${statusLabel(e.from || '—')} → ${statusLabel(e.to || '—')}`
          : e.action === 'severity_change'
            ? `${severityLabel(e.from || '—')} → ${severityLabel(e.to || '—')}`
            : e.action === 'assignee_change'
              ? `${esc(e.from || '—')} → ${esc(e.to || '—')}`
              : esc(e.note || e.action || '—');
        return `<li><time>${esc(String(e.at || '').slice(0, 19).replace('T', ' '))}</time> <strong>${esc(e.actor || '—')}</strong> — ${label}${e.note && e.action !== 'note' ? ` <span class="fp-muted">(${esc(e.note)})</span>` : ''}</li>`;
      }).join('')}</ul>`
      : `<p class="fp-muted">${esc(t('incidents.workflow.log_empty', 'Aucune action enregistrée — modifiez le statut ou la sévérité ci-dessus.'))}</p>`;

    return `
      <div class="fp-incident-soar" data-incident-soar data-incident-id="${esc(inc.id)}">
        <div class="fp-incident-soar-head">
          <h4 class="fp-section-sub">${esc(t('incidents.workflow.title', 'Gestion du cas (SOAR)'))}</h4>
          <p class="fp-muted fp-incident-soar-lead">${esc(t('incidents.workflow.lead', 'Statut et sévérité sont définis par l\'analyste CERT — enregistrés avec traçabilité.'))}</p>
        </div>
        <div class="fp-incident-soar-grid">
          <label class="fp-wf-field">${esc(t('table.status', 'Statut'))}
            <select class="fp-select" data-wf-status>${statusOpts}</select>
          </label>
          <label class="fp-wf-field">${esc(t('table.severity', 'Sévérité'))}
            <select class="fp-select" data-wf-severity>${sevOpts}</select>
          </label>
          <label class="fp-wf-field fp-wf-field-wide">${esc(t('table_cols.assignee', 'Assigné'))}
            <input type="text" class="fp-input" data-wf-assignee value="${esc(inc.assignee || '')}" placeholder="${esc(t('incidents.workflow.assignee_ph', 'analyste@cert'))}"/>
          </label>
        </div>
        <label class="fp-wf-field fp-wf-field-wide">${esc(t('incidents.workflow.note', 'Note analyste'))}
          <textarea class="fp-textarea fp-wf-note" data-wf-note rows="2" placeholder="${esc(t('incidents.workflow.note_ph', 'Contexte, décision, prochaine étape…'))}"></textarea>
        </label>
        <div class="fp-incident-soar-actions">
          <button type="button" class="fp-btn fp-btn-primary fp-btn-sm" data-wf-apply>${esc(t('incidents.workflow.apply', 'Enregistrer'))}</button>
          ${quickBtns}
        </div>
        <details class="fp-wf-log" open>
          <summary>${esc(t('incidents.workflow.log_title', 'Journal des actions'))} (${log.length})</summary>
          ${logHtml}
        </details>
      </div>`;
  }

  async function applyWorkflow(api, incidentId, payload) {
    const r = await fetch(`/api/master/incidents/${encodeURIComponent(incidentId)}/workflow`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(payload),
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || r.statusText);
    return body;
  }

  function bindWorkflowBar(container, api, onUpdated) {
    const root = container.querySelector('[data-incident-soar]');
    if (!root) return;
    const incidentId = root.dataset.incidentId;

    async function submit(extra = {}) {
      const status = root.querySelector('[data-wf-status]')?.value;
      const severity = root.querySelector('[data-wf-severity]')?.value;
      const assignee = root.querySelector('[data-wf-assignee]')?.value?.trim();
      const note = root.querySelector('[data-wf-note]')?.value?.trim();
      const payload = { status, severity, assignee, note, ...extra };
      if (extra.status === 'closed' && !payload.resolution) {
        const resolution = window.prompt(t('incidents.workflow.resolution_prompt', 'Résumé de clôture (obligatoire) :'));
        if (!resolution) return;
        payload.resolution = resolution;
      }
      try {
        if (ForensicUI?.toast) ForensicUI.toast(t('incidents.workflow.saving', 'Enregistrement…'), 'info');
        const result = await applyWorkflow(api, incidentId, payload);
        if (ForensicUI?.toast) ForensicUI.toast(t('incidents.workflow.saved', 'Cas mis à jour'), 'success');
        root.querySelector('[data-wf-note]').value = '';
        if (typeof onUpdated === 'function') await onUpdated(result.incident || result);
      } catch (e) {
        if (ForensicUI?.toast) ForensicUI.toast(e.message, 'error');
      }
    }

    root.querySelector('[data-wf-apply]')?.addEventListener('click', () => submit());
    root.querySelectorAll('[data-wf-quick]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const st = btn.dataset.wfQuick;
        root.querySelector('[data-wf-status]').value = st;
        submit({ status: st, quick_action: st });
      });
    });
  }

  window.IncidentWorkflow = {
    STATUSES,
    SEVERITIES,
    statusLabel,
    severityLabel,
    renderWorkflowBar,
    bindWorkflowBar,
    applyWorkflow,
  };
})();
