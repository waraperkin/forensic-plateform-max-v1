/* global window, document, ForensicUtils */
'use strict';

const ForensicComponents = {
  renderStatsPanel(stats, mapping) {
    return mapping
      .map(
        ({ id, label, key, color }) => `
      <div class="fp-stat">
        <div class="fp-stat-value" id="${id}" style="${color ? `color:${color}` : ''}">${stats[key] ?? '—'}</div>
        <div class="fp-stat-label">${label}</div>
      </div>`,
      )
      .join('');
  },

  tableSkeleton(cols, rows = 4) {
    return Array.from({ length: rows })
      .map(
        () =>
          `<tr>${Array.from({ length: cols })
            .map(() => '<td><div class="fp-skeleton"></div></td>')
            .join('')}</tr>`,
      )
      .join('');
  },

  renderServiceGrid(services, dotMap) {
    const rows = services
      .map((svc) => {
        const dotId = dotMap[svc.name];
        const dotHtml = dotId
          ? `<span class="fp-dot ${svc.status}" id="${dotId}"></span>`
          : `<span class="fp-dot ${svc.status}"></span>`;
        return `<div class="fp-svc-row">${dotHtml}<span>${ForensicUtils.escapeHtml(svc.name)}</span><span style="margin-left:auto;font-size:0.7rem;color:var(--text-muted)">${svc.code || svc.error || ''}</span></div>`;
      })
      .join('');
    const table = `<table class="fp-table"><thead><tr><th>Service</th><th>Statut</th><th>Détail</th></tr></thead><tbody>${services
      .map(
        (s) =>
          `<tr><td>${ForensicUtils.escapeHtml(s.name)}</td><td><span class="fp-tag fp-tag-${s.status}">${s.status}</span></td><td style="color:var(--text-muted)">${s.code || s.error || '—'}</td></tr>`,
      )
      .join('')}</tbody></table>`;
    return { rows, table };
  },

  bindUploadZone({ zoneId, inputId, onFiles, validator }) {
    const dz = document.getElementById(zoneId);
    const fi = document.getElementById(inputId);
    if (!dz || !fi) return;

    const handle = (fileList) => {
      const arr = [...fileList];
      if (validator) {
        const check = validator.validateQueue(arr);
        if (check.globalError && arr.length > validator.maxFiles) {
          window.ForensicUI?.toast(check.globalError, 'error');
          return;
        }
      }
      onFiles(arr);
    };

    const setDragActive = (active) => {
      dz.classList.toggle('drag-over', active);
      dz.classList.toggle('is-drag', active);
    };
    dz.addEventListener('dragenter', (e) => {
      e.preventDefault();
      setDragActive(true);
    });
    dz.addEventListener('dragover', (e) => {
      e.preventDefault();
      setDragActive(true);
    });
    dz.addEventListener('dragleave', (e) => {
      if (!dz.contains(e.relatedTarget)) setDragActive(false);
    });
    dz.addEventListener('drop', (e) => {
      e.preventDefault();
      setDragActive(false);
      handle(e.dataTransfer.files);
    });
    fi.addEventListener('change', (e) => handle(e.target.files));
    dz.addEventListener('click', (e) => {
      if (e.target.closest('.fp-file-rm')) return;
      fi.click();
    });
  },

  renderFileQueue(containerId, files, validator, onRemove) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = files
      .map((f, i) => {
        const v = validator ? validator.validateFile(f) : { valid: true, errors: [] };
        const invalid = !v.valid;
        return `<div class="fp-file-item${invalid ? ' invalid' : ''}">
        <span class="fp-file-name" title="${ForensicUtils.escapeHtml(f.name)}">${ForensicUtils.escapeHtml(f.name)}${invalid ? ' ⚠' : ''}</span>
        <span class="fp-file-meta">${ForensicUtils.sz(f.size)}</span>
        <button type="button" class="fp-file-rm" data-idx="${i}" aria-label="Retirer">✕</button>
      </div>`;
      })
      .join('');
    el.querySelectorAll('.fp-file-rm').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        onRemove(parseInt(btn.dataset.idx, 10));
      });
    });
  },

  updateUploadProgress({ barId, metaId, percent, speed, remaining }) {
    const bar = document.getElementById(barId);
    const meta = document.getElementById(metaId);
    if (bar) bar.style.width = `${Math.min(100, percent)}%`;
    if (meta) {
      meta.textContent = `${percent}% · ${ForensicUtils.sz(speed)}/s · ~${Math.ceil(remaining)}s restantes`;
    }
  },

  resetUploadProgress(barId, metaId) {
    const bar = document.getElementById(barId);
    const meta = document.getElementById(metaId);
    if (bar) bar.style.width = '0%';
    if (meta) meta.textContent = '';
  },

  bindCaseAutocomplete(inputId, listId, api) {
    const input = document.getElementById(inputId);
    const list = document.getElementById(listId);
    if (!input || !list) return;

    let cases = [];
    api.get('api/cases').then((data) => {
      cases = data || [];
    }).catch(() => {});

    const show = ForensicUtils.debounce((q) => {
      const ql = (q || '').toLowerCase();
      const hits = cases
        .filter((c) => !ql || String(c.case_id).toLowerCase().includes(ql))
        .slice(0, 8);
      if (!hits.length) {
        list.classList.remove('open');
        return;
      }
      list.innerHTML = hits
        .map(
          (c) =>
            `<div class="fp-ac-item" data-case="${ForensicUtils.escapeHtml(c.case_id)}">${ForensicUtils.escapeHtml(c.case_id)} <span style="color:var(--text-muted)">(${c.files} fichiers)</span></div>`,
        )
        .join('');
      list.classList.add('open');
      list.querySelectorAll('.fp-ac-item').forEach((item) => {
        item.addEventListener('click', () => {
          input.value = item.dataset.case;
          list.classList.remove('open');
        });
      });
    }, 200);

    input.addEventListener('input', () => show(input.value));
    input.addEventListener('focus', () => show(input.value));
    document.addEventListener('click', (e) => {
      if (!list.contains(e.target) && e.target !== input) list.classList.remove('open');
    });
  },
};

window.ForensicComponents = ForensicComponents;
