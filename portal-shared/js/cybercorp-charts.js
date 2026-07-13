'use strict';

function ccDrawBarChart(canvas, labels, values, opts = {}) {
  if (!canvas || !labels.length) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 320;
  const h = canvas.clientHeight || 140;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  const max = Math.max(...values, 1);
  const pad = 24;
  const barW = (w - pad * 2) / labels.length - 8;
  const colors = opts.colors || ['#1e88e5', '#00e5ff', '#5c6bc0', '#26c6da'];
  labels.forEach((lb, i) => {
    const v = values[i] || 0;
    const bh = ((h - pad * 2) * v) / max;
    const x = pad + i * (barW + 8);
    const y = h - pad - bh;
    const g = ctx.createLinearGradient(x, y, x, h - pad);
    g.addColorStop(0, colors[i % colors.length]);
    g.addColorStop(1, '#0d2137');
    ctx.fillStyle = g;
    ctx.fillRect(x, y, barW, bh);
    ctx.fillStyle = '#94a3b8';
    ctx.font = i18n.t('msg.10px_system_ui_sans_serif');
    ctx.textAlign = 'center';
    ctx.fillText(String(lb).slice(0, 8), x + barW / 2, h - 6);
  });
}

function ccRenderHeatmap(container, services) {
  if (!container) return;
  container.innerHTML = services
    .map((s) => {
      const cls = s.status === 'up' ? 'cc-heat-up' : s.status === 'yellow' ? 'cc-heat-warn' : 'cc-heat-down';
      return `<div class="cc-heat-cell ${cls}" title="${s.name} — ${s.status}"><span>${s.name}</span></div>`;
    })
    .join('');
}

function ccRenderTimeline(container, items) {
  if (!container) return;
  if (!items.length) {
    container.innerHTML = `<p class="fp-muted">${i18n.t('msg.aucun_evenement_recent')}</p>`;
    return;
  }
  container.innerHTML = `<ul class="cc-timeline">${items
    .map(
      (it) => `<li class="cc-timeline-item">
        <span class="cc-timeline-dot"></span>
        <div><strong>${it.title}</strong><span class="cc-timeline-meta">${it.meta}</span></div>
      </li>`,
    )
    .join('')}</ul>`;
}

window.CybercorpCharts = { ccDrawBarChart, ccRenderHeatmap, ccRenderTimeline };
