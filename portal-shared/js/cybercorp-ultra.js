'use strict';

function initSocClock() {
  const el = document.getElementById('cc-soc-clock');
  if (!el) return;
  const tick = () => {
    const d = new Date();
    el.textContent = d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  };
  tick();
  setInterval(tick, 1000);
}

function bindClickableCards(container) {
  const root = container || document;
  root.querySelectorAll('.cc-card-click[data-goto-tab]').forEach((card) => {
    if (card.dataset.bound) return;
    card.dataset.bound = '1';
    card.addEventListener('click', () => {
      const t = card.dataset.gotoTab;
      if (t && typeof window.tab === 'function') window.tab(t);
    });
  });
}

function renderEchart(domId, option) {
  if (typeof echarts === 'undefined') return null;
  const el = document.getElementById(domId);
  if (!el) return null;
  const chart = echarts.init(el, 'dark');
  chart.setOption(option);
  window.addEventListener('resize', () => chart.resize());
  return chart;
}

function echartBar(domId, labels, values, title) {
  return renderEchart(domId, {
    backgroundColor: 'transparent',
    title: { text: title, textStyle: { color: '#8ba3c7', fontSize: 12 } },
    grid: { left: 40, right: 12, top: 36, bottom: 28 },
    xAxis: { type: 'category', data: labels, axisLabel: { color: '#8ba3c7' } },
    yAxis: { type: 'value', axisLabel: { color: '#8ba3c7' }, splitLine: { lineStyle: { color: '#1e3a5f' } } },
    series: [{
      type: 'bar',
      data: values,
      itemStyle: {
        color: {
          type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
          colorStops: [{ offset: 0, color: '#00e5ff' }, { offset: 1, color: '#1565c0' }],
        },
      },
    }],
  });
}

window.CybercorpUltra = { initSocClock, bindClickableCards, renderEchart, echartBar };
