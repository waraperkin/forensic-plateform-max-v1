'use strict';

function socToolsBase() {
  return PortalConfig.socBaseUrl();
}

const SOC_TOOLS = [
  { name: 'OpenSearch Dashboards', path: '/dashboards/' },
  { name: 'Timesketch', path: '/timesketch/' },
  { name: 'OpenCTI', path: '/cti/' },
  { name: 'TheHive', path: '/thehive/' },
  { name: 'MISP', path: '/misp/' },
  { name: 'Cortex', path: '/cortex/' },
  { name: 'MinIO', path: '/minio/' },
  { name: 'Grafana', path: '/grafana/' },
  { name: 'HELK Kibana', path: '/helk/kibana/' },
  { name: 'HELK API', path: '/helk/api/' },
  { name: 'Velociraptor DFIR', path: '/velociraptor/app/index.html' },
];

function renderSocToolsTable(container) {
  if (!container) return;
  PortalConfig.whenReady(() => renderSocToolsTableInner(container));
}

function renderSocToolsTableInner(container) {
  const base = socToolsBase();
  container.innerHTML = `
    <div class="cc-soc-tools-block">
      <h3 class="fp-section-sub">Outils SOC — accès directs</h3>
      <p class="fp-muted cc-soc-tools-hint">Liens directs vers les outils SOC (même hôte). Ouvrir ou copier l'URL.</p>
      <div class="fp-table-wrap">
        <table class="fp-table cc-soc-tools-table">
          <thead><tr><th>Outil</th><th>URL</th><th></th></tr></thead>
          <tbody>
            ${SOC_TOOLS.map((t) => {
              const url = `${base}${t.path}`;
              const hint = t.desc ? `<div class="fp-muted" style="font-size:.8rem">${t.desc}</div>` : '';
              return `<tr>
                <td><strong>${t.name}</strong>${hint}</td>
                <td><code class="cc-url-cell">${url}</code></td>
                <td class="cc-soc-actions">
                  <button type="button" class="fp-btn fp-btn-sm fp-btn-primary" data-open-url="${url}">Ouvrir</button>
                  <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-embed-url="${url}" data-embed-name="${t.name}">Intégrer</button>
                  <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-copy-url="${url}">Copier</button>
                </td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>
      <div id="soc-proxy-embed" hidden aria-hidden="true"></div>
    </div>`;
  container.querySelectorAll('[data-open-url]').forEach((btn) => {
    btn.addEventListener('click', () => window.open(btn.dataset.openUrl, '_blank', 'noopener'));
  });
  container.querySelectorAll('[data-copy-url]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.copyUrl);
        btn.textContent = i18n.t('toast.copied');
        setTimeout(() => { btn.textContent = 'Copier'; }, 1500);
      } catch (_) {
        window.prompt(i18n.t('msg.copier_lurl'), btn.dataset.copyUrl);
      }
    });
  });
  container.querySelectorAll('[data-embed-url]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const embed = document.getElementById('soc-proxy-embed');
      if (!embed || !window.ProxyFrame) return;
      embed.hidden = false;
      embed.setAttribute('aria-hidden', 'false');
      embed.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      ProxyFrame.mount(embed, {
        url: btn.dataset.embedUrl,
        service: { name: btn.dataset.embedName || 'SOC' },
      });
    });
  });
}

function loadSocToolsPage() {
  const root = document.getElementById('soc-tools-root');
  if (!root) return;
  PortalConfig.whenReady(() => renderSocToolsTable(root));
}

window.SocTools = { SOC_TOOLS, renderSocToolsTable, loadSocToolsPage, socToolsBase };
