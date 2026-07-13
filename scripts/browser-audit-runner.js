/**
 * Audit portail — à exécuter via CDP Runtime.evaluate (chaîne JSON).
 * Retourne erreurs console, réseau, statut par onglet.
 */
async function runPortalAudit() {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const report = {
    started: new Date().toISOString(),
    tabs: [],
    console: window.__audit?.console ? [...window.__audit.console] : [],
    network: [],
    globalErrors: [],
  };

  const tabs = [
    'overview', 'health', 'access-center', 'threat-intel', 'ingest-evidence',
    'cert-ops', 'it-ops', 'cases', 'kb', 'hist', 'portal-documentation',
    'sekoia-assets', 'sekoia-rules', 'sekoia-apikeys', 'sekoia-fetch',
    's1-endpoints', 's1-policies', 's1-apikeys', 's1-fetch', 'tp-config',
    'sekoia-cc', 'xdr-view', 'audit-center',
    'gov-assets', 'gov-rules', 'gov-apikeys', 'gov-views',
    'cert-asset-investigation', 'cert-timeline-builder', 'cert-ioc-correlation',
    'soc-investigation-assisted', 'soc-autonomous', 'users', 'settings-admin',
  ];

  const ccSubs = ['overview', 'inventaire', 'connectors', 'modules', 'formats', 'playbooks', 'stats', 'audit', 'querybuilder', 'dashboard', 'assetprofile'];

  function collectNetwork() {
    return performance.getEntriesByType('resource')
      .filter((e) => e.transferSize === 0 && e.duration > 0 && /api\\//.test(e.name))
      .map((e) => ({ url: e.name, duration: e.duration }));
  }

  for (const tab of tabs) {
    const entry = { tab, ok: false, errors: [], buttons: 0 };
    try {
      const btn = document.querySelector(`[data-tab-btn="${tab}"]`);
      if (!btn) {
        entry.errors.push('tab-btn missing');
        report.tabs.push(entry);
        continue;
      }
      if (typeof window.tab === 'function') window.tab(tab);
      else btn.click();
      await sleep(1200);
      const panel = document.getElementById(`tab-${tab}`);
      entry.ok = !!(panel && panel.classList.contains('active'));
      const root = panel && panel.querySelector('[id$="-root"], .cc-tp-root');
      entry.hasContent = root ? (root.innerText || '').length > 3 : false;
      entry.loading = root ? /Chargement/i.test(root.innerText || '') : false;

      if (tab === 'sekoia-cc') {
        for (const sub of ccSubs) {
          const sb = panel && panel.querySelector(`[data-act="cc-sub"][data-sub="${sub}"]`);
          if (sb) { sb.click(); await sleep(400); }
        }
      }
      if (tab === 'soc-autonomous') {
        for (const sub of ['overview', 'incidents', 'recommendations', 'anomalies', 'correlations']) {
          const sb = document.querySelector(`[data-ai-auto-sub="${sub}"]`);
          if (sb) { sb.click(); await sleep(500); }
        }
      }
      if (tab === 'sekoia-fetch') {
        for (const v of ['table', 'json', 'timeline', 'histogram', 'top']) {
          const vb = panel && panel.querySelector(`[data-act="fetch-view"][data-view="${v}"]`);
          if (vb) { vb.click(); await sleep(200); }
        }
      }

      const activePanel = document.querySelector('.fp-panel.active');
      if (activePanel) {
        const buttons = activePanel.querySelectorAll('button:not([disabled]), [data-act], .cc-subtab');
        entry.buttons = buttons.length;
        for (let i = 0; i < Math.min(buttons.length, 8); i++) {
          try { buttons[i].click(); await sleep(150); } catch (_) { /* ignore */ }
        }
      }
    } catch (e) {
      entry.errors.push(String(e.message || e));
    }
    report.tabs.push(entry);
    await sleep(300);
  }

  if (window.__audit?.console) report.console.push(...window.__audit.console);
  report.console = [...new Set(report.console)].slice(0, 50);
  report.ended = new Date().toISOString();
  report.hasPortalAI = typeof window.PortalAI !== 'undefined';
  report.hasAutonomous = typeof window.PortalAI?.runAutonomousScan === 'function';
  report.hasSocAutonomousTab = !!document.querySelector('[data-tab-btn="soc-autonomous"]');
  return report;
}
return runPortalAudit();
