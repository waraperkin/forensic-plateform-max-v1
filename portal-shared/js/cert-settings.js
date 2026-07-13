'use strict';

async function authFetch(path, opts = {}) {
  const r = await fetch(`/api/auth${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || r.statusText);
  return d;
}

async function loadSettingsAdmin() {
  const root = document.getElementById('settings-root');
  if (!root || !window.PortalSession?.isAdmin) return;

  const settings = await authFetch('/settings');

  root.innerHTML = `
    <div class="cc-settings-header">
      <img src="shared/assets/cybercorp-logo.svg" alt="CYBERCORP" width="40" height="40">
      <div>
        <h3 class="fp-section-title" style="margin:0">Paramètres portail</h3>
        <p class="fp-muted">Branding et affichage CYBERCORP</p>
      </div>
    </div>
    <div class="fp-card cc-pro-panel">
      <label class="fp-label">Titre portail <input class="fp-input" id="set-title" value="${settings.portalTitle || ''}"></label>
      <label class="fp-label">Bannière <input class="fp-input" id="set-banner" value="${settings.bannerText || ''}"></label>
      <button type="button" class="fp-btn fp-btn-primary" id="set-save">Enregistrer</button>
      <p id="set-msg" class="fp-muted"></p>
    </div>
    <div class="fp-card cc-pro-panel fp-section-spaced">
      <h3 class="fp-section-sub">Mon compte — MFA</h3>
      <button type="button" class="fp-btn" id="mfa-setup-btn">Configurer MFA (QR)</button>
      <div id="mfa-qr" class="fp-mfa-qr"></div>
    </div>`;

  document.getElementById('set-save')?.addEventListener('click', async () => {
    await authFetch('/settings', {
      method: 'PUT',
      body: JSON.stringify({
        portalTitle: document.getElementById('set-title').value,
        bannerText: document.getElementById('set-banner').value,
      }),
    });
    document.getElementById('set-msg').textContent = i18n.t('msg.enregistre');
  });

  document.getElementById('mfa-setup-btn')?.addEventListener('click', async () => {
    const d = await authFetch('/mfa/setup', { method: 'POST' });
    const qr = document.getElementById('mfa-qr');
    qr.innerHTML = `<img src="${d.qrDataUrl}" alt="QR MFA" width="180"><p class="fp-muted">Scannez puis validez avec un code</p>
      <input class="fp-input" id="mfa-activate-code" placeholder="123456">
      <button type="button" class="fp-btn fp-btn-primary" id="mfa-activate-btn">Activer MFA</button>`;
    document.getElementById('mfa-activate-btn')?.addEventListener('click', async () => {
      await authFetch('/mfa/activate', {
        method: 'POST',
        body: JSON.stringify({ totp: document.getElementById('mfa-activate-code').value }),
      });
      alert(i18n.t('msg.mfa_active'));
    });
  });
}

window.PortalSettings = { loadSettingsAdmin };
