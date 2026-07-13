'use strict';

(function () {
  const form = document.getElementById('login-form');
  const errEl = document.getElementById('login-err');
  const mfaBlock = document.getElementById('mfa-block');
  let mfaPending = false;

  function showErr(msg) {
    if (!errEl) return;
    errEl.textContent = msg;
    errEl.hidden = !msg;
  }

  async function loadBranding() {
    try {
      const r = await fetch('/api/auth/public-settings');
      if (!r.ok) return;
      const s = await r.json();
      if (s.portalTitle) document.getElementById('login-title').textContent = s.portalTitle;
      if (s.bannerText) document.getElementById('login-banner').textContent = s.bannerText;
    } catch (_) { /* public read may 401 — defaults OK */ }
  }

  async function trySession() {
    try {
      const r = await fetch('/api/auth/session', { credentials: 'include' });
      const d = await r.json();
      if (d.authenticated) {
        const next = new URLSearchParams(location.search).get('next') || '/';
        location.href = next;
      }
    } catch (_) { /* ignore */ }
  }

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    showErr('');
    const body = {
      username: document.getElementById('login-user').value.trim(),
      password: document.getElementById('login-pass').value,
    };
    if (mfaPending) body.totp = document.getElementById('login-totp').value.trim();

    const btn = document.getElementById('login-submit');
    btn.disabled = true;
    try {
      const r = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) {
        showErr(d.error || i18n.t('msg.echec_de_connexion'));
        return;
      }
      if (d.mfaRequired) {
        mfaPending = true;
        mfaBlock.hidden = false;
        document.getElementById('login-totp').focus();
        showErr('Saisissez le code MFA');
        return;
      }
      const next = new URLSearchParams(location.search).get('next') || '/';
      location.href = next;
    } catch (ex) {
      showErr(ex.message);
    } finally {
      btn.disabled = false;
    }
  });

  loadBranding();
  trySession();
})();
