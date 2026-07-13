'use strict';

(function () {
  const params = new URLSearchParams(location.search);
  const token = params.get('token') || '';
  const errEl = document.getElementById('act-err');
  const form = document.getElementById('act-form');
  document.getElementById('act-token').value = token;

  function showErr(msg) {
    errEl.textContent = msg;
    errEl.hidden = !msg;
  }

  async function loadInfo() {
    if (!token) {
      showErr(i18n.t('msg.lien_dactivation_invalide_token_manquant'));
      form.hidden = true;
      return;
    }
    const r = await fetch(`/api/auth/activate-info?token=${encodeURIComponent(token)}`);
    const d = await r.json();
    if (!d.valid) {
      showErr(d.error || 'Invitation invalide');
      form.hidden = true;
      return;
    }
    document.getElementById('act-user').textContent = `${d.username} — rôle ${d.role} — périmètre ${d.portalScope.toUpperCase()}`;
    if (d.mfaPrepared) {
      document.getElementById('act-mfa-setup').textContent = i18n.t('msg.regenerer_le_qr_code_mfa');
    }
  }

  document.getElementById('act-mfa-setup')?.addEventListener('click', async () => {
    showErr('');
    try {
      const r = await fetch('/api/auth/activate/mfa-setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || r.statusText);
      document.getElementById('act-qr').innerHTML = `<img src="${d.qrDataUrl}" alt="QR MFA" width="200">`;
    } catch (e) {
      showErr(e.message);
    }
  });

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    showErr('');
    const p1 = document.getElementById('act-pass').value;
    const p2 = document.getElementById('act-pass2').value;
    if (p1 !== p2) {
      showErr('Les mots de passe ne correspondent pas.');
      return;
    }
    try {
      const r = await fetch('/api/auth/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          password: p1,
          totp: document.getElementById('act-totp').value,
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || r.statusText);
      location.href = '/login.html?activated=1';
    } catch (ex) {
      showErr(ex.message);
    }
  });

  loadInfo().catch((e) => showErr(e.message));
})();
