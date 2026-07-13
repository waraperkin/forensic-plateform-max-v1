'use strict';

window.PortalSession = { user: null, settings: null, isAdmin: false, isAnalyst: false };

async function bootstrapPortalSession() {
  const r = await fetch('/api/auth/session', { credentials: 'include' });
  if (r.status === 401) {
    location.href = `/login.html?next=${encodeURIComponent(location.pathname + location.search)}`;
    return false;
  }
  const d = await r.json();
  if (!d.authenticated) {
    location.href = '/login.html';
    return false;
  }
  window.PortalSession.user = d.user;
  window.PortalSession.settings = d.settings || {};
  window.PortalSession.isAdmin = d.user.role === 'admin';
  window.PortalSession.isAnalyst = d.user.role === 'analyst';

  const title = d.settings?.portalTitle || 'CERT CYBERCORP';
  document.title = title.includes('CYBERCORP') ? title : `${title} — CYBERCORP`;
  const h1 = document.getElementById('portal-title') || document.querySelector('.cc-brand h1');
  if (h1) h1.textContent = title;
  const banner = document.querySelector('.cc-brand-sub');
  if (banner && d.settings?.bannerText) banner.textContent = d.settings.bannerText;

  const userBar = document.getElementById('fp-user-bar');
  const initials = (d.user.username || 'U').slice(0, 2).toUpperCase();
  if (userBar) {
    userBar.innerHTML = `
      <span class="fp-role-pill fp-role-${d.user.role}">${d.user.role}</span>
      ${d.user.mfaEnabled ? '<span class="fp-mfa-badge" title="MFA actif">MFA</span>' : ''}
      <button type="button" class="cc-avatar" id="cc-user-menu-btn" aria-label="Menu utilisateur">${initials}</button>
      <div class="cc-user-dropdown" id="cc-user-menu-drop" hidden>
        <p style="margin:0.25rem 0.5rem;font-size:0.8rem;color:var(--text-muted)">${d.user.username}</p>
        ${d.user.role === 'admin' ? '<button type="button" data-goto-settings>⚙️ Settings</button>' : ''}
        <button type="button" id="btn-logout">Déconnexion</button>
      </div>`;
    document.getElementById('btn-logout')?.addEventListener('click', async () => {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
      location.href = '/login.html';
    });
  }

  document.querySelectorAll(i18n.t('msg.data_admin_only')).forEach((el) => {
    el.style.display = window.PortalSession.isAdmin ? '' : 'none';
  });
  document.querySelectorAll('[data-analyst-hide-write]').forEach((el) => {
    if (window.PortalSession.isAnalyst) el.setAttribute('disabled', 'disabled');
  });

  return true;
}
