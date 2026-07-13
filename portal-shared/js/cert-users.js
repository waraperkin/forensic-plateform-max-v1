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

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function hideAllPanels() {
  ['user-create-panel', 'user-edit-panel', 'user-reset-panel', 'user-delete-panel'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.hidden = true;
  });
}

let usersCache = [];

async function loadPortalUsers() {
  const root = document.getElementById('portal-users-root');
  if (!root) return;
  if (!window.PortalSession?.isAdmin) {
    root.innerHTML = '<p class="fp-muted">Accès réservé aux administrateurs.</p>';
    return;
  }

  const { users } = await authFetch('/users');
  usersCache = users;

  root.innerHTML = `
    <div class="cc-users-toolbar">
      <p class="fp-muted">Comptes portail CERT / IT — MFA obligatoire pour les nouvelles invitations.</p>
      <button type="button" class="fp-btn fp-btn-primary" id="btn-show-create-user">Créer un utilisateur</button>
    </div>

    <div id="user-create-panel" class="fp-card cc-pro-panel" hidden>
      <h3 class="fp-section-sub">Nouvel utilisateur</h3>
      <div class="fp-grid-3">
        <label class="fp-label">Login <input class="fp-input" id="inv-user" autocomplete="off"></label>
        <label class="fp-label">Rôle
          <select class="fp-select" id="inv-role">
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <label class="fp-label">Périmètre
          <select class="fp-select" id="inv-scope">
            <option value="cert">CERT</option>
            <option value="it">IT</option>
          </select>
        </label>
      </div>
      <div class="fp-form-row" style="margin-top:0.75rem">
        <button type="button" class="fp-btn fp-btn-primary" id="inv-submit">Générer le lien d’activation</button>
        <button type="button" class="fp-btn fp-btn-ghost" id="inv-cancel">Annuler</button>
      </div>
      <div id="inv-result" class="cc-invite-result" hidden>
        <p class="fp-muted">Transmettez ce lien à l’utilisateur (valide 7 jours) :</p>
        <div class="cc-url-copy-row">
          <input class="fp-input" id="inv-url" readonly>
          <button type="button" class="fp-btn fp-btn-sm" id="inv-copy">Copier</button>
        </div>
      </div>
      <p id="inv-err" class="fp-alert fp-alert-err" hidden></p>
    </div>

    <div id="user-edit-panel" class="fp-card cc-pro-panel" hidden>
      <h3 class="fp-section-sub">Éditer l’utilisateur <span id="edit-user-name"></span></h3>
      <input type="hidden" id="edit-user-id">
      <div class="fp-grid-3">
        <label class="fp-label">Rôle
          <select class="fp-select" id="edit-role">
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <label class="fp-label">Périmètre
          <select class="fp-select" id="edit-scope">
            <option value="cert">CERT</option>
            <option value="it">IT</option>
          </select>
        </label>
        <label class="fp-label">Statut
          <select class="fp-select" id="edit-active">
            <option value="true">Actif</option>
            <option value="false">Inactif</option>
          </select>
        </label>
      </div>
      <div class="fp-form-row" style="margin-top:0.75rem">
        <button type="button" class="fp-btn fp-btn-primary" id="edit-submit">Enregistrer</button>
        <button type="button" class="fp-btn fp-btn-ghost" id="edit-cancel">Annuler</button>
      </div>
      <p id="edit-err" class="fp-alert fp-alert-err" hidden></p>
    </div>

    <div id="user-reset-panel" class="fp-card cc-pro-panel" hidden>
      <h3 class="fp-section-sub">Réinitialiser le mot de passe <span id="reset-user-name"></span></h3>
      <input type="hidden" id="reset-user-id">
      <label class="fp-label">Nouveau mot de passe (min. 10)
        <input class="fp-input" id="reset-pw-val" type="password">
      </label>
      <div class="fp-form-row" style="margin-top:0.5rem">
        <button type="button" class="fp-btn fp-btn-primary" id="reset-pw-submit">Enregistrer</button>
        <button type="button" class="fp-btn fp-btn-ghost" id="reset-pw-cancel">Annuler</button>
      </div>
    </div>

    <div id="user-delete-panel" class="fp-card cc-pro-panel cc-danger-panel" hidden>
      <h3 class="fp-section-sub">Supprimer l’utilisateur</h3>
      <input type="hidden" id="delete-user-id">
      <p>Confirmez la suppression définitive de <strong id="delete-user-name"></strong>. Cette action est irréversible.</p>
      <div class="fp-form-row">
        <button type="button" class="fp-btn fp-btn-danger" id="delete-confirm">Supprimer définitivement</button>
        <button type="button" class="fp-btn fp-btn-ghost" id="delete-cancel">Annuler</button>
      </div>
      <p id="delete-err" class="fp-alert fp-alert-err" hidden></p>
    </div>

    <div class="fp-table-wrap cc-pro-panel fp-section-spaced">
      <table class="fp-table">
        <thead><tr>
          <th>Login</th><th>Rôle</th><th>Périmètre</th><th>Actif</th><th>MFA</th><th>Créé</th><th>Actions</th>
        </tr></thead>
        <tbody id="portal-users-tbody"></tbody>
      </table>
    </div>`;

  renderUsersTable();
  bindCreate();
}

function renderUsersTable() {
  const tbody = document.getElementById('portal-users-tbody');
  if (!tbody) return;
  tbody.innerHTML = usersCache
    .map((u) => {
      const status = u.pendingActivation ? i18n.t('msg.en_attente_activation') : u.active ? 'Actif' : 'Inactif';
      return `<tr>
        <td><strong>${esc(u.username)}</strong></td>
        <td>${esc(u.role)}</td>
        <td>${esc((u.portalScope || 'cert').toUpperCase())}</td>
        <td>${esc(status)}</td>
        <td>${u.mfaEnabled ? 'Oui' : u.mfaRequired ? 'Requis' : 'Non'}</td>
        <td><code>${esc((u.createdAt || '').slice(0, 10))}</code></td>
        <td class="cc-user-actions">
          <button type="button" class="fp-btn fp-btn-sm" data-edit="${u.id}">Éditer</button>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-ghost" data-reset-pw="${u.id}" ${u.pendingActivation ? 'disabled' : ''}>Reset MDP</button>
          <button type="button" class="fp-btn fp-btn-sm fp-btn-danger-ghost" data-delete="${u.id}">Supprimer</button>
        </td>
      </tr>`;
    })
    .join('');

  tbody.querySelectorAll('[data-edit]').forEach((btn) => {
    btn.addEventListener('click', () => openEdit(btn.dataset.edit));
  });
  tbody.querySelectorAll('[data-reset-pw]').forEach((btn) => {
    btn.addEventListener('click', () => openReset(btn.dataset.resetPw));
  });
  tbody.querySelectorAll('[data-delete]').forEach((btn) => {
    btn.addEventListener('click', () => openDelete(btn.dataset.delete));
  });
}

function userById(id) {
  return usersCache.find((u) => u.id === id);
}

function bindCreate() {
  const panel = document.getElementById('user-create-panel');
  document.getElementById('btn-show-create-user')?.addEventListener('click', () => {
    hideAllPanels();
    panel.hidden = false;
    document.getElementById('inv-result').hidden = true;
    document.getElementById('inv-err').hidden = true;
  });
  document.getElementById('inv-cancel')?.addEventListener('click', () => { panel.hidden = true; });

  document.getElementById('inv-submit')?.addEventListener('click', async () => {
    const err = document.getElementById('inv-err');
    err.hidden = true;
    try {
      const d = await authFetch('/users/invite', {
        method: 'POST',
        body: JSON.stringify({
          username: document.getElementById('inv-user').value,
          role: document.getElementById('inv-role').value,
          portalScope: document.getElementById('inv-scope').value,
        }),
      });
      document.getElementById('inv-result').hidden = false;
      document.getElementById('inv-url').value = d.activationUrl;
      const { users } = await authFetch('/users');
      usersCache = users;
      renderUsersTable();
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
    }
  });

  document.getElementById('inv-copy')?.addEventListener('click', async () => {
    const url = document.getElementById('inv-url').value;
    try { await navigator.clipboard.writeText(url); } catch (_) { window.prompt(i18n.t('msg.copier'), url); }
  });
}

function openEdit(id) {
  const u = userById(id);
  if (!u) return;
  hideAllPanels();
  const panel = document.getElementById('user-edit-panel');
  document.getElementById('edit-user-id').value = id;
  document.getElementById('edit-user-name').textContent = u.username;
  document.getElementById('edit-role').value = u.role === 'admin' ? 'admin' : 'analyst';
  document.getElementById('edit-scope').value = u.portalScope === 'it' ? 'it' : 'cert';
  document.getElementById('edit-active').value = u.active && !u.pendingActivation ? 'true' : 'false';
  document.getElementById('edit-err').hidden = true;
  panel.hidden = false;

  document.getElementById('edit-cancel').onclick = () => { panel.hidden = true; };
  document.getElementById('edit-submit').onclick = async () => {
    const err = document.getElementById('edit-err');
    err.hidden = true;
    try {
      await authFetch(`/users/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          role: document.getElementById('edit-role').value,
          portalScope: document.getElementById('edit-scope').value,
          active: document.getElementById('edit-active').value === 'true',
        }),
      });
      panel.hidden = true;
      loadPortalUsers();
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
    }
  };
}

function openReset(id) {
  const u = userById(id);
  if (!u) return;
  hideAllPanels();
  const panel = document.getElementById('user-reset-panel');
  document.getElementById('reset-user-id').value = id;
  document.getElementById('reset-user-name').textContent = u.username;
  document.getElementById('reset-pw-val').value = '';
  panel.hidden = false;

  document.getElementById('reset-pw-cancel').onclick = () => { panel.hidden = true; };
  document.getElementById('reset-pw-submit').onclick = async () => {
    const pw = document.getElementById('reset-pw-val').value;
    if (pw.length < 10) { alert(i18n.t('msg.mot_de_passe_minimum_10_caracteres')); return; }
    await authFetch(`/users/${id}`, { method: 'PATCH', body: JSON.stringify({ password: pw }) });
    panel.hidden = true;
    loadPortalUsers();
  };
}

function openDelete(id) {
  const u = userById(id);
  if (!u) return;
  hideAllPanels();
  const panel = document.getElementById('user-delete-panel');
  document.getElementById('delete-user-id').value = id;
  document.getElementById('delete-user-name').textContent = u.username;
  document.getElementById('delete-err').hidden = true;
  panel.hidden = false;

  document.getElementById('delete-cancel').onclick = () => { panel.hidden = true; };
  document.getElementById('delete-confirm').onclick = async () => {
    const err = document.getElementById('delete-err');
    err.hidden = true;
    try {
      await authFetch(`/users/${id}`, { method: 'DELETE' });
      panel.hidden = true;
      loadPortalUsers();
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
    }
  };
}

window.PortalUsers = { loadPortalUsers };
