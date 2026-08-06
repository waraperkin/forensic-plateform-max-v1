'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const store = require('./auth-store');
const session = require('./auth-session');
const { appendAuditFile } = require('./audit-log');

authenticator.options = { window: 1 };

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentification requise' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Droits administrateur requis' });
  next();
}

function activationBaseUrl(req) {
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
  let host = (req.headers.host || req.headers['x-forwarded-host'] || 'localhost').split(',')[0].trim();
  if (/^(u_|cert-portal|it-portal)/i.test(host)) {
    host = process.env.PORTAL_PUBLIC_HOST || 'localhost';
  }
  return `${proto}://${host}`.replace(/\/$/, '');
}

/** Notifie SEP par e-mail (création / invitation compte portail). */
async function notifyUserCreated(username, kind) {
  const base = (process.env.SEKOIA_CONTROLPLANE_URL || 'http://sekoia-controlplane:8901').replace(/\/$/, '');
  const token = (process.env.INTERNAL_API_TOKEN || '').trim();
  if (!token) return;
  try {
    await fetch(`${base}/control/sekoia/notify/event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Token': token,
      },
      body: JSON.stringify({
        event: 'user_created',
        subject: `[SEP] Compte utilisateur ${kind || 'créé'} — ${username}`,
        body: `Un compte utilisateur a été ${kind || 'créé'} sur le portail.\n`
          + `Login : ${username}\n`
          + `Horodatage : ${new Date().toISOString()}\n`,
        fingerprint: `user:${kind || 'create'}:${username}`,
      }),
    });
  } catch (_) { /* non bloquant */ }
}

function createAuthRouter() {
  const router = express.Router();
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Trop de tentatives de connexion' },
  });

  router.get('/public-settings', (req, res) => {
    const s = store.loadSettings();
    res.json({ portalTitle: s.portalTitle, bannerText: s.bannerText });
  });

  router.get('/activate-info', (req, res) => {
    const token = String(req.query.token || '').trim();
    const u = store.findByActivationToken(token);
    if (!u) return res.status(400).json({ valid: false, error: 'Invitation invalide ou expirée' });
    res.json({
      valid: true,
      username: u.username,
      role: u.role,
      portalScope: u.portalScope || 'cert',
      mfaPrepared: !!u.mfaSecret,
    });
  });

  router.post('/activate/mfa-setup', async (req, res) => {
    try {
      const { token } = req.body || {};
      const { user, secret } = await store.setupActivationMfa(String(token || '').trim());
      const otpauth = authenticator.keyuri(user.username, 'CERT CYBERCORP', secret);
      const qrDataUrl = await QRCode.toDataURL(otpauth);
      res.json({ qrDataUrl, otpauth });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  router.post('/activate', async (req, res) => {
    try {
      const { token, password, totp } = req.body || {};
      const user = await store.completeActivation({
        token: String(token || '').trim(),
        password,
        totp,
      });
      appendAuditFile({
        type: 'user',
        action: 'activate',
        user: user.username,
        role: user.role,
        service: 'cert-portal',
        message: 'Compte activé avec MFA',
      });
      res.json({ ok: true, user });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  router.get('/session', (req, res) => {
    if (!req.user) return res.json({ authenticated: false });
    res.json({
      authenticated: true,
      user: store.sanitizeUser(store.findById(req.user.id)),
      settings: store.loadSettings(),
    });
  });

  router.post('/login', loginLimiter, async (req, res) => {
    try {
      const { username, password, totp } = req.body || {};
      if (!username || !password) {
        return res.status(400).json({ error: 'Identifiants requis' });
      }
      const user = store.findByUsername(String(username).trim());
      if (!user) return res.status(401).json({ error: 'Identifiants invalides' });
      if (user.pendingActivation) {
        return res.status(403).json({
          error: 'Compte en attente d’activation. Utilisez le lien fourni par l’administrateur.',
          pendingActivation: true,
        });
      }
      if (!user.active) {
        return res.status(401).json({ error: 'Compte désactivé' });
      }
      const ok = await store.verifyPassword(password, user.passwordHash);
      if (!ok) return res.status(401).json({ error: 'Identifiants invalides' });

      if (user.mfaRequired && !user.mfaEnabled) {
        return res.status(403).json({
          error: 'MFA obligatoire — finalisez l’activation du compte.',
          mfaSetupRequired: true,
        });
      }

      if (user.mfaEnabled && user.mfaSecret) {
        if (!totp) {
          return res.json({ mfaRequired: true, username: user.username });
        }
        const valid = authenticator.verify({ token: String(totp).replace(/\s/g, ''), secret: user.mfaSecret });
        if (!valid) return res.status(401).json({ error: 'Code MFA invalide' });
      }

      const token = session.createSession(user);
      session.setSessionCookie(res, req, token);
      appendAuditFile({
        type: 'user',
        action: 'login',
        user: user.username,
        role: user.role,
        ip: req.ip || req.headers['x-forwarded-for'],
        service: 'cert-portal',
        message: 'Connexion réussie',
        context: { mfa: !!user.mfaEnabled },
      });
      res.json({
        ok: true,
        user: store.sanitizeUser(user),
        settings: store.loadSettings(),
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  router.post('/logout', (req, res) => {
    if (req.user) {
      appendAuditFile({
        type: 'user',
        action: 'logout',
        user: req.user.username,
        role: req.user.role,
        ip: req.ip || req.headers['x-forwarded-for'],
        service: 'cert-portal',
        message: 'Déconnexion',
      });
    }
    session.clearSessionCookie(res, req);
    res.json({ ok: true });
  });

  router.post('/mfa/setup', requireAuth, async (req, res) => {
    try {
      const user = store.findById(req.user.id);
      if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
      const secret = authenticator.generateSecret();
      const otpauth = authenticator.keyuri(user.username, 'CERT CYBERCORP', secret);
      const qrDataUrl = await QRCode.toDataURL(otpauth);
      await store.updateUser(user.id, { mfaSecret: secret, mfaEnabled: false });
      res.json({ secret, otpauth, qrDataUrl });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  router.post('/mfa/activate', requireAuth, async (req, res) => {
    try {
      const { totp } = req.body || {};
      const user = store.findById(req.user.id);
      if (!user?.mfaSecret) return res.status(400).json({ error: 'Configurer MFA dabord' });
      const valid = authenticator.verify({ token: String(totp).replace(/\s/g, ''), secret: user.mfaSecret });
      if (!valid) return res.status(400).json({ error: 'Code invalide' });
      await store.updateUser(user.id, { mfaEnabled: true });
      res.json({ ok: true, mfaEnabled: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  router.post('/mfa/disable', requireAuth, async (req, res) => {
    try {
      const user = store.findById(req.user.id);
      if (user?.mfaRequired) {
        return res.status(403).json({ error: 'MFA obligatoire pour ce compte' });
      }
      if (req.user.role !== 'admin') {
        const { password, totp } = req.body || {};
        if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
        if (password && !(await store.verifyPassword(password, user.passwordHash))) {
          return res.status(401).json({ error: 'Mot de passe incorrect' });
        }
        if (user.mfaEnabled && user.mfaSecret) {
          const valid = authenticator.verify({ token: String(totp || '').replace(/\s/g, ''), secret: user.mfaSecret });
          if (!valid) return res.status(401).json({ error: 'Code MFA requis' });
        }
      }
      await store.updateUser(req.user.id, { mfaEnabled: false, mfaSecret: null });
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  router.get('/users', requireAdmin, (req, res) => {
    res.json({ users: store.listUsersAdmin() });
  });

  router.post('/users', requireAdmin, async (req, res) => {
    try {
      const { username, password, role, portalScope } = req.body || {};
      if (!username || !password) return res.status(400).json({ error: 'username et password requis' });
      const u = await store.createUser({
        username: String(username).trim(),
        password,
        role,
        portalScope,
      });
      notifyUserCreated(u.username, 'créé').catch(() => {});
      res.status(201).json({ user: u });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  router.post('/users/invite', requireAdmin, async (req, res) => {
    try {
      const { username, role, portalScope } = req.body || {};
      if (!username) return res.status(400).json({ error: 'login requis' });
      const { user, activationToken } = await store.createUserInvite({
        username: String(username).trim(),
        role,
        portalScope,
      });
      const activationUrl = `${activationBaseUrl(req)}/activate.html?token=${activationToken}`;
      appendAuditFile({
        type: 'user',
        action: 'invite',
        user: req.user.username,
        service: 'cert-portal',
        message: `Invitation ${user.username}`,
        context: { invited: user.username, portalScope: user.portalScope },
      });
      notifyUserCreated(user.username, 'invité').catch(() => {});
      res.status(201).json({ user, activationUrl, activationToken });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  router.patch('/users/:id', requireAdmin, async (req, res) => {
    try {
      const u = await store.updateUser(req.params.id, req.body || {});
      appendAuditFile({
        type: 'user',
        action: 'update',
        user: req.user.username,
        service: 'cert-portal',
        message: `Mise à jour ${u.username}`,
        context: { target: u.username },
      });
      res.json({ user: u });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  router.delete('/users/:id', requireAdmin, async (req, res) => {
    try {
      if (req.params.id === req.user.id) {
        return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
      }
      const removed = await store.deleteUser(req.params.id);
      appendAuditFile({
        type: 'user',
        action: 'delete',
        user: req.user.username,
        service: 'cert-portal',
        message: `Suppression ${removed.username}`,
        context: { target: removed.username },
      });
      res.json({ ok: true, removed });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  router.get('/settings', requireAuth, (req, res) => {
    res.json(store.loadSettings());
  });

  router.put('/settings', requireAdmin, (req, res) => {
    try {
      const cur = store.loadSettings();
      const next = { ...cur, ...(req.body || {}) };
      store.saveSettings(next);
      res.json(next);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = { createAuthRouter, requireAuth, requireAdmin };
