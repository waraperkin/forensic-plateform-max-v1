'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const DATA_DIR = process.env.PORTAL_AUTH_DATA_DIR || '/shared-uploads/.portal-auth';
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');

const DEFAULT_SETTINGS = {
  portalTitle: 'CERT CYBERCORP',
  bannerText: 'Cyber Defense Operations Center',
  quickLinks: [],
  showTiPanel: true,
  showIngestPanel: true,
};

function ensureDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o750 });
}

function readJson(file, fallback) {
  ensureDir();
  try {
    if (!fs.existsSync(file)) return JSON.parse(JSON.stringify(fallback));
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return JSON.parse(JSON.stringify(fallback));
  }
}

function writeJson(file, data) {
  ensureDir();
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function loadUsers() {
  return readJson(USERS_FILE, { users: [] });
}

function saveUsers(db) {
  writeJson(USERS_FILE, db);
}

function loadSettings() {
  return { ...DEFAULT_SETTINGS, ...readJson(SETTINGS_FILE, {}) };
}

function saveSettings(settings) {
  writeJson(SETTINGS_FILE, settings);
}

function sanitizeUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    portalScope: u.portalScope || 'cert',
    active: u.active !== false && !u.pendingActivation,
    pendingActivation: !!u.pendingActivation,
    mfaRequired: u.mfaRequired !== false,
    mfaEnabled: !!u.mfaEnabled,
    createdAt: u.createdAt,
    updatedAt: u.updatedAt,
  };
}

function findByUsername(username) {
  const db = loadUsers();
  return db.users.find((u) => u.username === username) || null;
}

function findById(id) {
  const db = loadUsers();
  return db.users.find((u) => u.id === id) || null;
}

function findByActivationToken(token) {
  if (!token) return null;
  const db = loadUsers();
  const u = db.users.find((x) => x.activationToken === token);
  if (!u) return null;
  if (u.activationExpiresAt && new Date(u.activationExpiresAt) < new Date()) return null;
  return u;
}

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  if (!hash) return false;
  return bcrypt.compare(password, hash);
}

async function ensureBootstrapAdmin() {
  const db = loadUsers();
  if (db.users.length > 0) return;
  const user = process.env.PORTAL_ADMIN_USER || 'admin';
  const pass = process.env.PORTAL_ADMIN_PASSWORD || 'F0r3ns1c_Portal_2024!';
  const now = new Date().toISOString();
  db.users.push({
    id: uuidv4(),
    username: user,
    passwordHash: await hashPassword(pass),
    role: 'admin',
    portalScope: 'cert',
    active: true,
    pendingActivation: false,
    mfaRequired: false,
    mfaEnabled: false,
    mfaSecret: null,
    activationToken: null,
    activationExpiresAt: null,
    createdAt: now,
    updatedAt: now,
  });
  saveUsers(db);
}

function listUsers() {
  return loadUsers().users.map(sanitizeUser);
}

function listUsersAdmin() {
  return loadUsers().users.map((u) => ({
    ...sanitizeUser(u),
    hasPassword: !!u.passwordHash,
  }));
}

async function createUser({ username, password, role, portalScope }) {
  const db = loadUsers();
  if (db.users.some((u) => u.username === username)) {
    throw new Error('Utilisateur déjà existant');
  }
  const now = new Date().toISOString();
  const u = {
    id: uuidv4(),
    username,
    passwordHash: await hashPassword(password),
    role: role === 'admin' ? 'admin' : 'analyst',
    portalScope: portalScope === 'it' ? 'it' : 'cert',
    active: true,
    pendingActivation: false,
    mfaRequired: false,
    mfaEnabled: false,
    mfaSecret: null,
    activationToken: null,
    activationExpiresAt: null,
    createdAt: now,
    updatedAt: now,
  };
  db.users.push(u);
  saveUsers(db);
  return sanitizeUser(u);
}

async function createUserInvite({ username, role, portalScope }) {
  const db = loadUsers();
  const name = String(username).trim();
  if (!name) throw new Error('Login requis');
  if (db.users.some((u) => u.username === name)) {
    throw new Error('Utilisateur déjà existant');
  }
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  const u = {
    id: uuidv4(),
    username: name,
    passwordHash: null,
    role: role === 'admin' ? 'admin' : 'analyst',
    portalScope: portalScope === 'it' ? 'it' : 'cert',
    active: false,
    pendingActivation: true,
    mfaRequired: true,
    mfaEnabled: false,
    mfaSecret: null,
    activationToken: token,
    activationExpiresAt: expires,
    createdAt: now,
    updatedAt: now,
  };
  db.users.push(u);
  saveUsers(db);
  return { user: sanitizeUser(u), activationToken: token };
}

async function setupActivationMfa(token) {
  const db = loadUsers();
  const u = db.users.find((x) => x.activationToken === token);
  if (!u || !u.pendingActivation) throw new Error('Invitation invalide ou expirée');
  if (u.activationExpiresAt && new Date(u.activationExpiresAt) < new Date()) {
    throw new Error('Invitation expirée');
  }
  const secret = require('otplib').authenticator.generateSecret();
  u.mfaSecret = secret;
  u.updatedAt = new Date().toISOString();
  saveUsers(db);
  return { user: u, secret };
}

async function completeActivation({ token, password, totp }) {
  const db = loadUsers();
  const u = db.users.find((x) => x.activationToken === token);
  if (!u || !u.pendingActivation) throw new Error('Invitation invalide');
  if (u.activationExpiresAt && new Date(u.activationExpiresAt) < new Date()) {
    throw new Error('Invitation expirée');
  }
  if (!password || String(password).length < 10) {
    throw new Error('Mot de passe min. 10 caractères');
  }
  if (!u.mfaSecret) throw new Error('Configurer MFA avant activation');
  const { authenticator } = require('otplib');
  const valid = authenticator.verify({ token: String(totp).replace(/\s/g, ''), secret: u.mfaSecret });
  if (!valid) throw new Error('Code MFA invalide');

  u.passwordHash = await hashPassword(password);
  u.pendingActivation = false;
  u.active = true;
  u.mfaEnabled = true;
  u.mfaRequired = true;
  u.activationToken = null;
  u.activationExpiresAt = null;
  u.updatedAt = new Date().toISOString();
  saveUsers(db);
  return sanitizeUser(u);
}

async function updateUser(id, patch) {
  const db = loadUsers();
  const u = db.users.find((x) => x.id === id);
  if (!u) throw new Error('Utilisateur introuvable');
  if (patch.role) u.role = patch.role === 'admin' ? 'admin' : 'analyst';
  if (patch.portalScope) u.portalScope = patch.portalScope === 'it' ? 'it' : 'cert';
  if (typeof patch.active === 'boolean') u.active = patch.active;
  if (patch.password) {
    u.passwordHash = await hashPassword(patch.password);
    u.pendingActivation = false;
  }
  if (typeof patch.mfaEnabled === 'boolean') {
    u.mfaEnabled = patch.mfaEnabled;
    if (!patch.mfaEnabled) u.mfaSecret = null;
  }
  if (patch.mfaSecret !== undefined) u.mfaSecret = patch.mfaSecret;
  u.updatedAt = new Date().toISOString();
  saveUsers(db);
  return sanitizeUser(u);
}

async function deleteUser(id) {
  const db = loadUsers();
  const u = db.users.find((x) => x.id === id);
  if (!u) throw new Error('Utilisateur introuvable');
  const isActiveAdmin = (x) => x.role === 'admin' && !x.pendingActivation && x.active !== false;
  if (isActiveAdmin(u)) {
    const admins = db.users.filter(isActiveAdmin);
    if (admins.length <= 1) throw new Error('Impossible de supprimer le dernier administrateur actif');
  }
  db.users = db.users.filter((x) => x.id !== id);
  saveUsers(db);
  return { id, username: u.username };
}

module.exports = {
  DATA_DIR,
  loadSettings,
  saveSettings,
  DEFAULT_SETTINGS,
  ensureBootstrapAdmin,
  findByUsername,
  findById,
  findByActivationToken,
  verifyPassword,
  listUsers,
  listUsersAdmin,
  createUser,
  createUserInvite,
  setupActivationMfa,
  completeActivation,
  updateUser,
  deleteUser,
  sanitizeUser,
};
