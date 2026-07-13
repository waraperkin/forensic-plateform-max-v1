'use strict';

const crypto = require('crypto');

const SECRET = process.env.PORTAL_SESSION_SECRET || 'fp-portal-session-change-me-in-prod';
const MAX_AGE_MS = parseInt(process.env.PORTAL_SESSION_MAX_AGE_MS || String(8 * 3600 * 1000), 10);
const COOKIE_NAME = 'fp_portal_session';

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verify(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function createSession(user) {
  return sign({
    sub: user.id,
    username: user.username,
    role: user.role,
    exp: Date.now() + MAX_AGE_MS,
  });
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i < 1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

function cookieOptions(req) {
  const secure = process.env.PORTAL_COOKIE_SECURE !== '0'
    && (req.secure || req.get('x-forwarded-proto') === 'https');
  return {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    path: '/',
    maxAge: Math.floor(MAX_AGE_MS / 1000),
  };
}

function setSessionCookie(res, req, token) {
  const opts = cookieOptions(req);
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    'HttpOnly',
    `Path=${opts.path}`,
    `Max-Age=${opts.maxAge}`,
    `SameSite=${opts.sameSite}`,
  ];
  if (opts.secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res, req) {
  const opts = cookieOptions(req);
  const parts = [
    `${COOKIE_NAME}=`,
    'HttpOnly',
    `Path=${opts.path}`,
    'Max-Age=0',
    `SameSite=${opts.sameSite}`,
  ];
  if (opts.secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function sessionMiddleware(findById) {
  return (req, res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    const payload = verify(cookies[COOKIE_NAME]);
    if (payload) {
      const user = findById(payload.sub);
      if (user && user.active !== false) {
        req.user = {
          id: user.id,
          username: user.username,
          role: user.role,
        };
      }
    }
    next();
  };
}

module.exports = {
  COOKIE_NAME,
  createSession,
  verify,
  setSessionCookie,
  clearSessionCookie,
  sessionMiddleware,
};
