'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { db, audit } = require('./db');

const ROUNDS = 12;

function hashPassword(plain) {
  return bcrypt.hashSync(plain, ROUNDS);
}

function verifyPassword(plain, hash) {
  try {
    return bcrypt.compareSync(plain, hash);
  } catch (_) {
    return false;
  }
}

function randomPassword(len = 18) {
  const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i += 1) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

function findUserByUsername(username) {
  return db
    .prepare('SELECT * FROM users WHERE lower(username) = lower(?)')
    .get(String(username || '').trim());
}

function findUser(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role,
    mustChangePw: !!u.must_change_pw,
  };
}

/** Creates the bootstrap admin on very first boot and returns its password. */
function ensureBootstrapAdmin() {
  const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  if (count > 0) return null;
  const password = process.env.ADMIN_PASSWORD || randomPassword();
  const username = process.env.ADMIN_USERNAME || 'admin';
  db.prepare(
    'INSERT INTO users (username, email, password_hash, role, must_change_pw) VALUES (?,?,?,?,1)'
  ).run(username, process.env.ADMIN_EMAIL || '', hashPassword(password), 'admin');
  return { username, password };
}

/* ------------------------------------------------------------------ *
 * Brute-force throttling (in-memory, per username+ip)
 * ------------------------------------------------------------------ */
const attempts = new Map();
const MAX_ATTEMPTS = 8;
const LOCKOUT_MS = 10 * 60 * 1000;

function attemptKey(username, ip) {
  return `${String(username || '').toLowerCase()}|${ip}`;
}

function isLockedOut(username, ip) {
  const rec = attempts.get(attemptKey(username, ip));
  if (!rec) return false;
  if (Date.now() - rec.first > LOCKOUT_MS) {
    attempts.delete(attemptKey(username, ip));
    return false;
  }
  return rec.count >= MAX_ATTEMPTS;
}

function recordFailure(username, ip) {
  const key = attemptKey(username, ip);
  const rec = attempts.get(key);
  if (!rec || Date.now() - rec.first > LOCKOUT_MS) {
    attempts.set(key, { count: 1, first: Date.now() });
  } else {
    rec.count += 1;
  }
}

function clearFailures(username, ip) {
  attempts.delete(attemptKey(username, ip));
}

/* ------------------------------------------------------------------ *
 * Middleware
 * ------------------------------------------------------------------ */
function wantsJson(req) {
  return (
    req.xhr ||
    req.path.startsWith('/api/') ||
    (req.get('accept') || '').includes('application/json')
  );
}

function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    const fresh = findUser(req.session.user.id);
    if (!fresh || !fresh.active) {
      req.session.destroy(() => {});
      if (wantsJson(req)) return res.status(401).json({ error: 'Session no longer valid' });
      return res.redirect('/login');
    }
    req.user = fresh;
    res.locals.user = publicUser(fresh);
    // Force a password change before anything else is reachable.
    if (fresh.must_change_pw && !req.path.startsWith('/account/password') && !wantsJson(req)) {
      return res.redirect('/account/password');
    }
    return next();
  }
  if (wantsJson(req)) return res.status(401).json({ error: 'Not authenticated' });
  const target = encodeURIComponent(req.originalUrl || '/');
  return res.redirect(`/login?next=${target}`);
}

function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  if (wantsJson(req)) return res.status(403).json({ error: 'Administrator access required' });
  return res.status(403).render('error', {
    title: 'Forbidden',
    message: 'This page is restricted to administrators.',
  });
}

/* ------------------------------------------------------------------ *
 * CSRF (double-submit token stored in the session)
 * ------------------------------------------------------------------ */
function csrf(req, res, next) {
  if (req.session && !req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  }
  res.locals.csrfToken = req.session ? req.session.csrfToken : '';

  const safe = ['GET', 'HEAD', 'OPTIONS'];
  if (safe.includes(req.method)) return next();

  const supplied =
    req.get('x-csrf-token') || (req.body && req.body._csrf) || req.query._csrf || '';
  if (!req.session || !req.session.csrfToken || supplied !== req.session.csrfToken) {
    if (wantsJson(req)) return res.status(403).json({ error: 'Invalid CSRF token' });
    return res.status(403).render('error', {
      title: 'Request rejected',
      message: 'Invalid or expired CSRF token. Reload the page and try again.',
    });
  }
  return next();
}

function login(req, user) {
  db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id);
  req.session.user = publicUser(user);
  audit(req, 'auth.login', user.username);
}

module.exports = {
  hashPassword,
  verifyPassword,
  randomPassword,
  findUser,
  findUserByUsername,
  publicUser,
  ensureBootstrapAdmin,
  isLockedOut,
  recordFailure,
  clearFailures,
  requireAuth,
  requireAdmin,
  csrf,
  login,
  wantsJson,
};
