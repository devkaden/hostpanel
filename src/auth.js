'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { db, audit, getSetting } = require('./db');

const ROUNDS = 12;

/** Length-safe constant-time string comparison. */
function timingSafeEquals(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) {
    // Still do a comparison so the failure path costs roughly the same.
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

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

// A real hash at the same cost, used to equalise timing when no such user
// exists. Always returns false.
const DUMMY_HASH = bcrypt.hashSync('hostpanel-timing-equaliser', ROUNDS);

function dummyVerify(plain) {
  try {
    bcrypt.compareSync(String(plain || ''), DUMMY_HASH);
  } catch (_) {
    /* ignore */
  }
  return false;
}

/**
 * Rejection sampling rather than `byte % length`, which biases toward the
 * start of the alphabet when 256 is not a multiple of the alphabet size.
 */
function randomPassword(len = 18) {
  const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const limit = 256 - (256 % alphabet.length);
  let out = '';
  while (out.length < len) {
    for (const byte of crypto.randomBytes(len * 2)) {
      if (byte >= limit) continue;
      out += alphabet[byte % alphabet.length];
      if (out.length === len) break;
    }
  }
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
 * Brute-force throttling, persisted
 * ------------------------------------------------------------------ *
 * Kept in the database rather than in memory. In-memory counters are erased by
 * a restart, and this panel restarts itself whenever it is updated - so an
 * attacker who can trigger or simply wait for a restart gets a fresh allowance.
 * On a panel reachable from the internet that is the difference between a real
 * lockout and a speed bump.
 */
const MAX_ATTEMPTS = 8; // per username+IP
const MAX_PER_ACCOUNT = 20; // per username across every IP
const MAX_PER_IP = 30; // per IP across every username
const LOCKOUT_MS = 10 * 60 * 1000;

const countSince = db.prepare(
  'SELECT COUNT(*) AS n FROM login_attempts WHERE key = ? AND created_at > ?'
);
const insertAttempt = db.prepare(
  'INSERT INTO login_attempts (key, ip, created_at) VALUES (?,?,?)'
);
const clearKey = db.prepare('DELETE FROM login_attempts WHERE key = ?');
const reapAttempts = db.prepare('DELETE FROM login_attempts WHERE created_at < ?');

const attemptKey = (username, ip) => `u:${String(username || '').toLowerCase()}|${ip}`;
const accountKey = (username) => `a:${String(username || '').toLowerCase()}`;
const ipKey = (ip) => `i:${ip}`;

function countFor(key) {
  try {
    return countSince.get(key, Date.now() - LOCKOUT_MS).n;
  } catch (_) {
    return 0; // never let a database hiccup lock everybody out
  }
}

/**
 * Three buckets: username+IP, username across all IPs, and IP across all
 * usernames. The third is what catches someone working through a list of
 * likely usernames from one address, which the first two miss entirely.
 */
function isLockedOut(username, ip) {
  return (
    countFor(attemptKey(username, ip)) >= MAX_ATTEMPTS ||
    countFor(accountKey(username)) >= MAX_PER_ACCOUNT ||
    countFor(ipKey(ip)) >= MAX_PER_IP
  );
}

function recordFailure(username, ip) {
  const now = Date.now();
  try {
    insertAttempt.run(attemptKey(username, ip), String(ip || ''), now);
    insertAttempt.run(accountKey(username), String(ip || ''), now);
    insertAttempt.run(ipKey(ip), String(ip || ''), now);
  } catch (_) {
    /* throttling is best effort; never block a login path on it */
  }
}

function clearFailures(username, ip) {
  try {
    clearKey.run(attemptKey(username, ip));
    clearKey.run(accountKey(username));
  } catch (_) {
    /* ignore */
  }
}

// Old rows are meaningless once the window has passed.
const sweeper = setInterval(() => {
  try { reapAttempts.run(Date.now() - LOCKOUT_MS); } catch (_) { /* ignore */ }
}, LOCKOUT_MS);
if (sweeper.unref) sweeper.unref();

/* ------------------------------------------------------------------ *
 * Two-factor policy
 * ------------------------------------------------------------------ */
/** Whether this user must have two-factor set up before using the panel. */
function twoFactorRequiredFor(user) {
  const policy = getSetting('require_2fa') || 'off';
  if (policy === 'all') return true;
  if (policy === 'admins') return user.role === 'admin';
  return false;
}

/**
 * Invalidates every session belonging to a user.
 *
 * Called whenever a credential changes. A password changed because someone
 * suspects it leaked is worthless if the session created with the old one is
 * still signed in somewhere.
 */
function bumpSessionEpoch(userId) {
  db.prepare('UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?').run(userId);
  return db.prepare('SELECT session_epoch FROM users WHERE id = ?').get(userId).session_epoch;
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
    // A credential change since this session started invalidates it.
    if ((req.session.epoch || 0) !== fresh.session_epoch) {
      req.session.destroy(() => {});
      if (wantsJson(req)) return res.status(401).json({ error: 'Session no longer valid' });
      return res.redirect('/login?expired=1');
    }
    req.user = fresh;
    res.locals.user = publicUser(fresh);
    // A saved personal preference overrides the panel-wide default, so the
    // choice follows the account rather than the browser.
    if (fresh.pref_theme) res.locals.themeSetting = fresh.pref_theme;
    if (fresh.pref_ui_mode) res.locals.uiModeSetting = fresh.pref_ui_mode;
    // Force a password change before anything else is reachable.
    if (fresh.must_change_pw && !req.path.startsWith('/account/password') && !wantsJson(req)) {
      return res.redirect('/account/password');
    }
    // Then two-factor, if the policy demands it and this account has none.
    if (
      !fresh.totp_enabled &&
      twoFactorRequiredFor(fresh) &&
      !fresh.must_change_pw &&
      !req.path.startsWith('/account/2fa') &&
      !req.path.startsWith('/logout') &&
      !wantsJson(req)
    ) {
      return res.redirect('/account/2fa?required=1');
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

  const supplied = String(
    req.get('x-csrf-token') || (req.body && req.body._csrf) || req.query._csrf || ''
  );
  if (!req.session || !req.session.csrfToken || !timingSafeEquals(supplied, req.session.csrfToken)) {
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
  // Recorded so a later credential change can invalidate this session.
  req.session.epoch = findUser(user.id).session_epoch;
  audit(req, 'auth.login', user.username);
}

/** The minimum password length in force, which rises when 2FA is required. */
function minPasswordLength() {
  const configured = parseInt(getSetting('min_password_length') || '10', 10);
  return Number.isFinite(configured) && configured >= 8 ? configured : 10;
}

module.exports = {
  hashPassword,
  verifyPassword,
  dummyVerify,
  timingSafeEquals,
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
  twoFactorRequiredFor,
  bumpSessionEpoch,
  minPasswordLength,
};
