'use strict';

const express = require('express');
const { db, audit, getSetting } = require('../db');
const auth = require('../auth');
const totp = require('../totp');

/*
 * The QR code is a convenience, not a requirement.
 *
 * Every authenticator app can take the secret typed in by hand, so if this
 * package is missing - an offline install, a failed npm - enrolment still
 * works and the page shows the key instead. Making two-factor setup depend on
 * an optional rendering library would be the wrong trade entirely.
 */
let qrcode = null;
try {
  // eslint-disable-next-line global-require
  qrcode = require('qrcode');
} catch (_) {
  qrcode = null;
}

async function qrDataUrl(text) {
  if (!qrcode) return null;
  try {
    return await qrcode.toDataURL(text, { margin: 1, width: 240, errorCorrectionLevel: 'M' });
  } catch (_) {
    return null;
  }
}

const router = express.Router();

/**
 * Only same-origin, absolute paths may be redirected to after login.
 * "//evil.com" and "/\evil.com" also start with "/" but browsers treat them as
 * protocol-relative URLs, so a naive startsWith('/') check is an open redirect.
 */
function safeNext(value) {
  if (typeof value !== 'string' || !value.startsWith('/')) return '/';
  if (value.startsWith('//') || value.startsWith('/\\')) return '/';
  if (/[\r\n]/.test(value)) return '/';
  return value;
}

router.get('/login', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  return res.render('login', {
    title: 'Sign in',
    error: null,
    next: safeNext(req.query.next),
    username: '',
  });
});

router.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const next = safeNext(req.body.next);

  const fail = (message) =>
    res.status(401).render('login', { title: 'Sign in', error: message, next, username });

  if (!username || !password) return fail('Enter a username and password.');

  if (auth.isLockedOut(username, req.ip)) {
    audit(req, 'auth.lockout', username);
    return fail('Too many failed attempts. Try again in a few minutes.');
  }

  const user = auth.findUserByUsername(username);
  // Hash against a dummy when the account does not exist, so a missing user
  // and a wrong password take the same amount of time to reject.
  const passwordOk = user
    ? auth.verifyPassword(password, user.password_hash)
    : auth.dummyVerify(password);

  if (!user || !user.active || !passwordOk) {
    auth.recordFailure(username, req.ip);
    audit(req, 'auth.fail', username);
    return fail('Incorrect username or password.');
  }

  auth.clearFailures(username, req.ip);

  /*
   * The password is right, but the session is not created yet.
   *
   * With two-factor on, the user is only half-authenticated here. Nothing is
   * written to req.session.user until the code checks out - a session that
   * exists "but is not signed in yet" is exactly the kind of half-state that
   * turns into an authentication bypass.
   */
  if (user.totp_enabled) {
    return req.session.regenerate((err) => {
      if (err) return fail('Could not start a session. Try again.');
      req.session.pending2fa = { id: user.id, at: Date.now(), next };
      return req.session.save(() => res.redirect('/login/2fa'));
    });
  }

  return req.session.regenerate((err) => {
    if (err) return fail('Could not start a session. Try again.');
    auth.login(req, user);
    return req.session.save(() => res.redirect(user.must_change_pw ? '/account/password' : next));
  });
});

/* ------------------------------------------------------------------ *
 * Second factor at sign-in
 * ------------------------------------------------------------------ */
// Five minutes to type six digits is generous; leaving it open indefinitely
// would let a half-finished sign-in sit around on a shared computer.
const PENDING_MS = 5 * 60 * 1000;

function pendingUser(req) {
  const pending = req.session && req.session.pending2fa;
  if (!pending) return null;
  if (Date.now() - pending.at > PENDING_MS) {
    delete req.session.pending2fa;
    return null;
  }
  const user = auth.findUser(pending.id);
  return user && user.active && user.totp_enabled ? user : null;
}

router.get('/login/2fa', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  if (!pendingUser(req)) return res.redirect('/login');
  return res.render('login-2fa', { title: 'Two-factor code', error: null });
});

router.post('/login/2fa', (req, res) => {
  const user = pendingUser(req);
  if (!user) return res.redirect('/login');

  const code = String(req.body.code || '').trim();
  const fail = (message) =>
    res.status(401).render('login-2fa', { title: 'Two-factor code', error: message });

  // The same throttle as the password step. Without it the second factor is a
  // six-digit number with unlimited guesses, which is no factor at all.
  if (auth.isLockedOut(user.username, req.ip)) {
    audit(req, 'auth.2fa_lockout', user.username);
    return fail('Too many attempts. Try again in a few minutes.');
  }

  let ok = totp.verify(user.totp_secret, code);
  let usedRecovery = false;

  if (!ok) {
    // Recovery codes are single use: a used one is removed, so a code read off
    // a printout someone else has seen is worth nothing twice.
    let codes = [];
    try { codes = JSON.parse(user.recovery_codes || '[]'); } catch (_) { codes = []; }
    const hash = totp.hashRecoveryCode(code);
    const index = codes.indexOf(hash);
    if (index !== -1) {
      codes.splice(index, 1);
      db.prepare('UPDATE users SET recovery_codes = ? WHERE id = ?')
        .run(JSON.stringify(codes), user.id);
      ok = true;
      usedRecovery = true;
    }
  }

  if (!ok) {
    auth.recordFailure(user.username, req.ip);
    audit(req, 'auth.2fa_fail', user.username);
    return fail('That code is not right. Codes change every 30 seconds.');
  }

  auth.clearFailures(user.username, req.ip);
  const next = req.session.pending2fa.next || '/';
  delete req.session.pending2fa;

  return req.session.regenerate((err) => {
    if (err) return fail('Could not start a session. Try again.');
    auth.login(req, user);
    if (usedRecovery) audit(req, 'auth.2fa_recovery_used', user.username);
    return req.session.save(() =>
      res.redirect(user.must_change_pw ? '/account/password' : next)
    );
  });
});

router.post('/logout', (req, res) => {
  audit(req, 'auth.logout', req.session.user ? req.session.user.username : '');
  req.session.destroy(() => res.redirect('/login'));
});

// GET logout is handy for a plain link, but only with the CSRF token attached.
router.get('/logout', (req, res) => {
  if (!auth.timingSafeEquals(String(req.query._csrf || ''), req.session.csrfToken || '')) {
    return res.redirect('/');
  }
  req.session.destroy(() => res.redirect('/login'));
});

/* ------------------------------------------------------------------ *
 * Password change (also used for the forced first-login change)
 * ------------------------------------------------------------------ */
router.get('/account/password', auth.requireAuth, (req, res) => {
  res.render('password', {
    title: 'Change password',
    error: null,
    notice: req.user.must_change_pw
      ? 'Choose a new password before continuing.'
      : null,
    forced: Boolean(req.user.must_change_pw),
  });
});

router.post('/account/password', auth.requireAuth, (req, res) => {
  const current = String(req.body.current_password || '');
  const next = String(req.body.new_password || '');
  const confirm = String(req.body.confirm_password || '');

  const fail = (message) =>
    res.status(400).render('password', {
      title: 'Change password',
      error: message,
      notice: null,
      forced: Boolean(req.user.must_change_pw),
    });

  if (!auth.verifyPassword(current, req.user.password_hash)) {
    return fail('Your current password is not correct.');
  }
  const minLength = auth.minPasswordLength();
  if (next.length < minLength) {
    return fail(`The new password must be at least ${minLength} characters.`);
  }
  if (next !== confirm) return fail('The two new passwords do not match.');
  if (next === current) return fail('The new password must be different from the current one.');

  db.prepare('UPDATE users SET password_hash = ?, must_change_pw = 0 WHERE id = ?').run(
    auth.hashPassword(next),
    req.user.id
  );
  // Every other session signed in with the old password is now invalid. This
  // session keeps working because it records the new epoch immediately.
  req.session.epoch = auth.bumpSessionEpoch(req.user.id);
  req.session.user.mustChangePw = false;
  audit(req, 'account.password_changed', req.user.username);
  return res.redirect('/?changed=1');
});

/* ------------------------------------------------------------------ *
 * Two-factor enrolment
 * ------------------------------------------------------------------ */
router.get('/account/2fa', auth.requireAuth, async (req, res) => {
  // A secret is held in the session until a code proves the app has it. Writing
  // it to the user row first would leave accounts with a half-configured
  // secret nobody can produce codes for.
  if (!req.user.totp_enabled && !req.session.totpSetup) {
    req.session.totpSetup = totp.generateSecret();
  }
  const secret = req.user.totp_enabled ? null : req.session.totpSetup;
  const otpauth = secret
    ? totp.otpauthUrl({
        secret,
        account: req.user.username,
        issuer: getSetting('panel_title') || 'HostPanel',
      })
    : null;

  res.render('twofactor', {
    title: 'Two-factor authentication',
    error: null,
    notice: null,
    enabled: Boolean(req.user.totp_enabled),
    required: auth.twoFactorRequiredFor(req.user),
    justEnabled: false,
    recoveryCodes: null,
    remaining: countRecoveryCodes(req.user),
    secret,
    otpauth,
    qr: otpauth ? await qrDataUrl(otpauth) : null,
  });
});

function countRecoveryCodes(user) {
  try { return JSON.parse(user.recovery_codes || '[]').length; } catch (_) { return 0; }
}

router.post('/account/2fa/enable', auth.requireAuth, async (req, res) => {
  const secret = req.session.totpSetup;
  const code = String(req.body.code || '').trim();

  const otpauth = secret
    ? totp.otpauthUrl({
        secret,
        account: req.user.username,
        issuer: getSetting('panel_title') || 'HostPanel',
      })
    : null;

  const render = async (error) =>
    res.status(error ? 400 : 200).render('twofactor', {
      title: 'Two-factor authentication',
      error,
      notice: null,
      enabled: Boolean(req.user.totp_enabled),
      required: auth.twoFactorRequiredFor(req.user),
      justEnabled: false,
      recoveryCodes: null,
      remaining: countRecoveryCodes(req.user),
      secret,
      otpauth,
      qr: otpauth ? await qrDataUrl(otpauth) : null,
    });

  if (req.user.totp_enabled) return render('Two-factor is already on for this account.');
  if (!secret) return res.redirect('/account/2fa');

  // Proving a valid code before switching it on is what stops someone locking
  // themselves out with a mistyped secret or a phone whose clock is wrong.
  if (!totp.verify(secret, code)) {
    return render('That code is not right. Check the time on your phone, then try the next one.');
  }

  const codes = totp.generateRecoveryCodes(10);
  db.prepare(
    'UPDATE users SET totp_secret = ?, totp_enabled = 1, recovery_codes = ? WHERE id = ?'
  ).run(secret, JSON.stringify(codes.map(totp.hashRecoveryCode)), req.user.id);

  delete req.session.totpSetup;
  req.session.epoch = auth.bumpSessionEpoch(req.user.id);
  audit(req, 'account.2fa_enabled', req.user.username);

  // Shown once, in the clear. They are stored hashed, so there is no second
  // chance to see them - which the page says plainly.
  return res.render('twofactor', {
    title: 'Two-factor authentication',
    error: null,
    notice: null,
    enabled: true,
    required: auth.twoFactorRequiredFor(req.user),
    justEnabled: true,
    recoveryCodes: codes,
    remaining: codes.length,
    secret: null,
    otpauth: null,
    qr: null,
  });
});

router.post('/account/2fa/disable', auth.requireAuth, (req, res) => {
  const password = String(req.body.password || '');
  const render = (error, notice) =>
    res.status(error ? 400 : 200).render('twofactor', {
      title: 'Two-factor authentication',
      error,
      notice,
      enabled: Boolean(auth.findUser(req.user.id).totp_enabled),
      required: auth.twoFactorRequiredFor(req.user),
      justEnabled: false,
      recoveryCodes: null,
      remaining: countRecoveryCodes(auth.findUser(req.user.id)),
      secret: null,
      otpauth: null,
      qr: null,
    });

  if (auth.twoFactorRequiredFor(req.user)) {
    return render('Two-factor is required for this account and cannot be turned off.');
  }
  // Re-checking the password matters: otherwise anyone who sits down at an
  // unlocked browser can remove the second factor without knowing the first.
  if (!auth.verifyPassword(password, req.user.password_hash)) {
    return render('That password is not correct.');
  }

  db.prepare(
    "UPDATE users SET totp_secret = '', totp_enabled = 0, recovery_codes = '[]' WHERE id = ?"
  ).run(req.user.id);
  req.session.epoch = auth.bumpSessionEpoch(req.user.id);
  audit(req, 'account.2fa_disabled', req.user.username);
  return render(null, 'Two-factor authentication is off for this account.');
});

router.post('/account/2fa/recovery', auth.requireAuth, (req, res) => {
  const password = String(req.body.password || '');
  const user = auth.findUser(req.user.id);

  const render = (error, codes) =>
    res.status(error ? 400 : 200).render('twofactor', {
      title: 'Two-factor authentication',
      error,
      notice: null,
      enabled: Boolean(user.totp_enabled),
      required: auth.twoFactorRequiredFor(req.user),
      justEnabled: Boolean(codes),
      recoveryCodes: codes || null,
      remaining: codes ? codes.length : countRecoveryCodes(user),
      secret: null,
      otpauth: null,
      qr: null,
    });

  if (!user.totp_enabled) return render('Two-factor is not on for this account.');
  if (!auth.verifyPassword(password, req.user.password_hash)) {
    return render('That password is not correct.');
  }

  const codes = totp.generateRecoveryCodes(10);
  db.prepare('UPDATE users SET recovery_codes = ? WHERE id = ?')
    .run(JSON.stringify(codes.map(totp.hashRecoveryCode)), user.id);
  audit(req, 'account.2fa_recovery_regenerated', user.username);
  return render(null, codes);
});

/**
 * Saves the interface preferences of whoever is signed in. Called by the theme
 * and Simple/Advanced toggles so the choice survives a refresh, a new device
 * and a fresh login.
 */
router.post('/account/prefs', auth.requireAuth, (req, res) => {
  const theme = ['system', 'dark', 'light'].includes(req.body.theme) ? req.body.theme : null;
  const mode = ['simple', 'advanced'].includes(req.body.ui_mode) ? req.body.ui_mode : null;
  if (!theme && !mode) return res.status(400).json({ error: 'Nothing to save' });

  if (theme) db.prepare('UPDATE users SET pref_theme = ? WHERE id = ?').run(theme, req.user.id);
  if (mode) db.prepare('UPDATE users SET pref_ui_mode = ? WHERE id = ?').run(mode, req.user.id);
  return res.json({ ok: true, theme, ui_mode: mode });
});

router.get('/healthz', (req, res) => {
  res.json({ ok: true, panel: getSetting('panel_title'), time: new Date().toISOString() });
});

module.exports = router;
