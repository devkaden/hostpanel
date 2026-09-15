'use strict';

const express = require('express');
const { db, audit, getSetting } = require('../db');
const auth = require('../auth');

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
  return req.session.regenerate((err) => {
    if (err) return fail('Could not start a session. Try again.');
    auth.login(req, user);
    return req.session.save(() => res.redirect(user.must_change_pw ? '/account/password' : next));
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
  if (next.length < 10) return fail('The new password must be at least 10 characters.');
  if (next !== confirm) return fail('The two new passwords do not match.');
  if (next === current) return fail('The new password must be different from the current one.');

  db.prepare('UPDATE users SET password_hash = ?, must_change_pw = 0 WHERE id = ?').run(
    auth.hashPassword(next),
    req.user.id
  );
  req.session.user.mustChangePw = false;
  audit(req, 'account.password_changed', req.user.username);
  return res.redirect('/?changed=1');
});

router.get('/healthz', (req, res) => {
  res.json({ ok: true, panel: getSetting('panel_title'), time: new Date().toISOString() });
});

module.exports = router;
