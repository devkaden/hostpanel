'use strict';

const express = require('express');

const { db, audit } = require('../db');
const auth = require('../auth');
const { destroySessionsForUser } = require('../session-store');
const { wrap } = require('../middleware');

const router = express.Router();

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{1,30}$/i;

router.get('/users', auth.requireAdmin, (req, res) => {
  const users = db
    .prepare(
      `SELECT u.*, (SELECT COUNT(*) FROM sites s WHERE s.owner_id = u.id) AS site_count
       FROM users u ORDER BY u.role DESC, u.username`
    )
    .all();
  res.render('users', {
    title: 'Users',
    users,
    generatedPassword: null,
    error: null,
  });
});

router.post(
  '/users',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim();
    const role = req.body.role === 'admin' ? 'admin' : 'user';
    const quota = parseInt(req.body.site_quota || '0', 10) || 0;
    let password = String(req.body.password || '').trim();

    const render = (error, generated) => {
      const users = db
        .prepare(
          `SELECT u.*, (SELECT COUNT(*) FROM sites s WHERE s.owner_id = u.id) AS site_count
           FROM users u ORDER BY u.role DESC, u.username`
        )
        .all();
      return res.status(error ? 400 : 200).render('users', {
        title: 'Users',
        users,
        generatedPassword: generated || null,
        error,
      });
    };

    if (!USERNAME_RE.test(username)) {
      return render('Username must be 2-31 characters: letters, digits, dot, dash or underscore.');
    }
    if (auth.findUserByUsername(username)) return render('That username is already taken.');
    if (password && password.length < 10) {
      return render('A supplied password must be at least 10 characters.');
    }

    const generated = !password;
    if (generated) password = auth.randomPassword();

    db.prepare(
      'INSERT INTO users (username, email, password_hash, role, site_quota, must_change_pw) VALUES (?,?,?,?,?,1)'
    ).run(username, email, auth.hashPassword(password), role, quota);

    audit(req, 'user.create', username, { role, quota });
    return render(null, { username, password });
  })
);

router.post(
  '/users/:id/update',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const user = auth.findUser(id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const role = req.body.role === 'admin' ? 'admin' : 'user';
    const active = req.body.active === 'true' || req.body.active === true ? 1 : 0;
    const quota = parseInt(req.body.site_quota || '0', 10) || 0;
    const email = String(req.body.email !== undefined ? req.body.email : user.email || '').trim();

    // Never let the last active admin be demoted or disabled.
    if (user.role === 'admin' && (role !== 'admin' || !active)) {
      const admins = db
        .prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1 AND id != ?")
        .get(id).n;
      if (admins === 0) {
        return res.status(400).json({ error: 'There must be at least one active administrator.' });
      }
    }

    db.prepare('UPDATE users SET role = ?, active = ?, site_quota = ?, email = ? WHERE id = ?').run(
      role,
      active,
      quota,
      email,
      id
    );
    // Kick a disabled user out immediately, without touching anyone else's session.
    if (!active) destroySessionsForUser(id);
    audit(req, 'user.update', user.username, { role, active, quota });
    return res.json({ ok: true });
  })
);

router.post(
  '/users/:id/password',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const user = auth.findUser(id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    let password = String(req.body.password || '').trim();
    const generated = !password;
    if (generated) password = auth.randomPassword();
    else if (password.length < auth.minPasswordLength()) {
      return res.status(400).json({
        error: `Password must be at least ${auth.minPasswordLength()} characters.`,
      });
    }

    db.prepare('UPDATE users SET password_hash = ?, must_change_pw = 1 WHERE id = ?').run(
      auth.hashPassword(password),
      id
    );
    // A reset password must also end that user's existing sessions - both the
    // stored ones and, via the epoch, any that a stale cookie still points at.
    destroySessionsForUser(id);
    auth.bumpSessionEpoch(id);
    audit(req, 'user.reset_password', user.username);
    return res.json({ ok: true, password, generated });
  })
);

/**
 * Clears a user's second factor, for when they have lost the phone and the
 * recovery codes with it.
 *
 * Deliberately an administrator action rather than a self-service reset: a
 * "lost my authenticator" link that anyone who knows a password can use turns
 * two-factor back into one factor. If the policy requires 2FA, the next sign-in
 * walks them through setting it up again.
 */
router.post(
  '/users/:id/reset-2fa',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const user = auth.findUser(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.totp_enabled) {
      return res.status(400).json({ error: `${user.username} does not have two-factor on.` });
    }

    db.prepare(
      "UPDATE users SET totp_secret = '', totp_enabled = 0, recovery_codes = '[]' WHERE id = ?"
    ).run(id);
    destroySessionsForUser(id);
    auth.bumpSessionEpoch(id);
    audit(req, 'user.reset_2fa', user.username);
    return res.json({ ok: true });
  })
);

router.post(
  '/users/:id/delete',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const user = auth.findUser(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.id === req.user.id) {
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    }

    const siteCount = db.prepare('SELECT COUNT(*) AS n FROM sites WHERE owner_id = ?').get(id).n;
    if (siteCount > 0 && !req.body.reassign_to) {
      return res.status(400).json({
        error: `${user.username} owns ${siteCount} site(s). Choose someone to reassign them to first.`,
        siteCount,
      });
    }
    if (siteCount > 0) {
      const target = auth.findUser(parseInt(req.body.reassign_to, 10));
      if (!target) return res.status(400).json({ error: 'Reassignment target not found.' });
      db.prepare('UPDATE sites SET owner_id = ? WHERE owner_id = ?').run(target.id, id);
    }

    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    audit(req, 'user.delete', user.username, { reassigned: siteCount });
    return res.json({ ok: true });
  })
);

module.exports = router;
