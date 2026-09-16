'use strict';

/**
 * The security page: what has been tried against this panel lately.
 *
 * Administrators only. The alerts name accounts and addresses, and a standard
 * user knowing which usernames are being guessed is a head start nobody needs
 * to be given.
 */

const express = require('express');

const { db, getSetting } = require('../db');
const auth = require('../auth');
const alerts = require('../alerts');
const { wrap } = require('../middleware');
const { limiter } = require('../ratelimit');

const router = express.Router();

/*
 * Every route in this file is rate limited. The same instance is mounted on
 * the app as well; it counts a request once, wherever it first sees it.
 */
router.use(limiter);

/** Failed sign-ins over the last day, by address - the raw material of an alert. */
function recentFailures(hours = 24) {
  try {
    return db
      .prepare(
        `SELECT ip, COUNT(*) AS attempts, MAX(created_at) AS last_at
           FROM login_attempts
          WHERE key LIKE 'i:%' AND created_at > ?
          GROUP BY ip
          ORDER BY attempts DESC
          LIMIT 12`
      )
      .all(Date.now() - hours * 3600 * 1000);
  } catch (_) {
    return [];
  }
}

router.get('/security', auth.requireAdmin, (req, res) => {
  const showAll = req.query.all === '1';
  res.render('security', {
    title: 'Security',
    rows: alerts.list({ limit: 100, onlyNew: !showAll }),
    showAll,
    unread: alerts.unreadCount(),
    failures: recentFailures(),
    policy: {
      twoFactor: getSetting('require_2fa') || 'off',
      minPassword: auth.minPasswordLength(),
    },
  });
});

router.post(
  '/security/acknowledge',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const id = String(req.body.id || '');
    // "Clear all" is the common case - an attack produces one alert, but a bad
    // week produces several and dismissing them one at a time is busywork.
    if (id === 'all') {
      alerts.acknowledge(req, 'all');
    } else {
      const numeric = parseInt(id, 10);
      if (!Number.isFinite(numeric)) return res.status(400).json({ error: 'No such alert' });
      alerts.acknowledge(req, numeric);
    }
    if (auth.wantsJson(req)) return res.json({ ok: true });
    return res.redirect('/security');
  })
);

module.exports = router;
