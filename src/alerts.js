'use strict';

/**
 * Security alerts: things worth knowing about that nobody would find by
 * reading the activity log.
 *
 * A panel on the public internet gets probed constantly. Most of it is noise -
 * a bot trying "admin/admin" once and moving on - and surfacing every failed
 * sign-in would train whoever runs this to ignore the one that matters. So an
 * alert is raised only for a pattern: enough failures in a short window to mean
 * somebody is working at it, a sign-in from an address never seen before, a
 * recovery code being spent.
 *
 * Alerts are raised at most once per window per subject, because an alert that
 * fires fifty times during one attack is fifty things to dismiss rather than
 * one thing to read.
 */

const { db, audit } = require('./db');

/* Kinds, and what each one means.
 *
 * severity: 'critical' is "act now", 'warning' is "look at this", 'info' is
 * "for the record". Only the first two are counted in the header badge. */
const KINDS = {
  brute_force: {
    severity: 'critical',
    label: 'Repeated failed sign-ins',
  },
  account_locked: {
    severity: 'warning',
    label: 'Account temporarily locked',
  },
  new_location: {
    severity: 'warning',
    label: 'Sign-in from a new address',
  },
  recovery_used: {
    severity: 'warning',
    label: 'Recovery code used',
  },
  twofactor_disabled: {
    severity: 'warning',
    label: 'Two-factor turned off',
  },
  admin_created: {
    severity: 'warning',
    label: 'New administrator account',
  },
  password_reset: {
    severity: 'info',
    label: 'Password reset by an administrator',
  },
};

// How long the same alert stays suppressed after being raised.
const DEDUPE_MS = 15 * 60 * 1000;
// How far back a burst of failures counts as one attack.
const BURST_WINDOW_MS = 10 * 60 * 1000;
// Failures within that window before it stops being someone mistyping.
const BURST_THRESHOLD = 10;

function ensureTable() {
  db.exec(`
CREATE TABLE IF NOT EXISTS security_alerts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  kind         TEXT NOT NULL,
  severity     TEXT NOT NULL,
  subject      TEXT NOT NULL DEFAULT '',
  detail       TEXT NOT NULL DEFAULT '',
  ip           TEXT NOT NULL DEFAULT '',
  created_at   INTEGER NOT NULL,
  acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_new ON security_alerts(acknowledged, created_at);
`);
}
ensureTable();

/**
 * Records an alert, unless the same one was already raised recently.
 *
 * Returns the row, or null when it was suppressed as a duplicate.
 */
function raise(kind, { subject = '', detail = '', ip = '' } = {}) {
  const meta = KINDS[kind];
  if (!meta) return null;

  try {
    const recent = db
      .prepare(
        'SELECT id FROM security_alerts WHERE kind = ? AND subject = ? AND created_at > ? LIMIT 1'
      )
      .get(kind, subject, Date.now() - DEDUPE_MS);
    if (recent) return null;

    const info = db
      .prepare(
        'INSERT INTO security_alerts (kind, severity, subject, detail, ip, created_at) ' +
          'VALUES (?,?,?,?,?,?)'
      )
      .run(kind, meta.severity, subject, detail, String(ip || ''), Date.now());

    // Also in the service log, so it reaches whatever collects those.
    console.warn(
      `[security] ${meta.severity}: ${meta.label}` +
        `${subject ? ` (${subject})` : ''}${detail ? ` - ${detail}` : ''}`
    );
    return { id: info.lastInsertRowid, kind, ...meta, subject, detail, ip };
  } catch (_) {
    return null; // alerting must never break the thing it is watching
  }
}

/**
 * Looks at recent failures and raises an alert if they add up to an attack.
 *
 * Called after a failed sign-in. Counts by address rather than by username,
 * because someone working through a list of likely names is the case that a
 * per-account counter misses entirely.
 */
function noteFailedLogin({ username, ip }) {
  try {
    const since = Date.now() - BURST_WINDOW_MS;
    const fromIp = db
      .prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE key = ? AND created_at > ?')
      .get(`i:${ip}`, since).n;

    if (fromIp >= BURST_THRESHOLD) {
      const names = db
        .prepare(
          "SELECT DISTINCT key FROM login_attempts WHERE ip = ? AND key LIKE 'a:%' AND created_at > ?"
        )
        .all(String(ip || ''), since)
        .map((r) => r.key.slice(2));

      raise('brute_force', {
        subject: String(ip || 'unknown address'),
        ip,
        detail:
          `${fromIp} failed sign-ins in ${BURST_WINDOW_MS / 60000} minutes` +
          (names.length ? `, against: ${names.slice(0, 6).join(', ')}` : ''),
      });
    }
  } catch (_) {
    /* ignore */
  }
}

/** Raised when a lockout actually takes effect, which is a fact worth keeping. */
function noteLockout({ username, ip }) {
  raise('account_locked', {
    subject: username,
    ip,
    detail: `Too many failed attempts from ${ip}. Sign-in is blocked for ten minutes.`,
  });
}

/**
 * Raised the first time an account signs in from an address.
 *
 * Addresses are compared exactly. A home connection changing address will
 * produce an occasional alert, which is the right trade: a false "was this
 * you?" costs a moment, and a missed one costs the panel.
 */
function noteLogin({ user, ip }) {
  try {
    const seen = db
      .prepare(
        "SELECT 1 FROM audit_log WHERE user_id = ? AND action = 'auth.login' AND ip = ? LIMIT 1"
      )
      .get(user.id, String(ip || ''));
    if (seen) return;

    // Never alert on the very first sign-in of an account: there is no
    // "usual" address yet, so it would fire for everyone once, meaninglessly.
    const anyBefore = db
      .prepare("SELECT COUNT(*) AS n FROM audit_log WHERE user_id = ? AND action = 'auth.login'")
      .get(user.id).n;
    if (anyBefore <= 1) return;

    raise('new_location', {
      subject: user.username,
      ip,
      detail: `First sign-in from ${ip}.`,
    });
  } catch (_) {
    /* ignore */
  }
}

function list({ limit = 50, onlyNew = false } = {}) {
  try {
    return db
      .prepare(
        `SELECT * FROM security_alerts ${onlyNew ? 'WHERE acknowledged = 0' : ''} ` +
          'ORDER BY id DESC LIMIT ?'
      )
      .all(limit)
      .map((row) => ({ ...row, label: (KINDS[row.kind] || {}).label || row.kind }));
  } catch (_) {
    return [];
  }
}

/** How many unacknowledged alerts deserve attention, for the header badge. */
function unreadCount() {
  try {
    return db
      .prepare(
        "SELECT COUNT(*) AS n FROM security_alerts WHERE acknowledged = 0 AND severity != 'info'"
      )
      .get().n;
  } catch (_) {
    return 0;
  }
}

function acknowledge(req, id) {
  if (id === 'all') {
    db.prepare('UPDATE security_alerts SET acknowledged = 1 WHERE acknowledged = 0').run();
    audit(req, 'security.alerts_cleared', 'all');
    return;
  }
  db.prepare('UPDATE security_alerts SET acknowledged = 1 WHERE id = ?').run(parseInt(id, 10));
  audit(req, 'security.alert_cleared', String(id));
}

/** Old, acknowledged alerts are not worth keeping forever. */
function prune(days = 60) {
  try {
    db.prepare('DELETE FROM security_alerts WHERE acknowledged = 1 AND created_at < ?')
      .run(Date.now() - days * 86400000);
  } catch (_) {
    /* ignore */
  }
}

module.exports = {
  KINDS,
  raise,
  noteFailedLogin,
  noteLockout,
  noteLogin,
  list,
  unreadCount,
  acknowledge,
  prune,
};
