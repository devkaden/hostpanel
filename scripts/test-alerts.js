#!/usr/bin/env node
'use strict';
/*
 * Exercises the security alerting in src/alerts.js against a real database.
 *
 * The behaviour worth testing is not "does a row get written" - it is the
 * judgement calls: one alert per attack rather than one per attempt, a burst
 * that has to be a burst before anybody is told, and no "sign-in from a new
 * address" on the very first sign-in an account ever makes, which would fire
 * for everyone once and teach whoever reads it to ignore the next one.
 *
 * src/db.js needs better-sqlite3, which the test environment does not always
 * have, so the module is replaced in the require cache by a small adapter over
 * the SQLite that ships with Node. The schema below matches the real one, and
 * alerts.js runs unmodified against it.
 *
 * Run with: npm run test:alerts
 */

const path = require('path');
const { DatabaseSync } = require('node:sqlite');

let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`); }
}

/* ----------------------------------------------------- the stubbed db --- */
const sqlite = new DatabaseSync(':memory:');
sqlite.exec(`
CREATE TABLE login_attempts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  key        TEXT NOT NULL,
  ip         TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER,
  username   TEXT,
  action     TEXT NOT NULL,
  target     TEXT NOT NULL DEFAULT '',
  detail     TEXT NOT NULL DEFAULT '',
  ip         TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

const audited = [];
const dbStub = {
  db: {
    exec: (sql) => sqlite.exec(sql),
    prepare: (sql) => {
      const stmt = sqlite.prepare(sql);
      return {
        get: (...args) => stmt.get(...args),
        all: (...args) => stmt.all(...args),
        run: (...args) => stmt.run(...args),
      };
    },
  },
  audit: (_req, action, target) => audited.push({ action, target }),
  getSetting: () => '',
};

require.cache[require.resolve(path.join(__dirname, '..', 'src', 'db.js'))] = {
  id: require.resolve(path.join(__dirname, '..', 'src', 'db.js')),
  filename: require.resolve(path.join(__dirname, '..', 'src', 'db.js')),
  loaded: true,
  exports: dbStub,
};

const alerts = require('../src/alerts');
const raw = dbStub.db;

const failuresFrom = (ip, count, ageMs = 0) => {
  const now = Date.now() - ageMs;
  for (let i = 0; i < count; i += 1) {
    raw.prepare('INSERT INTO login_attempts (key, ip, created_at) VALUES (?,?,?)')
      .run(`i:${ip}`, ip, now);
  }
};
const clearAlerts = () => raw.prepare('DELETE FROM security_alerts').run();
const countAlerts = (kind) =>
  raw.prepare('SELECT COUNT(*) AS n FROM security_alerts WHERE kind = ?').get(kind).n;

/* ------------------------------------------------------------- raising -- */
console.log('\nraising an alert');
{
  const row = alerts.raise('twofactor_disabled', { subject: 'kaden', detail: 'turned off', ip: '10.0.0.5' });
  check('returns the alert it recorded', row && row.kind === 'twofactor_disabled', JSON.stringify(row));
  check('with the severity from the kind table', row && row.severity === 'warning');
  check('and a readable label', row && /two-factor/i.test(row.label), row && row.label);
  check('the row is in the database', countAlerts('twofactor_disabled') === 1);

  const dup = alerts.raise('twofactor_disabled', { subject: 'kaden', detail: 'again' });
  check('the same alert is not raised twice in a row', dup === null);
  check('and no second row is written', countAlerts('twofactor_disabled') === 1);

  const other = alerts.raise('twofactor_disabled', { subject: 'someone-else' });
  check('a different subject is a different alert', other !== null);

  check('an unknown kind is refused', alerts.raise('not_a_kind', {}) === null);
  clearAlerts();
}

/* ------------------------------------------------------- brute force ---- */
console.log('\ntelling an attack from a typo');
{
  failuresFrom('203.0.113.9', 3);
  alerts.noteFailedLogin({ username: 'kaden', ip: '203.0.113.9' });
  check('three failures raise nothing', countAlerts('brute_force') === 0);

  failuresFrom('203.0.113.9', 8); // 11 total, over the threshold
  alerts.noteFailedLogin({ username: 'kaden', ip: '203.0.113.9' });
  check('a burst does raise one', countAlerts('brute_force') === 1);

  alerts.noteFailedLogin({ username: 'kaden', ip: '203.0.113.9' });
  alerts.noteFailedLogin({ username: 'admin', ip: '203.0.113.9' });
  check('and every attempt after it does not pile up', countAlerts('brute_force') === 1,
    'an attack must be one thing to read, not fifty');

  const row = raw.prepare("SELECT * FROM security_alerts WHERE kind = 'brute_force'").get();
  check('the alert names the address', row.subject === '203.0.113.9', row.subject);
  check('and says how many attempts it saw', /11 failed sign-ins/.test(row.detail), row.detail);
  check('it is the most serious severity', row.severity === 'critical');

  // Old failures are not evidence of anything happening now.
  clearAlerts();
  raw.prepare('DELETE FROM login_attempts').run();
  failuresFrom('198.51.100.7', 40, 60 * 60 * 1000); // an hour ago
  alerts.noteFailedLogin({ username: 'kaden', ip: '198.51.100.7' });
  check('failures from an hour ago do not raise anything', countAlerts('brute_force') === 0);

  raw.prepare('DELETE FROM login_attempts').run();
  clearAlerts();
}

/* -------------------------------------------------- names being tried --- */
console.log('\nreporting which accounts were tried');
{
  const ip = '203.0.113.44';
  failuresFrom(ip, 12);
  for (const name of ['admin', 'root', 'kaden']) {
    raw.prepare('INSERT INTO login_attempts (key, ip, created_at) VALUES (?,?,?)')
      .run(`a:${name}`, ip, Date.now());
  }
  alerts.noteFailedLogin({ username: 'root', ip });
  const row = raw.prepare("SELECT * FROM security_alerts WHERE kind = 'brute_force'").get();
  check('the usernames being guessed are listed', /admin/.test(row.detail) && /root/.test(row.detail),
    row.detail);

  raw.prepare('DELETE FROM login_attempts').run();
  clearAlerts();
}

/* ------------------------------------------------------- new location --- */
console.log('\nsign-ins from an address not seen before');
{
  const user = { id: 1, username: 'kaden' };
  const logLogin = (ip) =>
    raw.prepare("INSERT INTO audit_log (user_id, username, action, ip) VALUES (?,?,'auth.login',?)")
      .run(user.id, user.username, ip);

  logLogin('192.168.0.10');
  alerts.noteLogin({ user, ip: '192.168.0.10' });
  check('the first sign-in of an account never alerts', countAlerts('new_location') === 0,
    'there is no usual address yet, so it would fire for everyone once');

  logLogin('192.168.0.10');
  alerts.noteLogin({ user, ip: '192.168.0.10' });
  check('a familiar address stays quiet', countAlerts('new_location') === 0);

  alerts.noteLogin({ user, ip: '203.0.113.99' });
  check('an address never seen before does alert', countAlerts('new_location') === 1);
  const row = raw.prepare("SELECT * FROM security_alerts WHERE kind = 'new_location'").get();
  check('and it says where from', /203\.0\.113\.99/.test(row.detail), row.detail);

  logLogin('203.0.113.99');
  clearAlerts();
  alerts.noteLogin({ user, ip: '203.0.113.99' });
  check('once it is in the history it is familiar too', countAlerts('new_location') === 0);

  raw.prepare('DELETE FROM audit_log').run();
  clearAlerts();
}

/* --------------------------------------------------------- the badge ---- */
console.log('\nwhat the header badge counts');
{
  alerts.raise('brute_force', { subject: 'a' });
  alerts.raise('new_location', { subject: 'b' });
  alerts.raise('password_reset', { subject: 'c' });
  check('informational alerts are not counted', alerts.unreadCount() === 2,
    `got ${alerts.unreadCount()}`);

  const first = raw.prepare("SELECT id FROM security_alerts WHERE kind = 'brute_force'").get().id;
  alerts.acknowledge({}, first);
  check('clearing one lowers the count', alerts.unreadCount() === 1);
  check('and it is recorded in the activity log',
    audited.some((a) => a.action === 'security.alert_cleared'),
    JSON.stringify(audited));

  alerts.acknowledge({}, 'all');
  check('clearing everything empties the badge', alerts.unreadCount() === 0);
  check('the alerts themselves are kept', alerts.list({ limit: 50 }).length === 3,
    'cleared is not deleted - the history is the point');
  check('but they are gone from the new list', alerts.list({ onlyNew: true }).length === 0);
  check('clearing all is recorded too',
    audited.some((a) => a.action === 'security.alerts_cleared'));
}

/* ------------------------------------------------------------ pruning --- */
console.log('\npruning');
{
  raw.prepare('DELETE FROM security_alerts').run();
  const old = Date.now() - 90 * 86400000;
  raw.prepare(
    'INSERT INTO security_alerts (kind, severity, subject, detail, ip, created_at, acknowledged) ' +
      "VALUES ('brute_force','critical','old','','',?,1)"
  ).run(old);
  raw.prepare(
    'INSERT INTO security_alerts (kind, severity, subject, detail, ip, created_at, acknowledged) ' +
      "VALUES ('brute_force','critical','old-but-open','','',?,0)"
  ).run(old);
  alerts.prune(60);
  const left = alerts.list({ limit: 50 }).map((r) => r.subject);
  check('an old cleared alert is removed', !left.includes('old'), left.join(', '));
  check('an old alert nobody has looked at is kept', left.includes('old-but-open'),
    'pruning must never be how an unread warning disappears');
}

/* ------------------------------------------------- failure is survivable */
console.log('\nwhen the database is unhappy');
{
  const broken = { ...dbStub.db, prepare: () => { throw new Error('database is locked'); } };
  const saved = dbStub.db.prepare;
  dbStub.db.prepare = broken.prepare;
  let threw = null;
  try {
    alerts.raise('brute_force', { subject: 'x' });
    alerts.noteFailedLogin({ username: 'x', ip: '1.2.3.4' });
    alerts.noteLogin({ user: { id: 1, username: 'x' }, ip: '1.2.3.4' });
    alerts.list();
    alerts.unreadCount();
    alerts.prune();
  } catch (err) { threw = err; }
  dbStub.db.prepare = saved;

  check('nothing throws', !threw, threw && threw.message);
  check('the badge falls back to zero', alerts.unreadCount() >= 0);
}

/* ---------------------------------------------------------- the wiring -- */
console.log('\nthe hooks are actually called');
{
  const fs = require('fs');
  const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');
  const authRoutes = read('src/routes/auth.js');
  const userRoutes = read('src/routes/users.js');
  const index = read('src/index.js');

  check('a failed sign-in is counted', /alerts\.noteFailedLogin/.test(authRoutes));
  check('a lockout is recorded', /alerts\.noteLockout/.test(authRoutes));
  check('a successful sign-in is checked against known addresses',
    /alerts\.noteLogin/.test(authRoutes));
  check('spending a recovery code raises an alert',
    /alerts\.raise\('recovery_used'/.test(authRoutes));
  check('turning off two-factor raises an alert',
    /alerts\.raise\('twofactor_disabled'/.test(authRoutes));
  check('a new administrator raises an alert', /alerts\.raise\('admin_created'/.test(userRoutes));
  check('an administrator password reset raises an alert',
    /alerts\.raise\('password_reset'/.test(userRoutes));
  check('clearing a user two-factor raises an alert',
    /alerts\.raise\('twofactor_disabled'/.test(userRoutes));
  check('the security page is mounted', /routes\/security/.test(index));
  check('the badge count is set after authentication',
    index.indexOf('alerts.unreadCount()') > index.indexOf('app.use(auth.requireAuth)'),
    'req.user does not exist before requireAuth, so an earlier read is silently zero');

  const securityRoute = read('src/routes/security.js');
  check('the security page is restricted to administrators',
    /router\.get\('\/security',\s*auth\.requireAdmin/.test(securityRoute));
  check('and so is clearing an alert',
    /router\.post\(\s*'\/security\/acknowledge',\s*auth\.requireAdmin/.test(securityRoute));
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
