'use strict';

const fs = require('fs');
const Database = require('better-sqlite3');
const config = require('./config');

const db = new Database(config.dbFile);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// The database stores password hashes and the NPMplus credentials, so keep it
// unreadable to anyone but the owner (WAL files included).
for (const suffix of ['', '-wal', '-shm']) {
  try {
    fs.chmodSync(config.dbFile + suffix, 0o600);
  } catch (_) {
    /* the sidecar files may not exist yet */
  }
}

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  username       TEXT NOT NULL UNIQUE,
  email          TEXT,
  password_hash  TEXT NOT NULL,
  role           TEXT NOT NULL DEFAULT 'user',
  active         INTEGER NOT NULL DEFAULT 1,
  must_change_pw INTEGER NOT NULL DEFAULT 0,
  site_quota     INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  last_login     TEXT
);

CREATE TABLE IF NOT EXISTS sites (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  name            TEXT NOT NULL UNIQUE,
  domain          TEXT,
  extra_domains   TEXT NOT NULL DEFAULT '',
  type            TEXT NOT NULL,
  owner_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  port            INTEGER NOT NULL UNIQUE,
  runtime_version TEXT,
  install_command TEXT NOT NULL DEFAULT '',
  start_command   TEXT NOT NULL DEFAULT '',
  app_port        INTEGER NOT NULL DEFAULT 3000,
  env_json        TEXT NOT NULL DEFAULT '{}',
  memory_mb       INTEGER NOT NULL DEFAULT 0,
  cpu_limit       REAL NOT NULL DEFAULT 0,
  container_id    TEXT,
  db_container_id TEXT,
  db_name         TEXT,
  db_user         TEXT,
  db_password     TEXT,
  npm_proxy_id    INTEGER,
  npm_cert_id     INTEGER,
  ssl             INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'created',
  notes           TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cron_jobs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id     INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  schedule    TEXT NOT NULL,
  command     TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  last_run    TEXT,
  last_exit   INTEGER,
  last_output TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS templates (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  type        TEXT NOT NULL,
  config_json TEXT NOT NULL DEFAULT '{}',
  created_by  INTEGER,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  sid        TEXT PRIMARY KEY,
  expires    INTEGER NOT NULL,
  data       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER,
  username   TEXT,
  action     TEXT NOT NULL,
  target     TEXT NOT NULL DEFAULT '',
  detail     TEXT NOT NULL DEFAULT '',
  ip         TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sites_owner   ON sites(owner_id);
CREATE INDEX IF NOT EXISTS idx_cron_site     ON cron_jobs(site_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires);
`);

/* ------------------------------------------------------------------ *
 * Lightweight forward migrations. Each entry is idempotent.
 * ------------------------------------------------------------------ */
function addColumnIfMissing(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
  if (!cols.includes(column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

addColumnIfMissing('sites', 'extra_domains', "TEXT NOT NULL DEFAULT ''");
addColumnIfMissing('sites', 'custom_image', "TEXT NOT NULL DEFAULT ''");
addColumnIfMissing('sites', 'extra_volumes', "TEXT NOT NULL DEFAULT ''");
addColumnIfMissing('sites', 'extra_labels', "TEXT NOT NULL DEFAULT '{}'");
addColumnIfMissing('sites', 'docker_network', "TEXT NOT NULL DEFAULT ''");
addColumnIfMissing('sites', 'memory_mb', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('sites', 'cpu_limit', 'REAL NOT NULL DEFAULT 0');
addColumnIfMissing('sites', 'notes', "TEXT NOT NULL DEFAULT ''");
// Space-separated OS packages to bake into the site's image. Node and PHP
// images are deliberately minimal, so anything that shells out - ffmpeg,
// yt-dlp, imagemagick, git - is simply absent, and an app that needs one fails
// at runtime with a message about a missing binary rather than a missing
// dependency.
addColumnIfMissing('sites', 'system_packages', "TEXT NOT NULL DEFAULT ''");

/* ------------------------------------------------------ two-factor auth --- */
addColumnIfMissing('users', 'totp_secret', "TEXT NOT NULL DEFAULT ''");
addColumnIfMissing('users', 'totp_enabled', 'INTEGER NOT NULL DEFAULT 0');
// Hashed, one-time, for when the phone is gone.
addColumnIfMissing('users', 'recovery_codes', "TEXT NOT NULL DEFAULT '[]'");
/*
 * Bumped whenever a credential changes, and compared against the value stored
 * in the session. Without it, changing a password or turning off two-factor
 * leaves every session that was already open still signed in - which is the
 * opposite of what someone changing their password after a scare expects.
 */
addColumnIfMissing('users', 'session_epoch', 'INTEGER NOT NULL DEFAULT 1');

/*
 * Failed sign-ins, kept on disk rather than in memory.
 *
 * In-memory throttling is defeated by restarting the service, and a panel on
 * the public internet gets restarted by its own updater. Persisting it means a
 * lockout actually lasts.
 */
db.exec(`
CREATE TABLE IF NOT EXISTS login_attempts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  key        TEXT NOT NULL,
  ip         TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_key ON login_attempts(key, created_at);
`);
addColumnIfMissing('users', 'site_quota', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('users', 'must_change_pw', 'INTEGER NOT NULL DEFAULT 0');

// Per-person interface preferences. Empty means "follow the panel default",
// so an existing user keeps whatever the administrator has configured.
addColumnIfMissing('users', 'pref_theme', "TEXT NOT NULL DEFAULT ''");
addColumnIfMissing('users', 'pref_ui_mode', "TEXT NOT NULL DEFAULT ''");

/*
 * Before the internal port became configurable, app_port defaulted to 3000 for
 * every site type but was only ever used by Node - the others were always
 * served on 80. Now that the value is real, correct those stale rows so an
 * existing site does not suddenly expect nginx or Apache on port 3000.
 */
db.prepare(
  "UPDATE sites SET app_port = 80 WHERE type IN ('static','php','wordpress') AND app_port = 3000"
).run();

/* ------------------------------------------------------------------ *
 * Settings helpers
 * ------------------------------------------------------------------ */
const SETTING_DEFAULTS = {
  npmplus_url: '',
  npmplus_email: '',
  npmplus_password: '',
  npmplus_le_email: '',
  npmplus_enabled: '0',
  npmplus_insecure: '0',
  host_ip: config.hostIp || '',
  panel_title: 'HostPanel',
  allow_host_shell: '1',

  // Two-factor policy: off | admins | all.
  // "admins" is the sensible default for a panel reachable from outside: the
  // accounts that can reach the Docker socket are the ones worth protecting.
  require_2fa: 'off',
  // Minimum password length. Raised automatically when 2FA is required.
  min_password_length: '10',
  // Largest single upload, in MB. Empty means "use the value from .env".
  max_upload_mb: '',

  // Ports. Empty means "use the value from .env / the built-in default",
  // so an untouched install keeps behaving exactly as before.
  panel_port: '',
  port_range_start: '',
  port_range_end: '',

  // Appearance.
  theme: 'system', // system | dark | light
  brand_accent: '#4f8cff',
  brand_logo: '', // data: URL or an image URL
  ui_mode: 'simple', // default for new visitors: simple | advanced

  // First-run wizard.
  setup_complete: '0',
};

/** Reads a setting that should fall back to a config.js default when blank. */
function getNumericSetting(key, fallback) {
  const raw = getSetting(key, '');
  const parsed = parseInt(raw, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function getSetting(key, fallback) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  if (row) return row.value;
  if (fallback !== undefined) return fallback;
  return SETTING_DEFAULTS[key] !== undefined ? SETTING_DEFAULTS[key] : '';
}

function setSetting(key, value) {
  db.prepare(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  ).run(key, String(value == null ? '' : value));
}

function allSettings() {
  const out = { ...SETTING_DEFAULTS };
  for (const row of db.prepare('SELECT key, value FROM settings').all()) {
    out[row.key] = row.value;
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * Audit log
 * ------------------------------------------------------------------ */
function audit(req, action, target = '', detail = '') {
  try {
    const user = req && req.session ? req.session.user : null;
    db.prepare(
      'INSERT INTO audit_log (user_id, username, action, target, detail, ip) VALUES (?,?,?,?,?,?)'
    ).run(
      user ? user.id : null,
      user ? user.username : 'system',
      action,
      String(target),
      typeof detail === 'string' ? detail : JSON.stringify(detail),
      req && req.ip ? req.ip : ''
    );
  } catch (err) {
    console.error('[audit] failed:', err.message);
  }
}

module.exports = {
  db,
  getSetting,
  setSetting,
  getNumericSetting,
  allSettings,
  audit,
  SETTING_DEFAULTS,
};
