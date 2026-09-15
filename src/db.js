'use strict';

const Database = require('better-sqlite3');
const config = require('./config');

const db = new Database(config.dbFile);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

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
addColumnIfMissing('sites', 'memory_mb', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('sites', 'cpu_limit', 'REAL NOT NULL DEFAULT 0');
addColumnIfMissing('sites', 'notes', "TEXT NOT NULL DEFAULT ''");
addColumnIfMissing('users', 'site_quota', 'INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('users', 'must_change_pw', 'INTEGER NOT NULL DEFAULT 0');

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
};

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

module.exports = { db, getSetting, setSetting, allSettings, audit, SETTING_DEFAULTS };
