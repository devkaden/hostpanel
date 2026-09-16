'use strict';

const path = require('path');
const fs = require('fs');

try {
  require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
} catch (_) {
  /* dotenv is optional at runtime */
}

const DATA_DIR = process.env.HOSTPANEL_DATA || '/opt/hostpanel/data';

const config = {
  // --- server ---
  port: parseInt(process.env.PORT || '8890', 10),
  bindAddress: process.env.BIND_ADDRESS || '0.0.0.0',
  sessionSecret: process.env.SESSION_SECRET || 'change-me-in-dotenv',
  // Opt-in, not opt-out: trusting X-Forwarded-For when the panel is reachable
  // directly lets anyone spoof their client IP and walk past the login lockout.
  // Only turn this on when the panel really does sit behind a reverse proxy.
  trustProxy: process.env.TRUST_PROXY === 'true',
  // Set true only when the panel itself is served over HTTPS (e.g. behind NPMplus)
  secureCookies: process.env.SECURE_COOKIES === 'true',
  // An escape hatch, not a setting to leave on. If something in the panel
  // breaks only in one browser, turning the Content-Security-Policy off for a
  // moment says whether the policy is the cause - a question that otherwise
  // takes hours, because a CSP refusal surfaces as a vague browser error
  // rather than as anything naming CSP.
  disableCsp: process.env.DISABLE_CSP === 'true',
  sessionHours: parseInt(process.env.SESSION_HOURS || '12', 10),

  // --- storage ---
  dataDir: DATA_DIR,
  sitesDir: path.join(DATA_DIR, 'sites'),
  backupsDir: path.join(DATA_DIR, 'backups'),
  tmpDir: path.join(DATA_DIR, 'tmp'),
  dbFile: path.join(DATA_DIR, 'hostpanel.db'),

  // --- docker ---
  dockerSocket: process.env.DOCKER_SOCKET || '/var/run/docker.sock',
  // IP that NPMplus should point proxy hosts at. Auto-detected on first boot
  // if not set; override in Settings or here.
  hostIp: process.env.HOST_IP || '',
  portRangeStart: parseInt(process.env.PORT_RANGE_START || '21000', 10),
  portRangeEnd: parseInt(process.env.PORT_RANGE_END || '21999', 10),
  networkPrefix: 'hostpanel-site-',
  containerPrefix: 'hp-',

  // --- limits ---
  maxUploadBytes: parseInt(process.env.MAX_UPLOAD_MB || '512', 10) * 1024 * 1024,
  maxEditableBytes: 2 * 1024 * 1024,

  // --- images ---
  phpVersions: ['8.4', '8.3', '8.2', '8.1'],
  nodeVersions: ['24', '22', '20'],
  wordpressPhpVersions: ['8.3', '8.2'],
  mariadbImage: 'mariadb:11',

  siteTypes: {
    static: { label: 'Static / HTML', icon: 'S' },
    php: { label: 'PHP', icon: 'P' },
    wordpress: { label: 'WordPress', icon: 'W' },
    node: { label: 'Node.js', icon: 'N' },
  },
};

try {
  for (const dir of [config.dataDir, config.sitesDir, config.backupsDir, config.tmpDir]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  // The data directory holds the SQLite database, which contains password
  // hashes and the NPMplus credentials. Keep it owner-only.
  fs.chmodSync(config.dataDir, 0o750);
  fs.chmodSync(config.tmpDir, 0o700);
} catch (err) {
  console.error(
    `\nHostPanel could not create its data directory at ${config.dataDir}\n` +
      `  ${err.message}\n\n` +
      'Run the panel as root, or point HOSTPANEL_DATA at a writable path in .env.\n'
  );
  process.exit(1);
}

module.exports = config;
