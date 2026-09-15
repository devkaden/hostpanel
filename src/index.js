'use strict';

const path = require('path');
const http = require('http');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');

const config = require('./config');
const { db, getSetting, setSetting, allSettings } = require('./db');
const SqliteStore = require('./session-store');
const auth = require('./auth');
const docker = require('./docker');
const npmplus = require('./npmplus');
const cron = require('./cron');
const terminal = require('./terminal');
const { detectHostIp } = require('./netutil');

const app = express();
app.disable('x-powered-by');
if (config.trustProxy) app.set('trust proxy', 1);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true, limit: '2mb' }));
// Generous enough for the file editor to POST a 2 MB text file as JSON.
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use('/static', express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

// xterm.js is served from node_modules so the panel works on an offline LAN.
const MODULES = path.join(__dirname, '..', 'node_modules');
app.use('/vendor/xterm', express.static(path.join(MODULES, '@xterm', 'xterm'), { maxAge: '7d' }));
app.use(
  '/vendor/xterm-addon-fit',
  express.static(path.join(MODULES, '@xterm', 'addon-fit'), { maxAge: '7d' })
);

const store = new SqliteStore({ ttlMs: config.sessionHours * 3600 * 1000 });
const sessionMiddleware = session({
  name: 'hostpanel.sid',
  secret: config.sessionSecret,
  store,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.secureCookies,
    maxAge: config.sessionHours * 3600 * 1000,
  },
});
app.use(sessionMiddleware);
app.use(auth.csrf);

/**
 * Security headers. No CSP nonce machinery here because the pages use inline
 * scripts throughout, but everything else is locked down: the panel is never
 * framed, MIME types are never sniffed, and no referrer leaks the panel URL.
 */
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'X-DNS-Prefetch-Control': 'off',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=()',
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self' data:",
      "connect-src 'self' ws: wss:",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "object-src 'none'",
    ].join('; '),
  });
  if (config.secureCookies) {
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

/**
 * Serialises a value for embedding inside a <script> block. Plain
 * JSON.stringify is unsafe there: a string containing "</script>" ends the
 * block and everything after it is parsed as HTML.
 */
function jsonForScript(value) {
  return JSON.stringify(value === undefined ? null : value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

// Common template locals.
app.use((req, res, next) => {
  res.locals.jsonScript = jsonForScript;
  res.locals.panelTitle = getSetting('panel_title') || 'HostPanel';
  res.locals.siteTypes = config.siteTypes;
  res.locals.currentPath = req.path;
  res.locals.flash = null;
  res.locals.hostShell = terminal.hostShellAvailable();
  next();
});

/* ------------------------------------------------------------------ *
 * Routes
 * ------------------------------------------------------------------ */
app.use(require('./routes/auth'));
app.use(auth.requireAuth);
app.use(require('./routes/dashboard'));
app.use(require('./routes/sites'));
app.use(require('./routes/files'));
app.use(require('./routes/cron'));
app.use(require('./routes/logs'));
app.use(require('./routes/users'));
app.use(require('./routes/settings'));

app.use((req, res) => {
  if (auth.wantsJson(req)) return res.status(404).json({ error: 'Not found' });
  return res.status(404).render('error', {
    title: 'Not found',
    message: 'That page does not exist.',
  });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err.stack || err.message);
  const status = err.status || 500;
  if (auth.wantsJson(req)) return res.status(status).json({ error: err.message });
  return res.status(status).render('error', {
    title: 'Something went wrong',
    message: err.message || 'Unexpected error',
  });
});

/* ------------------------------------------------------------------ *
 * Boot
 * ------------------------------------------------------------------ */
async function boot() {
  const bootstrap = auth.ensureBootstrapAdmin();
  if (bootstrap) {
    const banner = '='.repeat(62);
    console.log(`\n${banner}`);
    console.log('  HostPanel first run - administrator account created');
    console.log(`  username: ${bootstrap.username}`);
    console.log(`  password: ${bootstrap.password}`);
    console.log('  You will be asked to change this on first login.');
    console.log(`${banner}\n`);
    try {
      require('fs').writeFileSync(
        path.join(config.dataDir, 'initial-admin-password.txt'),
        `username: ${bootstrap.username}\npassword: ${bootstrap.password}\n`,
        { mode: 0o600 }
      );
    } catch (_) {
      /* non-fatal */
    }
  }

  if (!getSetting('host_ip')) {
    const detected = detectHostIp();
    if (detected) {
      setSetting('host_ip', detected);
      console.log(`[boot] detected host IP ${detected} (change it in Settings if wrong)`);
    }
  }

  const ping = await docker.ping(true);
  console.log(
    ping.ok
      ? '[boot] Docker connection OK'
      : `[boot] Docker unavailable: ${ping.error} - site management will not work until this is fixed`
  );

  if (npmplus.isEnabled()) {
    const test = await npmplus.testConnection();
    console.log(
      test.ok
        ? `[boot] NPMplus reachable (${test.proxyHosts} proxy hosts)`
        : `[boot] NPMplus check failed: ${test.error}`
    );
  } else {
    console.log('[boot] NPMplus integration is off (configure it in Settings)');
  }

  // Reconcile stored status with what Docker actually reports.
  try {
    const tpl = require('./site-templates');
    for (const site of db.prepare('SELECT * FROM sites').all()) {
      const state = await docker.containerState(tpl.containerName(site));
      const mapped =
        state === 'missing'
          ? 'error'
          : state === 'running' || state === 'healthy'
            ? 'running'
            : state === 'starting'
              ? 'running'
              : 'stopped';
      if (mapped !== site.status) {
        db.prepare('UPDATE sites SET status = ? WHERE id = ?').run(mapped, site.id);
      }
    }
  } catch (err) {
    console.error('[boot] status reconciliation skipped:', err.message);
  }

  cron.start();

  const server = http.createServer(app);
  terminal.attach(server, sessionMiddleware);

  server.listen(config.port, config.bindAddress, () => {
    console.log(`[boot] ${getSetting('panel_title')} listening on http://${config.bindAddress}:${config.port}`);
  });

  const shutdown = (signal) => {
    console.log(`\n[shutdown] ${signal} received`);
    cron.stop();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

process.on('unhandledRejection', (err) => {
  console.error('[unhandledRejection]', err && err.stack ? err.stack : err);
});

if (require.main === module) {
  boot().catch((err) => {
    console.error('[boot] fatal:', err);
    process.exit(1);
  });
}

module.exports = { app, boot, allSettings };
