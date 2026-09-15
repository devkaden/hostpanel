'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const config = require('./config');
const { db, audit } = require('./db');
const docker = require('./docker');
const tpl = require('./site-templates');
const npmplus = require('./npmplus');

const NAME_RE = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/;
const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;

/* ------------------------------------------------------------------ *
 * Provisioning progress (in-memory ring buffer per site)
 * ------------------------------------------------------------------ */
const progress = new Map();
const busy = new Set();

function setBusy(siteId, value) {
  if (value) busy.add(String(siteId));
  else busy.delete(String(siteId));
}

function isBusy(siteId) {
  return busy.has(String(siteId));
}

function pushProgress(siteId, line) {
  const key = String(siteId);
  if (!progress.has(key)) progress.set(key, []);
  const arr = progress.get(key);
  arr.push({ at: Date.now(), line });
  if (arr.length > 300) arr.shift();
  console.log(`[site:${siteId}] ${line}`);
}

function getProgress(siteId) {
  return progress.get(String(siteId)) || [];
}

function clearProgress(siteId) {
  progress.delete(String(siteId));
}

/* ------------------------------------------------------------------ *
 * Paths and ownership
 * ------------------------------------------------------------------ */
function siteDirs(site) {
  const root = path.join(config.sitesDir, site.name);
  return {
    root,
    app: path.join(root, 'app'),
    logs: path.join(root, 'logs'),
    conf: path.join(root, 'conf'),
    db: path.join(root, 'db'),
  };
}

/** UID/GID the container process runs as, so bind mounts stay writable. */
function ownerUid(type) {
  switch (type) {
    case 'php':
    case 'wordpress':
      return { uid: 33, gid: 33 }; // www-data
    case 'node':
      return { uid: 1000, gid: 1000 }; // node
    default:
      return null; // static: nginx only reads
  }
}

async function chownRecursive(dir, uid, gid) {
  if (process.platform !== 'linux' || process.getuid() !== 0) return;
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    try {
      await fsp.chown(cur, uid, gid);
      const st = await fsp.lstat(cur);
      if (st.isDirectory()) {
        for (const entry of await fsp.readdir(cur)) stack.push(path.join(cur, entry));
      }
    } catch (_) {
      /* best effort */
    }
  }
}

/* ------------------------------------------------------------------ *
 * Queries
 * ------------------------------------------------------------------ */
function getSite(id) {
  return db.prepare('SELECT * FROM sites WHERE id = ?').get(id);
}

function getSiteByName(name) {
  return db.prepare('SELECT * FROM sites WHERE name = ?').get(name);
}

function listSites(user) {
  const sql = `SELECT s.*, u.username AS owner_name
               FROM sites s JOIN users u ON u.id = s.owner_id`;
  if (user && user.role !== 'admin') {
    return db.prepare(`${sql} WHERE s.owner_id = ? ORDER BY s.name`).all(user.id);
  }
  return db.prepare(`${sql} ORDER BY s.name`).all();
}

function canAccess(user, site) {
  if (!user || !site) return false;
  return user.role === 'admin' || site.owner_id === user.id;
}

function allDomains(site) {
  const extra = (site.extra_domains || '')
    .split(/[\s,]+/)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  const list = site.domain ? [site.domain.toLowerCase(), ...extra] : extra;
  return [...new Set(list)];
}

/* ------------------------------------------------------------------ *
 * Port allocation
 * ------------------------------------------------------------------ */
function allocatePort() {
  const used = new Set(db.prepare('SELECT port FROM sites').all().map((r) => r.port));
  for (let p = config.portRangeStart; p <= config.portRangeEnd; p += 1) {
    if (!used.has(p)) return p;
  }
  throw new Error('No free ports left in the configured range');
}

/* ------------------------------------------------------------------ *
 * Validation
 * ------------------------------------------------------------------ */
function validateNew(input, user) {
  const errors = [];
  const name = String(input.name || '').trim().toLowerCase();
  if (!NAME_RE.test(name)) {
    errors.push('Name must be 3-32 characters, lowercase letters, digits and hyphens only.');
  } else if (getSiteByName(name)) {
    errors.push(`A site named "${name}" already exists.`);
  }

  const type = String(input.type || '');
  if (!config.siteTypes[type]) errors.push('Pick a valid site type.');

  const domain = String(input.domain || '').trim().toLowerCase();
  if (domain && !DOMAIN_RE.test(domain)) errors.push('Domain does not look like a valid hostname.');

  const extras = String(input.extra_domains || '')
    .split(/[\s,]+/)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  for (const d of extras) {
    if (!DOMAIN_RE.test(d)) errors.push(`"${d}" is not a valid hostname.`);
  }

  if (type === 'node') {
    const appPort = parseInt(input.app_port || '3000', 10);
    if (!Number.isInteger(appPort) || appPort < 1 || appPort > 65535) {
      errors.push('App port must be between 1 and 65535.');
    }
  }

  if (input.env_json) {
    try {
      const parsed = JSON.parse(input.env_json);
      if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) {
        errors.push('Environment variables must be a JSON object.');
      }
    } catch (_) {
      errors.push('Environment variables are not valid JSON.');
    }
  }

  if (user && user.role !== 'admin' && user.site_quota > 0) {
    const count = db.prepare('SELECT COUNT(*) AS n FROM sites WHERE owner_id = ?').get(user.id).n;
    if (count >= user.site_quota) {
      errors.push(`You have reached your limit of ${user.site_quota} sites.`);
    }
  }

  return { errors, name, type, domain, extras };
}

/* ------------------------------------------------------------------ *
 * Create + provision
 * ------------------------------------------------------------------ */
function createSiteRecord(input, user) {
  const { errors, name, type, domain, extras } = validateNew(input, user);
  if (errors.length) {
    const err = new Error(errors.join(' '));
    err.validation = errors;
    throw err;
  }

  const port = allocatePort();
  const isWp = type === 'wordpress';
  const dbPassword = crypto.randomBytes(18).toString('base64url');

  const defaults = {
    static: { runtime: '', start: '', install: '' },
    php: { runtime: input.runtime_version || '8.3', start: '', install: '' },
    wordpress: { runtime: input.runtime_version || '8.3', start: '', install: '' },
    node: {
      runtime: input.runtime_version || '22',
      start: input.start_command || 'npm start',
      install: input.install_command || 'npm install --omit=dev',
    },
  }[type];

  const info = db
    .prepare(
      `INSERT INTO sites
        (name, domain, extra_domains, type, owner_id, port, runtime_version,
         install_command, start_command, app_port, env_json, memory_mb, cpu_limit,
         db_name, db_user, db_password, status)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'creating')`
    )
    .run(
      name,
      domain,
      extras.join(','),
      type,
      input.owner_id && user.role === 'admin' ? parseInt(input.owner_id, 10) : user.id,
      port,
      defaults.runtime,
      defaults.install,
      defaults.start,
      parseInt(input.app_port || '3000', 10),
      input.env_json || '{}',
      parseInt(input.memory_mb || '0', 10) || 0,
      parseFloat(input.cpu_limit || '0') || 0,
      isWp ? 'wordpress' : null,
      isWp ? 'wp_user' : null,
      isWp ? dbPassword : null
    );

  return getSite(info.lastInsertRowid);
}

async function writeSeedFiles(site) {
  const dirs = siteDirs(site);
  for (const dir of [dirs.root, dirs.app, dirs.logs, dirs.conf]) {
    await fsp.mkdir(dir, { recursive: true });
  }
  if (site.type === 'wordpress') await fsp.mkdir(dirs.db, { recursive: true });

  // Config files are seeded once and then left alone: a rebuild must never
  // discard edits the user made through the file manager.
  const seedOnce = async (file, contents) => {
    if (!fs.existsSync(file)) await fsp.writeFile(file, contents);
  };

  if (site.type === 'static') {
    await seedOnce(path.join(dirs.conf, 'nginx-site.conf'), tpl.DEFAULT_NGINX_CONF);
    await seedOnce(path.join(dirs.app, 'index.html'), tpl.seedIndexHtml(site));
  }

  if (site.type === 'php' || site.type === 'wordpress') {
    await seedOnce(path.join(dirs.conf, 'php-custom.ini'), tpl.DEFAULT_PHP_INI);
  }

  if (site.type === 'php') {
    await seedOnce(path.join(dirs.app, 'index.php'), tpl.seedIndexPhp(site));
  }

  if (site.type === 'node') {
    const files = tpl.seedNodeApp(site);
    for (const [file, contents] of Object.entries(files)) {
      const target = path.join(dirs.app, file);
      if (!fs.existsSync(target)) await fsp.writeFile(target, contents);
    }
  }

  const owner = ownerUid(site.type);
  if (owner) await chownRecursive(dirs.app, owner.uid, owner.gid);
  await fsp.chmod(dirs.logs, 0o777).catch(() => {});
  return dirs;
}

function setStatus(siteId, status) {
  db.prepare('UPDATE sites SET status = ? WHERE id = ?').run(status, siteId);
}

/**
 * Full provision: directories, images, network, containers, first start and
 * (optionally) the NPMplus proxy host + certificate.
 */
async function provisionSite(siteId, { createProxy = true } = {}) {
  let site = getSite(siteId);
  if (!site) throw new Error('Site not found');
  const log = (line) => pushProgress(siteId, line);

  setBusy(siteId, true);
  try {
    setStatus(siteId, 'provisioning');
    log('Creating site directories');
    const dirs = await writeSeedFiles(site);

    log('Ensuring Docker network');
    await docker.ensureNetwork(tpl.networkName(site));

    const spec = tpl.buildSpec(site, dirs);

    if (spec.dbImage) {
      log(`Preparing database image ${spec.dbImage}`);
      await docker.ensureImage(spec.dbImage, log);
    }
    log(`Preparing image ${spec.image}`);
    await docker.ensureImage(spec.image, log);

    // Remove any stale containers from a previous attempt.
    await docker.removeContainer(spec.name).catch(() => {});
    if (spec.dbName) await docker.removeContainer(spec.dbName).catch(() => {});

    if (spec.dbCreate) {
      log('Creating database container');
      const dbc = await docker.client().createContainer(spec.dbCreate);
      await dbc.start();
      db.prepare('UPDATE sites SET db_container_id = ? WHERE id = ?').run(dbc.id, siteId);
      log('Waiting for the database to accept connections');
      await waitForDatabase(spec.dbName, log);
    }

    log('Creating application container');
    const container = await docker.client().createContainer(spec.create);
    db.prepare('UPDATE sites SET container_id = ? WHERE id = ?').run(container.id, siteId);

    if (site.type === 'node' && site.install_command) {
      // Run the install in a throwaway container sharing the same /app mount,
      // so a start command that crashes cannot block dependency installation.
      log(`Running install: ${site.install_command}`);
      const res = await docker.runOneShot(
        spec.image,
        ['sh', '-lc', site.install_command],
        { binds: [`${dirs.app}:/app`], workdir: '/app', onProgress: log }
      );
      log(res.output.slice(-4000) || '(no output)');
      if (res.exitCode !== 0) {
        log(`Install command exited with code ${res.exitCode} - starting anyway`);
      }
      const owner = ownerUid('node');
      await chownRecursive(dirs.app, owner.uid, owner.gid);
    }
    await container.start();

    setStatus(siteId, 'running');
    log('Container is running');

    site = getSite(siteId);
    if (createProxy && allDomains(site).length && npmplus.isEnabled()) {
      log('Configuring NPMplus reverse proxy');
      try {
        const result = await npmplus.syncProxyHost(site);
        db.prepare('UPDATE sites SET npm_proxy_id = ?, npm_cert_id = ?, ssl = ? WHERE id = ?').run(
          result.proxyId,
          result.certId || null,
          result.ssl ? 1 : 0,
          siteId
        );
        log(
          result.ssl
            ? `Proxy host #${result.proxyId} created with a Let's Encrypt certificate`
            : `Proxy host #${result.proxyId} created (no certificate)`
        );
      } catch (err) {
        log(`NPMplus step failed: ${err.message}`);
        log('The site is running; you can retry the proxy from the site page.');
      }
    } else if (createProxy && allDomains(site).length) {
      log('NPMplus is not configured - skipping reverse proxy setup');
    }

    log('Done');
    return getSite(siteId);
  } catch (err) {
    setStatus(siteId, 'error');
    pushProgress(siteId, `ERROR: ${err.message}`);
    throw err;
  } finally {
    setBusy(siteId, false);
  }
}

async function waitForDatabase(dbContainer, log, attempts = 40) {
  for (let i = 0; i < attempts; i += 1) {
    try {
      const res = await docker.exec(dbContainer, [
        'sh',
        '-c',
        'mariadb-admin ping -h 127.0.0.1 --silent || mysqladmin ping -h 127.0.0.1 --silent',
      ]);
      if (res.exitCode === 0) return true;
    } catch (_) {
      /* container may still be booting */
    }
    await new Promise((r) => setTimeout(r, 1500));
    if (i % 5 === 4 && log) log(`Still waiting for the database (${i + 1}/${attempts})`);
  }
  throw new Error('Database did not become ready in time');
}

/* ------------------------------------------------------------------ *
 * Lifecycle actions
 * ------------------------------------------------------------------ */
async function startSite(site) {
  if (site.db_container_id) await docker.startContainer(tpl.dbContainerName(site)).catch(() => {});
  await docker.startContainer(tpl.containerName(site));
  setStatus(site.id, 'running');
}

async function stopSite(site) {
  await docker.stopContainer(tpl.containerName(site));
  if (site.db_container_id) await docker.stopContainer(tpl.dbContainerName(site)).catch(() => {});
  setStatus(site.id, 'stopped');
}

async function restartSite(site) {
  await docker.restartContainer(tpl.containerName(site));
  setStatus(site.id, 'running');
}

/** Recreates the container from the current settings, keeping the site data. */
async function rebuildSite(siteId) {
  const site = getSite(siteId);
  if (!site) throw new Error('Site not found');
  const log = (line) => pushProgress(siteId, line);
  clearProgress(siteId);
  setBusy(siteId, true);
  setStatus(siteId, 'provisioning');
  log('Rebuilding container from current settings');

  try {
    const dirs = siteDirs(site);
    await writeSeedFiles(site);
    const spec = tpl.buildSpec(site, dirs);

    await docker.ensureImage(spec.image, log);
    await docker.removeContainer(spec.name).catch(() => {});
    await docker.ensureNetwork(tpl.networkName(site));

    if (spec.dbCreate && !(await docker.getContainer(spec.dbName))) {
      log('Recreating database container');
      await docker.ensureImage(spec.dbImage, log);
      const dbc = await docker.client().createContainer(spec.dbCreate);
      await dbc.start();
      db.prepare('UPDATE sites SET db_container_id = ? WHERE id = ?').run(dbc.id, siteId);
      await waitForDatabase(spec.dbName, log);
    } else if (spec.dbName) {
      await docker.startContainer(spec.dbName).catch(() => {});
    }

    const container = await docker.client().createContainer(spec.create);
    await container.start();
    db.prepare('UPDATE sites SET container_id = ?, status = ? WHERE id = ?').run(
      container.id,
      'running',
      siteId
    );
    log('Rebuild complete');
    return getSite(siteId);
  } catch (err) {
    setStatus(siteId, 'error');
    log(`ERROR: ${err.message}`);
    throw err;
  } finally {
    setBusy(siteId, false);
  }
}

async function runInstall(site) {
  if (site.type !== 'node') throw new Error('Install commands only apply to Node.js sites');
  const cmd = site.install_command || 'npm install --omit=dev';
  const dirs = siteDirs(site);
  const spec = tpl.buildSpec(site, dirs);

  clearProgress(site.id);
  setBusy(site.id, true);
  pushProgress(site.id, `Running: ${cmd}`);

  try {
    const res = await docker.runOneShot(spec.image, ['sh', '-lc', cmd], {
      binds: [`${dirs.app}:/app`],
      workdir: '/app',
      onProgress: (line) => pushProgress(site.id, line),
    });
    pushProgress(site.id, res.output.slice(-6000) || '(no output)');
    pushProgress(site.id, `Exit code ${res.exitCode}`);

    const owner = ownerUid('node');
    await chownRecursive(dirs.app, owner.uid, owner.gid);

    pushProgress(site.id, 'Restarting the site');
    await docker.restartContainer(tpl.containerName(site)).catch((err) =>
      pushProgress(site.id, `Could not restart: ${err.message}`)
    );
    return res;
  } catch (err) {
    pushProgress(site.id, `ERROR: ${err.message}`);
    throw err;
  } finally {
    setBusy(site.id, false);
  }
}

async function deleteSite(siteId, { deleteFiles = true } = {}) {
  const site = getSite(siteId);
  if (!site) throw new Error('Site not found');

  if (site.npm_proxy_id && npmplus.isEnabled()) {
    try {
      await npmplus.deleteProxyHost(site.npm_proxy_id);
    } catch (err) {
      console.error('[sites] failed to remove NPMplus proxy host:', err.message);
    }
  }

  await docker.removeContainer(tpl.containerName(site)).catch(() => {});
  if (site.db_container_id) await docker.removeContainer(tpl.dbContainerName(site)).catch(() => {});
  await docker.removeNetwork(tpl.networkName(site)).catch(() => {});

  if (deleteFiles) {
    const dirs = siteDirs(site);
    await fsp.rm(dirs.root, { recursive: true, force: true }).catch((err) => {
      console.error('[sites] failed to remove files:', err.message);
    });
  }

  db.prepare('DELETE FROM sites WHERE id = ?').run(siteId);
  clearProgress(siteId);
  return true;
}

/* ------------------------------------------------------------------ *
 * Live status for the dashboard
 * ------------------------------------------------------------------ */
async function statusFor(site) {
  const state = await docker.containerState(tpl.containerName(site));
  let dbState = null;
  if (site.type === 'wordpress') {
    dbState = await docker.containerState(tpl.dbContainerName(site));
  }
  return { state, dbState };
}

async function diskUsage(site) {
  const dirs = siteDirs(site);
  let total = 0;
  const stack = [dirs.app];
  let files = 0;
  while (stack.length && files < 200000) {
    const cur = stack.pop();
    let entries;
    try {
      entries = await fsp.readdir(cur, { withFileTypes: true });
    } catch (_) {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(cur, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile()) {
        files += 1;
        try {
          total += (await fsp.stat(full)).size;
        } catch (_) {
          /* ignore */
        }
      }
    }
  }
  return { bytes: total, files };
}

module.exports = {
  NAME_RE,
  DOMAIN_RE,
  siteDirs,
  getSite,
  getSiteByName,
  listSites,
  canAccess,
  allDomains,
  allocatePort,
  validateNew,
  createSiteRecord,
  provisionSite,
  rebuildSite,
  runInstall,
  startSite,
  stopSite,
  restartSite,
  deleteSite,
  statusFor,
  diskUsage,
  pushProgress,
  getProgress,
  clearProgress,
  setBusy,
  isBusy,
  setStatus,
  writeSeedFiles,
  ownerUid,
  chownRecursive,
};
