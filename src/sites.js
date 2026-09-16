'use strict';

const fs = require('fs');
const net = require('net');
const http = require('http');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const config = require('./config');
const { db, audit, getNumericSetting } = require('./db');
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
function portRange() {
  return {
    start: getNumericSetting('port_range_start', config.portRangeStart),
    end: getNumericSetting('port_range_end', config.portRangeEnd),
  };
}

function allocatePort() {
  const used = new Set(db.prepare('SELECT port FROM sites').all().map((r) => r.port));
  const { start, end } = portRange();
  for (let p = start; p <= end; p += 1) {
    if (!used.has(p)) return p;
  }
  throw new Error(
    `No free ports left between ${start} and ${end}. Widen the range in Settings, or delete a site.`
  );
}

/** Which site, if any, already holds this port. */
function siteUsingPort(port, excludeSiteId) {
  return db
    .prepare('SELECT id, name FROM sites WHERE port = ? AND id IS NOT ?')
    .get(port, excludeSiteId || null);
}

/**
 * Checks a user-supplied host port: valid number, not taken by another site,
 * and not already bound by something else on this machine.
 */
async function checkHostPort(port, excludeSiteId) {
  const parsed = parseInt(port, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    return { ok: false, error: 'Port must be a number between 1 and 65535.' };
  }
  if (parsed < 1024) {
    return {
      ok: false,
      error: `Port ${parsed} is reserved for system services. Pick something above 1024.`,
    };
  }
  if (parsed === config.port || parsed === getNumericSetting('panel_port', config.port)) {
    return { ok: false, error: `Port ${parsed} is the control panel's own port.` };
  }

  const clash = siteUsingPort(parsed, excludeSiteId);
  if (clash) {
    return { ok: false, error: `Port ${parsed} is already used by the site "${clash.name}".` };
  }

  const free = await portIsFree(parsed, excludeSiteId);
  if (!free) {
    return {
      ok: false,
      error: `Something else on this machine is already listening on port ${parsed}.`,
    };
  }
  return { ok: true, port: parsed };
}

/**
 * True when nothing is listening on the port. A port held by this site's own
 * container counts as free, since that container is about to be replaced.
 */
function portIsFree(port, excludeSiteId) {
  return new Promise((resolve) => {
    const tester = net
      .createServer()
      .once('error', async (err) => {
        if (err.code !== 'EADDRINUSE') return resolve(true);
        if (!excludeSiteId) return resolve(false);
        const own = db.prepare('SELECT port FROM sites WHERE id = ?').get(excludeSiteId);
        return resolve(Boolean(own && own.port === port));
      })
      .once('listening', () => tester.close(() => resolve(true)))
      .listen(port, '0.0.0.0');
  });
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

  // An explicitly chosen port must already have been validated by the caller.
  const port = input.port ? parseInt(input.port, 10) : allocatePort();
  const isWp = type === 'wordpress';
  const dbPassword = crypto.randomBytes(18).toString('base64url');

  const defaults = {
    static: { runtime: '', start: '', install: '', appPort: 80 },
    php: { runtime: input.runtime_version || '8.3', start: '', install: '', appPort: 80 },
    wordpress: { runtime: input.runtime_version || '8.3', start: '', install: '', appPort: 80 },
    node: {
      runtime: input.runtime_version || '22',
      start: input.start_command || 'npm start',
      install: input.install_command || 'npm install --omit=dev',
      appPort: 3000,
    },
  }[type];

  const appPort = parseInt(input.app_port, 10) || defaults.appPort;

  const info = db
    .prepare(
      `INSERT INTO sites
        (name, domain, extra_domains, type, owner_id, port, runtime_version,
         install_command, start_command, app_port, env_json, memory_mb, cpu_limit,
         db_name, db_user, db_password, custom_image, extra_volumes, extra_labels,
         docker_network, status)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'creating')`
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
      appPort,
      input.env_json || '{}',
      parseInt(input.memory_mb || '0', 10) || 0,
      parseFloat(input.cpu_limit || '0') || 0,
      isWp ? 'wordpress' : null,
      isWp ? 'wp_user' : null,
      isWp ? dbPassword : null,
      String(input.custom_image || '').trim(),
      String(input.extra_volumes || ''),
      String(input.extra_labels || '{}'),
      String(input.docker_network || '').trim()
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

  const appPort = tpl.appPortFor(site);

  if (site.type === 'static') {
    await writeManaged(dirs, 'nginx-site.conf', tpl.nginxConf(appPort));
    await seedOnce(path.join(dirs.app, 'index.html'), tpl.seedIndexHtml(site));
  }

  if (site.type === 'php' || site.type === 'wordpress') {
    await seedOnce(path.join(dirs.conf, 'php-custom.ini'), tpl.DEFAULT_PHP_INI);
    await writeManaged(dirs, 'apache-ports.conf', tpl.apachePortsConf(appPort));
    await writeManaged(dirs, 'apache-vhost.conf', tpl.apacheVhostConf(appPort));
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

/**
 * Writes a config file the panel generates, without ever destroying user edits.
 *
 * A hash of the last generated content is kept alongside the file. The file is
 * only rewritten when what is on disk still matches that hash, i.e. nobody has
 * touched it. Once the user edits it, the panel stops overwriting it and the
 * file is theirs - so changing the internal port later will not take effect
 * until they update it themselves, which is the safer failure.
 */
async function writeManaged(dirs, filename, contents) {
  const file = path.join(dirs.conf, filename);
  const hashFile = path.join(dirs.conf, `.${filename}.hash`);
  const hashOf = (text) => crypto.createHash('sha256').update(text).digest('hex');

  if (fs.existsSync(file)) {
    let recorded = null;
    try {
      recorded = (await fsp.readFile(hashFile, 'utf8')).trim();
    } catch (_) {
      recorded = null;
    }
    const current = hashOf(await fsp.readFile(file, 'utf8'));

    // No hash on record means this file predates managed config - it may well
    // contain edits made before the panel started tracking them. Adopt it as
    // the user's and never overwrite it.
    if (!recorded) {
      await fsp.writeFile(hashFile, current);
      return false;
    }

    if (recorded !== current) return false; // user-edited, leave alone
    if (current === hashOf(contents)) return false; // already up to date
  }

  await fsp.writeFile(file, contents);
  await fsp.writeFile(hashFile, hashOf(contents));
  return true;
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

    if (tpl.ownsNetwork(site)) {
      log('Ensuring Docker network');
      await docker.ensureNetwork(tpl.networkName(site));
    } else {
      log(`Using existing Docker network ${tpl.networkName(site)}`);
    }

    const spec = tpl.buildSpec(site, dirs);

    if (spec.dbImage) {
      log(`Preparing database image ${spec.dbImage}`);
      await docker.ensureImage(spec.dbImage, log);
    }
    log(`Preparing image ${spec.image}`);
    await ensureSiteImage(site, log);
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
        if (err.existingProxy) {
          log(
            'Left it untouched. Use "Create proxy + SSL" on the site page to take it over ' +
              'deliberately, or point this site at a different domain.'
          );
        } else {
          log('The site is running; you can retry the proxy from the site page.');
        }
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
/**
 * Bakes the site's requested OS packages into an image of its own.
 *
 * Must happen before the container is created, because the container is
 * created from the image. Running an install inside the container instead
 * would work exactly once: the next rebuild recreates it from the base image
 * and the packages are gone again.
 */
async function ensureSiteImage(site, log) {
  const packages = tpl.systemPackages(site);
  if (!packages.length) return;
  await docker.buildImageWithPackages(
    tpl.baseImageFor(site),
    packages,
    tpl.derivedImageName(site),
    log
  );
}

/**
 * True when a Node site has a package.json but no installed dependencies.
 *
 * This is the state every Node deploy passes through, and on its own it is a
 * dead end: the container exits immediately with "Cannot find module ...", and
 * because the shell attaches to a running container, there is nowhere to go and
 * run the install from. The panel has to notice and handle it.
 */
function needsDependencies(site) {
  if (site.type !== 'node') return false;
  const dirs = siteDirs(site);
  if (!fs.existsSync(path.join(dirs.app, 'package.json'))) return false;
  return !fs.existsSync(path.join(dirs.app, 'node_modules'));
}

async function startSite(site) {
  if (site.db_container_id) await docker.startContainer(tpl.dbContainerName(site)).catch(() => {});

  // Install first if the dependencies are missing, rather than starting a
  // container that is certain to exit. Doing it automatically is the whole
  // point: uploading a project without node_modules is the normal way to
  // deploy, not a mistake to be reported back to the user.
  if (needsDependencies(site)) {
    pushProgress(site.id, 'No node_modules found - installing dependencies first');
    await runInstall(site, { restart: false }).catch((err) => {
      pushProgress(site.id, `Install failed: ${err.message}`);
      throw new Error(
        `Dependencies could not be installed: ${err.message}. ` +
        'The site was not started because it would exit immediately.'
      );
    });
  }

  await docker.startContainer(tpl.containerName(site));
  setStatus(site.id, 'running');
}

async function stopSite(site) {
  await docker.stopContainer(tpl.containerName(site));
  if (site.db_container_id) await docker.stopContainer(tpl.dbContainerName(site)).catch(() => {});
  setStatus(site.id, 'stopped');
}

async function restartSite(site) {
  if (needsDependencies(site)) {
    pushProgress(site.id, 'No node_modules found - installing dependencies first');
    await runInstall(site, { restart: false });
  }
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

    await ensureSiteImage(site, log);
    await docker.ensureImage(spec.image, log);
    await docker.removeContainer(spec.name).catch(() => {});
    if (tpl.ownsNetwork(site)) await docker.ensureNetwork(tpl.networkName(site));

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

async function runInstall(site, opts) {
  const restart = !opts || opts.restart !== false;
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

    if (res.exitCode !== 0) {
      throw new Error(`the install command exited with code ${res.exitCode}`);
    }

    if (restart) {
      pushProgress(site.id, 'Restarting the site');
      await docker.restartContainer(tpl.containerName(site)).catch((err) =>
        pushProgress(site.id, `Could not restart: ${err.message}`)
      );
    }
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
  // Never delete a network the user pointed us at - it may serve other things.
  if (tpl.ownsNetwork(site)) await docker.removeNetwork(tpl.networkName(site)).catch(() => {});

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
  // Surfaced so the UI can explain an exited Node container rather than just
  // reporting it as stopped: missing dependencies is by far the most common
  // reason, and it is fixable in one click.
  //
  // "running but not answering" is the other state worth naming. A container
  // can be perfectly healthy while the app inside it is unreachable, and the
  // preview then shows a blank page with nothing to explain it.
  const probe = state === 'running' ? await probeSite(site.port) : {};
  return {
    state,
    dbState,
    reachable: state === 'running' ? probe.answers : null,
    framingRefusedBy: probe.framingRefusedBy || null,
    needsDependencies: needsDependencies(site),
  };
}

/**
 * Asks the site for its headers, to learn two things the UI cannot guess.
 *
 * Whether anything answers at all, and whether the site allows being shown in
 * a frame. The second matters because a site that sends X-Frame-Options: DENY
 * - which many frameworks do by default - renders as a blank white rectangle
 * in the preview, with no error anywhere. That is indistinguishable from a
 * broken panel, and it is not something the panel can or should override: the
 * header is the site's own decision. It can only be reported.
 */
function probeSite(port, timeoutMs = 2000) {
  return new Promise((resolve) => {
    if (!port) return resolve({ answers: false });

    const req = http.request(
      { host: '127.0.0.1', port, method: 'HEAD', path: '/', timeout: timeoutMs },
      (res) => {
        const xfo = String(res.headers['x-frame-options'] || '').toLowerCase();
        const csp = String(res.headers['content-security-policy'] || '').toLowerCase();
        const ancestors = (csp.match(/frame-ancestors([^;]*)/) || [])[1];

        let framingRefusedBy = null;
        if (xfo.includes('deny') || xfo.includes('sameorigin')) {
          framingRefusedBy = `X-Frame-Options: ${xfo}`;
        } else if (ancestors !== undefined && /'none'/.test(ancestors)) {
          framingRefusedBy = "Content-Security-Policy: frame-ancestors 'none'";
        }

        res.resume();
        resolve({ answers: true, framingRefusedBy });
      }
    );
    req.on('timeout', () => { req.destroy(); resolve({ answers: false }); });
    req.on('error', () => resolve({ answers: false }));
    req.end();
    return undefined;
  });
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
  portRange,
  siteUsingPort,
  checkHostPort,
  portIsFree,
  validateNew,
  createSiteRecord,
  provisionSite,
  rebuildSite,
  runInstall,
  needsDependencies,
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
  writeManaged,
  ownerUid,
  chownRecursive,
};
