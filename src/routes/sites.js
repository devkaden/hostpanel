'use strict';

const express = require('express');

const config = require('../config');
const { db, audit } = require('../db');
const sites = require('../sites');
const docker = require('../docker');
const npmplus = require('../npmplus');
const tpl = require('../site-templates');
const terminal = require('../terminal');
const { loadSite, wrap } = require('../middleware');
const { humanBytes } = require('../netutil');

const router = express.Router();

/* ------------------------------------------------------------------ *
 * New site
 * ------------------------------------------------------------------ */
router.get('/sites/new', (req, res) => {
  res.render('site-new', {
    title: 'New site',
    errors: [],
    form: { type: req.query.type || 'static', runtime_version: '', app_port: 3000 },
    config,
    owners:
      req.user.role === 'admin'
        ? db.prepare('SELECT id, username FROM users WHERE active = 1 ORDER BY username').all()
        : [],
    npmplusOn: npmplus.isEnabled(),
  });
});

router.post(
  '/sites',
  wrap(async (req, res) => {
    let site;
    try {
      site = sites.createSiteRecord(req.body, req.user);
    } catch (err) {
      return res.status(400).render('site-new', {
        title: 'New site',
        errors: err.validation || [err.message],
        form: req.body,
        config,
        owners:
          req.user.role === 'admin'
            ? db.prepare('SELECT id, username FROM users WHERE active = 1 ORDER BY username').all()
            : [],
        npmplusOn: npmplus.isEnabled(),
      });
    }

    audit(req, 'site.create', site.name, { type: site.type, port: site.port });
    sites.clearProgress(site.id);
    sites.pushProgress(site.id, `Creating ${site.type} site "${site.name}" on port ${site.port}`);

    // Provision in the background so the browser can watch the progress stream.
    sites
      .provisionSite(site.id, { createProxy: Boolean(req.body.setup_proxy) })
      .catch((err) => console.error(`[sites] provisioning ${site.name} failed:`, err.message));

    return res.redirect(`/sites/${site.id}?provisioning=1`);
  })
);

/* ------------------------------------------------------------------ *
 * Site overview
 * ------------------------------------------------------------------ */
router.get(
  '/sites/:id',
  loadSite,
  wrap(async (req, res) => {
    const site = req.site;
    const live = await sites.statusFor(site);
    const stats = live.state === 'running' ? await docker.stats(tpl.containerName(site)) : null;
    const disk = await sites.diskUsage(site);
    const inspectInfo = await docker.inspect(tpl.containerName(site));

    let proxyHost = null;
    let proxyError = null;
    if (site.npm_proxy_id && npmplus.isEnabled()) {
      try {
        proxyHost = await npmplus.getProxyHost(site.npm_proxy_id);
      } catch (err) {
        proxyError = err.message;
      }
    }

    res.render('site', {
      title: site.name,
      site,
      live,
      stats,
      disk: { ...disk, human: humanBytes(disk.bytes) },
      dirs: sites.siteDirs(site),
      domains: sites.allDomains(site),
      containerName: tpl.containerName(site),
      dbContainerName: site.type === 'wordpress' ? tpl.dbContainerName(site) : null,
      image: tpl.imageFor(site),
      inspectInfo,
      proxyHost,
      proxyError,
      npmplusOn: npmplus.isEnabled(),
      npmplusConfigured: npmplus.isConfigured(),
      provisioning: req.query.provisioning === '1',
      config,
      hostShell: terminal.hostShellAvailable(),
      owners:
        req.user.role === 'admin'
          ? db.prepare('SELECT id, username FROM users WHERE active = 1 ORDER BY username').all()
          : [],
    });
  })
);

/* ------------------------------------------------------------------ *
 * Provisioning progress (SSE)
 * ------------------------------------------------------------------ */
router.get('/sites/:id/progress', loadSite, (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  let sent = 0;
  let finished = false;
  let interval;
  let heartbeat;

  const stop = () => {
    clearInterval(interval);
    clearInterval(heartbeat);
  };

  const push = () => {
    const lines = sites.getProgress(req.site.id);
    for (; sent < lines.length; sent += 1) {
      res.write(`data: ${JSON.stringify(lines[sent])}\n\n`);
    }
    // "done" fires exactly once, when nothing is running for this site any more.
    if (!finished && !sites.isBusy(req.site.id)) {
      finished = true;
      const fresh = sites.getSite(req.site.id);
      res.write(`event: done\ndata: ${JSON.stringify({ status: fresh ? fresh.status : 'gone' })}\n\n`);
      stop();
      res.end();
    }
  };

  // Give a just-started background job a moment to mark itself busy.
  setTimeout(() => {
    push();
    interval = setInterval(push, 1000);
  }, 400);
  heartbeat = setInterval(() => res.write(': ping\n\n'), 20000);
  req.on('close', stop);
});

/* ------------------------------------------------------------------ *
 * Lifecycle actions
 * ------------------------------------------------------------------ */
const ACTIONS = {
  start: async (site) => sites.startSite(site),
  stop: async (site) => sites.stopSite(site),
  restart: async (site) => sites.restartSite(site),
  rebuild: async (site) => sites.rebuildSite(site.id),
  install: async (site) => sites.runInstall(site),
  reprovision: async (site) => sites.provisionSite(site.id, { createProxy: false }),
};

router.post(
  '/sites/:id/action/:action',
  loadSite,
  wrap(async (req, res) => {
    const action = req.params.action;
    const handler = ACTIONS[action];
    if (!handler) return res.status(400).json({ error: 'Unknown action' });

    audit(req, `site.${action}`, req.site.name);

    if (action === 'rebuild' || action === 'reprovision' || action === 'install') {
      sites.clearProgress(req.site.id);
      handler(req.site).catch((err) =>
        sites.pushProgress(req.site.id, `ERROR: ${err.message}`)
      );
      return res.json({ ok: true, background: true });
    }

    try {
      await handler(req.site);
      return res.json({ ok: true, state: (await sites.statusFor(sites.getSite(req.site.id))).state });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  })
);

/* ------------------------------------------------------------------ *
 * Settings
 * ------------------------------------------------------------------ */
router.post(
  '/sites/:id/settings',
  loadSite,
  wrap(async (req, res) => {
    const site = req.site;
    const body = req.body;
    const errors = [];

    const domain = String(body.domain || '').trim().toLowerCase();
    if (domain && !sites.DOMAIN_RE.test(domain)) errors.push('Domain is not a valid hostname.');

    const extras = String(body.extra_domains || '')
      .split(/[\s,]+/)
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean);
    for (const d of extras) if (!sites.DOMAIN_RE.test(d)) errors.push(`"${d}" is not a valid hostname.`);

    let envJson = site.env_json;
    if (body.env_json !== undefined) {
      const raw = String(body.env_json).trim() || '{}';
      try {
        const parsed = JSON.parse(raw);
        if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) {
          errors.push('Environment variables must be a JSON object.');
        } else {
          envJson = JSON.stringify(parsed);
        }
      } catch (_) {
        errors.push('Environment variables are not valid JSON.');
      }
    }

    const appPort = parseInt(body.app_port || site.app_port, 10);
    if (site.type === 'node' && (!Number.isInteger(appPort) || appPort < 1 || appPort > 65535)) {
      errors.push('App port must be between 1 and 65535.');
    }

    if (errors.length) return res.status(400).json({ error: errors.join(' ') });

    db.prepare(
      `UPDATE sites SET domain = ?, extra_domains = ?, runtime_version = ?, install_command = ?,
         start_command = ?, app_port = ?, env_json = ?, memory_mb = ?, cpu_limit = ?,
         notes = ?, owner_id = ? WHERE id = ?`
    ).run(
      domain,
      extras.join(','),
      String(body.runtime_version || site.runtime_version || ''),
      String(body.install_command !== undefined ? body.install_command : site.install_command),
      String(body.start_command !== undefined ? body.start_command : site.start_command),
      appPort,
      envJson,
      parseInt(body.memory_mb || '0', 10) || 0,
      parseFloat(body.cpu_limit || '0') || 0,
      String(body.notes !== undefined ? body.notes : site.notes).slice(0, 4000),
      req.user.role === 'admin' && body.owner_id ? parseInt(body.owner_id, 10) : site.owner_id,
      site.id
    );

    audit(req, 'site.settings', site.name);
    return res.json({
      ok: true,
      needsRebuild: true,
      message: 'Saved. Rebuild the container for image, port, env or resource changes to take effect.',
    });
  })
);

/* ------------------------------------------------------------------ *
 * NPMplus proxy
 * ------------------------------------------------------------------ */
router.post(
  '/sites/:id/proxy',
  loadSite,
  wrap(async (req, res) => {
    if (!npmplus.isEnabled()) {
      return res.status(400).json({ error: 'NPMplus integration is turned off in Settings.' });
    }
    const site = sites.getSite(req.site.id);
    const requestSsl = req.body.ssl !== 'false' && req.body.ssl !== false;
    try {
      const result = await npmplus.syncProxyHost(site, { requestSsl });
      db.prepare('UPDATE sites SET npm_proxy_id = ?, npm_cert_id = ?, ssl = ? WHERE id = ?').run(
        result.proxyId,
        result.certId || null,
        result.ssl ? 1 : 0,
        site.id
      );
      audit(req, 'site.proxy_sync', site.name, { proxyId: result.proxyId, ssl: result.ssl });
      return res.json({ ok: true, ...result });
    } catch (err) {
      if (err.partial && err.proxyId) {
        db.prepare('UPDATE sites SET npm_proxy_id = ?, ssl = 0 WHERE id = ?').run(err.proxyId, site.id);
      }
      return res.status(502).json({ error: err.message, partial: Boolean(err.partial) });
    }
  })
);

router.post(
  '/sites/:id/proxy/delete',
  loadSite,
  wrap(async (req, res) => {
    const site = sites.getSite(req.site.id);
    if (!site.npm_proxy_id) return res.status(400).json({ error: 'No proxy host is linked.' });
    try {
      await npmplus.deleteProxyHost(site.npm_proxy_id);
      db.prepare('UPDATE sites SET npm_proxy_id = NULL, npm_cert_id = NULL, ssl = 0 WHERE id = ?').run(
        site.id
      );
      audit(req, 'site.proxy_delete', site.name);
      return res.json({ ok: true });
    } catch (err) {
      return res.status(502).json({ error: err.message });
    }
  })
);

/* ------------------------------------------------------------------ *
 * Delete
 * ------------------------------------------------------------------ */
router.post(
  '/sites/:id/delete',
  loadSite,
  wrap(async (req, res) => {
    const site = req.site;
    if (String(req.body.confirm || '') !== site.name) {
      return res.status(400).json({ error: 'Type the site name exactly to confirm.' });
    }
    const deleteFiles = req.body.delete_files !== 'false' && req.body.delete_files !== false;
    await sites.deleteSite(site.id, { deleteFiles });
    audit(req, 'site.delete', site.name, { deleteFiles });
    return res.json({ ok: true, redirect: '/' });
  })
);

/* ------------------------------------------------------------------ *
 * Terminal page
 * ------------------------------------------------------------------ */
router.get('/sites/:id/terminal', loadSite, (req, res) => {
  res.render('terminal', {
    title: `${req.site.name} - terminal`,
    site: req.site,
    target: req.query.target === 'db' ? 'db' : 'app',
    containerName:
      req.query.target === 'db' && req.site.type === 'wordpress'
        ? tpl.dbContainerName(req.site)
        : tpl.containerName(req.site),
    isHostShell: false,
  });
});

router.get('/host/terminal', (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).render('error', {
      title: 'Forbidden',
      message: 'The host shell is restricted to administrators.',
    });
  }
  return res.render('terminal', {
    title: 'Host shell',
    site: null,
    target: 'host',
    containerName: 'panel host',
    isHostShell: true,
    hostShellAvailable: terminal.hostShellAvailable(),
  });
});

module.exports = router;
