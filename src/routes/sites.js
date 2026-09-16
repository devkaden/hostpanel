'use strict';

const express = require('express');

const config = require('../config');
const { db, audit, getSetting } = require('../db');
const sites = require('../sites');
const docker = require('../docker');
const npmplus = require('../npmplus');
const tpl = require('../site-templates');
const terminal = require('../terminal');
const templates = require('../templates');
const { loadSite, wrap } = require('../middleware');
const preview = require('../preview');
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
    templates: templates.list(),
  });
});

router.post(
  '/sites',
  wrap(async (req, res) => {
    let site;
    try {
      // A preset fills in anything the form left blank.
      if (req.body.template_id) req.body = templates.applyTo(req.body, req.body.template_id);

      // A hand-picked host port has to clear the same checks as an edit.
      if (String(req.body.port || '').trim()) {
        const verdict = await sites.checkHostPort(req.body.port, null);
        if (!verdict.ok) {
          const err = new Error(verdict.error);
          err.validation = [verdict.error];
          throw err;
        }
        req.body.port = verdict.port;
      }
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
        templates: templates.list(),
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

/** Live port validation for the new-site and settings forms. */
router.get(
  '/api/ports/check',
  wrap(async (req, res) => {
    const excludeId = req.query.site ? parseInt(req.query.site, 10) : null;
    if (excludeId) {
      const site = sites.getSite(excludeId);
      if (!site || !sites.canAccess(req.user, site)) {
        return res.status(403).json({ ok: false, error: 'Access denied' });
      }
    }
    return res.json(await sites.checkHostPort(req.query.port, excludeId));
  })
);

router.get(
  '/api/ports/suggest',
  wrap(async (req, res) => {
    try {
      res.json({ port: sites.allocatePort(), range: sites.portRange() });
    } catch (err) {
      res.status(409).json({ error: err.message });
    }
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
    let proxyIssues = [];
    if (site.npm_proxy_id && npmplus.isEnabled()) {
      try {
        proxyHost = await npmplus.getProxyHost(site.npm_proxy_id);
        // Diagnosed here rather than on a button press, so the page says what
        // is wrong before anyone has to wonder why the domain is not working.
        proxyIssues = npmplus.diagnoseProxy(site, proxyHost).map((i) => i.says);
      } catch (err) {
        proxyError = err.message;
      }
    }

    const domainList = sites.allDomains(site);
    const previewDomainUrl = domainList.length
      ? `http${site.ssl ? 's' : ''}://${domainList[0]}/`
      : '';

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
      proxyIssues,
      npmplusOn: npmplus.isEnabled(),
      npmplusConfigured: npmplus.isConfigured(),
      provisioning: req.query.provisioning === '1',
      busy: sites.isBusy(site.id),
      hostIp: getSetting('host_ip') || '',
      /*
       * Two preview addresses, because neither works on its own.
       *
       * The direct one hits the container by port, so it works before DNS or
       * the reverse proxy exist. But it is plain http, and a browser will not
       * embed an http frame in a page served over https - which is exactly
       * what happens once the panel itself is behind the reverse proxy. The
       * frame is blocked silently, with no error and no console message: a
       * blank white rectangle.
       *
       * So when the site has a domain, that is the preferred source, since it
       * matches the panel's own scheme. The direct URL stays available as the
       * fallback and is what gets shown before a domain is configured.
       */
      previewUrl: getSetting('host_ip') ? `http://${getSetting('host_ip')}:${site.port}/` : '',
      // Minted per page load, so a preview left open in a tab for days stops
      // working rather than staying a live door to the site.
      previewToken: preview.issueToken(site.id, req.user.id),
      previewDomainUrl,
      // Checked against the address the browser will actually be asked to
      // frame, which is the proxied one whenever a domain exists.
      previewProbe: previewDomainUrl ? await sites.probeUrl(previewDomainUrl) : null,
      // The origin to name in a frame-ancestors rule, taken from the request so
      // it is right whether the panel is reached by IP or through the proxy.
      panelOrigin: `${req.protocol}://${req.get('host')}`,
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

  // Tell the client up front whether anything is actually running, so it can
  // decide whether the finish is worth acting on.
  res.write(`event: state\ndata: ${JSON.stringify({ busy: sites.isBusy(req.site.id) })}\n\n`);

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
/*
 * A null-prototype object, and looked up with hasOwnProperty below.
 *
 * A plain object inherits from Object.prototype, so ACTIONS["constructor"] and
 * ACTIONS["toString"] are both functions - and the action comes straight out of
 * the URL. The lookup would find something that was never meant to be callable
 * here and call it with a site record.
 */
const ACTIONS = Object.assign(Object.create(null), {
  start: async (site) => sites.startSite(site),
  stop: async (site) => sites.stopSite(site),
  restart: async (site) => sites.restartSite(site),
  rebuild: async (site) => sites.rebuildSite(site.id),
  install: async (site) => sites.runInstall(site),
  reprovision: async (site) => sites.provisionSite(site.id, { createProxy: false }),
});

router.post(
  '/sites/:id/action/:action',
  loadSite,
  wrap(async (req, res) => {
    const action = String(req.params.action || '');
    const handler = Object.prototype.hasOwnProperty.call(ACTIONS, action) ? ACTIONS[action] : null;
    if (typeof handler !== 'function') return res.status(400).json({ error: 'Unknown action' });

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

    /*
     * Absent means "unchanged", not "empty".
     *
     * This form is also posted a field at a time - the framing checkbox beside
     * Check & Fix does exactly that - and reading a missing field as an empty
     * string would quietly delete the site's domain as a side effect of
     * saving something else.
     */
    const domain = String(body.domain !== undefined ? body.domain : site.domain || '')
      .trim()
      .toLowerCase();
    if (domain && !sites.DOMAIN_RE.test(domain)) errors.push('Domain is not a valid hostname.');

    const extras = String(
      body.extra_domains !== undefined ? body.extra_domains : site.extra_domains || ''
    )
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
    if (!Number.isInteger(appPort) || appPort < 1 || appPort > 65535) {
      errors.push('Internal port must be between 1 and 65535.');
    }

    // Host port: only re-validate when it actually changed.
    let hostPort = site.port;
    if (body.port !== undefined && String(body.port).trim() !== String(site.port)) {
      const verdict = await sites.checkHostPort(body.port, site.id);
      if (!verdict.ok) errors.push(verdict.error);
      else hostPort = verdict.port;
    }

    // Advanced Docker options.
    let extraLabels = site.extra_labels;
    if (body.extra_labels !== undefined) {
      const raw = String(body.extra_labels).trim() || '{}';
      try {
        const parsed = JSON.parse(raw);
        if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) {
          errors.push('Container labels must be a JSON object.');
        } else {
          extraLabels = JSON.stringify(parsed);
        }
      } catch (_) {
        errors.push('Container labels are not valid JSON.');
      }
    }

    const customImage = String(
      body.custom_image !== undefined ? body.custom_image : site.custom_image
    ).trim();
    if (customImage && !/^[\w.\-\/:@]+$/.test(customImage)) {
      errors.push('That does not look like a valid Docker image name.');
    }

    const dockerNetwork = String(
      body.docker_network !== undefined ? body.docker_network : site.docker_network
    ).trim();
    if (dockerNetwork && !/^[\w.\-]+$/.test(dockerNetwork)) {
      errors.push('That does not look like a valid Docker network name.');
    }

    const extraVolumes = String(
      body.extra_volumes !== undefined ? body.extra_volumes : site.extra_volumes
    );

    if (errors.length) return res.status(400).json({ error: errors.join(' ') });

    db.prepare(
      `UPDATE sites SET domain = ?, extra_domains = ?, runtime_version = ?, install_command = ?,
         start_command = ?, app_port = ?, port = ?, env_json = ?, memory_mb = ?, cpu_limit = ?,
         notes = ?, owner_id = ?, custom_image = ?, extra_volumes = ?, extra_labels = ?,
         docker_network = ?, system_packages = ?, allow_framing = ? WHERE id = ?`
    ).run(
      domain,
      extras.join(','),
      String(body.runtime_version || site.runtime_version || ''),
      String(body.install_command !== undefined ? body.install_command : site.install_command),
      String(body.start_command !== undefined ? body.start_command : site.start_command),
      appPort,
      hostPort,
      envJson,
      parseInt(body.memory_mb || '0', 10) || 0,
      parseFloat(body.cpu_limit || '0') || 0,
      String(body.notes !== undefined ? body.notes : site.notes).slice(0, 4000),
      req.user.role === 'admin' && body.owner_id ? parseInt(body.owner_id, 10) : site.owner_id,
      customImage,
      extraVolumes,
      extraLabels,
      dockerNetwork,
      String(
        body.system_packages !== undefined ? body.system_packages : site.system_packages
      ).slice(0, 500),
      body.allow_framing === undefined
        ? site.allow_framing || 0
        : body.allow_framing === true || body.allow_framing === 'true' || body.allow_framing === '1'
          ? 1
          : 0,
      site.id
    );

    audit(req, 'site.settings', site.name);

    /*
     * Keep the proxy host in step, without being asked.
     *
     * Changing a site's port or its domains here is exactly what leaves the
     * reverse proxy pointing somewhere that no longer answers - and the
     * symptom arrives later, as "the domain stopped working", with nothing to
     * connect it back to this form. The panel created that host and knows what
     * it should say, so it corrects it now rather than waiting to be told.
     *
     * Only a host the panel is already linked to: taking over someone else's
     * is a decision, and decisions do not belong in a side effect.
     */
    let proxyNote = '';
    const moved =
      String(domain) !== String(site.domain || '') ||
      extras.join(',') !== String(site.extra_domains || '') ||
      Number(hostPort) !== Number(site.port);

    if (moved && site.npm_proxy_id && npmplus.isEnabled()) {
      try {
        const updated = sites.getSite(site.id);
        const repair = await npmplus.repairProxy(updated);
        if (repair.fixed.length) {
          proxyNote = ' The reverse proxy was updated to match.';
          audit(req, 'site.proxy_repair', site.name, repair.fixed.join(' '));
        }
      } catch (err) {
        proxyNote = ` The reverse proxy could not be updated: ${err.message}`;
      }
    }

    return res.json({
      ok: true,
      needsRebuild: true,
      message:
        'Saved. Rebuild the container for image, port, env or resource changes to take effect.' +
        proxyNote,
    });
  })
);

/**
 * Renames a site.
 *
 * Its own endpoint rather than a field on the settings form, because it is not
 * a saved value: the container is replaced and the site's directory moves. A
 * field that quietly did all that when you tabbed out of it would be a trap.
 */
router.post(
  '/sites/:id/rename',
  loadSite,
  wrap(async (req, res) => {
    const site = sites.getSite(req.site.id);
    const name = String(req.body.name || '').trim().toLowerCase();
    if (sites.isBusy(site.id)) {
      return res.status(409).json({ error: 'This site is busy. Wait for the current job to finish.' });
    }
    try {
      const renamed = await sites.renameSite(site.id, name);
      audit(req, 'site.rename', site.name, `now ${renamed.name}`);
      return res.json({ ok: true, name: renamed.name });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
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
    const adopt = req.body.adopt === true || req.body.adopt === 'true';
    try {
      const result = await npmplus.syncProxyHost(site, { requestSsl, adopt });
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
      // An existing proxy host is a question for the user, not a failure.
      if (err.existingProxy) {
        return res.status(409).json({ error: err.message, existingProxy: err.existingProxy });
      }
      return res.status(502).json({ error: err.message, partial: Boolean(err.partial) });
    }
  })
);

/**
 * Checks a site's proxy host against what the site actually needs, and fixes
 * whatever has drifted.
 *
 * Separate from /proxy (which is "create or re-sync, and get a certificate")
 * because the common case is different: nothing about the site has changed,
 * something about the proxy has, and what the user wants is to be told what is
 * wrong and have it put right - not to re-run the whole certificate dance.
 */
router.get(
  '/api/sites/:id/proxy/check',
  loadSite,
  wrap(async (req, res) => {
    const site = sites.getSite(req.site.id);
    return res.json(await npmplus.checkProxy(site));
  })
);

router.post(
  '/sites/:id/proxy/repair',
  loadSite,
  wrap(async (req, res) => {
    if (!npmplus.isEnabled()) {
      return res.status(400).json({ error: 'NPMplus integration is turned off in Settings.' });
    }
    const site = sites.getSite(req.site.id);
    const adopt = req.body.adopt === true || req.body.adopt === 'true';
    const requestSsl = req.body.ssl === true || req.body.ssl === 'true';
    try {
      const result = await npmplus.repairProxy(site, { adopt, requestSsl });
      db.prepare('UPDATE sites SET npm_proxy_id = ?, npm_cert_id = ?, ssl = ? WHERE id = ?').run(
        result.proxyId,
        result.certId || null,
        result.ssl ? 1 : 0,
        site.id
      );
      audit(req, 'site.proxy_repair', site.name, result.fixed.join(' '));
      return res.json({
        ok: true,
        ...result,
        message: result.fixed.length
          ? `Fixed ${result.fixed.length} thing${result.fixed.length === 1 ? '' : 's'}.`
          : 'Nothing needed fixing.',
      });
    } catch (err) {
      if (err.existingProxy) {
        return res.status(409).json({ error: err.message, existingProxy: err.existingProxy });
      }
      return res.status(502).json({ error: err.message });
    }
  })
);

/**
 * Turns HTTPS on or off.
 *
 * One switch instead of the old pair of buttons ("Re-sync proxy + SSL" and
 * "Sync without SSL"), which described how the panel talks to NPMplus rather
 * than what the user wanted, and gave no way to turn a certificate off again
 * short of deleting the proxy host.
 */
router.post(
  '/sites/:id/proxy/ssl',
  loadSite,
  wrap(async (req, res) => {
    if (!npmplus.isEnabled()) {
      return res.status(400).json({ error: 'NPMplus integration is turned off in Settings.' });
    }
    const site = sites.getSite(req.site.id);
    const enabled = req.body.enabled === true || req.body.enabled === 'true' || req.body.enabled === 'on';
    try {
      const result = await npmplus.setSsl(site, enabled);
      db.prepare('UPDATE sites SET npm_cert_id = ?, ssl = ? WHERE id = ?').run(
        result.certId || null,
        result.ssl ? 1 : 0,
        site.id
      );
      audit(req, enabled ? 'site.ssl_on' : 'site.ssl_off', site.name);
      return res.json({
        ok: true,
        ...result,
        message: enabled
          ? 'HTTPS is on. The certificate renews itself.'
          : 'HTTPS is off. The site answers over plain HTTP.',
      });
    } catch (err) {
      return res.status(502).json({ error: err.message });
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
 * Presets
 * ------------------------------------------------------------------ */
router.post(
  '/sites/:id/save-template',
  loadSite,
  wrap(async (req, res) => {
    try {
      const template = templates.createFromSite(
        sites.getSite(req.site.id),
        { name: req.body.name, description: req.body.description },
        req.user.id
      );
      audit(req, 'template.create', template.name, { fromSite: req.site.name });
      return res.json({ ok: true, template });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  })
);

router.get(
  '/api/templates',
  wrap(async (req, res) => {
    res.json({ templates: templates.list() });
  })
);

router.post(
  '/api/templates/:id/delete',
  wrap(async (req, res) => {
    const template = templates.get(parseInt(req.params.id, 10));
    if (!template) return res.status(404).json({ error: 'Preset not found' });
    if (req.user.role !== 'admin' && template.created_by !== req.user.id) {
      return res.status(403).json({ error: 'You can only delete presets you created.' });
    }
    templates.remove(template.id);
    audit(req, 'template.delete', template.name);
    return res.json({ ok: true });
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
