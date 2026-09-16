'use strict';

const express = require('express');
const os = require('os');

const config = require('../config');
const { db } = require('../db');
const sites = require('../sites');
const docker = require('../docker');
const npmplus = require('../npmplus');
const { humanBytes } = require('../netutil');

const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const list = sites.listSites(req.user);
    const withStatus = await Promise.all(
      list.map(async (site) => ({
        ...site,
        live: await sites.statusFor(site),
        domains: sites.allDomains(site),
      }))
    );

    const ping = await docker.ping();
    const counts = withStatus.reduce(
      (acc, s) => {
        acc.total += 1;
        if (s.live.state === 'running' || s.live.state === 'healthy') acc.running += 1;
        else if (s.live.state === 'missing') acc.missing += 1;
        else acc.stopped += 1;
        return acc;
      },
      { total: 0, running: 0, stopped: 0, missing: 0 }
    );

    res.render('dashboard', {
      title: 'Dashboard',
      sites: withStatus,
      counts,
      docker: ping,
      npmplusOn: npmplus.isEnabled(),
      changed: req.query.changed === '1',
      host: {
        hostname: os.hostname(),
        load: os.loadavg().map((n) => Math.round(n * 100) / 100),
        uptime: Math.round(os.uptime() / 3600),
        memFree: humanBytes(os.freemem()),
        memTotal: humanBytes(os.totalmem()),
        cpus: os.cpus().length,
      },
      userCount:
        req.user.role === 'admin' ? db.prepare('SELECT COUNT(*) AS n FROM users').get().n : null,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * Status poll. Container stats cost a second each (Docker samples twice), so
 * they are only gathered when a single site is requested with ?stats=1 - the
 * dashboard polls without them.
 */
router.get('/api/status', async (req, res, next) => {
  try {
    const wantId = req.query.site ? parseInt(req.query.site, 10) : null;
    const wantStats = req.query.stats === '1';
    const list = sites.listSites(req.user).filter((s) => !wantId || s.id === wantId);

    const out = await Promise.all(
      list.map(async (site) => {
        const live = await sites.statusFor(site);
        const stats =
          wantStats && wantId && (live.state === 'running' || live.state === 'healthy')
            ? await docker.stats(`${config.containerPrefix}${site.name}`)
            : null;
        return {
          id: site.id,
          name: site.name,
          state: live.state,
          dbState: live.dbState,
          busy: sites.isBusy(site.id),
          uptimeMs: live.uptimeMs,
          restartCount: live.restartCount,
          exitCode: live.exitCode,
          reachable: live.reachable,
          stats,
        };
      })
    );
    res.json({ sites: out, docker: await docker.ping() });
  } catch (err) {
    next(err);
  }
});

router.get('/audit', (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const rows = isAdmin
    ? db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 300').all()
    : db.prepare('SELECT * FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 300').all(req.user.id);
  res.render('audit', { title: 'Activity log', rows });
});

module.exports = router;
