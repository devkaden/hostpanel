'use strict';

const express = require('express');

const { audit } = require('../db');
const cron = require('../cron');
const { loadSite, wrap } = require('../middleware');
const { limiter } = require('../ratelimit');

const router = express.Router();

/*
 * Every route in this file is rate limited. The same instance is mounted on
 * the app as well; it counts a request once, wherever it first sees it.
 */
router.use(limiter);

const PRESETS = [
  { label: 'Every 5 minutes', value: '*/5 * * * *' },
  { label: 'Every 15 minutes', value: '*/15 * * * *' },
  { label: 'Hourly', value: '0 * * * *' },
  { label: 'Daily at 03:00', value: '0 3 * * *' },
  { label: 'Weekly (Sunday 04:00)', value: '0 4 * * 0' },
  { label: 'Monthly (1st, 05:00)', value: '0 5 1 * *' },
];

const EXAMPLES = {
  wordpress: 'php /var/www/html/wp-cron.php',
  php: 'php /var/www/html/cron.php',
  node: 'node scripts/cleanup.js',
  static: 'find . -name "*.tmp" -delete',
};

router.get('/sites/:id/cron', loadSite, (req, res) => {
  res.render('cron', {
    title: `${req.site.name} - cron`,
    site: req.site,
    jobs: cron.listJobs(req.site.id),
    presets: PRESETS,
    example: EXAMPLES[req.site.type] || '',
  });
});

router.get(
  '/api/sites/:id/cron',
  loadSite,
  wrap(async (req, res) => {
    res.json({ jobs: cron.listJobs(req.site.id) });
  })
);

router.post(
  '/api/sites/:id/cron',
  loadSite,
  wrap(async (req, res) => {
    const job = cron.createJob(req.site.id, {
      name: req.body.name,
      schedule: req.body.schedule,
      command: req.body.command,
      enabled: req.body.enabled !== 'false' && req.body.enabled !== false,
    });
    audit(req, 'cron.create', req.site.name, `${job.schedule} ${job.command}`);
    res.json({ ok: true, job });
  })
);

function ownJob(req, res) {
  const job = cron.getJob(parseInt(req.params.jobId, 10));
  if (!job || job.site_id !== req.site.id) {
    res.status(404).json({ error: 'Job not found' });
    return null;
  }
  return job;
}

router.post(
  '/api/sites/:id/cron/:jobId',
  loadSite,
  wrap(async (req, res) => {
    if (!ownJob(req, res)) return undefined;
    const job = cron.updateJob(parseInt(req.params.jobId, 10), {
      name: req.body.name,
      schedule: req.body.schedule,
      command: req.body.command,
      enabled:
        req.body.enabled === undefined
          ? undefined
          : req.body.enabled !== 'false' && req.body.enabled !== false,
    });
    audit(req, 'cron.update', req.site.name, `#${job.id}`);
    return res.json({ ok: true, job });
  })
);

router.post(
  '/api/sites/:id/cron/:jobId/delete',
  loadSite,
  wrap(async (req, res) => {
    if (!ownJob(req, res)) return undefined;
    cron.deleteJob(parseInt(req.params.jobId, 10));
    audit(req, 'cron.delete', req.site.name, `#${req.params.jobId}`);
    return res.json({ ok: true });
  })
);

router.post(
  '/api/sites/:id/cron/:jobId/run',
  loadSite,
  wrap(async (req, res) => {
    if (!ownJob(req, res)) return undefined;
    const result = await cron.runJob(parseInt(req.params.jobId, 10), { manual: true });
    audit(req, 'cron.run', req.site.name, `#${req.params.jobId}`);
    return res.json({ ok: true, ...result });
  })
);

module.exports = router;
