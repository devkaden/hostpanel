'use strict';

/**
 * First-run wizard. Walks a new administrator through the three things that
 * must be right before anything else works: the address NPMplus forwards to,
 * the NPMplus connection itself, and a first site.
 */

const express = require('express');

const config = require('../config');
const { getSetting, setSetting, allSettings, audit, db } = require('../db');
const auth = require('../auth');
const docker = require('../docker');
const npmplus = require('../npmplus');
const { detectHostIp } = require('../netutil');
const { wrap } = require('../middleware');
const { limiter } = require('../ratelimit');

const router = express.Router();

/*
 * Every route in this file is rate limited. The same instance is mounted on
 * the app as well; it counts a request once, wherever it first sees it.
 */
router.use(limiter);

function isComplete() {
  return getSetting('setup_complete') === '1';
}

router.get(
  '/setup',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const settings = allSettings();
    res.render('setup', {
      title: 'Set up HostPanel',
      settings: { ...settings, npmplus_password: settings.npmplus_password ? '********' : '' },
      detectedIp: detectHostIp(),
      docker: await docker.ping(),
      siteCount: db.prepare('SELECT COUNT(*) AS n FROM sites').get().n,
      config,
      complete: isComplete(),
    });
  })
);

/** Saves one step without demanding the whole form be valid. */
router.post(
  '/setup/save',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const body = req.body;
    const allowed = [
      'host_ip',
      'panel_title',
      'npmplus_url',
      'npmplus_email',
      'npmplus_le_email',
      'theme',
      'ui_mode',
      'brand_accent',
    ];
    for (const key of allowed) {
      if (body[key] !== undefined) setSetting(key, String(body[key]).trim());
    }
    if (body.npmplus_password && body.npmplus_password !== '********') {
      setSetting('npmplus_password', String(body.npmplus_password));
    }
    if (body.npmplus_enabled !== undefined) {
      setSetting('npmplus_enabled', body.npmplus_enabled ? '1' : '0');
    }
    if (body.npmplus_insecure !== undefined) {
      setSetting('npmplus_insecure', body.npmplus_insecure ? '1' : '0');
    }
    npmplus.invalidateToken();
    audit(req, 'setup.save', 'wizard');
    res.json({ ok: true });
  })
);

router.post(
  '/setup/finish',
  auth.requireAdmin,
  wrap(async (req, res) => {
    setSetting('setup_complete', '1');
    audit(req, 'setup.finish', 'wizard');
    res.json({ ok: true, redirect: '/' });
  })
);

router.post(
  '/setup/skip',
  auth.requireAdmin,
  wrap(async (req, res) => {
    setSetting('setup_complete', '1');
    audit(req, 'setup.skip', 'wizard');
    res.json({ ok: true, redirect: '/' });
  })
);

/** Lets the admin run the wizard again later from Settings. */
router.post(
  '/setup/restart',
  auth.requireAdmin,
  wrap(async (req, res) => {
    setSetting('setup_complete', '0');
    res.json({ ok: true, redirect: '/setup' });
  })
);

module.exports = router;
module.exports.isComplete = isComplete;
