'use strict';

const express = require('express');

const config = require('../config');
const { allSettings, setSetting, getSetting, audit } = require('../db');
const sites = require('../sites');
const templates = require('../templates');
const auth = require('../auth');
const docker = require('../docker');
const npmplus = require('../npmplus');
const terminal = require('../terminal');
const { detectHostIp, humanBytes } = require('../netutil');
const { wrap } = require('../middleware');

const router = express.Router();

const MASK = '********';

router.get(
  '/settings',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const settings = allSettings();
    const info = await docker.systemInfo();
    res.render('settings', {
      title: 'Settings',
      settings: { ...settings, npmplus_password: settings.npmplus_password ? MASK : '' },
      saved: req.query.saved === '1',
      docker: await docker.ping(),
      dockerInfo: info,
      dockerMem: info.memTotal ? humanBytes(info.memTotal) : '-',
      detectedIp: detectHostIp(),
      config,
      hostShellSupported: Boolean(terminal.hostShellAvailable() || process.env.FORCE_SHELL_UI),
      dataDir: config.dataDir,
      portRange: sites.portRange(),
      templates: templates.list(),
      effectivePanelPort: config.port,
    });
  })
);

router.post(
  '/settings',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const body = req.body;

    setSetting('panel_title', String(body.panel_title || 'HostPanel').slice(0, 60));
    setSetting('host_ip', String(body.host_ip || '').trim());
    setSetting('allow_host_shell', body.allow_host_shell ? '1' : '0');

    // Appearance.
    const theme = ['system', 'dark', 'light'].includes(body.theme) ? body.theme : 'system';
    setSetting('theme', theme);
    setSetting('ui_mode', body.ui_mode === 'advanced' ? 'advanced' : 'simple');
    const accent = String(body.brand_accent || '').trim();
    setSetting('brand_accent', /^#[0-9a-f]{6}$/i.test(accent) ? accent : '#4f8cff');
    const logo = String(body.brand_logo || '').trim();
    // Only a same-origin path or an inline image, so this cannot become a
    // tracking beacon or a way to smuggle script into every page.
    if (!logo || /^(\/[\w\-./]*|data:image\/(png|jpeg|gif|webp|svg\+xml);base64,[A-Za-z0-9+/=]+)$/.test(logo)) {
      setSetting('brand_logo', logo);
    }

    // Ports. Blank means "fall back to the value in .env".
    const panelPort = parseInt(body.panel_port, 10);
    setSetting('panel_port', Number.isInteger(panelPort) && panelPort > 0 ? String(panelPort) : '');
    const rangeStart = parseInt(body.port_range_start, 10);
    const rangeEnd = parseInt(body.port_range_end, 10);
    if (Number.isInteger(rangeStart) && Number.isInteger(rangeEnd) && rangeEnd > rangeStart) {
      setSetting('port_range_start', String(rangeStart));
      setSetting('port_range_end', String(rangeEnd));
    }

    setSetting('npmplus_url', String(body.npmplus_url || '').trim().replace(/\/+$/, ''));
    setSetting('npmplus_email', String(body.npmplus_email || '').trim());
    setSetting('npmplus_le_email', String(body.npmplus_le_email || '').trim());
    setSetting('npmplus_enabled', body.npmplus_enabled ? '1' : '0');
    setSetting('npmplus_insecure', body.npmplus_insecure ? '1' : '0');

    // Only overwrite the stored password when a new one was actually typed.
    const pw = String(body.npmplus_password || '');
    if (pw && pw !== MASK) setSetting('npmplus_password', pw);

    npmplus.invalidateToken();
    audit(req, 'settings.update', 'panel');
    res.redirect('/settings?saved=1');
  })
);

router.post(
  '/settings/npmplus/test',
  auth.requireAdmin,
  wrap(async (req, res) => {
    // Allow testing values typed into the form before they are saved.
    const temp = {
      npmplus_url: String(req.body.npmplus_url || '').trim().replace(/\/+$/, ''),
      npmplus_email: String(req.body.npmplus_email || '').trim(),
      npmplus_password: String(req.body.npmplus_password || ''),
      npmplus_insecure: req.body.npmplus_insecure ? '1' : '0',
    };

    const previous = {};
    for (const key of Object.keys(temp)) previous[key] = getSetting(key);

    const usingTyped = temp.npmplus_password && temp.npmplus_password !== MASK;
    if (!usingTyped) temp.npmplus_password = previous.npmplus_password;

    for (const [key, value] of Object.entries(temp)) setSetting(key, value);
    npmplus.invalidateToken();

    const result = await npmplus.testConnection();

    // Restore whatever was stored before, so a test never silently saves.
    for (const [key, value] of Object.entries(previous)) setSetting(key, value);
    npmplus.invalidateToken();

    res.json(result);
  })
);

router.post(
  '/settings/detect-ip',
  auth.requireAdmin,
  wrap(async (req, res) => {
    res.json({ ip: detectHostIp() });
  })
);

router.get(
  '/api/npmplus/proxy-hosts',
  auth.requireAdmin,
  wrap(async (req, res) => {
    if (!npmplus.isConfigured()) return res.status(400).json({ error: 'NPMplus is not configured' });
    try {
      const hosts = await npmplus.listProxyHosts();
      res.json({
        hosts: (hosts || []).map((h) => ({
          id: h.id,
          domains: h.domain_names,
          forward: `${h.forward_scheme}://${h.forward_host}:${h.forward_port}`,
          enabled: h.enabled,
          ssl: Boolean(h.certificate_id),
        })),
      });
    } catch (err) {
      res.status(502).json({ error: err.message });
    }
  })
);

module.exports = router;
