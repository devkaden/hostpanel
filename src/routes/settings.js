'use strict';

const express = require('express');

const config = require('../config');
const { db, allSettings, setSetting, getSetting, audit } = require('../db');
const sites = require('../sites');
const templates = require('../templates');
const auth = require('../auth');
const docker = require('../docker');
const npmplus = require('../npmplus');
const terminal = require('../terminal');
const { detectHostIp, humanBytes, stripTrailingSlashes } = require('../netutil');
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
      security: securityReview(),
    });
  })
);

/**
 * A plain list of what is and is not in place, for a panel that faces outward.
 *
 * Not a score and not a badge. Each entry says what the current state is and
 * what it means, so the decision stays with the person running it - a panel
 * reachable only over a VPN genuinely does not need HSTS, and telling them
 * otherwise teaches them to ignore the list.
 */
function securityReview() {
  const users = db
    .prepare('SELECT username, role, totp_enabled, active FROM users WHERE active = 1')
    .all();
  const admins = users.filter((u) => u.role === 'admin');
  const adminsWithout2fa = admins.filter((u) => !u.totp_enabled);
  const policy = getSetting('require_2fa') || 'off';

  const items = [];

  items.push({
    id: 'twofactor',
    label: 'Two-factor authentication',
    ok: policy !== 'off' && adminsWithout2fa.length === 0,
    warn: policy !== 'off' && adminsWithout2fa.length > 0,
    detail:
      policy === 'off'
        ? 'Not required. Anyone who learns a password is in.'
        : adminsWithout2fa.length
          ? `Required, but ${adminsWithout2fa.length} administrator account(s) have not set it up yet: ` +
            adminsWithout2fa.map((u) => u.username).join(', ')
          : `Required for ${policy === 'all' ? 'everyone' : 'administrators'}, and every account has it.`,
  });

  items.push({
    id: 'cookies',
    label: 'Secure cookies',
    ok: config.secureCookies,
    detail: config.secureCookies
      ? 'Session cookies are marked Secure, so they are never sent over plain HTTP.'
      : 'Session cookies are not marked Secure. Set SECURE_COOKIES=true once the panel is served over HTTPS, ' +
        'otherwise a single plain-HTTP request can expose the session.',
  });

  items.push({
    id: 'proxy',
    label: 'Client addresses',
    ok: !config.trustProxy || config.secureCookies,
    warn: config.trustProxy && !config.secureCookies,
    detail: config.trustProxy
      ? 'TRUST_PROXY is on, so the address in X-Forwarded-For is believed. Correct behind your own reverse ' +
        'proxy; wrong if the panel is also reachable directly, because then anyone can forge the address ' +
        'the rate limiter counts against.'
      : 'TRUST_PROXY is off, so rate limiting counts the connecting address. Turn it on only if the panel ' +
        'is reachable exclusively through your reverse proxy.',
  });

  items.push({
    id: 'secret',
    label: 'Session secret',
    ok: config.sessionSecret !== 'change-me-in-dotenv' && config.sessionSecret.length >= 32,
    detail:
      config.sessionSecret === 'change-me-in-dotenv'
        ? 'Still the built-in default. Anyone with the source can forge a session cookie. Set SESSION_SECRET.'
        : config.sessionSecret.length < 32
          ? 'Shorter than 32 characters. Generate a long random one.'
          : 'Set to something of its own.',
  });

  items.push({
    id: 'hostshell',
    label: 'Host shell',
    ok: getSetting('allow_host_shell') !== '1',
    warn: getSetting('allow_host_shell') === '1',
    detail:
      getSetting('allow_host_shell') === '1'
        ? 'Enabled. Any administrator gets a root shell on this machine through the browser. Worth turning ' +
          'off if the panel is reachable from outside.'
        : 'Disabled.',
  });

  items.push({
    id: 'passwords',
    label: 'Password length',
    ok: parseInt(getSetting('min_password_length') || '10', 10) >= 12,
    detail: `Minimum ${getSetting('min_password_length') || '10'} characters. Twelve or more is a sensible ` +
      'floor for an account reachable from the internet.',
  });

  items.push({
    id: 'docker',
    label: 'What an account can reach',
    ok: null,
    detail:
      'Every administrator can reach the Docker socket through this panel, which is equivalent to root on ' +
      'this host. Give administrator only to people you would give root to, and use standard accounts for ' +
      'everyone else.',
  });

  return {
    items,
    failing: items.filter((i) => i.ok === false).length,
    warning: items.filter((i) => i.warn).length,
  };
}

router.post(
  '/settings',
  auth.requireAdmin,
  wrap(async (req, res) => {
    const body = req.body;

    setSetting('panel_title', String(body.panel_title || 'HostPanel').slice(0, 60));
    setSetting('host_ip', String(body.host_ip || '').trim());
    setSetting('allow_host_shell', body.allow_host_shell ? '1' : '0');

    // Security.
    const policy = ['off', 'admins', 'all'].includes(body.require_2fa) ? body.require_2fa : 'off';
    setSetting('require_2fa', policy);
    const maxUpload = parseInt(body.max_upload_mb, 10);
    setSetting(
      'max_upload_mb',
      Number.isInteger(maxUpload) && maxUpload >= 1 && maxUpload <= 20480 ? String(maxUpload) : ''
    );

    setSetting(
      'rate_limit_profile',
      ['relaxed', 'standard', 'strict'].includes(body.rate_limit_profile)
        ? body.rate_limit_profile
        : 'standard'
    );

    const minLen = parseInt(body.min_password_length, 10);
    setSetting(
      'min_password_length',
      Number.isInteger(minLen) && minLen >= 8 && minLen <= 128 ? String(minLen) : '10'
    );

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

    setSetting('npmplus_url', stripTrailingSlashes(body.npmplus_url));
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
      npmplus_url: stripTrailingSlashes(req.body.npmplus_url),
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

/**
 * Checks every site's proxy host in one pass, and optionally fixes them.
 *
 * Doing this site by site is the reason proxy hosts drift in the first place:
 * nobody opens twelve pages to find the one whose port moved. Sites are
 * handled one at a time rather than in parallel - NPMplus is a small container
 * on somebody's homelab, and twelve simultaneous API calls is a rude thing to
 * do to it.
 */
router.post(
  '/api/npmplus/check-all',
  auth.requireAdmin,
  wrap(async (req, res) => {
    if (!npmplus.isEnabled()) {
      return res.status(400).json({ error: 'NPMplus integration is turned off.' });
    }
    const fix = req.body.fix === true || req.body.fix === 'true';
    const rows = db.prepare('SELECT * FROM sites ORDER BY name').all();
    const results = [];

    for (const site of rows) {
      if (!npmplus.domainsOf(site).length) continue; // nothing to proxy
      try {
        if (!fix) {
          const check = await npmplus.checkProxy(site);
          results.push({
            id: site.id, name: site.name, ok: check.ok,
            issues: check.issues.map((i) => i.says), fixed: [], error: check.error || null,
          });
          continue;
        }
        const repair = await npmplus.repairProxy(site);
        db.prepare('UPDATE sites SET npm_proxy_id = ?, npm_cert_id = ?, ssl = ? WHERE id = ?').run(
          repair.proxyId, repair.certId || null, repair.ssl ? 1 : 0, site.id
        );
        results.push({
          id: site.id, name: site.name, ok: true,
          issues: repair.issues.map((i) => i.says), fixed: repair.fixed, error: null,
        });
      } catch (err) {
        // One site that cannot be fixed must not stop the other eleven.
        results.push({
          id: site.id, name: site.name, ok: false, issues: [], fixed: [],
          error: err.existingProxy
            ? `${err.message} Open this site to take it over.`
            : err.message,
        });
      }
    }

    if (fix) audit(req, 'npmplus.check_all', 'all sites', `${results.length} checked`);
    return res.json({
      ok: true,
      fixed: fix,
      checked: results.length,
      problems: results.filter((r) => !r.ok || r.fixed.length).length,
      results,
    });
  })
);

module.exports = router;
