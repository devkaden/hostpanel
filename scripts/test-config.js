#!/usr/bin/env node
'use strict';
/*
 * Tests the configurable-port logic, template presets and container spec
 * building, with ./db and ./config stubbed so no dependencies are needed.
 *
 * Run with: npm run test:config
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');
const Module = require('module');

const APP = path.join(__dirname, '..', 'src');

let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`); }
}

/* ------------------------------------------------------------ stubs ---- */
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-cfg-'));

function stub(relPath, exports) {
  const full = path.join(APP, relPath);
  const m = new Module(full, null);
  m.filename = full;
  m.loaded = true;
  m.exports = exports;
  require.cache[full] = m;
  return m;
}

const settings = {};
const siteRows = [];

stub('config.js', {
  port: 8890,
  portRangeStart: 21000,
  portRangeEnd: 21999,
  sitesDir: path.join(TMP, 'sites'),
  containerPrefix: 'hp-',
  networkPrefix: 'hostpanel-site-',
  mariadbImage: 'mariadb:11',
  siteTypes: { static: {}, php: {}, wordpress: {}, node: {} },
});

stub('db.js', {
  db: {
    prepare(sql) {
      return {
        all: () => (/FROM sites/.test(sql) ? siteRows.map((s) => ({ port: s.port })) : []),
        get: (...args) => {
          if (/SELECT id, name FROM sites WHERE port/.test(sql)) {
            const [port, exclude] = args;
            return siteRows.find((s) => s.port === port && s.id !== exclude) || undefined;
          }
          if (/SELECT port FROM sites WHERE id/.test(sql)) {
            return siteRows.find((s) => s.id === args[0]);
          }
          return undefined;
        },
        run: () => ({ lastInsertRowid: 1 }),
      };
    },
  },
  audit: () => {},
  getSetting: (k, fb) => (settings[k] !== undefined ? settings[k] : fb || ''),
  setSetting: (k, v) => { settings[k] = v; },
  getNumericSetting: (k, fb) => {
    const n = parseInt(settings[k], 10);
    return Number.isInteger(n) && n > 0 ? n : fb;
  },
});
stub('docker.js', {});
stub('npmplus.js', {});

const sites = require(path.join(APP, 'sites.js'));
const tpl = require(path.join(APP, 'site-templates.js'));

/* ------------------------------------------------------- port range ---- */
(async function run() {
  console.log('\nport range comes from settings');
  {
    check('defaults to the config range', sites.portRange().start === 21000);
    settings.port_range_start = '30000';
    settings.port_range_end = '30010';
    check('honours a configured range', sites.portRange().start === 30000, JSON.stringify(sites.portRange()));

    siteRows.length = 0;
    check('allocates the first port in the range', sites.allocatePort() === 30000);
    siteRows.push({ id: 1, name: 'a', port: 30000 });
    check('skips a port already taken', sites.allocatePort() === 30001);

    for (let p = 30001; p <= 30010; p += 1) siteRows.push({ id: p, name: 'x' + p, port: p });
    let msg = '';
    try { sites.allocatePort(); } catch (e) { msg = e.message; }
    check('explains an exhausted range', /No free ports left between 30000 and 30010/.test(msg), msg);
    siteRows.length = 0;
    delete settings.port_range_start;
    delete settings.port_range_end;
  }

  console.log('\nhost port validation');
  {
    siteRows.length = 0;
    siteRows.push({ id: 1, name: 'blog', port: 21000 });

    let r = await sites.checkHostPort('not-a-number', null);
    check('rejects junk', !r.ok && /between 1 and 65535/.test(r.error), r.error);

    r = await sites.checkHostPort('80', null);
    check('rejects a privileged port', !r.ok && /reserved for system services/.test(r.error), r.error);

    r = await sites.checkHostPort('8890', null);
    check('rejects the panel port', !r.ok && /control panel/.test(r.error), r.error);

    r = await sites.checkHostPort('21000', null);
    check('rejects a port another site holds', !r.ok && /already used by the site "blog"/.test(r.error), r.error);

    r = await sites.checkHostPort('21000', 1);
    check('allows a site to keep its own port', r.ok && r.port === 21000, JSON.stringify(r));

    r = await sites.checkHostPort('21500', null);
    check('accepts a free port', r.ok && r.port === 21500, JSON.stringify(r));

    // Something genuinely listening must be detected.
    const blocker = net.createServer();
    await new Promise((resolve) => blocker.listen(0, '0.0.0.0', resolve));
    const busyPort = blocker.address().port;
    r = await sites.checkHostPort(String(busyPort), null);
    check('detects a port in use on the host', !r.ok && /already listening/.test(r.error), r.error);
    await new Promise((resolve) => blocker.close(resolve));
    siteRows.length = 0;
  }

  console.log('\ncontainer spec honours the configured ports');
  {
    const dirs = {
      root: path.join(TMP, 'sites', 'demo'),
      app: path.join(TMP, 'sites', 'demo', 'app'),
      logs: path.join(TMP, 'sites', 'demo', 'logs'),
      conf: path.join(TMP, 'sites', 'demo', 'conf'),
      db: path.join(TMP, 'sites', 'demo', 'db'),
    };
    const base = { id: 1, name: 'demo', port: 21007, env_json: '{}', extra_labels: '{}' };

    for (const type of ['static', 'php', 'node']) {
      const site = { ...base, type, app_port: type === 'node' ? 4000 : 8080 };
      const spec = tpl.buildSpec(site, dirs);
      const wanted = type === 'node' ? 4000 : 8080;
      check(`${type}: exposes the internal port ${wanted}`,
        Object.keys(spec.create.ExposedPorts)[0] === `${wanted}/tcp`,
        JSON.stringify(spec.create.ExposedPorts));
      check(`${type}: publishes it on the host port`,
        spec.create.HostConfig.PortBindings[`${wanted}/tcp`][0].HostPort === '21007');
    }

    const wp = { ...base, type: 'wordpress', app_port: 80, db_name: 'wordpress', db_user: 'u', db_password: 'p' };
    const wpSpec = tpl.buildSpec(wp, dirs);
    check('wordpress: no Cmd override (entrypoint must still run setup)',
      wpSpec.create.Cmd === undefined, JSON.stringify(wpSpec.create.Cmd));
    check('wordpress: mounts a ports.conf so the port is changeable',
      wpSpec.create.HostConfig.Binds.some((b) => b.includes('apache-ports.conf')));

    // Generated config actually contains the chosen port.
    check('nginx conf listens on the configured port', tpl.nginxConf(8080).includes('listen 8080;'));
    check('apache ports.conf uses the configured port', tpl.apachePortsConf(8080).includes('Listen 8080'));
    check('apache vhost uses the configured port', tpl.apacheVhostConf(8080).includes('<VirtualHost *:8080>'));
  }

  console.log('\ncustom image, network and labels');
  {
    const dirs = {
      root: path.join(TMP, 'sites', 'demo'), app: path.join(TMP, 'sites', 'demo', 'app'),
      logs: path.join(TMP, 'sites', 'demo', 'logs'), conf: path.join(TMP, 'sites', 'demo', 'conf'),
      db: path.join(TMP, 'sites', 'demo', 'db'),
    };
    const site = {
      id: 2, name: 'custom', type: 'static', port: 21008, app_port: 80, env_json: '{}',
      custom_image: 'caddy:2-alpine', docker_network: 'shared-net',
      extra_labels: '{"com.example.a":"1","hostpanel.site":"hacked"}',
      extra_volumes: 'uploads:/data\n/etc:/etc\n',
    };
    const spec = tpl.buildSpec(site, dirs);
    check('uses the custom image', spec.image === 'caddy:2-alpine', spec.image);
    check('uses the named network', spec.create.HostConfig.NetworkMode === 'shared-net');
    check('does not own a user-supplied network', tpl.ownsNetwork(site) === false);
    check('owns its own per-site network by default', tpl.ownsNetwork({ id: 3 }) === true);
    check('keeps a user label', spec.create.Labels['com.example.a'] === '1');
    check('refuses to let a label overwrite hostpanel.site',
      spec.create.Labels['hostpanel.site'] === 'custom', spec.create.Labels['hostpanel.site']);
    const binds = spec.create.HostConfig.Binds;
    check('accepts a mount inside the site folder',
      binds.some((b) => b.endsWith(':/data') && b.includes('/sites/demo/uploads')), binds.join('|'));
    // The escaping "/etc:/etc" entry must be dropped. Checked by host path, not
    // substring: a legitimate bind mounts a conf file *into* /etc.
    check('rejects a mount escaping the site folder',
      !binds.some((b) => b.startsWith('/etc:')), binds.join('|'));
  }

  console.log('\nmanaged config files never clobber user edits');
  {
    const dirs = { conf: path.join(TMP, 'managed') };
    fs.mkdirSync(dirs.conf, { recursive: true });
    const file = path.join(dirs.conf, 'nginx-site.conf');

    check('writes on first run', (await sites.writeManaged(dirs, 'nginx-site.conf', 'listen 80;')) === true);
    check('rewrites when the content changes',
      (await sites.writeManaged(dirs, 'nginx-site.conf', 'listen 8080;')) === true);
    check('file has the new content', fs.readFileSync(file, 'utf8') === 'listen 8080;');

    fs.writeFileSync(file, 'listen 8080; # my own tweak');
    check('leaves a user-edited file alone',
      (await sites.writeManaged(dirs, 'nginx-site.conf', 'listen 9090;')) === false);
    check('user edit survives', fs.readFileSync(file, 'utf8').includes('my own tweak'));

    // A file that predates hash tracking is adopted, never overwritten.
    const legacy = path.join(dirs.conf, 'legacy.conf');
    fs.writeFileSync(legacy, 'listen 80; # written before the panel tracked this');
    check('adopts an untracked pre-existing file instead of overwriting it',
      (await sites.writeManaged(dirs, 'legacy.conf', 'listen 9999;')) === false);
    check('pre-existing content is preserved',
      fs.readFileSync(legacy, 'utf8').includes('before the panel tracked this'));
    check('and it is now tracked', fs.existsSync(path.join(dirs.conf, '.legacy.conf.hash')));
  }

  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})();
