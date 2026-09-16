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

  /* ------------------------------------------------ upload streaming ---- */
  console.log('\nraw upload streaming');
  {
    const http = require('http');
    const { Transform } = require('stream');
    const { pipeline } = require('stream/promises');

    const LIMIT = 1024 * 1024; // 1 MB for the test
    const uploadDir = path.join(TMP, 'uploads');
    fs.mkdirSync(uploadDir, { recursive: true });

    // Mirrors the handler in src/routes/files.js.
    const server = http.createServer(async (req, res) => {
      const name = decodeURIComponent((req.url.split('path=')[1] || 'f').split('&')[0]);
      const tmp = path.join(uploadDir, 'tmp-' + Math.random().toString(16).slice(2));
      let written = 0;
      let tooBig = false;

      const counter = new Transform({
        transform(chunk, _enc, cb) {
          written += chunk.length;
          if (written > LIMIT) {
            tooBig = true;
            return cb(new Error('over the limit'));
          }
          return cb(null, chunk);
        },
      });

      try {
        await pipeline(req, counter, fs.createWriteStream(tmp));
        fs.renameSync(tmp, path.join(uploadDir, name));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, bytes: written }));
      } catch (err) {
        try { fs.unlinkSync(tmp); } catch (_) { /* already gone */ }
        res.writeHead(tooBig ? 413 : 400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    function put(name, body) {
      return new Promise((resolve, reject) => {
        const req = http.request(
          { method: 'PUT', host: '127.0.0.1', port, path: '/?path=' + encodeURIComponent(name),
            headers: { 'Content-Type': 'application/octet-stream' } },
          (res) => {
            let text = '';
            res.on('data', (d) => { text += d; });
            res.on('end', () => {
              let parsed = {};
              try { parsed = JSON.parse(text); } catch (_) { parsed = {}; }
              resolve({ status: res.statusCode, body: parsed });
            });
          }
        );
        req.on('error', reject);
        req.end(body);
      });
    }

    // A normal small file.
    let r = await put('hello.txt', Buffer.from('hello world'));
    check('accepts a small file', r.status === 200 && r.body.bytes === 11, JSON.stringify(r));
    check('writes the right content',
      fs.readFileSync(path.join(uploadDir, 'hello.txt'), 'utf8') === 'hello world');

    // Zero bytes must not hang or error.
    r = await put('empty.txt', Buffer.alloc(0));
    check('accepts a zero-byte file', r.status === 200 && r.body.bytes === 0, JSON.stringify(r));
    check('zero-byte file exists', fs.existsSync(path.join(uploadDir, 'empty.txt')));

    // Large enough to exercise backpressure across many chunks.
    const big = Buffer.alloc(900 * 1024, 0x61);
    r = await put('big.bin', big);
    check('accepts a large file under the limit',
      r.status === 200 && r.body.bytes === big.length, JSON.stringify(r));
    check('large file is byte-for-byte intact',
      fs.statSync(path.join(uploadDir, 'big.bin')).size === big.length);

    // Over the limit must be refused, and must not leave a partial file.
    r = await put('toobig.bin', Buffer.alloc(LIMIT + 4096, 0x62));
    check('refuses a file over the limit', r.status === 413, JSON.stringify(r));
    check('no partial file is left behind', !fs.existsSync(path.join(uploadDir, 'toobig.bin')));
    check('no temp files are left behind',
      fs.readdirSync(uploadDir).filter((f) => f.startsWith('tmp-')).length === 0,
      fs.readdirSync(uploadDir).join(', '));

    // A nested path still lands in the right place.
    fs.mkdirSync(path.join(uploadDir, 'sub'), { recursive: true });
    r = await put('sub/nested.txt', Buffer.from('nested'));
    check('accepts a nested path', r.status === 200, JSON.stringify(r));

    await new Promise((resolve) => server.close(resolve));
  }

  fs.rmSync(TMP, { recursive: true, force: true });
  console.log('\nnode sites install their dependencies before starting');
{
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'sites.js'), 'utf8');
  // A Node app with a package.json and no node_modules exits instantly with
  // "Cannot find module", and exec needs a running container - so the shell is
  // unavailable at exactly the moment it is needed. Starting has to handle it.
  check('the missing-dependency state is detected',
    /function needsDependencies/.test(src));
  check('starting installs first rather than starting a doomed container',
    /startSite[\s\S]{0,600}needsDependencies\(site\)[\s\S]{0,400}runInstall/.test(src));
  check('restarting does too', /restartSite[\s\S]{0,300}needsDependencies/.test(src));
  check('a failing install is not reported as success',
    /the install command exited with code/.test(src));
  check('the status carries the flag so the page can explain it',
    /needsDependencies: needsDependencies\(site\)/.test(src));

  const term = fs.readFileSync(path.join(__dirname, '..', 'src', 'terminal.js'), 'utf8');
  check('a shell still opens when the container is down',
    /runInteractive/.test(term) && !/The container is \$\{state\}\. Start the site first/.test(term));
  check('and the throwaway container is removed afterwards',
    /rescue\.container\.remove/.test(term));

  const view = fs.readFileSync(path.join(__dirname, '..', 'src', 'views', 'site.ejs'), 'utf8');
  check('the install button is not hidden behind advanced mode',
    !/btn adv" data-action="install"/.test(view));
  check('and a missing-dependency site says so plainly',
    /Dependencies are not installed/.test(view));
}

console.log('\nsystem packages and unreachable apps');
{
  const tplSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'site-templates.js'), 'utf8');
  const sitesSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'sites.js'), 'utf8');
  const view = fs.readFileSync(path.join(__dirname, '..', 'src', 'views', 'site.ejs'), 'utf8');

  // Package names are interpolated into a shell command, so they have to look
  // like package names and nothing else.
  const clean = (value) =>
    String(value || '')
      .split(/[\s,]+/)
      .map((p) => p.trim())
      .filter(Boolean)
      .filter((p) => /^[a-zA-Z0-9][a-zA-Z0-9._+-]*$/.test(p))
      .slice(0, 40);

  check('accepts real package names',
    clean('ffmpeg yt-dlp imagemagick').join(' ') === 'ffmpeg yt-dlp imagemagick');
  check('accepts commas as separators', clean('ffmpeg, git').length === 2);
  // Every surviving token has to be a bare package name. "rm" surviving from
  // "ffmpeg; rm -rf /" is fine - it reaches apt as a package that does not
  // exist, not as a command - but a semicolon or a slash must never survive.
  const injected = clean('ffmpeg; rm -rf /');
  check('no shell metacharacter survives',
    injected.every((p) => /^[a-zA-Z0-9][a-zA-Z0-9._+-]*$/.test(p)), injected.join(' '));
  check('and the dangerous parts are dropped',
    !injected.includes('ffmpeg;') && !injected.includes('/') && !injected.includes('-rf'),
    injected.join(' '));
  check('rejects backticks and substitution', clean('$(id) `id` ffmpeg').join(' ') === 'ffmpeg');
  check('rejects a leading dash that would read as a flag', clean('--force-yes').length === 0);
  check('caps the list', clean(Array.from({ length: 80 }, (_, i) => 'p' + i).join(' ')).length === 40);

  check('packages produce a site-specific image, not a mutated base',
    /derivedImageName/.test(tplSrc) && /hostpanel-\$\{site\.name\}/.test(tplSrc));
  check('the image is built before the container is created',
    /ensureSiteImage\(site, log\);\s*\n\s*await docker\.ensureImage/.test(sitesSrc));
  check('a site with no extra packages uses the base image unchanged',
    /if \(systemPackages\(site\)\.length\) return derivedImageName\(site\);/.test(tplSrc));

  const dockerSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'docker.js'), 'utf8');
  // The plain yt-dlp release is a Python zipapp and a slim Node image has no
  // Python: it downloads, chmods, and then fails at the first run. The _linux
  // builds are self-contained.
  check('yt-dlp uses the self-contained build, not the Python zipapp',
    /yt-dlp_linux/.test(dockerSrc));
  check('and the architecture is chosen rather than assumed',
    /yt-dlp_linux_aarch64/.test(dockerSrc) && /uname -m/.test(dockerSrc));
  check('installing is not called done until the program runs',
    /yt-dlp --version/.test(dockerSrc));
  check('the build reports what ended up on PATH',
    /installed programs/.test(dockerSrc));
  check('an unchanged package list is not rebuilt every time',
    /existing\.Comment === stamp/.test(dockerSrc));

  check('the panel checks whether anything answers on the port',
    /function probeSite/.test(sitesSrc) && /reachable/.test(sitesSrc));
  check('and explains a blank preview rather than leaving it blank',
    /nothing is answering on port/.test(view) && /0\.0\.0\.0/.test(view));

  // The three ways a preview goes blank with no error anywhere. Each one looks
  // identical from the outside, so each has to be named separately.
  check('a site that refuses framing is detected, not shown as a white box',
    /framingRefusedBy/.test(sitesSrc) && /x-frame-options/.test(sitesSrc));
  check('and frame-ancestors counts too',
    /frame-ancestors/.test(sitesSrc));
  /*
   * The preview is served through the panel rather than framed directly.
   * Everything the old approach needed - probing for framing headers,
   * switching to the domain to dodge mixed content, telling the user to edit
   * their reverse proxy - exists only because the frame pointed somewhere
   * else. It points at the panel now, so none of it is needed and none of it
   * should come back.
   */
  const routes = fs.readFileSync(path.join(__dirname, '..', 'src', 'routes', 'sites.js'), 'utf8');
  check('there is a preview proxy route', /'\/preview\/:id/.test(routes));
  check('it is behind the site access check', /loadSite,/.test(
    routes.slice(routes.indexOf("'/preview/:id"), routes.indexOf("'/preview/:id") + 400)
  ));
  check('the frame points at the panel, not the site',
    /src="\/preview\/<%= site\.id %>\/"/.test(view));

  // Same-origin is what makes the preview work and also what would let a
  // site's scripts reach into the panel. The sandbox withholds it.
  // The comment above the iframe explains why the token is absent, so only
  // the attribute itself is checked.
  const sandboxAttr = (view.match(/sandbox="[^"]*"/) || [''])[0];
  check('the frame is sandboxed without allow-same-origin',
    sandboxAttr === 'sandbox="allow-scripts allow-forms allow-popups"', sandboxAttr);

  check('the user is not asked to edit their reverse proxy',
    !/proxy_hide_header|more_clear_headers/.test(view));

  /*
   * The last thing to blank the preview was the panel's own policy.
   * X-Frame-Options: DENY and frame-ancestors 'none' were set on every
   * response including /preview/, so the browser refused to let the panel
   * frame the panel:
   *
   *   Refused to load .../preview/1/ because it does not appear in the
   *   frame-ancestors directive of the Content Security Policy
   *
   * Proxying put the preview beyond everyone's framing rules except ours.
   */
  const index = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8');
  const at = index.indexOf("req.path.startsWith('/preview/')");
  const previewHeaders = at === -1 ? '' : index.slice(at, at + 700);

  check('the preview path gets its own headers', at !== -1,
    'otherwise the panel-wide frame-ancestors applies to it');
  check('the panel may frame it', /frame-ancestors 'self'/.test(previewHeaders), previewHeaders);
  check('nobody else may', !/frame-ancestors '\*'/.test(previewHeaders));
  check('and it is not sent X-Frame-Options at all',
    !/X-Frame-Options/.test(previewHeaders),
    'DENY there refuses the panel too, and it overrides nothing');
  check('the preview is not given the panel\'s own content policy',
    !/default-src/.test(previewHeaders),
    "a policy written for the panel would only break the user's site");
  check('the exemption returns before the strict headers are set',
    previewHeaders.indexOf('return next()') !== -1);
  check('every other page still refuses framing outright',
    /frame-ancestors 'none'/.test(index) && /'X-Frame-Options': 'DENY'/.test(index));
}

/* ------------------------------------------------------------- rename --- */
{
  console.log('\nrenaming a site');
  const sitesSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'sites.js'), 'utf8');
  const routes = fs.readFileSync(path.join(__dirname, '..', 'src', 'routes', 'sites.js'), 'utf8');
  const view = fs.readFileSync(path.join(__dirname, '..', 'src', 'views', 'site.ejs'), 'utf8');

  const fn = sitesSrc.slice(
    sitesSrc.indexOf('async function renameSite'),
    sitesSrc.indexOf('async function deleteSite')
  );
  check('there is a rename', fn.length > 0);
  check('the new name is held to the same rule as a new site',
    /NAME_RE\.test\(name\)/.test(fn));
  check('a name already in use is refused', /getSiteByName\(name\)/.test(fn));
  check('and so is a directory already sitting there',
    /fs\.existsSync\(newRoot\)/.test(fn),
    'renaming onto an existing folder would merge two sites');

  // The order is the whole trick: a running container holds the old directory,
  // so moving first leaves a container serving a path that no longer exists.
  check('containers go before the directory moves',
    fn.indexOf('removeContainer') < fn.indexOf('fsp.rename'),
    'a container holding the old directory open turns this into a half-move');
  check('the files are moved, not copied', /fsp\.rename\(oldDirs\.root, newRoot\)/.test(fn),
    'copying gigabytes to change a name is the wrong trade');
  check('the database is told only after the move succeeds',
    fn.indexOf('fsp.rename(oldDirs.root') < fn.indexOf("UPDATE sites SET name"),
    'otherwise a failed move leaves a row describing a site that is not there');
  check('the container is rebuilt under the new name', /rebuildSite\(siteId/.test(fn));
  check('a failed rename puts the directory back',
    /fsp\.rename\(newRoot, oldDirs\.root\)/.test(fn));
  check('a site that was stopped stays stopped', /wasRunning/.test(fn),
    'renaming is not a reason to put something back online');
  check('the port is not touched', !/SET port|allocatePort/.test(fn),
    'keeping the port is what saves the reverse proxy from needing a change');
  check('the site keeps its id', !/DELETE FROM sites|INSERT INTO sites/.test(fn),
    'cron jobs, the owner and the Docker network all hang off the id');

  check('the route is behind the site access check',
    /'\/sites\/:id\/rename',\s*\n\s*loadSite/.test(routes));
  check('a busy site cannot be renamed underneath a running job',
    /rename'[\s\S]{0,400}sites\.isBusy/.test(routes));

  check('the page explains what renaming actually does',
    /container is replaced and the site folder moves/.test(view));
  check('and asks before doing it', /Rename to "/.test(view));
}

console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})();
