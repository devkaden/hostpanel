#!/usr/bin/env node
'use strict';
/*
 * Integration test for the NPMplus client against a fake NPMplus 2.15.1
 * server that behaves like a real one: POST /api/tokens answers
 * {expires} with the JWT only in a __Host-Http-token cookie, and every other
 * endpoint 403s unless that cookie comes back.
 *
 * ./db is stubbed so this runs without the blocked npm dependencies.
 */

const http = require('http');
const path = require('path');
const Module = require('module');

const APP = path.join(__dirname, '..', 'src');

/* ---------------------------------------------------------- stub ./db ---- */
const settings = {
  npmplus_url: '',
  npmplus_email: 'admin@example.com',
  npmplus_password: 'correct-horse',
  npmplus_le_email: 'admin@example.com',
  npmplus_enabled: '1',
  npmplus_insecure: '0',
  host_ip: '192.168.1.50',
};
const dbPath = path.join(APP, 'db.js');
const stub = new Module(dbPath, null);
stub.filename = dbPath;
stub.loaded = true;
stub.exports = {
  getSetting: (k, fallback) => (settings[k] !== undefined ? settings[k] : fallback || ''),
  setSetting: (k, v) => { settings[k] = v; },
};
require.cache[dbPath] = stub;

const npmplus = require(path.join(APP, 'npmplus.js'));

/* ------------------------------------------------- fake NPMplus server --- */
const JWT = 's%3AeyJhbGciOiJSUzI1NiJ9.fake-signed-token.sig';
const COOKIE_NAME = '__Host-Http-token';
const REAL_PASSWORD = 'correct-horse';

// Exactly what NPMplus 2.15.x permits when creating a certificate.
const ALLOWED_CERT_FIELDS = new Set(['provider', 'nice_name', 'domain_names', 'meta']);
const ALLOWED_CERT_META = new Set([
  'certificate', 'certificate_key', 'reuse_key', 'dns_challenge',
  'dns_provider_credentials', 'dns_provider', 'letsencrypt_certificate', 'propagation_seconds',
]);
const certPayloads = [];
const proxyWrites = [];

// Exactly the fields NPMplus 2.15.x permits on a proxy host.
const ALLOWED_PROXY_FIELDS = new Set([
  'domain_names', 'forward_scheme', 'forward_host', 'forward_port', 'certificate_id',
  'ssl_forced', 'hsts_enabled', 'hsts_subdomains', 'trust_forwarded_proto', 'http2_support',
  'npmplus_http3_support', 'block_exploits', 'caching_enabled', 'allow_websocket_upgrade',
  'npmplus_noindex', 'npmplus_crowdsec_appsec', 'npmplus_proxy_request_buffering',
  'npmplus_proxy_response_buffering', 'npmplus_upstream_compression', 'npmplus_fancyindex',
  'npmplus_x_frame_options', 'npmplus_auth_request', 'npmplus_auth_request_upstream',
  'npmplus_access_list_ids', 'npmplus_access_list_type', 'advanced_config',
  'npmplus_location_config', 'meta', 'locations',
]);

// What NPMplus already has. The default entry is an unrelated domain; a test
// swaps in a colliding one to simulate a domain that is already proxied.
const DEFAULT_HOSTS = [{
  id: 7, domain_names: ['old.example.com'], forward_scheme: 'http',
  forward_host: '1.2.3.4', forward_port: 80, enabled: 1, certificate_id: 0,
}];
let existingHosts = DEFAULT_HOSTS;
let mode = 'modern';
const calls = [];

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (d) => { body += d; });
  req.on('end', () => {
    const cookie = req.headers.cookie || '';
    const authed = cookie.includes(`${COOKIE_NAME}=${JWT}`) ||
      (mode === 'legacy' && req.headers.authorization === 'Bearer legacy-token');
    calls.push({ method: req.method, url: req.url, authed, cookie, auth: req.headers.authorization });

    const json = (code, obj, headers = {}) => {
      res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
      res.end(JSON.stringify(obj));
    };

    if (req.url === '/api') {
      return json(200, { status: 'OK', setup: true, version: '2026-06-25-r1-ee3cf8a-2.15.1', password: true, oidc: false });
    }

    if (req.method === 'POST' && req.url === '/api/tokens') {
      const creds = JSON.parse(body || '{}');
      if (creds.secret !== REAL_PASSWORD) {
        return json(400, { error: { code: 400, message: 'Invalid email or password' } });
      }
      if (mode === 'totp') {
        return json(200, { requiresTotp: true, expires: new Date(Date.now() + 86400000).toISOString() },
          { 'Set-Cookie': `__Host-Http-challenge_token=chal; Path=/; HttpOnly; Secure; SameSite=Strict` });
      }
      if (mode === 'legacy') {
        return json(200, { token: 'legacy-token', expires: new Date(Date.now() + 86400000).toISOString() });
      }
      if (mode === 'nocookie') {
        return json(200, { expires: new Date(Date.now() + 86400000).toISOString() });
      }
      // modern NPMplus: cookie only, exactly like the real response
      return json(200, { expires: new Date(Date.now() + 86400000).toISOString() },
        { 'Set-Cookie': `${COOKIE_NAME}=${JWT}; Path=/; Expires=Wed, 16 Sep 2026 23:05:58 GMT; HttpOnly; Secure; SameSite=Strict` });
    }

    if (!authed) return json(403, { error: { code: 403, message: 'Not authorised' } });

    if (req.url.startsWith('/api/nginx/proxy-hosts')) {
      const one = req.url.match(/^\/api\/nginx\/proxy-hosts\/(\d+)(\/enable|\/disable)?$/);

      // Turning a host back on is its own endpoint, not a field on the update.
      if (one && one[2] === '/enable' && req.method === 'POST') {
        const host = existingHosts.find((h) => h.id === Number(one[1]));
        if (!host) return json(404, { error: { code: 404, message: 'not found' } });
        host.enabled = 1;
        return json(200, true);
      }

      if (req.method === 'GET') {
        if (one) {
          const host = existingHosts.find((h) => h.id === Number(one[1]));
          return host ? json(200, host) : json(404, { error: { code: 404, message: 'not found' } });
        }
        return json(200, existingHosts);
      }
      if (req.method === 'POST' || req.method === 'PUT') {
        // NPMplus schemas are additionalProperties:false. Reject anything the
        // real server would reject, so the client payload stays valid.
        const payload = JSON.parse(body || '{}');
        const extra = Object.keys(payload).filter((k) => !ALLOWED_PROXY_FIELDS.has(k));
        if (extra.length) {
          return json(400, { error: { code: 400, message: 'data must NOT have additional properties' } });
        }
        proxyWrites.push({ method: req.method, id: one ? Number(one[1]) : null, payload });
        // An update is remembered, so a later read shows what the client set.
        if (one) {
          const host = existingHosts.find((h) => h.id === Number(one[1]));
          if (host) Object.assign(host, payload);
        }
        return json(req.method === 'POST' ? 201 : 200, { id: one ? Number(one[1]) : 42, ...payload });
      }
      if (req.method === 'DELETE') return json(200, true);
    }
    if (req.method === 'POST' && req.url === '/api/nginx/certificates') {
      const payload = JSON.parse(body || '{}');
      const topExtra = Object.keys(payload).filter((k) => !ALLOWED_CERT_FIELDS.has(k));
      if (topExtra.length) {
        return json(400, { error: { code: 400, message: 'data must NOT have additional properties' } });
      }
      const meta = payload.meta || {};
      if (mode === 'legacy') {
        // Classic NPM demands the agreement flag and accepts the email.
        if (meta.letsencrypt_agree !== true) {
          return json(400, { error: { code: 400, message: "data/meta must have required property 'letsencrypt_agree'" } });
        }
      } else {
        // NPMplus: meta is additionalProperties:false and has no email keys.
        const metaExtra = Object.keys(meta).filter((k) => !ALLOWED_CERT_META.has(k));
        if (metaExtra.length) {
          return json(400, { error: { code: 400, message: 'data/meta must NOT have additional properties' } });
        }
      }
      certPayloads.push(payload);
      return json(201, { id: 99, ...payload });
    }
    return json(404, { error: { code: 404, message: 'not found' } });
  });
});

/* -------------------------------------------------------------- tests ---- */
let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`); }
}

server.listen(0, '127.0.0.1', async () => {
  settings.npmplus_url = `http://127.0.0.1:${server.address().port}`;
  const site = {
    id: 1, name: 'myapp', domain: 'app.example.com', extra_domains: 'www.example.com',
    port: 21000, npm_proxy_id: null, npm_cert_id: null,
  };

  try {
    console.log('\nmodern NPMplus (cookie auth)');
    npmplus.invalidateToken();
    const session = await npmplus.getSession(true);
    check('signs in with no token in the body', !session.token);
    check('captures the __Host-Http-token cookie', /__Host-Http-token=/.test(session.cookies || ''), `cookies: ${session.cookies}`);

    const hosts = await npmplus.listProxyHosts();
    check('authenticated GET succeeds', Array.isArray(hosts) && hosts.length === 1);
    check('cookie was replayed on the GET', calls[calls.length - 1].cookie.includes('__Host-Http-token'));

    const test = await npmplus.testConnection();
    check('testConnection reports ok', test.ok === true, JSON.stringify(test));
    check('testConnection reports cookie auth', test.authMode === 'session cookie', JSON.stringify(test));
    check('testConnection reports the version', /2\.15\.1/.test(test.version || ''), JSON.stringify(test));

    npmplus.invalidateToken();
    const sync = await npmplus.syncProxyHost(site);
    check('creates the proxy host', sync.proxyId === 42, JSON.stringify(sync));
    check('requests a certificate', sync.certId === 99, JSON.stringify(sync));
    check('reports ssl active', sync.ssl === true);

    const created = calls.find((c) => c.method === 'POST' && c.url === '/api/nginx/proxy-hosts');
    check('proxy POST was authenticated', created && created.authed);

    npmplus.invalidateToken();
    check('deletes a proxy host', (await npmplus.deleteProxyHost(42)) === true);

    console.log('\ncertificate request shape');
    {
      const last = certPayloads[certPayloads.length - 1];
      check('a certificate was accepted by the strict schema', Boolean(last), 'none sent');
      check('meta omits letsencrypt_email', last && last.meta.letsencrypt_email === undefined,
        JSON.stringify(last && last.meta));
      check('meta omits letsencrypt_agree', last && last.meta.letsencrypt_agree === undefined,
        JSON.stringify(last && last.meta));
      check('meta still sets dns_challenge', last && last.meta.dns_challenge === false);
    }

    console.log('\nstrict NPMplus schema (additionalProperties: false)');
    npmplus.invalidateToken();
    const sent = calls.filter((c) => c.method === 'POST' && c.url === '/api/nginx/proxy-hosts');
    check('proxy payload was accepted by the strict schema', sent.length > 0);
    check('payload omits the removed access_list_id field',
      !JSON.stringify(sent).includes('access_list_id'));

    console.log('\na domain NPMplus already proxies');
    existingHosts = [{
      id: 4, domain_names: ['kjserver.net'], forward_scheme: 'http',
      forward_host: '10.0.0.9', forward_port: 8080, enabled: 1, certificate_id: 0,
    }];
    const claimed = { ...site, domain: 'kjserver.net', extra_domains: '' };
    npmplus.invalidateToken();
    let takeover = null;
    try { await npmplus.syncProxyHost(claimed); } catch (e) { takeover = e; }
    check('refuses to repoint it without permission', takeover !== null, 'no error thrown');
    check('reports the existing host id', takeover && takeover.existingProxy &&
      takeover.existingProxy.id === 4, takeover && takeover.message);
    check('reports where it currently points',
      takeover && /10\.0\.0\.9:8080/.test(takeover.message), takeover && takeover.message);

    npmplus.invalidateToken();
    const adopted = await npmplus.syncProxyHost(claimed, { adopt: true, requestSsl: false });
    check('adopts it when explicitly told to', adopted.proxyId === 4, JSON.stringify(adopted));
    existingHosts = DEFAULT_HOSTS;

    /* ------------------------------------------- checking and repairing -- */
    console.log('\nchecking a proxy host against the site');
    mode = 'modern';
    settings.npmplus_password = REAL_PASSWORD;
    npmplus.invalidateToken();
    {
      // A host that has drifted in every way that matters: wrong port, wrong
      // forwarding address, a missing domain, websockets off, turned off.
      existingHosts = [{
        id: 11, domain_names: ['app.example.com'], forward_scheme: 'http',
        forward_host: '10.9.9.9', forward_port: 9999, enabled: 0, certificate_id: 0,
        allow_websocket_upgrade: false, advanced_config: '',
      }];
      const drifted = { ...site, npm_proxy_id: 11, npm_cert_id: null };
      const found = npmplus.diagnoseProxy(drifted, existingHosts[0]).map((i) => i.code);

      check('spots the wrong forwarding port', found.includes('forward_port'), found.join(', '));
      check('spots the wrong forwarding address', found.includes('forward_host'), found.join(', '));
      check('spots the missing domain', found.includes('domains'), found.join(', '));
      check('spots websockets being off', found.includes('websocket'), found.join(', '));
      check('spots the host being disabled', found.includes('disabled'), found.join(', '));
      const said = npmplus.diagnoseProxy(drifted, existingHosts[0]);
      check('says so in plain words',
        said.some((i) => /forwards to port 9999, but this site listens on 21000/.test(i.says)),
        JSON.stringify(said));

      const report = await npmplus.checkProxy(drifted);
      check('checkProxy finds the host and reports it is not ok', report.reachable && !report.ok);
      check('and changes nothing', existingHosts[0].forward_port === 9999);

      proxyWrites.length = 0;
      const repair = await npmplus.repairProxy(drifted);
      const written = proxyWrites.filter((w) => w.method === 'PUT').pop();
      check('repair updates the existing host rather than making a new one',
        written && written.id === 11, JSON.stringify(proxyWrites));
      check('it corrects the port', written.payload.forward_port === 21000);
      check('it corrects the forwarding address', written.payload.forward_host === '192.168.1.50');
      check('it restores both domains',
        written.payload.domain_names.join(',') === 'app.example.com,www.example.com',
        written.payload.domain_names.join(','));
      check('it turns websockets on', written.payload.allow_websocket_upgrade === true);
      check('it turns the host back on', existingHosts[0].enabled === 1);
      check('it says what it changed', repair.fixed.length >= 4, JSON.stringify(repair.fixed));
      check('and the site keeps the same proxy id', repair.proxyId === 11);

      const after = await npmplus.checkProxy({ ...drifted, allow_framing: 0 });
      check('a second check comes back clean', after.ok, JSON.stringify(after.issues));
      check('and a repair then changes nothing',
        (await npmplus.repairProxy({ ...drifted, allow_framing: 0 })).fixed.length === 0);
    }

    console.log('\nframing, and the config the user wrote themselves');
    {
      existingHosts = [{
        id: 12, domain_names: ['app.example.com', 'www.example.com'], forward_scheme: 'http',
        forward_host: '192.168.1.50', forward_port: 21000, enabled: 1, certificate_id: 0,
        allow_websocket_upgrade: true,
        advanced_config: 'client_max_body_size 512m;',
      }];
      const framed = { ...site, npm_proxy_id: 12, allow_framing: 1 };

      proxyWrites.length = 0;
      const repair = await npmplus.repairProxy(framed);
      const sentConfig = proxyWrites.filter((w) => w.method === 'PUT').pop().payload.advanced_config;

      check('the framing header is cleared', /more_clear_headers "X-Frame-Options";/.test(sentConfig),
        sentConfig);
      check("the user's own directive survives", /client_max_body_size 512m;/.test(sentConfig),
        'a sync must never silently drop hand-written config');
      check('the panel marks its own block', sentConfig.includes('# >>> hostpanel'));
      check('it says what it did', repair.fixed.some((f) => /X-Frame-Options/.test(f)),
        JSON.stringify(repair.fixed));

      // And turning it back off removes only the panel's block.
      proxyWrites.length = 0;
      await npmplus.repairProxy({ ...framed, allow_framing: 0 });
      const off = proxyWrites.filter((w) => w.method === 'PUT').pop().payload.advanced_config;
      check('turning framing off removes the directive', !/more_clear_headers/.test(off), off);
      check('and still keeps the user config', /client_max_body_size 512m;/.test(off), off);
      check('with no leftover markers', !off.includes('hostpanel'), off);

      check('the block can be stripped from config that never had one',
        npmplus.withoutManagedBlock('server_tokens off;') === 'server_tokens off;');
      check('and from an empty config', npmplus.withoutManagedBlock('') === '');
      check('and from null', npmplus.withoutManagedBlock(null) === '');
    }

    console.log('\nrepairing a host the panel did not create');
    {
      existingHosts = [{
        id: 13, domain_names: ['app.example.com'], forward_scheme: 'http',
        forward_host: '172.16.0.4', forward_port: 3000, enabled: 1, certificate_id: 0,
        allow_websocket_upgrade: true, advanced_config: '',
      }];
      const unlinked = { ...site, npm_proxy_id: null, extra_domains: '' };
      let refused = null;
      try { await npmplus.repairProxy(unlinked); } catch (e) { refused = e; }
      check('it refuses to take over silently', refused && refused.existingProxy,
        refused && refused.message);
      check('the host is untouched', existingHosts[0].forward_port === 3000);

      const taken = await npmplus.repairProxy(unlinked, { adopt: true });
      check('and adopts it when told to', taken.proxyId === 13, JSON.stringify(taken));
    }

    console.log('\na site with nothing to check');
    {
      const noDomain = { ...site, domain: '', extra_domains: '' };
      const issues = npmplus.diagnoseProxy(noDomain, null).map((i) => i.code);
      check('a site with no domain is not reported as broken', issues.join(',') === 'no_domain',
        issues.join(','));
      const missing = npmplus.diagnoseProxy(site, null).map((i) => i.code);
      check('a site whose host has vanished is', missing.includes('missing'), missing.join(','));
    }
    existingHosts = DEFAULT_HOSTS;

    console.log('\nlegacy NPM (bearer token) — backward compatibility');
    mode = 'legacy';
    npmplus.invalidateToken();
    const legacy = await npmplus.getSession(true);
    check('uses the body token', legacy.token === 'legacy-token');
    check('legacy GET succeeds', (await npmplus.listProxyHosts()).length === 1);
    check('bearer header was sent', calls[calls.length - 1].auth === 'Bearer legacy-token');

    certPayloads.length = 0;
    npmplus.invalidateToken();
    const legacySync = await npmplus.syncProxyHost({ ...site, npm_proxy_id: null, npm_cert_id: null });
    const legacyCert = certPayloads[certPayloads.length - 1];
    check('legacy NPM gets a certificate too', legacySync.certId === 99, JSON.stringify(legacySync));
    check('legacy meta carries letsencrypt_agree',
      legacyCert && legacyCert.meta.letsencrypt_agree === true, JSON.stringify(legacyCert && legacyCert.meta));
    check('legacy meta carries the email',
      legacyCert && typeof legacyCert.meta.letsencrypt_email === 'string',
      JSON.stringify(legacyCert && legacyCert.meta));

    console.log('\nTOTP-enabled account');
    mode = 'totp';
    npmplus.invalidateToken();
    let msg = '';
    try { await npmplus.getSession(true); } catch (e) { msg = e.message; }
    check('explains that TOTP is unsupported', /two-factor/i.test(msg), msg);

    console.log('\nserver issues no session at all');
    mode = 'nocookie';
    npmplus.invalidateToken();
    msg = '';
    try { await npmplus.getSession(true); } catch (e) { msg = e.message; }
    check('names the missing cookie and body keys', /Body keys/.test(msg) && /Set-Cookie/.test(msg), msg);

    console.log('\nwrong password');
    mode = 'modern';
    settings.npmplus_password = 'wrong';
    npmplus.invalidateToken();
    const bad = await npmplus.testConnection();
    check('fails at the auth step', bad.ok === false && bad.step === 'auth', JSON.stringify(bad));
    check('surfaces the NPMplus message', /Invalid email or password/.test(bad.error), bad.error);
  } catch (err) {
    fail += 1;
    console.log(`\n  THREW  ${err.stack}`);
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  server.close();
  process.exit(fail ? 1 : 0);
});
