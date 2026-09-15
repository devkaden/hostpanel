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
      if (req.method === 'GET') return json(200, [{ id: 7, domain_names: ['old.example.com'], forward_scheme: 'http', forward_host: '1.2.3.4', forward_port: 80, enabled: 1, certificate_id: 0 }]);
      if (req.method === 'POST') return json(201, { id: 42, ...JSON.parse(body) });
      if (req.method === 'PUT') return json(200, { id: 42, ...JSON.parse(body) });
      if (req.method === 'DELETE') return json(200, true);
    }
    if (req.method === 'POST' && req.url === '/api/nginx/certificates') {
      return json(201, { id: 99, ...JSON.parse(body) });
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

    console.log('\nlegacy NPM (bearer token) — backward compatibility');
    mode = 'legacy';
    npmplus.invalidateToken();
    const legacy = await npmplus.getSession(true);
    check('uses the body token', legacy.token === 'legacy-token');
    check('legacy GET succeeds', (await npmplus.listProxyHosts()).length === 1);
    check('bearer header was sent', calls[calls.length - 1].auth === 'Bearer legacy-token');

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
