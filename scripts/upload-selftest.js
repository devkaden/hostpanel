#!/usr/bin/env node
'use strict';
/*
 * Uploads real files to the running panel, from the panel's own machine, with
 * no browser involved.
 *
 * The point is to split one question into two. "Uploads hang" can mean the
 * server never finishes, or the browser never asks. Server logs alone cannot
 * tell those apart - a request that is never made looks exactly like a quiet
 * server. This talks to the live HTTP port the same way the file manager does:
 * same route, same headers, same raw body. If it passes, the server is fine
 * and the problem is in the browser or on the network between them.
 *
 * It mints its own session by writing directly to the session table, so no
 * password is needed and nothing about your login is changed.
 *
 * Run on the panel host:  npm run test:upload-live
 */

const http = require('http');
const crypto = require('crypto');

process.env.NODE_ENV = process.env.NODE_ENV || 'production';

require('./require-install')('test:upload-live');

const config = require('../src/config');
const { db, getNumericSetting } = require('../src/db');

const PORT = getNumericSetting('panel_port', config.port);
const HOST = '127.0.0.1';

function die(msg) {
  console.error('\n  ' + msg + '\n');
  process.exit(1);
}

/* ------------------------------------------------- mint a session -------- */
// Mirrors what express-session + cookie-parser do: "s:<sid>.<base64 hmac>".
function signedCookie(sid, secret) {
  const mac = crypto
    .createHmac('sha256', secret)
    .update(sid)
    .digest('base64')
    .replace(/=+$/, '');
  return 's:' + sid + '.' + mac;
}

const admin = db
  .prepare("SELECT * FROM users WHERE role = 'admin' AND active = 1 ORDER BY id LIMIT 1")
  .get();
if (!admin) die('No active administrator in the database - nothing to run as.');

const siteArg = process.argv[2];
const site = siteArg
  ? db.prepare('SELECT * FROM sites WHERE name = ? OR id = ?').get(siteArg, parseInt(siteArg, 10) || -1)
  : db.prepare('SELECT * FROM sites ORDER BY id LIMIT 1').get();
if (!site) {
  die(siteArg ? `No site called "${siteArg}".` : 'No sites exist yet - create one first.');
}

const sid = crypto.randomBytes(24).toString('hex');
const csrfToken = crypto.randomBytes(24).toString('hex');
const expires = Date.now() + 10 * 60 * 1000;

db.prepare(
  'INSERT INTO sessions (sid, expires, data) VALUES (?,?,?) ' +
    'ON CONFLICT(sid) DO UPDATE SET expires = excluded.expires, data = excluded.data'
).run(
  sid,
  expires,
  JSON.stringify({
    cookie: {
      originalMaxAge: 10 * 60 * 1000,
      expires: new Date(expires).toISOString(),
      httpOnly: true,
      path: '/',
      sameSite: 'lax',
      secure: !!config.secureCookies,
    },
    user: { id: admin.id, username: admin.username, email: admin.email, role: admin.role },
    csrfToken,
  })
);

const cookie = 'hostpanel.sid=' + encodeURIComponent(signedCookie(sid, config.sessionSecret));

function cleanup() {
  try { db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid); } catch (_) { /* ignore */ }
}
process.on('exit', cleanup);

/* --------------------------------------------------------- requests ------ */
function request(method, urlPath, body, extraHeaders) {
  return new Promise((resolve, reject) => {
    const headers = Object.assign(
      {
        Cookie: cookie,
        Accept: 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      extraHeaders || {}
    );
    if (Buffer.isBuffer(body)) headers['Content-Length'] = body.length;

    const req = http.request({ host: HOST, port: PORT, method, path: urlPath, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () =>
        resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') })
      );
    });
    req.setTimeout(90000, () => req.destroy(new Error('the request timed out after 90s')));
    req.on('error', reject);
    if (Buffer.isBuffer(body)) req.write(body);
    req.end();
  });
}

function putRaw(name, buffer, dir) {
  const url =
    `/api/sites/${site.id}/files/raw` +
    `?dir=${encodeURIComponent(dir || '')}&path=${encodeURIComponent(name)}`;
  return request('PUT', url, buffer, { 'Content-Type': 'application/octet-stream' });
}

/* ------------------------------------------------------------ run -------- */
let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`); }
}

const CASES = [
  { name: '__selftest-tiny.txt', size: 12 },
  { name: '__selftest-empty.txt', size: 0 },
  { name: '__selftest/nested/deep.txt', size: 2048 },
  { name: '__selftest-1mb.bin', size: 1024 * 1024 },
  { name: '__selftest-8mb.bin', size: 8 * 1024 * 1024 },
];

(async () => {
  console.log(`\nPanel   http://${HOST}:${PORT}`);
  console.log(`Site    ${site.name} (id ${site.id})`);
  console.log(`As      ${admin.username}\n`);

  // Prove the session and route are reachable before blaming the upload.
  let listing;
  try {
    listing = await request('GET', `/api/sites/${site.id}/files`);
  } catch (err) {
    die(
      `Could not reach the panel on ${HOST}:${PORT} - ${err.message}\n  ` +
        'Is the service running?  systemctl status hostpanel'
    );
  }
  check('the panel answers an authenticated API call', listing.status === 200,
    `HTTP ${listing.status}: ${listing.body.slice(0, 200)}`);
  if (listing.status !== 200) {
    console.log('\n  Stopping: without a working session the upload result would mean nothing.\n');
    process.exit(1);
  }

  for (const c of CASES) {
    const buf = Buffer.alloc(c.size, 'x');
    const began = Date.now();
    let res;
    try {
      res = await putRaw(c.name, buf, '');
    } catch (err) {
      check(`${c.name} (${c.size} bytes)`, false, err.message);
      continue;
    }
    const ms = Date.now() - began;
    let parsed = {};
    try { parsed = JSON.parse(res.body || '{}'); } catch (_) { /* not json */ }
    check(
      `${c.name} (${c.size} bytes) in ${ms}ms`,
      res.status === 200 && parsed.ok === true && parsed.bytes === c.size,
      `HTTP ${res.status}: ${res.body.slice(0, 300)}`
    );
  }

  // A body larger than the limit must be refused from the declared length
  // alone, before a single byte is sent. Deliberately never sends that body:
  // the headers go out and we wait for the answer, which is the whole point -
  // a 512 MB upload should be rejected in milliseconds, not after 512 MB.
  {
    const over = config.maxUploadBytes + 1;
    const res = await new Promise((resolve) => {
      const req = http.request(
        {
          host: HOST,
          port: PORT,
          method: 'PUT',
          path: `/api/sites/${site.id}/files/raw?dir=&path=__selftest-over.bin`,
          headers: {
            Cookie: cookie,
            Accept: 'application/json',
            'X-CSRF-Token': csrfToken,
            'Content-Type': 'application/octet-stream',
            'Content-Length': String(over),
          },
        },
        (res2) => {
          const chunks = [];
          res2.on('data', (c) => chunks.push(c));
          res2.on('end', () => {
            req.destroy();
            resolve({ status: res2.statusCode, body: Buffer.concat(chunks).toString('utf8') });
          });
        }
      );
      req.setTimeout(15000, () => {
        req.destroy();
        resolve({ status: 0, body: 'no answer within 15s - the server waited for the body' });
      });
      req.on('error', () => { /* the destroy above lands here */ });
      req.flushHeaders(); // headers only; the body is never written
    });
    check('an oversized upload is refused from its headers alone', res.status === 413,
      `HTTP ${res.status}: ${String(res.body).slice(0, 200)}`);
  }

  // Tidy up after ourselves.
  const paths = CASES.map((c) => c.name).concat(['__selftest']);
  await request(
    'POST',
    `/api/sites/${site.id}/files/delete`,
    Buffer.from(JSON.stringify({ paths })),
    { 'Content-Type': 'application/json' }
  ).catch(() => {});

  console.log(`\n${pass} passed, ${fail} failed`);
  if (!fail) {
    console.log(
      '\n  The server accepts uploads correctly on this machine.\n' +
        '  If the browser still hangs, the problem is between the browser and\n' +
        '  this port - open the panel, press F12, and watch the Console and\n' +
        '  Network tabs while dropping a file.\n'
    );
  } else {
    console.log('\n  The server itself is failing. The output above says how.\n');
  }
  process.exit(fail ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
