#!/usr/bin/env node
'use strict';
/*
 * Rate limiting, and the other findings from the security scan.
 *
 * The limiter is exercised for real - counted, exhausted, recovered - rather
 * than checked for its presence, because the failure that matters is not "no
 * limiter" but "a limiter that counts the wrong thing": one that keys on the
 * address alone locks out everyone behind a household router, and one that
 * keys on the account alone does nothing at all to a stranger at the login
 * page.
 *
 * Run with: npm run test:ratelimit
 */

const path = require('path');
const Module = require('module');

const APP = path.join(__dirname, '..', 'src');

let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`); }
}

/* --------------------------------------------------------- stub ./db ---- */
const settings = {};
const dbPath = path.join(APP, 'db.js');
const stub = new Module(dbPath, null);
stub.filename = dbPath;
stub.loaded = true;
stub.exports = {
  getSetting: (k, fb) => (settings[k] !== undefined ? settings[k] : fb || ''),
  getNumericSetting: (k, fb) => {
    const n = parseInt(settings[k], 10);
    return Number.isInteger(n) && n > 0 ? n : fb;
  },
};
require.cache[dbPath] = stub;

const rl = require(path.join(APP, 'ratelimit.js'));

const request = (over) => Object.assign(
  { method: 'GET', path: '/', ip: '10.0.0.1', session: null, xhr: false, get: () => '' },
  over
);

/* ----------------------------------------------------------- buckets --- */
console.log('\nwhich bucket a request lands in');
{
  check('a signed-out request is the strict bucket',
    rl.bucketFor(request({ path: '/login', method: 'POST' })) === 'auth',
    'these are the paths a stranger can reach');
  check('and so is a signed-out GET',
    rl.bucketFor(request({ path: '/login' })) === 'auth');
  check('a signed-in read is the generous bucket',
    rl.bucketFor(request({ session: { user: { id: 1 } } })) === 'read');
  check('a signed-in write is not',
    rl.bucketFor(request({ method: 'POST', session: { user: { id: 1 } } })) === 'write');
  check('reads are allowed more than writes',
    rl.BUCKETS.read.max > rl.BUCKETS.write.max);
  check('a preview is its own bucket, not the signed-out one',
    rl.bucketFor(request({ path: '/preview/abc123/logo.png' })) === 'preview',
    'it carries a token rather than a session, and one page is a burst of requests');
  check('and a generous one',
    rl.BUCKETS.preview.max > rl.BUCKETS.read.max,
    'forty images and a few fonts is what a correct page looks like');
  check('previews are counted per token',
    rl.keyFor(request({ path: '/preview/abc123/a.png' }), 'preview')
      === rl.keyFor(request({ path: '/preview/abc123/b.png', ip: '9.9.9.9' }), 'preview'));
  check('and two previews do not share an allowance',
    rl.keyFor(request({ path: '/preview/abc123/a.png' }), 'preview')
      !== rl.keyFor(request({ path: '/preview/zzz999/a.png' }), 'preview'));
  check('and both more than the signed-out bucket',
    rl.BUCKETS.write.max > rl.BUCKETS.auth.max);
}

/* -------------------------------------------------------- who is counted */
console.log('\nwho the count is against');
{
  const a = request({ session: { user: { id: 7 } }, ip: '10.0.0.1' });
  const b = request({ session: { user: { id: 7 } }, ip: '198.51.100.4' });
  const c = request({ session: { user: { id: 8 } }, ip: '10.0.0.1' });

  check('the same account from two addresses is one count',
    rl.keyFor(a, 'read') === rl.keyFor(b, 'read'),
    'otherwise a limit is escaped by opening a phone hotspot');
  check('two accounts on one address are not',
    rl.keyFor(a, 'read') !== rl.keyFor(c, 'read'),
    'one person must not be able to spend a housemate\'s allowance');
  check('signed out, the address is what is left',
    rl.keyFor(request({ ip: '203.0.113.1' }), 'auth').includes('203.0.113.1'));
  check('the buckets are counted separately',
    rl.keyFor(a, 'read') !== rl.keyFor(a, 'write'));
}

/* -------------------------------------------------------- the counting -- */
console.log('\ncounting');
{
  rl.reset();
  let last;
  for (let i = 0; i < 5; i += 1) last = rl.take('k', 60000, 5);
  check('the allowance is spent exactly, not early', last.allowed, JSON.stringify(last));
  check('and nothing is left', last.remaining === 0);

  const over = rl.take('k', 60000, 5);
  check('the next one is refused', !over.allowed);
  check('it says when to come back', over.resetAt > Date.now());

  check('another key is unaffected', rl.take('other', 60000, 5).allowed,
    'one noisy account must not lock out everybody else');

  // A window that has passed starts again.
  rl.reset();
  const expired = rl.take('k', -1, 1);
  check('an expired window starts over', expired.allowed && rl.take('k', -1, 1).allowed);
  rl.reset();
}

/* ------------------------------------------------- the middleware itself */
console.log('\nthe middleware');
{
  rl.reset();
  settings.rate_limit_read = '3';

  const headers = {};
  const res = {
    statusCode: 200,
    set: (k, v) => { if (typeof k === 'object') Object.assign(headers, k); else headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    render(view, locals) { this.body = locals; this.view = view; return this; },
  };
  const req = request({ session: { user: { id: 1 } }, path: '/api/status',
    get: (h) => (h === 'accept' ? 'application/json' : '') });

  let allowed = 0;
  for (let i = 0; i < 3; i += 1) rl.middleware(req, res, () => { allowed += 1; });
  check('a configured limit is honoured', allowed === 3, `let ${allowed} through`);
  check('the remaining count is reported', headers['X-RateLimit-Remaining'] === '0', headers['X-RateLimit-Remaining']);

  rl.middleware(req, res, () => { allowed += 1; });
  check('the fourth is refused', allowed === 3);
  check('with 429', res.statusCode === 429, String(res.statusCode));
  check('and Retry-After', Number(headers['Retry-After']) > 0, headers['Retry-After']);
  check('the answer is JSON for an API call', res.body && typeof res.body.error === 'string');
  check('and it says what to do', /wait/i.test(res.body.error), res.body.error);

  // A browser asking for a page gets a page, not JSON it will display raw.
  rl.reset();
  const pageRes = { ...res, statusCode: 200, set: res.set, status: res.status, json: res.json, render: res.render };
  const pageReq = request({ session: { user: { id: 2 } }, path: '/sites' });
  for (let i = 0; i < 4; i += 1) rl.middleware(pageReq, pageRes, () => {});
  check('a page request gets the error page', pageRes.view === 'error', String(pageRes.view));

  delete settings.rate_limit_read;
  rl.reset();
}

/* -------------------------------------------------- long-lived requests - */
console.log('\nstreams are not traffic');
{
  rl.reset();
  settings.rate_limit_read = '1';
  const res = {
    set: () => {}, status() { return this; }, json() { return this; }, render() { return this; },
  };
  let through = 0;
  const stream = request({ session: { user: { id: 3 } }, path: '/sites/1/progress' });
  for (let i = 0; i < 5; i += 1) rl.middleware(stream, res, () => { through += 1; });
  check('a progress stream is never counted', through === 5,
    'a build log left open would otherwise spend the whole allowance');
  delete settings.rate_limit_read;
  rl.reset();
}

/* --------------------------------------------- the rest of the findings - */
console.log('\nthe other things the scan found');
{
  const fs = require('fs');
  const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

  // 1. Polynomial regular expression on user input.
  const { stripTrailingSlashes } = require(path.join(APP, 'netutil.js'));
  check('trailing slashes come off', stripTrailingSlashes('https://npm.local///') === 'https://npm.local');
  check('an inner slash is kept', stripTrailingSlashes('https://npm.local/a/b') === 'https://npm.local/a/b');
  check('whitespace goes too', stripTrailingSlashes('  https://npm.local/  ') === 'https://npm.local');
  check('nothing is not a problem', stripTrailingSlashes('') === '' && stripTrailingSlashes(null) === '');
  check('a long string is capped', stripTrailingSlashes('a'.repeat(5000)).length === 2048);

  // The actual point: a pathological input has to be fast. The regex this
  // replaced made this take seconds.
  const started = Date.now();
  stripTrailingSlashes(`https://x/${'/'.repeat(50000)}`);
  const ms = Date.now() - started;
  check(`50,000 trailing slashes are handled instantly (${ms}ms)`, ms < 50, `${ms}ms`);

  check('and no regex does this job any more',
    !/replace\(\/\\\/\+\$\//.test(read('src/routes/settings.js') + read('src/npmplus.js')));

  // 2. Server-side URL redirect.
  const authRoutes = read('src/routes/auth.js');
  check('the redirect target is rebuilt from a parse, not just checked',
    /new URL\(value, 'http:\/\/hostpanel\.invalid'\)/.test(authRoutes));
  check('and anything that resolves elsewhere is dropped',
    /parsed\.origin !== 'http:\/\/hostpanel\.invalid'/.test(authRoutes));

  // 3. Unvalidated dynamic method call.
  const siteRoutes = read('src/routes/sites.js');
  check('the action table has no prototype to reach through',
    /Object\.create\(null\)/.test(siteRoutes),
    'ACTIONS["constructor"] was a function before this');
  check('and the lookup checks the key belongs to it',
    /hasOwnProperty\.call\(ACTIONS, action\)/.test(siteRoutes));
  check('and that what came back is callable',
    /typeof handler !== 'function'/.test(siteRoutes));

  // 4. Clear-text logging of sensitive information.
  const index = read('src/index.js');
  const logged = index.split('\n').filter((l) => /console\.log/.test(l) && /bootstrap\.password/.test(l));
  check('the first-run password is not printed to the log',
    logged.length === 0,
    `it would live in the journal, and in every log shipper after it: ${logged.join(' / ')}`);
  check('the log says where to read it instead',
    /written to \$\{passwordFile\}/.test(index));
  check('and it is still written to the 0600 file',
    /mode: 0o600/.test(index) && /bootstrap\.password/.test(index));

  // 5. Disabling certificate validation.
  const sitesSrc = read('src/sites.js');
  check('the probe only skips certificate checks on this network',
    /rejectUnauthorized: !isPrivateHost\(parsed\.hostname\)/.test(sitesSrc));

  // sites.js reaches for Docker and the reverse proxy on require, neither of
  // which this test has or needs.
  for (const [rel, exports] of [
    ['config.js', { sitesDir: '/tmp/hp-rl', containerPrefix: 'hp-', networkPrefix: 'hp-net-',
      port: 8890, portRangeStart: 21000, portRangeEnd: 21999, siteTypes: {} }],
    ['docker.js', {}],
    ['npmplus.js', {}],
  ]) {
    const full = path.join(APP, rel);
    const m = new Module(full, null);
    m.filename = full;
    m.loaded = true;
    m.exports = exports;
    require.cache[full] = m;
  }
  const { isPrivateHost } = require(path.join(APP, 'sites.js'));
  for (const host of ['127.0.0.1', '10.4.5.6', '192.168.0.26', '172.16.0.1', '172.31.255.254',
    'localhost', 'nas.local', '::1']) {
    check(`${host} counts as this network`, isPrivateHost(host));
  }
  for (const host of ['kjserver.net', '8.8.8.8', '172.32.0.1', '11.0.0.1', '', '999.1.1.1']) {
    check(`${host || '(empty)'} does not`, !isPrivateHost(host));
  }

  // 6. DOM text reinterpreted as HTML.
  const appJs = read('src/public/js/app.js');
  check('an id read out of the document is reduced to digits',
    /getAttribute\('data-site-actions'\) \|\| ''\)\.replace\(\/\[\^0-9\]\/g, ''\)/.test(appJs),
    'every URL in that handler is built from it');

  // 7. The limiter is actually mounted, before the routes.
  check('the limiter is mounted', /app\.use\(rateLimit\.build\(\)\)/.test(index));
  check('after the session, so it can count per account',
    index.indexOf('app.use(sessionMiddleware)') < index.indexOf('app.use(rateLimit.build())'));
  check('and before every route',
    index.indexOf('app.use(rateLimit.build())') < index.indexOf("require('./routes/auth')"));
  check('the error page can render that early',
    index.indexOf('app.locals.jsonScript') < index.indexOf('app.use(rateLimit.build())'),
    'the 429 page renders before the per-request locals are set');
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
