#!/usr/bin/env node
'use strict';
/*
 * Certificate pinning, against a real HTTPS server with a real self-signed
 * certificate.
 *
 * This replaced `rejectUnauthorized: false`, and the only claim worth testing
 * is the one that made it worth doing: that a *different* certificate on the
 * same address is refused. A pin that accepts anything is the thing it
 * replaced, with more code.
 *
 * Run with: npm run test:certpin
 */

const https = require('https');
const crypto = require('crypto');
const path = require('path');
const Module = require('module');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');

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
  setSetting: (k, v) => { settings[k] = v; },
};
require.cache[dbPath] = stub;

const certpin = require(path.join(APP, 'certpin.js'));

/* ------------------------------------------------------ two identities -- */
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-pin-'));
function selfSigned(name) {
  const key = path.join(TMP, `${name}.key`);
  const cert = path.join(TMP, `${name}.crt`);
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-keyout', key, '-out', cert,
    '-days', '2', '-nodes', '-subj', `/CN=${name}`,
  ], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert, 'utf8') };
}

/**
 * A certificate with no subject at all, which is what Let's Encrypt issues now
 * - the name lives only in the subjectAltName. Node reports `subject` as
 * undefined for these, and reading it as a string was a real crash in front of
 * a real user: "Cannot read properties of undefined (reading 'split')".
 */
function sanOnly(name) {
  const key = path.join(TMP, `${name}.san.key`);
  const cert = path.join(TMP, `${name}.san.crt`);
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-keyout', key, '-out', cert,
    '-days', '2', '-nodes', '-subj', '/', '-addext', `subjectAltName=DNS:${name}`,
  ], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert, 'utf8') };
}

let real;
let impostor;
let subjectless;
try {
  real = selfSigned('npmplus.local');
  impostor = selfSigned('npmplus.local'); // same name, different key
  subjectless = sanOnly('npm.example.net');
} catch (err) {
  console.log('  SKIP  openssl is not available here\n');
  process.exit(0);
}

/* --------------------------------------------------------- reading it -- */
console.log('\nreading a certificate');
{
  const details = certpin.describe(real.cert);
  check('the subject comes out', details.subject === 'npmplus.local', details.subject);
  check('it knows the certificate signed itself', details.selfSigned === true);
  check('there is a fingerprint to compare',
    /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(details.fingerprint), details.fingerprint);
  check('and an expiry date', !details.expired && Date.parse(details.validTo) > Date.now());
  check('the name to verify against is the certificate\'s own',
    details.servername === 'npmplus.local', details.servername);

  check('two certificates for the same name have different fingerprints',
    certpin.describe(impostor.cert).fingerprint !== details.fingerprint,
    'otherwise the fingerprint is not identifying anything');

  let threw = null;
  try { certpin.fromPem('this is not a certificate'); } catch (err) { threw = err; }
  check('junk is refused with something a person can act on',
    threw && /BEGIN CERTIFICATE/.test(threw.message), threw && threw.message);

  // Pasted text usually arrives with a covering note around it.
  const messy = `Here you go:\n\n${real.cert}\n\nthanks`;
  check('a certificate pasted with text around it still works',
    certpin.fromPem(messy).fingerprint === details.fingerprint);
}

console.log('\na certificate with no subject, which is what is issued now');
{
  let threw = null;
  let details = null;
  try { details = certpin.describe(subjectless.cert); } catch (err) { threw = err; }

  check('reading it does not throw', !threw, threw && threw.message);
  check('the name comes from the subjectAltName instead',
    details && details.subject === 'npm.example.net', details && details.subject);
  check('and so does the name to verify against',
    details && details.servername === 'npm.example.net', details && details.servername);
  check('the issuer says something rather than "undefined"',
    details && details.issuer && !/undefined/.test(details.issuer), details && details.issuer);
  check('it is still recognised as self-signed',
    details && details.selfSigned === true,
    'two absent fields compare equal, so this cannot be a string comparison');
  check('and it reports how long is left', details && typeof details.daysLeft === 'number',
    String(details && details.daysLeft));
}

/* ------------------------------------------------------ what it stores -- */
console.log('\nwhat gets stored');
{
  check('nothing is trusted to begin with', certpin.stored() === null);

  const saved = certpin.trust(real.cert);
  check('trusting one stores it', Boolean(settings.npmplus_ca_pem));
  check('and the fingerprint separately, for the settings page',
    settings.npmplus_ca_fingerprint === saved.fingerprint);
  check('it reads back', certpin.stored().fingerprint === saved.fingerprint);

  const opts = certpin.tlsOptionsFor('192.168.0.9');
  check('the pinned certificate becomes the only authority',
    Array.isArray(opts.ca) && opts.ca.length === 1 && opts.ca[0].includes('BEGIN CERTIFICATE'));
  check('and the name checked is the one the certificate carries',
    opts.servername === 'npmplus.local',
    'a self-signed certificate rarely names the address anyone types');
  check('nothing else is set', !('rejectUnauthorized' in opts),
    'verification stays on - that is the entire point');

  certpin.forget();
  check('forgetting it clears both settings',
    certpin.stored() === null && !settings.npmplus_ca_fingerprint);
  check('and then verification falls back to the system authorities',
    Object.keys(certpin.tlsOptionsFor('192.168.0.9')).length === 0);
}

/* ------------------------------------------------- against a real server */
(async () => {
  console.log('\nagainst a real HTTPS server');

  const server = https.createServer({ key: real.key, cert: real.cert }, (req, res) =>
    res.end('{"ok":true}')
  );
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const url = `https://127.0.0.1:${port}`;

  const get = (extra) =>
    new Promise((resolve) => {
      const req = https.request(
        { host: '127.0.0.1', port, path: '/', method: 'GET', ...extra },
        (res) => { res.resume(); resolve({ status: res.statusCode }); }
      );
      req.on('error', (err) => resolve({ error: err.code || err.message }));
      req.end();
    });

  // 1. Untrusted to begin with, which is the behaviour being relied on.
  const bare = await get({});
  check('an unknown self-signed certificate is refused',
    bare.error === 'DEPTH_ZERO_SELF_SIGNED_CERT' || bare.error === 'SELF_SIGNED_CERT_IN_CHAIN',
    String(bare.error));

  // 2. Fetched out of band, with nothing disabled anywhere.
  let captured = null;
  try { captured = await certpin.capture(url); } catch (err) { captured = { error: err.message }; }
  check('the certificate can be fetched to look at',
    captured && captured.fingerprint === certpin.describe(real.cert).fingerprint,
    JSON.stringify(captured && captured.error));
  check('fetching it trusts nothing by itself', certpin.stored() === null,
    'looking at a fingerprint and accepting it are two decisions');

  // 3. Once pinned, the connection works - verification still on.
  certpin.trust(real.cert);
  const pinned = await get(certpin.tlsOptionsFor('127.0.0.1'));
  check('the pinned certificate is accepted', pinned.status === 200, String(pinned.error));

  // 4. The claim that matters.
  certpin.forget();
  certpin.trust(impostor.cert);
  const swapped = await get(certpin.tlsOptionsFor('127.0.0.1'));
  check('a different certificate on the same address is refused',
    Boolean(swapped.error), `got HTTP ${swapped.status}`);
  check('and refused for the right reason',
    /SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME/.test(String(swapped.error)), String(swapped.error));

  certpin.forget();

  // 5. A certificate that already verifies must not be offered for pinning.
  const captured2 = await certpin.capture(url);
  check('capture reports whether the address already verifies',
    captured2 && captured2.alreadyTrusted === false,
    String(captured2 && captured2.alreadyTrusted));
  check('an unreachable address is reported as unknown, not as untrusted',
    (await certpin.verifiesNormally('https://127.0.0.1:1/')) === null,
    'those are different answers and only one of them is actionable');
  check('a plain http address has no certificate question to answer',
    (await certpin.verifiesNormally('http://127.0.0.1/')) === null);

  server.close();

  /* ------------------------------------------------------- the wiring -- */
  console.log('\nthe wiring');
  {
    const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
    const npmplusSrc = read('src/npmplus.js');

    check('nothing turns certificate checking off any more',
      !/rejectUnauthorized:\s*false/.test(npmplusSrc),
      'this is what the pin replaced');
    check('the pin is applied to every https request',
      /certpin\.tlsOptionsFor\(target\.hostname\)/.test(npmplusSrc));
    check('a certificate failure says what to do about it',
      /Trust this certificate/.test(npmplusSrc));
    check('and says so differently when a pin is already in force',
      /not serving the certificate this panel was told to trust/.test(npmplusSrc));

    const settingsRoutes = read('src/routes/settings.js');
    check('fetching and trusting are separate endpoints',
      /certificate\/fetch/.test(settingsRoutes) && /certificate\/trust/.test(settingsRoutes),
      'one button that did both would be "accept whatever is there" again');
    check('and both are administrators only',
      (settingsRoutes.match(/certificate\/(fetch|trust|forget)',\s*\n\s*auth\.requireAdmin/g) || [])
        .length === 3);
    check('trusting a certificate is recorded in the activity log',
      /npmplus\.certificate_trusted/.test(settingsRoutes));

    const view = read('src/views/settings.ejs');
    check('the old accept-anything checkbox is gone',
      !/npmplus_insecure/.test(view + read('src/views/setup.ejs')));
    check('the fingerprint is shown before it is trusted',
      /Trust this certificate\?/.test(view) && /Check that fingerprint/.test(view));
    check('a certificate that needs no pin is not offered one',
      /cert\.alreadyTrusted === true/.test(view) && /Nothing to do here/.test(view),
      'pinning a renewing certificate breaks the panel weeks later, silently');
    check('and pinning a short-lived one comes with the warning',
      /stops connecting on that day/.test(view) && /cert\.daysLeft/.test(view));
  }

  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
