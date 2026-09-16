#!/usr/bin/env node
'use strict';
/*
 * Verifies the two-factor implementation against the published test vectors.
 *
 * This matters more than most tests here. Two-factor authentication that is
 * subtly wrong is worse than none: it locks out the legitimate owner while
 * giving a false sense of protection, and the failure only shows up when
 * someone is already standing outside their own panel. RFC 4226 and RFC 6238
 * both ship reference values, so correctness is checkable rather than assumed.
 *
 * Run with: npm run test:totp
 */

const crypto = require('crypto');
const totp = require('../src/totp');

let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`); }
}

// Both RFCs use this ASCII secret.
const SECRET_ASCII = '12345678901234567890';
const SECRET_B32 = totp.base32Encode(Buffer.from(SECRET_ASCII));

console.log('\nbase32 (RFC 4648)');
{
  check('encodes the RFC 4226 secret', SECRET_B32 === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', SECRET_B32);
  check('round-trips', totp.base32Decode(SECRET_B32).toString() === SECRET_ASCII);
  check('ignores spaces and dashes',
    totp.base32Decode('GEZD GNBV-GY3T QOJQ GEZD GNBV GY3T QOJQ').toString() === SECRET_ASCII);
  check('ignores padding', totp.base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====').toString() === SECRET_ASCII);

  let threw = false;
  try { totp.base32Decode('not-valid-base32!'); } catch (_) { threw = true; }
  check('rejects characters outside the alphabet', threw);
}

console.log('\nHOTP (RFC 4226, appendix D)');
{
  // The published values for counters 0-9.
  const expected = [
    '755224', '287082', '359152', '969429', '338314',
    '254676', '287922', '162583', '399871', '520489',
  ];
  const secret = Buffer.from(SECRET_ASCII);
  let allOk = true;
  expected.forEach((want, counter) => {
    const got = totp.hotp(secret, counter);
    if (got !== want) {
      allOk = false;
      console.log(`        counter ${counter}: expected ${want}, got ${got}`);
    }
  });
  check('all ten reference values match', allOk);
}

console.log('\nTOTP (RFC 6238, appendix B)');
{
  // SHA-1, 8 digits. Times are in seconds, the helper takes milliseconds.
  const vectors = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];
  let allOk = true;
  for (const [seconds, want] of vectors) {
    const got = totp.totp(SECRET_B32, { time: seconds * 1000, digits: 8 });
    if (got !== want) {
      allOk = false;
      console.log(`        T=${seconds}: expected ${want}, got ${got}`);
    }
  }
  check('all six reference values match', allOk);

  // Beyond 2^31 seconds the counter no longer fits in 32 bits. Writing it as
  // one 32-bit value would silently wrap and produce valid-looking wrong codes
  // from 2038 onward, so the last vector above is the one that matters most.
  check('the counter is written as a full 64-bit value',
    totp.totp(SECRET_B32, { time: 20000000000 * 1000, digits: 8 }) === '65353130');
}

console.log('\nverification window');
{
  const now = Date.now();
  const current = totp.totp(SECRET_B32, { time: now });

  check('accepts the current code', totp.verify(SECRET_B32, current, { time: now }));
  check('accepts a code from the previous step',
    totp.verify(SECRET_B32, totp.totp(SECRET_B32, { time: now - 30000 }), { time: now }));
  check('accepts a code from the next step',
    totp.verify(SECRET_B32, totp.totp(SECRET_B32, { time: now + 30000 }), { time: now }));
  check('rejects a code two steps old',
    !totp.verify(SECRET_B32, totp.totp(SECRET_B32, { time: now - 90000 }), { time: now }));
  check('rejects a code two steps ahead',
    !totp.verify(SECRET_B32, totp.totp(SECRET_B32, { time: now + 90000 }), { time: now }));

  check('rejects an empty code', !totp.verify(SECRET_B32, '', { time: now }));
  check('rejects a short code', !totp.verify(SECRET_B32, '123', { time: now }));
  check('rejects letters', !totp.verify(SECRET_B32, 'abcdef', { time: now }));
  check('rejects null', !totp.verify(SECRET_B32, null, { time: now }));
  check('tolerates spaces in what the user typed',
    totp.verify(SECRET_B32, current.slice(0, 3) + ' ' + current.slice(3), { time: now }));

  // A wrong code must fail for every secret, not just occasionally.
  let falseAccepts = 0;
  for (let i = 0; i < 300; i += 1) {
    const other = totp.generateSecret();
    if (totp.verify(other, current, { time: now })) falseAccepts += 1;
  }
  check('a code from one secret does not validate against others',
    falseAccepts === 0, `${falseAccepts} false accepts in 300`);
}

console.log('\nsecrets');
{
  const secrets = new Set();
  for (let i = 0; i < 500; i += 1) secrets.add(totp.generateSecret());
  check('500 generated secrets are all distinct', secrets.size === 500);

  const one = totp.generateSecret();
  check('is 160 bits, as RFC 4226 recommends', totp.base32Decode(one).length === 20);
  check('uses only the base32 alphabet', /^[A-Z2-7]+$/.test(one));
}

console.log('\notpauth URI');
{
  const url = totp.otpauthUrl({
    secret: SECRET_B32,
    account: 'kaden',
    issuer: 'My Panel & Co',
  });
  check('names the scheme and type', url.startsWith('otpauth://totp/'));
  check('carries the secret', url.includes('secret=' + SECRET_B32));
  // An unescaped space or ampersand here breaks real authenticator apps.
  check('escapes the label', url.includes('My%20Panel%20%26%20Co%3Akaden'), url);
  check('states the algorithm explicitly', /algorithm=SHA1/.test(url));
  check('states digits and period', /digits=6/.test(url) && /period=30/.test(url));
}

console.log('\nrecovery codes');
{
  const codes = totp.generateRecoveryCodes(10);
  check('generates the number asked for', codes.length === 10);
  check('all distinct', new Set(codes).size === 10);
  check('formatted in readable groups', codes.every((c) => /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(c)));
  check('avoids characters people mistype',
    codes.every((c) => !/[IO01]/.test(c)), codes.join(' '));

  const hash = totp.hashRecoveryCode(codes[0]);
  check('hashes to something that is not the code', hash !== codes[0] && hash.length === 64);
  check('the hash ignores case and dashes',
    totp.hashRecoveryCode(codes[0].toLowerCase().replace(/-/g, '')) === hash);
  check('different codes hash differently',
    totp.hashRecoveryCode(codes[1]) !== hash);

  // 32^12 is far beyond guessing, but check the distribution is not obviously
  // broken - a generator stuck on a few characters would show up here.
  const chars = new Set(codes.join('').replace(/-/g, '').split(''));
  check('draws on most of the alphabet', chars.size >= 16, `${chars.size} distinct characters`);
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
