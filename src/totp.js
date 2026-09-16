'use strict';

/**
 * TOTP (RFC 6238) and HOTP (RFC 4226), built on Node's own crypto.
 *
 * Deliberately dependency-free. Two-factor authentication is the one thing on
 * this panel that must not break, and every dependency is a supply chain that
 * can. The algorithm is about forty lines and its correctness is verifiable
 * against the published test vectors, which is exactly what scripts/test-totp.js
 * does - so this is better tested here than an imported package would be.
 */

const crypto = require('crypto');

/* ------------------------------------------------------------ base32 ----- */
// RFC 4648 alphabet, which is what every authenticator app expects.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(input) {
  const clean = String(input || '').toUpperCase().replace(/[=\s-]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) throw new Error('That is not a valid secret key.');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/* -------------------------------------------------------------- codes ---- */
/**
 * One HOTP value. `counter` is a 64-bit big-endian number; TOTP is HOTP with
 * the counter derived from the clock.
 */
function hotp(secretBuffer, counter, digits = 6, algorithm = 'sha1') {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);

  const digest = crypto.createHmac(algorithm, secretBuffer).update(buf).digest();
  // Dynamic truncation: the low nibble of the last byte picks the offset.
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, '0');
}

function totp(secretBase32, { time = Date.now(), step = 30, digits = 6, algorithm = 'sha1' } = {}) {
  const counter = Math.floor(time / 1000 / step);
  return hotp(base32Decode(secretBase32), counter, digits, algorithm);
}

/**
 * Checks a code against the current step and one step either side.
 *
 * The window exists because phone clocks drift and people type slowly. One
 * step each way is the usual compromise: ninety seconds of validity, rather
 * than the several minutes a wider window would allow an intercepted code.
 */
function verify(secretBase32, code, { time = Date.now(), step = 30, window = 1, digits = 6 } = {}) {
  const supplied = String(code || '').replace(/\s/g, '');
  if (!/^\d+$/.test(supplied) || supplied.length !== digits) return false;

  const secret = base32Decode(secretBase32);
  const counter = Math.floor(time / 1000 / step);
  for (let drift = -window; drift <= window; drift += 1) {
    const expected = hotp(secret, counter + drift, digits);
    // Constant-time: a timing difference would leak how much of a guess is
    // right, which over enough attempts is the whole code.
    const a = Buffer.from(expected);
    const b = Buffer.from(supplied);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}

/** A fresh 160-bit secret, which is what RFC 4226 recommends. */
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

/**
 * The otpauth:// URI an authenticator app scans.
 *
 * Both label and issuer are encoded: a panel title with a space or an ampersand
 * in it would otherwise produce a URI that some apps parse wrongly and others
 * refuse outright.
 */
function otpauthUrl({ secret, account, issuer }) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/* --------------------------------------------------------- recovery ------ */
/**
 * Single-use codes for when the phone is lost.
 *
 * Without these, losing a phone means losing the account, and the only way back
 * is a shell on the server - which the people this panel is handed to will not
 * have. Grouped in fours because a twenty-character run is easy to mistype.
 */
function generateRecoveryCodes(count = 10) {
  const codes = [];
  // No I, O, 0 or 1: they are the characters people transcribe wrongly.
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const limit = 256 - (256 % chars.length);
  while (codes.length < count) {
    let code = '';
    while (code.length < 12) {
      for (const byte of crypto.randomBytes(24)) {
        if (byte >= limit) continue; // rejection sampling, no modulo bias
        code += chars[byte % chars.length];
        if (code.length === 12) break;
      }
    }
    codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8, 12)}`);
  }
  return codes;
}

/** Recovery codes are stored hashed, like passwords - they are passwords. */
function hashRecoveryCode(code) {
  return crypto
    .createHash('sha256')
    .update(String(code || '').toUpperCase().replace(/[\s-]/g, ''))
    .digest('hex');
}

module.exports = {
  base32Encode,
  base32Decode,
  hotp,
  totp,
  verify,
  generateSecret,
  otpauthUrl,
  generateRecoveryCodes,
  hashRecoveryCode,
};
