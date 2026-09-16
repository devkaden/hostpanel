'use strict';

/**
 * Trusting one specific certificate, instead of trusting nothing at all.
 *
 * A homelab NPMplus usually serves its admin interface over a certificate it
 * signed itself, which no certificate authority will vouch for. The panel used
 * to answer that with `rejectUnauthorized: false`, which is a bigger
 * concession than it looks: it does not mean "trust my NPMplus", it means
 * "accept whatever certificate arrives". Anyone able to answer on that address
 * - on the same LAN, or with a poisoned DNS entry - gets handed the NPMplus
 * administrator password on the next call.
 *
 * So the certificate is pinned instead. It is fetched once, shown to whoever
 * is setting this up as a fingerprint they can compare, and stored. From then
 * on it is the only certificate that will do: Node verifies normally, with
 * that one certificate as the entire list of authorities, and a swapped
 * certificate fails the handshake exactly as an expired public one would.
 *
 * Fetching it is the awkward part, and is deliberately not done in Node: the
 * TLS socket is torn down on a verification failure before the peer
 * certificate can be read, so reading it in process would mean turning
 * verification off to get it - the thing this exists to remove. `openssl
 * s_client` does it in one call, out of band, and a pasted certificate works
 * for anyone without openssl to hand.
 */

const crypto = require('crypto');
const https = require('https');
const { execFile } = require('child_process');
const { URL } = require('url');

const { getSetting, setSetting } = require('./db');

const PEM_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/;

/**
 * What a certificate says about itself, in the terms the settings page shows.
 *
 * `servername` is the name the certificate is actually issued for, which is
 * frequently not the address anyone types - a self-signed certificate made by
 * a container's entrypoint tends to say "localhost" or the container's own
 * name. It is used as the SNI name so that Node's hostname check has something
 * true to compare against; identity here comes from the pin, not the name.
 */
function describe(pem) {
  const cert = new crypto.X509Certificate(pem);

  /*
   * Every field here can be absent, and one of them usually is.
   *
   * A certificate issued by Let's Encrypt today carries no subject at all -
   * the name it is for lives only in the subjectAltName, and Node reports
   * `subject` as undefined rather than as an empty string. Reading it as a
   * string is what broke the first version of this: "Cannot read properties
   * of undefined (reading 'split')" in front of somebody trying to connect
   * their own reverse proxy.
   */
  const dnValue = (dn, field) => {
    const line = String(dn || '')
      .split('\n')
      .find((entry) => entry.startsWith(`${field}=`));
    return line ? line.slice(field.length + 1) : '';
  };

  const sanDns = String(cert.subjectAltName || '')
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.startsWith('DNS:'))
    .map((part) => part.slice(4));

  const cn = dnValue(cert.subject, 'CN');
  const issuerCn = dnValue(cert.issuer, 'CN') || dnValue(cert.issuer, 'O');

  /*
   * Self-signed is asked of the certificate rather than guessed by comparing
   * two strings: with no subject and no issuer, comparing them says "equal"
   * and every public certificate looks self-signed.
   */
  let selfSigned = false;
  try {
    selfSigned = cert.checkIssued(cert);
  } catch (_) {
    selfSigned = Boolean(cert.subject) && cert.subject === cert.issuer;
  }

  const validTo = cert.validTo || '';
  const expiresAt = Date.parse(validTo);
  const daysLeft = Number.isFinite(expiresAt)
    ? Math.round((expiresAt - Date.now()) / 86400000)
    : null;

  return {
    pem: String(pem).trim() + '\n',
    fingerprint: cert.fingerprint256,
    // What to call it: the name it is actually for, then the subject, then an
    // honest admission rather than "undefined".
    subject: cn || sanDns[0] || String(cert.subject || '').replace(/\n/g, ', ') || '(no name)',
    issuer: issuerCn || String(cert.issuer || '').replace(/\n/g, ', ') || '(unknown issuer)',
    validFrom: cert.validFrom || '',
    validTo,
    daysLeft,
    expired: daysLeft !== null && daysLeft < 0,
    selfSigned,
    // The name to verify against. SAN first, because that is where a modern
    // certificate keeps it and what Node's hostname check reads.
    servername: sanDns[0] || cn || '',
  };
}

/** Reads a pasted certificate, or throws something a person can act on. */
function fromPem(text) {
  const match = String(text || '').match(PEM_RE);
  if (!match) {
    throw new Error(
      'That does not contain a certificate. Paste everything from the BEGIN CERTIFICATE line ' +
        'to the END CERTIFICATE line.'
    );
  }
  try {
    return describe(match[0]);
  } catch (err) {
    throw new Error(`That certificate could not be read: ${err.message}`);
  }
}

/**
 * Fetches the certificate an address is currently serving.
 *
 * Nothing is trusted or stored here - this only answers "what is over there",
 * so that a person can look at the fingerprint before deciding.
 */
function capture(urlString, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(urlString);
    } catch (_) {
      return reject(new Error('That is not a valid URL.'));
    }
    if (target.protocol !== 'https:') {
      return reject(new Error('That address is not HTTPS, so there is no certificate to trust.'));
    }

    const port = target.port || '443';
    const args = [
      's_client',
      '-connect',
      `${target.hostname}:${port}`,
      '-servername',
      target.hostname,
    ];

    return execFile(
      'openssl',
      args,
      { timeout: timeoutMs, maxBuffer: 2 * 1024 * 1024, encoding: 'utf8' },
      async (err, stdout) => {
        const match = String(stdout || '').match(PEM_RE);
        if (match) {
          let details;
          try {
            details = describe(match[0]);
          } catch (parseErr) {
            return reject(new Error(`The certificate could not be read: ${parseErr.message}`));
          }
          // Reported with the certificate, so the page can say "nothing to do
          // here" instead of offering a pin that would expire into a fault.
          details.alreadyTrusted = await verifiesNormally(urlString);
          return resolve(details);
        }
        if (err && err.code === 'ENOENT') {
          return reject(
            new Error(
              'openssl is not installed on this machine, so the certificate cannot be fetched ' +
                'automatically. Paste it instead.'
            )
          );
        }
        return reject(
          new Error(
            `Nothing answered with a certificate at ${target.hostname}:${port}` +
              `${err && err.killed ? ' before the timeout' : ''}. Check the URL and that NPMplus is running.`
          )
        );
      }
    );
  });
}


/**
 * Whether an address already presents a certificate this machine trusts.
 *
 * Asked before offering to pin anything, because pinning a certificate that
 * did not need pinning is a trap with a delay on it: a Let's Encrypt
 * certificate is replaced every couple of months, and a pin taken today stops
 * matching at the first renewal - by which time nobody connects the broken
 * reverse proxy to a button they pressed in the summer.
 *
 * Answers null when the address could not be reached at all, which is a
 * different thing from "not trusted" and should not be reported as one.
 */
function verifiesNormally(urlString, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let target;
    try {
      target = new URL(urlString);
    } catch (_) {
      return resolve(null);
    }
    if (target.protocol !== 'https:') return resolve(null);

    const req = https.request(
      {
        host: target.hostname,
        port: target.port || 443,
        path: '/',
        method: 'HEAD',
        timeout: timeoutMs,
        // No ca and no servername override: this is deliberately the plain
        // question, "does this verify the way any other client would".
      },
      (res) => {
        res.resume();
        resolve(true);
      }
    );
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', (err) => {
      const certFailure = [
        'DEPTH_ZERO_SELF_SIGNED_CERT',
        'SELF_SIGNED_CERT_IN_CHAIN',
        'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        'CERT_HAS_EXPIRED',
        'ERR_TLS_CERT_ALTNAME_INVALID',
        'CERT_UNTRUSTED',
        'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
      ].includes(err.code);
      resolve(certFailure ? false : null);
    });
    req.end();
  });
}

/* ------------------------------------------------------------------ *
 * What is stored
 * ------------------------------------------------------------------ */
function stored() {
  const pem = getSetting('npmplus_ca_pem') || '';
  if (!pem) return null;
  try {
    return describe(pem);
  } catch (_) {
    return null; // a corrupted setting is the same as none
  }
}

function trust(pem) {
  const details = fromPem(pem);
  setSetting('npmplus_ca_pem', details.pem);
  setSetting('npmplus_ca_fingerprint', details.fingerprint);
  return details;
}

function forget() {
  setSetting('npmplus_ca_pem', '');
  setSetting('npmplus_ca_fingerprint', '');
}

/**
 * The TLS options for a request to this host: the pinned certificate as the
 * only authority, and the name that certificate is issued for.
 *
 * Empty when nothing is pinned, in which case the request verifies against the
 * system's normal set of authorities - which is what should happen for an
 * NPMplus with a real certificate.
 */
function tlsOptionsFor(hostname) {
  const pin = stored();
  if (!pin) return {};
  return {
    ca: [pin.pem],
    // Falls back to the address when the certificate names nothing usable;
    // then the hostname check applies as normal and a mismatch is a real
    // failure worth seeing.
    servername: pin.servername || hostname,
  };
}

module.exports = {
  capture, describe, fromPem, stored, trust, forget, tlsOptionsFor, verifiesNormally,
};
