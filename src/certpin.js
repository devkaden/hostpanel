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
  const cn = (cert.subject.split('\n').find((line) => line.startsWith('CN=')) || '').slice(3);
  const sanDns = String(cert.subjectAltName || '')
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.startsWith('DNS:'))
    .map((part) => part.slice(4));

  return {
    pem: pem.trim() + '\n',
    fingerprint: cert.fingerprint256,
    subject: cn || cert.subject.replace(/\n/g, ', '),
    issuer: (cert.issuer.split('\n').find((line) => line.startsWith('CN=')) || cert.issuer)
      .replace(/^CN=/, '')
      .replace(/\n/g, ', '),
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    expired: Date.parse(cert.validTo) < Date.now(),
    selfSigned: cert.subject === cert.issuer,
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
      (err, stdout) => {
        const match = String(stdout || '').match(PEM_RE);
        if (match) {
          try {
            return resolve(describe(match[0]));
          } catch (parseErr) {
            return reject(new Error(`The certificate could not be read: ${parseErr.message}`));
          }
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

module.exports = { capture, describe, fromPem, stored, trust, forget, tlsOptionsFor };
