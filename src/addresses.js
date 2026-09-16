'use strict';

/**
 * Where an address is, which is a question two different parts of the panel
 * need to answer the same way.
 *
 * Its own file because both callers are about the same decision - whether
 * skipping a certificate check is defensible - and because sites.js and
 * npmplus.js cannot import each other: sites.js already depends on npmplus.js.
 */

/**
 * True for an address on this machine or this network.
 *
 * Used to decide whether skipping certificate verification is defensible. A
 * homelab site on 192.168.x with a certificate the panel issued itself is the
 * case this exists for; a name that resolves out on the internet is not, and
 * there "the certificate is wrong" is a real answer rather than noise to
 * suppress.
 */
function isPrivateHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return false;
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host === '::1' || host.startsWith('fc') || host.startsWith('fd')) return true; // IPv6 loopback / ULA

  const parts = host.split('.');
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p))) return false;
  const [a, b] = parts.map(Number);
  if (parts.some((p) => Number(p) > 255)) return false;
  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}


module.exports = { isPrivateHost };
