'use strict';

const os = require('os');

/**
 * Best guess at the LAN address NPMplus should forward traffic to.
 * Prefers a private IPv4 on a non-virtual interface.
 */
function detectHostIp() {
  const ifaces = os.networkInterfaces();
  const candidates = [];

  for (const [name, addrs] of Object.entries(ifaces)) {
    if (/^(lo|docker|br-|veth|virbr|tailscale|zt|wg)/i.test(name)) continue;
    for (const addr of addrs || []) {
      if (addr.family !== 'IPv4' || addr.internal) continue;
      candidates.push({ name, address: addr.address, score: scoreAddress(addr.address, name) });
    }
  }

  candidates.sort((a, b) => b.score - a.score);
  return candidates.length ? candidates[0].address : '';
}

function scoreAddress(ip, name) {
  let score = 0;
  if (/^192\.168\./.test(ip)) score += 30;
  else if (/^10\./.test(ip)) score += 28;
  else if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) score += 20;
  else score += 10; // public address, still usable
  if (/^(eth|en|ens|eno|enp)/i.test(name)) score += 5;
  return score;
}

function humanBytes(bytes) {
  if (bytes === null || bytes === undefined) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = Number(bytes);
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value >= 10 || i === 0 ? Math.round(value) : value.toFixed(1)} ${units[i]}`;
}

module.exports = { detectHostIp, humanBytes };
