'use strict';

/**
 * NPMplus / Nginx Proxy Manager API client.
 *
 * NPMplus keeps the upstream NPM v2 REST API, so this talks to:
 *   POST   /api/tokens
 *   GET    /api/nginx/proxy-hosts
 *   POST   /api/nginx/proxy-hosts
 *   PUT    /api/nginx/proxy-hosts/:id
 *   DELETE /api/nginx/proxy-hosts/:id
 *   POST   /api/nginx/certificates
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

const { getSetting } = require('./db');

let tokenCache = { token: null, expiresAt: 0, forUrl: '' };

function cfg() {
  return {
    url: (getSetting('npmplus_url') || '').replace(/\/+$/, ''),
    email: getSetting('npmplus_email'),
    password: getSetting('npmplus_password'),
    leEmail: getSetting('npmplus_le_email') || getSetting('npmplus_email'),
    enabled: getSetting('npmplus_enabled') === '1',
    insecure: getSetting('npmplus_insecure', '0') === '1',
    hostIp: getSetting('host_ip'),
  };
}

function isEnabled() {
  const c = cfg();
  return Boolean(c.enabled && c.url && c.email && c.password);
}

function isConfigured() {
  const c = cfg();
  return Boolean(c.url && c.email && c.password);
}

/* ------------------------------------------------------------------ *
 * Low-level request
 * ------------------------------------------------------------------ */
function request(method, pathname, { body, token, timeout = 30000 } = {}) {
  const c = cfg();
  if (!c.url) return Promise.reject(new Error('NPMplus URL is not configured'));

  const target = new URL(c.url + pathname);
  const isHttps = target.protocol === 'https:';
  const lib = isHttps ? https : http;
  const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));

  const options = {
    method,
    hostname: target.hostname,
    port: target.port || (isHttps ? 443 : 80),
    path: target.pathname + target.search,
    headers: {
      Accept: 'application/json',
      ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    timeout,
  };
  if (isHttps && c.insecure) options.rejectUnauthorized = false;

  return new Promise((resolve, reject) => {
    const req = lib.request(options, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        try {
          parsed = text ? JSON.parse(text) : null;
        } catch (_) {
          parsed = null;
        }
        if (res.statusCode >= 200 && res.statusCode < 300) {
          return resolve(parsed !== null ? parsed : text);
        }
        const detail =
          (parsed && (parsed.error?.message || parsed.message || parsed.error)) ||
          text.slice(0, 400) ||
          `HTTP ${res.statusCode}`;
        const err = new Error(`NPMplus ${method} ${pathname} failed: ${detail}`);
        err.statusCode = res.statusCode;
        err.body = parsed;
        return reject(err);
      });
    });
    req.on('timeout', () => {
      req.destroy(new Error(`NPMplus request timed out after ${timeout}ms`));
    });
    req.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') {
        return reject(new Error(`Could not connect to NPMplus at ${c.url} (connection refused)`));
      }
      if (err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || err.code === 'SELF_SIGNED_CERT_IN_CHAIN') {
        return reject(
          new Error(
            'NPMplus is using a self-signed certificate. Enable "Allow self-signed certificate" in Settings.'
          )
        );
      }
      return reject(err);
    });
    if (payload) req.write(payload);
    req.end();
  });
}

/* ------------------------------------------------------------------ *
 * Auth
 * ------------------------------------------------------------------ */
async function getToken(force = false) {
  const c = cfg();
  if (!isConfigured()) throw new Error('NPMplus credentials are not configured');
  if (
    !force &&
    tokenCache.token &&
    tokenCache.forUrl === c.url &&
    Date.now() < tokenCache.expiresAt - 60000
  ) {
    return tokenCache.token;
  }
  const res = await request('POST', '/api/tokens', {
    body: { identity: c.email, secret: c.password },
  });
  if (!res || !res.token) throw new Error('NPMplus did not return a token - check the credentials');
  const expiresAt = res.expires ? new Date(res.expires).getTime() : Date.now() + 60 * 60 * 1000;
  tokenCache = { token: res.token, expiresAt, forUrl: c.url };
  return res.token;
}

async function api(method, pathname, body, timeout) {
  let token = await getToken();
  try {
    return await request(method, pathname, { body, token, timeout });
  } catch (err) {
    if (err.statusCode === 401 || err.statusCode === 403) {
      token = await getToken(true);
      return request(method, pathname, { body, token, timeout });
    }
    throw err;
  }
}

// Let's Encrypt issuance is synchronous in NPM and regularly takes a minute.
const CERT_TIMEOUT_MS = 180000;

async function testConnection() {
  const c = cfg();
  if (!isConfigured()) {
    return { ok: false, error: 'URL, email and password are all required.' };
  }
  try {
    await getToken(true);
    const hosts = await api('GET', '/api/nginx/proxy-hosts');
    return {
      ok: true,
      proxyHosts: Array.isArray(hosts) ? hosts.length : 0,
      url: c.url,
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/* ------------------------------------------------------------------ *
 * Proxy hosts
 * ------------------------------------------------------------------ */
function domainsOf(site) {
  const extra = (site.extra_domains || '')
    .split(/[\s,]+/)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  const list = site.domain ? [site.domain.toLowerCase(), ...extra] : extra;
  return [...new Set(list)];
}

function proxyPayload(site, domains, certificateId) {
  const c = cfg();
  const forwardHost = c.hostIp;
  if (!forwardHost) {
    throw new Error(
      'Host IP is not set. Add the IP that NPMplus should forward traffic to in Settings.'
    );
  }
  return {
    domain_names: domains,
    forward_scheme: 'http',
    forward_host: forwardHost,
    forward_port: site.port,
    access_list_id: 0,
    certificate_id: certificateId || 0,
    ssl_forced: Boolean(certificateId),
    http2_support: Boolean(certificateId),
    hsts_enabled: false,
    hsts_subdomains: false,
    block_exploits: true,
    caching_enabled: false,
    allow_websocket_upgrade: true,
    advanced_config: '',
    locations: [],
    meta: { letsencrypt_agree: false, dns_challenge: false },
  };
}

async function listProxyHosts() {
  return api('GET', '/api/nginx/proxy-hosts');
}

async function findProxyHostByDomain(domain) {
  const hosts = await listProxyHosts();
  if (!Array.isArray(hosts)) return null;
  const needle = String(domain).toLowerCase();
  return hosts.find((h) => (h.domain_names || []).some((d) => String(d).toLowerCase() === needle));
}

async function requestCertificate(domains) {
  const c = cfg();
  if (!c.leEmail) {
    throw new Error("A Let's Encrypt email is required before a certificate can be requested.");
  }
  const cert = await api(
    'POST',
    '/api/nginx/certificates',
    {
      provider: 'letsencrypt',
      nice_name: domains[0],
      domain_names: domains,
      meta: {
        letsencrypt_email: c.leEmail,
        letsencrypt_agree: true,
        dns_challenge: false,
      },
    },
    CERT_TIMEOUT_MS
  );
  if (!cert || !cert.id) throw new Error('NPMplus did not return a certificate id');
  return cert.id;
}

async function deleteCertificate(id) {
  if (!id) return false;
  try {
    await api('DELETE', `/api/nginx/certificates/${id}`);
    return true;
  } catch (err) {
    if (err.statusCode === 404) return false;
    throw err;
  }
}

/**
 * Creates or updates the proxy host for a site, optionally requesting a
 * Let's Encrypt certificate. Returns { proxyId, certId, ssl }.
 */
async function syncProxyHost(site, { requestSsl = true } = {}) {
  const domains = domainsOf(site);
  if (!domains.length) throw new Error('This site has no domain, so there is nothing to proxy.');

  let proxyId = site.npm_proxy_id || null;

  // If we lost track of the id, try to adopt an existing host for the domain.
  if (!proxyId) {
    const existing = await findProxyHostByDomain(domains[0]);
    if (existing) proxyId = existing.id;
  }

  // Step 1: make sure the proxy host exists and points at the right port.
  if (proxyId) {
    try {
      await api('PUT', `/api/nginx/proxy-hosts/${proxyId}`, proxyPayload(site, domains, site.npm_cert_id));
    } catch (err) {
      if (err.statusCode === 404) {
        proxyId = null;
      } else {
        throw err;
      }
    }
  }
  if (!proxyId) {
    const created = await api('POST', '/api/nginx/proxy-hosts', proxyPayload(site, domains, 0));
    if (!created || !created.id) throw new Error('NPMplus did not return a proxy host id');
    proxyId = created.id;
  }

  // Step 2: certificate.
  let certId = site.npm_cert_id || null;
  let ssl = Boolean(certId);
  if (requestSsl) {
    try {
      if (!certId) certId = await requestCertificate(domains);
      await api('PUT', `/api/nginx/proxy-hosts/${proxyId}`, proxyPayload(site, domains, certId));
      ssl = true;
    } catch (err) {
      // The site still works over HTTP; surface the reason to the caller.
      const e = new Error(
        `Proxy host #${proxyId} is live, but the certificate step failed: ${err.message}`
      );
      e.proxyId = proxyId;
      e.partial = true;
      throw e;
    }
  }

  return { proxyId, certId, ssl };
}

async function deleteProxyHost(id) {
  if (!id) return false;
  try {
    await api('DELETE', `/api/nginx/proxy-hosts/${id}`);
    return true;
  } catch (err) {
    if (err.statusCode === 404) return false;
    throw err;
  }
}

async function getProxyHost(id) {
  if (!id) return null;
  try {
    return await api('GET', `/api/nginx/proxy-hosts/${id}`);
  } catch (err) {
    if (err.statusCode === 404) return null;
    throw err;
  }
}

function invalidateToken() {
  tokenCache = { token: null, expiresAt: 0, forUrl: '' };
}

module.exports = {
  isEnabled,
  isConfigured,
  testConnection,
  syncProxyHost,
  deleteProxyHost,
  getProxyHost,
  listProxyHosts,
  findProxyHostByDomain,
  requestCertificate,
  deleteCertificate,
  invalidateToken,
  domainsOf,
  cfg,
};
