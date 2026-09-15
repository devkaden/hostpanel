'use strict';

/**
 * NPMplus / Nginx Proxy Manager API client.
 *
 * Endpoints used:
 *   POST   /api/tokens          (sign in)
 *   POST   /api/tokens/totp     (sign in, second factor)
 *   GET    /api/nginx/proxy-hosts
 *   POST   /api/nginx/proxy-hosts
 *   PUT    /api/nginx/proxy-hosts/:id
 *   DELETE /api/nginx/proxy-hosts/:id
 *   POST   /api/nginx/certificates
 *
 * AUTH: current NPMplus (2.15.x and up) does NOT return a JWT in the response
 * body and does NOT accept an Authorization: Bearer header. POST /api/tokens
 * answers {expires} and puts the signed JWT in an httpOnly cookie
 * (`__Host-Http-token`). So this client keeps a cookie jar and replays those
 * cookies on every call.
 *
 * If TOTP is enabled on the account, the first call instead answers
 * {requiresTotp: true, expires} plus a `__Host-Http-challenge_token` cookie,
 * and a six-digit code must be posted to /api/tokens/totp to exchange it.
 *
 * Older NPM/NPMplus builds returned {token} and took a Bearer header; that path
 * still works and is preferred when a token is present in the body.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

const { getSetting } = require('./db');

// Session state: a Bearer token (legacy NPM) and/or a cookie jar (NPMplus).
let tokenCache = { token: null, cookies: null, expiresAt: 0, forUrl: '' };

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

/** Turns Set-Cookie headers into the `name=value; name=value` form to send back. */
function collectCookies(setCookieHeaders, existing) {
  const jar = new Map();
  if (existing) {
    for (const pair of existing.split('; ')) {
      const eq = pair.indexOf('=');
      if (eq > 0) jar.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
  }
  for (const raw of setCookieHeaders || []) {
    const first = String(raw).split(';')[0];
    const eq = first.indexOf('=');
    if (eq <= 0) continue;
    const name = first.slice(0, eq).trim();
    const value = first.slice(eq + 1).trim();
    // An empty value is the server clearing that cookie.
    if (!value || value === 'null') jar.delete(name);
    else jar.set(name, value);
  }
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
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
function request(
  method,
  pathname,
  { body, token, cookies, withResponse = false, timeout = 30000 } = {}
) {
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
      ...(cookies ? { Cookie: cookies } : {}),
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
        const contentType = res.headers['content-type'] || 'unknown';
        let parsed = null;
        try {
          parsed = text ? JSON.parse(text) : null;
        } catch (_) {
          parsed = null;
        }
        if (res.statusCode >= 200 && res.statusCode < 300) {
          if (parsed !== null) {
            // The sign-in calls need the Set-Cookie headers, not just the body.
            return resolve(
              withResponse
                ? { body: parsed, setCookie: res.headers['set-cookie'] || [], statusCode: res.statusCode }
                : parsed
            );
          }
          // A 200 that is not JSON almost always means the URL reached
          // something other than the NPMplus API - a login page, an SPA
          // shell, or a proxy in front of it.
          const err = new Error(
            `NPMplus ${method} ${pathname} returned ${res.statusCode} with ` +
              `content-type "${contentType}" instead of JSON. ` +
              `First bytes: ${JSON.stringify(text.slice(0, 160))}`
          );
          err.statusCode = res.statusCode;
          err.notJson = true;
          return reject(err);
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
/**
 * Signs in and caches the session. Returns {token, cookies}; either may be
 * null depending on which NPM generation is on the other end.
 */
async function getSession(force = false) {
  const c = cfg();
  if (!isConfigured()) throw new Error('NPMplus credentials are not configured');

  const cached =
    tokenCache.forUrl === c.url &&
    (tokenCache.token || tokenCache.cookies) &&
    Date.now() < tokenCache.expiresAt - 60000;
  if (!force && cached) return tokenCache;

  const res = await request('POST', '/api/tokens', {
    body: { identity: c.email, secret: c.password },
    withResponse: true,
  });

  const payload = res.body || {};
  const cookies = collectCookies(res.setCookie, null);
  const expiresAt = payload.expires
    ? new Date(payload.expires).getTime()
    : Date.now() + 60 * 60 * 1000;

  // Account has TOTP enabled: only a challenge cookie was issued.
  if (payload.requiresTotp) {
    throw new Error(
      'This NPMplus account has two-factor authentication enabled, which the panel cannot ' +
        'complete on its own. Use an NPMplus account without TOTP for the API connection.'
    );
  }

  // Legacy NPM: JWT in the body, used as a Bearer header.
  if (payload.token) {
    tokenCache = { token: payload.token, cookies: cookies || null, expiresAt, forUrl: c.url };
    return tokenCache;
  }

  // Current NPMplus: JWT arrives only as an httpOnly cookie.
  if (cookies && /(^|; )__Host-Http-token=/.test(cookies)) {
    tokenCache = { token: null, cookies, expiresAt, forUrl: c.url };
    return tokenCache;
  }

  // Neither - say precisely what came back so this is debuggable.
  throw new Error(
    'NPMplus accepted the sign-in but issued no session. Body keys: ' +
      `[${Object.keys(payload).join(', ') || 'none'}]; cookies: ` +
      `[${(res.setCookie || []).map((s) => String(s).split('=')[0]).join(', ') || 'none'}]. ` +
      'If NPMplus sits behind another reverse proxy, make sure that proxy is not stripping Set-Cookie.'
  );
}

// Kept for callers that only need the bearer token concept.
async function getToken(force = false) {
  const session = await getSession(force);
  return session.token || session.cookies;
}

async function api(method, pathname, body, timeout) {
  let session = await getSession();
  try {
    return await request(method, pathname, {
      body,
      token: session.token,
      cookies: session.cookies,
      timeout,
    });
  } catch (err) {
    if (err.statusCode === 401 || err.statusCode === 403) {
      session = await getSession(true);
      return request(method, pathname, {
        body,
        token: session.token,
        cookies: session.cookies,
        timeout,
      });
    }
    throw err;
  }
}

// Let's Encrypt issuance is synchronous in NPM and regularly takes a minute.
const CERT_TIMEOUT_MS = 180000;

/**
 * Three-step probe so a failure says which step broke:
 *   1. is the URL actually the NPMplus API?   GET /api
 *   2. do the credentials work?               POST /api/tokens
 *   3. can we read proxy hosts?               GET /api/nginx/proxy-hosts
 */
async function testConnection() {
  const c = cfg();
  if (!isConfigured()) {
    return { ok: false, error: 'URL, email and password are all required.' };
  }

  // Step 1 - reach the API root. NPM/NPMplus answers {status:"OK", version:{}}.
  let version = null;
  try {
    const root = await request('GET', '/api', { timeout: 15000 });
    if (root && root.status) {
      // NPMplus reports a version string ("2026-06-25-r1-...-2.15.1"); classic
      // NPM reports {major, minor, revision}.
      if (typeof root.version === 'string') version = root.version;
      else if (root.version && root.version.major !== undefined) {
        version = `${root.version.major}.${root.version.minor}.${root.version.revision}`;
      } else version = 'unknown';

      if (root.password === false && root.oidc === true) {
        return {
          ok: false,
          step: 'reach',
          version,
          error:
            'This NPMplus instance has password login disabled and only accepts OIDC/SSO, ' +
            'so the panel cannot sign in. Enable password auth for a dedicated API account.',
        };
      }
    } else {
      return {
        ok: false,
        step: 'reach',
        error:
          `${c.url}/api answered, but not like the NPMplus API does. ` +
          'Point the URL at the admin interface itself (default https://<host>:81).',
      };
    }
  } catch (err) {
    return {
      ok: false,
      step: 'reach',
      error: err.notJson
        ? `${err.message} — this URL is not serving the NPMplus API. The admin interface is on port 81 over https by default.`
        : `Could not reach the NPMplus API at ${c.url}/api — ${err.message}`,
    };
  }

  // Step 2 - authenticate.
  let authMode = 'unknown';
  try {
    const session = await getSession(true);
    authMode = session.token ? 'bearer token' : 'session cookie';
  } catch (err) {
    return { ok: false, step: 'auth', version, error: err.message };
  }

  // Step 3 - read something real.
  try {
    const hosts = await api('GET', '/api/nginx/proxy-hosts');
    return {
      ok: true,
      version,
      authMode,
      proxyHosts: Array.isArray(hosts) ? hosts.length : 0,
      url: c.url,
    };
  } catch (err) {
    return { ok: false, step: 'read', version, authMode, error: err.message };
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
  // Only fields both NPM and NPMplus accept. Their schemas are
  // additionalProperties:false, and NPMplus dropped `access_list_id` in favour
  // of `npmplus_access_list_ids`, so sending it rejects the whole request with
  // "data must NOT have additional properties". Access lists are left alone
  // either way - the panel does not manage them.
  return {
    domain_names: domains,
    forward_scheme: 'http',
    forward_host: forwardHost,
    forward_port: site.port,
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

/**
 * Requests a Let's Encrypt certificate.
 *
 * The two NPM generations disagree about `meta`:
 *   - NPMplus 2.15.x accepts only {dns_challenge} (plus DNS-provider keys).
 *     The ACME account email lives in NPMplus's own configuration, so sending
 *     letsencrypt_email/letsencrypt_agree is rejected outright by its
 *     additionalProperties:false schema.
 *   - Classic NPM requires letsencrypt_agree and takes the email per request.
 *
 * Cookie auth means modern NPMplus, so that shape is tried first; either way
 * the other shape is attempted if the first is rejected.
 */
async function requestCertificate(domains) {
  const c = cfg();
  const session = await getSession();
  const modernFirst = !session.token; // cookie auth == current NPMplus

  const modernMeta = { dns_challenge: false };
  const legacyMeta = {
    letsencrypt_email: c.leEmail,
    letsencrypt_agree: true,
    dns_challenge: false,
  };

  const attempt = async (meta) =>
    api(
      'POST',
      '/api/nginx/certificates',
      { provider: 'letsencrypt', nice_name: domains[0], domain_names: domains, meta },
      CERT_TIMEOUT_MS
    );

  const order = modernFirst ? [modernMeta, legacyMeta] : [legacyMeta, modernMeta];
  let lastError = null;

  for (const meta of order) {
    // Classic NPM cannot issue a certificate without an email to register.
    if (meta === legacyMeta && !c.leEmail) continue;
    try {
      const cert = await attempt(meta);
      if (!cert || !cert.id) throw new Error('NPMplus did not return a certificate id');
      return cert.id;
    } catch (err) {
      lastError = err;
      // Only a schema disagreement is worth retrying with the other shape.
      const schemaMismatch =
        err.statusCode === 400 &&
        /(additional propert|required propert)/i.test(err.message || '');
      if (!schemaMismatch) throw err;
    }
  }

  throw lastError || new Error('Could not request a certificate');
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
async function syncProxyHost(site, { requestSsl = true, adopt = false } = {}) {
  const domains = domainsOf(site);
  if (!domains.length) throw new Error('This site has no domain, so there is nothing to proxy.');

  let proxyId = site.npm_proxy_id || null;

  // A proxy host for this domain may already exist that the panel did not
  // create - very likely on a homelab where the domain was already in use.
  // Repointing it would silently break whatever it currently serves, so that
  // needs an explicit decision rather than happening as a side effect.
  if (!proxyId) {
    const existing = await findProxyHostByDomain(domains[0]);
    if (existing && !adopt) {
      const err = new Error(
        `NPMplus already has proxy host #${existing.id} for ${domains[0]}, forwarding to ` +
          `${existing.forward_scheme}://${existing.forward_host}:${existing.forward_port}. ` +
          `Taking it over would repoint it at this site (${cfg().hostIp}:${site.port}).`
      );
      err.existingProxy = {
        id: existing.id,
        domains: existing.domain_names,
        forward: `${existing.forward_scheme}://${existing.forward_host}:${existing.forward_port}`,
      };
      throw err;
    }
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
  tokenCache = { token: null, cookies: null, expiresAt: 0, forUrl: '' };
}

module.exports = {
  isEnabled,
  isConfigured,
  testConnection,
  getSession,
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
