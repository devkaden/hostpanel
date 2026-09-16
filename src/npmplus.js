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
const { stripTrailingSlashes } = require('./netutil');
const certpin = require('./certpin');

// Session state: a Bearer token (legacy NPM) and/or a cookie jar (NPMplus).
let tokenCache = { token: null, cookies: null, expiresAt: 0, forUrl: '' };

function cfg() {
  return {
    url: stripTrailingSlashes(getSetting('npmplus_url')),
    email: getSetting('npmplus_email'),
    password: getSetting('npmplus_password'),
    leEmail: getSetting('npmplus_le_email') || getSetting('npmplus_email'),
    enabled: getSetting('npmplus_enabled') === '1',
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
  /*
   * Certificate verification is always on.
   *
   * A self-signed NPMplus is handled by trusting that one certificate - see
   * src/certpin.js - rather than by accepting any certificate at all, which is
   * what this used to do. The difference matters on the network where it is
   * used: "accept anything" hands the NPMplus administrator password to
   * whoever answers on that address next.
   */
  if (isHttps) Object.assign(options, certpin.tlsOptionsFor(target.hostname));

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
      const certErrors = [
        'DEPTH_ZERO_SELF_SIGNED_CERT',
        'SELF_SIGNED_CERT_IN_CHAIN',
        'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        'CERT_HAS_EXPIRED',
        'ERR_TLS_CERT_ALTNAME_INVALID',
      ];
      if (certErrors.includes(err.code)) {
        const pin = certpin.stored();
        return reject(
          new Error(
            pin
              ? `NPMplus is not serving the certificate this panel was told to trust ` +
                `(${pin.fingerprint.slice(0, 17)}...). If you replaced it, press "Trust this ` +
                'certificate" in Settings again. If you did not, something else is answering ' +
                `at ${target.hostname}.`
              : `NPMplus at ${target.hostname} is using a certificate this machine cannot ` +
                'verify (' + err.code + '). If it signed that certificate itself, press ' +
                '"Trust this certificate" in Settings to pin it.'
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

/* ------------------------------------------------------------------ *
 * The panel's own block inside a proxy host's advanced config
 * ------------------------------------------------------------------ *
 * Anything the panel needs nginx to do goes between these markers, and
 * everything outside them is left exactly as it was found. Before this, every
 * sync sent advanced_config: '' - so a hand-written directive survived until
 * the next time anyone pressed Re-sync, and then vanished without a word.
 */
const MANAGED_BEGIN = '# >>> hostpanel: managed, do not edit this block >>>';
const MANAGED_END = '# <<< hostpanel <<<';

/*
 * NPMplus adds X-Frame-Options: SAMEORIGIN to every proxied response, so a site
 * cannot be embedded anywhere else even if the site itself is happy to be.
 * `more_clear_headers` rather than `proxy_hide_header`: the latter only drops
 * headers the *upstream* sent, and this one is added by nginx itself
 * afterwards.
 *
 * Off unless a site asks for it. The panel's own preview does not need it -
 * that is served back through the panel - so this exists for embedding a site
 * somewhere else, and clearing a clickjacking defence is not something to do
 * to someone's public site as a side effect of pressing Fix.
 */
const FRAMING_BLOCK = [
  MANAGED_BEGIN,
  '# Allows this site to be shown inside a frame on another page.',
  'more_clear_headers "X-Frame-Options";',
  MANAGED_END,
].join('\n');

/** Strips the panel's block from an advanced config, leaving the rest intact. */
function withoutManagedBlock(advanced) {
  const text = String(advanced || '');
  const start = text.indexOf(MANAGED_BEGIN);
  if (start === -1) return text.trim();
  const end = text.indexOf(MANAGED_END, start);
  const tail = end === -1 ? '' : text.slice(end + MANAGED_END.length);
  return (text.slice(0, start) + tail).replace(/\n{3,}/g, '\n\n').trim();
}

/** What the advanced config should say for this site, keeping the user's own lines. */
function advancedConfigFor(site, existingAdvanced) {
  const theirs = withoutManagedBlock(existingAdvanced);
  if (!site.allow_framing) return theirs;
  return theirs ? `${theirs}\n\n${FRAMING_BLOCK}` : FRAMING_BLOCK;
}

/*
 * Fields a proxy host's custom locations carry on the way out but will not
 * accept on the way back in - the record's own identity and timestamps.
 */
const LOCATION_READ_ONLY = new Set([
  'id',
  'proxy_host_id',
  'created_on',
  'modified_on',
  'owner_user_id',
  'is_deleted',
]);

/**
 * Custom locations, carried across a sync.
 *
 * Everything the API gave back is sent back, minus the read-only keys above.
 *
 * The first version listed the five fields it knew about instead, which is the
 * same shape of mistake twice over. Sending an unexpected key is rejected with
 * "must NOT have additional properties" - but so is *omitting* a required one,
 * and NPMplus requires two that classic NPM does not:
 *
 *   data/locations/0 must have required property 'npmplus_access_list_ids'
 *
 * which is what someone saw when they added a domain to a site whose proxy
 * host had a custom location on it. A list of known fields has to be right
 * about a schema this code does not own, and is wrong the moment that schema
 * gains a field. Passing through what was read is right by construction: these
 * values came from NPMplus, and nothing here wants to change them.
 */
function keepLocations(locations) {
  if (!Array.isArray(locations)) return [];
  return locations
    .filter((l) => l && typeof l === 'object')
    .map((l) => {
      const out = {};
      for (const [key, value] of Object.entries(l)) {
        if (!LOCATION_READ_ONLY.has(key)) out[key] = value;
      }
      return out;
    });
}

function proxyPayload(site, domains, certificateId, existingHost) {
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
    advanced_config: advancedConfigFor(site, existingHost && existingHost.advanced_config),
    locations: keepLocations(existingHost && existingHost.locations),
    meta: { letsencrypt_agree: false, dns_challenge: false },
  };
}


/**
 * Updates a proxy host, and survives a schema the panel does not own.
 *
 * Custom locations are carried across untouched, but NPMplus validates them
 * strictly and its requirements differ from classic NPM's. If an update is
 * rejected over the locations specifically, they are dropped from the payload
 * and it is sent again: leaving them out of a PUT leaves them as they are,
 * which is the right outcome anyway - this code never wants to change them,
 * only to avoid deleting them.
 *
 * The alternative, failing the whole update, means a custom location on one
 * proxy host stops a domain from being set on the site it belongs to, which is
 * a poor trade for a field nobody here is trying to edit.
 */
async function putProxyHost(proxyId, payload) {
  try {
    return await api('PUT', `/api/nginx/proxy-hosts/${proxyId}`, payload);
  } catch (err) {
    const aboutLocations = /data\/locations/.test(err.message || '');
    if (!aboutLocations || !('locations' in payload)) throw err;

    console.warn(
      `[npmplus] proxy host #${proxyId}: NPMplus rejected the custom locations ` +
        `(${err.message}). Updating everything else and leaving them untouched.`
    );
    const { locations, ...rest } = payload;
    return api('PUT', `/api/nginx/proxy-hosts/${proxyId}`, rest);
  }
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
  //
  // The current host is read first so its advanced config and custom
  // locations survive the update. Sending a blank advanced_config here is how
  // a hand-written directive used to disappear at the next Re-sync.
  let current = null;
  if (proxyId) {
    try {
      current = await getProxyHost(proxyId);
    } catch (_) {
      current = null;
    }
    try {
      await putProxyHost(proxyId, proxyPayload(site, domains, site.npm_cert_id, current));
    } catch (err) {
      if (err.statusCode === 404) {
        proxyId = null;
      } else {
        throw err;
      }
    }
  }
  if (!proxyId) {
    const created = await api('POST', '/api/nginx/proxy-hosts', proxyPayload(site, domains, 0, null));
    if (!created || !created.id) throw new Error('NPMplus did not return a proxy host id');
    proxyId = created.id;
  }

  // Step 2: certificate.
  let certId = site.npm_cert_id || null;
  let ssl = Boolean(certId);
  if (requestSsl) {
    try {
      if (!certId) certId = await requestCertificate(domains);
      await putProxyHost(proxyId, proxyPayload(site, domains, certId, current));
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

/* ------------------------------------------------------------------ *
 * Checking a proxy host, and putting it right
 * ------------------------------------------------------------------ *
 * A proxy host drifts out of step with the panel in ways nobody notices until
 * a site stops answering: the site's port was changed and the proxy still
 * forwards to the old one, a domain was added here but never there, the host
 * IP changed, somebody disabled the host while debugging something else. Every
 * one of those shows up as "the site is up but the domain does not work",
 * which is a miserable thing to diagnose by hand across a dozen sites.
 *
 * So: say exactly what is wrong in words, and offer to fix it.
 */

/** Compares what NPMplus has against what this site needs. */
function diagnoseProxy(site, host) {
  const c = cfg();
  const domains = domainsOf(site);
  const issues = [];
  const add = (code, says) => issues.push({ code, says });

  if (!domains.length) {
    add('no_domain', 'This site has no domain, so there is nothing for the proxy to forward.');
    return issues;
  }
  if (!c.hostIp) {
    add('no_host_ip', 'Host IP is not set in Settings, so the proxy has nowhere to forward to.');
    return issues;
  }
  if (!host) {
    add('missing', `No proxy host exists for ${domains.join(', ')}.`);
    return issues;
  }

  const have = (host.domain_names || []).map((d) => String(d).toLowerCase()).sort();
  const want = [...domains].sort();
  if (have.join(',') !== want.join(',')) {
    add('domains', `The proxy host serves ${have.join(', ') || 'nothing'}, but this site has ${want.join(', ')}.`);
  }
  if (String(host.forward_host) !== String(c.hostIp)) {
    add('forward_host', `It forwards to ${host.forward_host}, but this panel's host is ${c.hostIp}.`);
  }
  if (Number(host.forward_port) !== Number(site.port)) {
    add('forward_port', `It forwards to port ${host.forward_port}, but this site listens on ${site.port}.`);
  }
  if (host.forward_scheme && host.forward_scheme !== 'http') {
    add('scheme', `It forwards over ${host.forward_scheme}; the container speaks plain http.`);
  }
  if (host.enabled === 0 || host.enabled === false) {
    add('disabled', 'The proxy host is turned off in NPMplus.');
  }
  if (!host.allow_websocket_upgrade) {
    add('websocket', 'WebSocket upgrades are off, so live features on the site will not connect.');
  }
  const hasFraming = String(host.advanced_config || '').includes(MANAGED_BEGIN);
  if (site.allow_framing && !hasFraming) {
    add('framing', 'This site is set to allow framing, but the proxy still sends X-Frame-Options.');
  }
  if (!site.allow_framing && hasFraming) {
    add('framing', 'The proxy still clears X-Frame-Options, but this site no longer allows framing.');
  }
  return issues;
}

/**
 * Finds the proxy host for a site and reports what is wrong with it.
 *
 * Never changes anything - this is what the page shows before offering a fix.
 */
async function checkProxy(site) {
  if (!isEnabled()) {
    return { ok: false, reachable: false, issues: [], error: 'NPMplus integration is turned off.' };
  }
  let host = null;
  try {
    if (site.npm_proxy_id) host = await getProxyHost(site.npm_proxy_id);
    if (!host) {
      const domains = domainsOf(site);
      if (domains.length) host = await findProxyHostByDomain(domains[0]);
    }
  } catch (err) {
    return { ok: false, reachable: false, issues: [], error: err.message };
  }
  const issues = diagnoseProxy(site, host);
  return {
    ok: issues.length === 0,
    reachable: true,
    host: host ? { id: host.id, domains: host.domain_names } : null,
    issues,
  };
}

/**
 * Fixes whatever checkProxy found, and reports what it changed.
 *
 * `adopt` is required before taking over a proxy host the panel did not
 * create, exactly as in syncProxyHost: repointing a host that currently serves
 * something else is not a repair.
 */
async function repairProxy(site, { adopt = false, requestSsl = false } = {}) {
  const domains = domainsOf(site);
  if (!domains.length) throw new Error('This site has no domain, so there is nothing to proxy.');

  let host = null;
  if (site.npm_proxy_id) host = await getProxyHost(site.npm_proxy_id);
  if (!host) {
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
    host = existing;
  }

  const issues = diagnoseProxy(site, host);
  if (!issues.length && !requestSsl) {
    return { proxyId: host ? host.id : null, certId: site.npm_cert_id || null,
      ssl: Boolean(site.ssl), issues: [], fixed: [] };
  }

  let proxyId = host ? host.id : null;
  const fixed = [];

  if (!proxyId) {
    const created = await api('POST', '/api/nginx/proxy-hosts', proxyPayload(site, domains, 0, null));
    if (!created || !created.id) throw new Error('NPMplus did not return a proxy host id');
    proxyId = created.id;
    fixed.push(`Created proxy host #${proxyId} for ${domains.join(', ')}.`);
  } else {
    // The certificate goes back on only if HTTPS is meant to be on. A site
    // switched to plain HTTP keeps its certificate id so it can be turned back
    // on without issuing a new one, and a repair must not quietly undo that.
    await putProxyHost(proxyId, proxyPayload(site, domains, site.ssl ? site.npm_cert_id : 0, host));
    for (const issue of issues) {
      if (issue.code === 'disabled') continue; // handled by its own endpoint below
      fixed.push(REPAIR_SAYS[issue.code] ? REPAIR_SAYS[issue.code](site, domains) : issue.says);
    }
  }

  // Re-enabling is its own endpoint; `enabled` is not a field the update
  // schema accepts, and sending it rejects the whole request.
  if (issues.some((i) => i.code === 'disabled')) {
    await enableProxyHost(proxyId);
    fixed.push('Turned the proxy host back on.');
  }

  let certId = site.npm_cert_id || null;
  let ssl = Boolean(site.ssl);
  if (requestSsl && !certId) {
    certId = await requestCertificate(domains);
    await putProxyHost(proxyId, proxyPayload(site, domains, certId, host));
    ssl = true;
    fixed.push('Requested a certificate and turned on HTTPS.');
  }

  return { proxyId, certId, ssl, issues, fixed };
}

/**
 * Turns HTTPS on or off for a site, as one decision rather than two buttons.
 *
 * Turning it off detaches the certificate but does not delete it: the common
 * reason to turn HTTPS off is that the certificate could not be issued yet -
 * DNS has not propagated, port 80 is not open - and deleting a working
 * certificate because someone flipped a switch would be its own small
 * disaster. Turning it back on reuses whatever is there.
 */
async function setSsl(site, enabled) {
  const domains = domainsOf(site);
  if (!domains.length) throw new Error('This site has no domain, so there is nothing to secure.');

  const proxyId = site.npm_proxy_id;
  const host = proxyId ? await getProxyHost(proxyId) : null;
  if (!host) {
    throw new Error('This site has no proxy host yet. Press Check & Fix to create one first.');
  }

  if (!enabled) {
    await putProxyHost(proxyId, proxyPayload(site, domains, 0, host));
    return { proxyId, certId: site.npm_cert_id || null, ssl: false };
  }

  let certId = site.npm_cert_id || null;
  if (!certId) certId = await requestCertificate(domains);
  await putProxyHost(proxyId, proxyPayload(site, domains, certId, host));
  return { proxyId, certId, ssl: true };
}

/* What each repaired issue is called afterwards, in the past tense. */
const REPAIR_SAYS = {
  domains: (site, domains) => `Set the domains to ${domains.join(', ')}.`,
  forward_host: (site) => `Pointed it at ${cfg().hostIp}.`,
  forward_port: (site) => `Pointed it at port ${site.port}.`,
  scheme: () => 'Set the forwarding scheme back to http.',
  websocket: () => 'Turned WebSocket upgrades on.',
  framing: (site) =>
    site.allow_framing
      ? 'Cleared the X-Frame-Options header so this site can be framed.'
      : 'Restored the X-Frame-Options header.',
};

async function enableProxyHost(id) {
  try {
    await api('POST', `/api/nginx/proxy-hosts/${id}/enable`);
    return true;
  } catch (err) {
    if (err.statusCode === 404) return false;
    throw err;
  }
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
  keepLocations,
  putProxyHost,
  isConfigured,
  testConnection,
  getSession,
  syncProxyHost,
  checkProxy,
  repairProxy,
  setSsl,
  diagnoseProxy,
  enableProxyHost,
  advancedConfigFor,
  withoutManagedBlock,
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
