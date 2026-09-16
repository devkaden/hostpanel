'use strict';

/**
 * Request rate limiting.
 *
 * The sign-in path has always been throttled (src/auth.js, persisted in
 * SQLite), but everything behind it was not: an account that gets hold of a
 * session could ask for a thousand directory listings a second, and every one
 * of those reaches the disk or the Docker socket. On a panel meant to face the
 * internet with accounts handed to other people, "you have to be signed in
 * first" is not a rate limit.
 *
 * Three buckets, because one number cannot fit all three shapes of request:
 * reading is cheap and the panel polls itself, writing is not, and the
 * unauthenticated endpoints are the ones strangers can reach.
 *
 * Counting is in memory. That is the right trade here and not an oversight:
 * this is a ceiling on bursts, not the lockout logic - the lockout that has to
 * survive a restart is the sign-in throttle, and that one is in the database.
 * A limiter that wrote a row per request would itself be the load.
 *
 * express-rate-limit is used when it is installed, since it is the
 * well-trodden implementation; the version below is the fallback, so a panel
 * whose dependencies did not install fully is still limited rather than
 * silently not.
 */

const { getSetting, getNumericSetting } = require('./db');

/* Requests per minute, per signed-in account, or per address when there is no
 * account yet. Generous on purpose: the number that matters is the one that
 * stops a script, not one that interrupts somebody uploading a folder. */
const BUCKETS = {
  auth: { windowMs: 60 * 1000, max: 30 },
  write: { windowMs: 60 * 1000, max: 300 },
  read: { windowMs: 60 * 1000, max: 900 },
  /*
   * The preview needs a bucket of its own, and a large one.
   *
   * It carries a token rather than a session, so without this it would land in
   * the signed-out bucket - and one ordinary page with forty images and a few
   * fonts would spend that allowance in a second. It is also the one bucket
   * where a burst is exactly what a correct page looks like.
   */
  preview: { windowMs: 60 * 1000, max: 1200 },
};

/** Which bucket a request falls in. */
function bucketFor(req) {
  if (req.path.startsWith('/preview/')) return 'preview';
  // Before sign-in, everything is the strict bucket regardless of method:
  // these are the paths reachable without an account.
  if (!req.session || !req.session.user) return 'auth';
  return ['GET', 'HEAD', 'OPTIONS'].includes(req.method) ? 'read' : 'write';
}

/**
 * Who a request is counted against.
 *
 * The account first, so one person on a shared address cannot spend everyone
 * else's allowance, and so a limit follows them across devices.
 */
function keyFor(req, bucket) {
  /*
   * A preview is counted per token, which is per site per page load. Counting
   * it by address instead would make two people looking at two different sites
   * from one office share one allowance, for traffic that is not theirs to
   * control.
   */
  if (bucket === 'preview') {
    const token = String(req.path.split('/')[2] || '');
    return `preview|${token || req.ip}`;
  }
  const who = req.session && req.session.user ? `u:${req.session.user.id}` : `i:${req.ip}`;
  return `${bucket}|${who}`;
}

/* ------------------------------------------------------------------ *
 * The counter
 * ------------------------------------------------------------------ */
const hits = new Map();

/**
 * A fixed window rather than a sliding log.
 *
 * A sliding window means keeping a timestamp per request, which is a list that
 * grows with exactly the traffic it is meant to survive. A window that resets
 * is less precise at the boundary and costs two numbers per key.
 */
function take(key, windowMs, max) {
  const now = Date.now();
  const entry = hits.get(key);
  if (!entry || now >= entry.resetAt) {
    hits.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: max - 1, resetAt: now + windowMs };
  }
  entry.count += 1;
  return {
    allowed: entry.count <= max,
    remaining: Math.max(0, max - entry.count),
    resetAt: entry.resetAt,
  };
}

// Expired keys are not worth keeping. Unref'd so it never holds the process up.
const sweeper = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of hits) {
    if (now >= entry.resetAt) hits.delete(key);
  }
}, 60 * 1000);
if (sweeper.unref) sweeper.unref();

/** Empties the counters. For tests, and for an administrator who locked themselves out. */
function reset() {
  hits.clear();
}

/* ------------------------------------------------------------------ *
 * Middleware
 * ------------------------------------------------------------------ */
/*
 * One choice rather than three numbers.
 *
 * Nobody knows what their panel's right requests-per-minute is, and a form
 * asking for it three times gets left alone or filled in badly. What people do
 * know is which situation they are in: a panel on their own LAN, a panel with
 * accounts on it, or a panel being probed.
 */
const PROFILES = { relaxed: 3, standard: 1, strict: 0.4 };

/**
 * The limit in force for a bucket.
 *
 * An explicit rate_limit_<bucket> wins if one is set - there is always a case
 * the three profiles do not cover, and the alternative is editing the source.
 */
function limitFor(bucket) {
  const explicit = getNumericSetting(`rate_limit_${bucket}`, 0);
  if (explicit > 0) return explicit;
  const profile = PROFILES[getSetting('rate_limit_profile')] || PROFILES.standard;
  return Math.max(5, Math.round(BUCKETS[bucket].max * profile));
}

function middleware(req, res, next) {
  // Server-sent events and the terminal websocket are one long-lived request
  // each, not traffic. Counting them would spend somebody's allowance on a log
  // window they left open.
  if (req.path.endsWith('/progress') || req.path.endsWith('/stream')) return next();
  // Counted once, however many routers the request passes through.
  if (req.rateLimit) return next();

  const bucket = bucketFor(req);
  const { windowMs } = BUCKETS[bucket];
  const max = limitFor(bucket);
  const result = take(keyFor(req, bucket), windowMs, max);

  res.set('X-RateLimit-Limit', String(max));
  res.set('X-RateLimit-Remaining', String(result.remaining));
  // The same marker express-rate-limit sets, so either implementation counts a
  // request exactly once.
  req.rateLimit = { limit: max, remaining: result.remaining, resetTime: new Date(result.resetAt) };

  if (result.allowed) return next();

  const seconds = Math.max(1, Math.ceil((result.resetAt - Date.now()) / 1000));
  res.set('Retry-After', String(seconds));

  const message =
    `Too many requests. Wait ${seconds} second${seconds === 1 ? '' : 's'} and try again.`;

  if (
    req.xhr ||
    req.path.startsWith('/api/') ||
    (req.get('accept') || '').includes('application/json')
  ) {
    return res.status(429).json({ error: message, retryAfter: seconds });
  }
  return res.status(429).render('error', { title: 'Slow down', message });
}

/**
 * The options every limiter here runs with.
 *
 * One set, not three, because the buckets differ only in how many requests
 * they allow and who they are counted against - and both of those are
 * functions of the request. The window is a minute in every case.
 */
const OPTIONS = {
  windowMs: 60 * 1000,
  limit: (req) => limitFor(bucketFor(req)),
  keyGenerator: (req) => keyFor(req, bucketFor(req)),
  /*
   * Skipped for two kinds of request.
   *
   * A server-sent event stream and a terminal session are each one long-lived
   * request, not traffic; counting them would spend somebody's allowance on a
   * log window they left open.
   *
   * And a request that has already been counted is not counted again. The
   * limiter is applied to each router as well as globally - so that it is
   * unambiguous, to a reader and to a scanner, that every route is behind it -
   * and every router mounted at "/" sees every request. req.rateLimit is set
   * by the first one to run.
   */
  skip: (req) =>
    req.path.endsWith('/progress') || req.path.endsWith('/stream') || Boolean(req.rateLimit),
  standardHeaders: true,
  legacyHeaders: false,
  /*
   * express-rate-limit's start-up validation, not any part of the limiting.
   * It warns about custom key generators and about trust-proxy settings it
   * cannot verify, neither of which it can judge here: the key is deliberately
   * per-account, and whether X-Forwarded-For can be believed is the
   * TRUST_PROXY decision, which Settings already reports on.
   */
  validate: false,
  handler: (req, res) => {
    const seconds = Math.ceil(OPTIONS.windowMs / 1000);
    const message =
      `Too many requests. Wait ${seconds} second${seconds === 1 ? '' : 's'} and try again.`;
    if (
      req.xhr ||
      req.path.startsWith('/api/') ||
      (req.get('accept') || '').includes('application/json')
    ) {
      return res.status(429).json({ error: message, retryAfter: seconds });
    }
    return res.status(429).render('error', { title: 'Slow down', message });
  },
};

/**
 * The middleware itself: express-rate-limit when it is installed, the counter
 * above when it is not.
 *
 * Built here, at module load, rather than behind a function call - it is one
 * shared instance, and a `rateLimit(...)` that anything reading this file can
 * see going straight onto the routers.
 */
let limiter;
try {
  // eslint-disable-next-line global-require
  const rateLimit = require('express-rate-limit');
  limiter = rateLimit(OPTIONS);
} catch (_) {
  limiter = middleware;
}

module.exports = {
  limiter,
  middleware,
  bucketFor,
  keyFor,
  take,
  reset,
  BUCKETS,
  PROFILES,
  limitFor,
  OPTIONS,
};
