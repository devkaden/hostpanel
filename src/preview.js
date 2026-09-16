'use strict';

/**
 * Serves a site's own pages back through the panel, so the preview always works.
 *
 * The preview used to point an iframe straight at the site, which fails in
 * three unrelated ways that all look identical - a blank white rectangle with
 * nothing in the console:
 *
 *   1. The site, or the reverse proxy in front of it, sends X-Frame-Options.
 *      NPMplus does by default, so a site that frames fine on its own port is
 *      refused once it has a domain.
 *   2. A panel on HTTPS cannot embed a plain-HTTP frame. Browsers block it
 *      silently, which is the state as soon as the panel is behind the proxy.
 *   3. The site's port may not be open to the machine the browser is on, even
 *      though it is open to the server.
 *
 * Proxying removes all three at once: the frame is same-origin with the panel,
 * over whatever scheme the panel is already using, from an address the browser
 * has demonstrably reached. No configuration anywhere, and nothing for the user
 * to know about.
 *
 * The cost is that URLs have to be rewritten, which is handled below.
 */

const http = require('http');

/* ------------------------------------------------------------------ *
 * URL rewriting
 * ------------------------------------------------------------------ */
/*
 * The preview lives under /preview/<id>/, so a page written for the site root
 * needs its links adjusted.
 *
 * Relative URLs are handled by a <base> tag. Root-relative ones ("/style.css")
 * ignore <base> entirely and would escape to the panel itself, so those are
 * rewritten here. Protocol-relative ("//cdn...") and absolute URLs are left
 * alone: they already point somewhere real.
 */

/** True for a URL that must be prefixed: starts with one slash, not two. */
function isRootRelative(value) {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//');
}

function prefixUrl(value, base) {
  return isRootRelative(value) ? base.replace(/\/$/, '') + value : value;
}

/** Rewrites the root-relative URLs in a srcset, which is a comma-separated list. */
function rewriteSrcset(value, base) {
  return value
    .split(',')
    .map((part) => {
      const trimmed = part.trim();
      if (!trimmed) return part;
      const [url, ...rest] = trimmed.split(/\s+/);
      return [prefixUrl(url, base), ...rest].join(' ');
    })
    .join(', ');
}

/** Rewrites url(...) inside CSS, including the quoted forms. */
function rewriteCss(css, base) {
  return String(css).replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (match, quote, url) => {
    if (!isRootRelative(url)) return match;
    return `url(${quote}${prefixUrl(url, base)}${quote})`;
  });
}

const URL_ATTRIBUTES = ['href', 'src', 'action', 'poster', 'data-src', 'formaction'];

/**
 * Rewrites a page so it renders correctly underneath the preview path.
 *
 * Deliberately a regex pass rather than a full parse. A preview does not need
 * to be perfect, it needs to be fast and never to fail on malformed markup -
 * and every site type this panel serves is some mix of HTML, templating output
 * and framework scaffolding that a strict parser would reject.
 */
function rewriteHtml(html, base) {
  let out = String(html);

  // 1. Attributes carrying a single URL.
  for (const attr of URL_ATTRIBUTES) {
    const re = new RegExp(`(\\s${attr}\\s*=\\s*)(["'])(/(?!/)[^"']*)\\2`, 'gi');
    out = out.replace(re, (_m, lead, quote, url) => `${lead}${quote}${prefixUrl(url, base)}${quote}`);
  }

  // 2. srcset, which holds several.
  out = out.replace(/(\ssrcset\s*=\s*)(["'])([^"']*)\2/gi, (_m, lead, quote, value) =>
    `${lead}${quote}${rewriteSrcset(value, quote === '"' ? base : base)}${quote}`
  );

  // 3. Inline <style> blocks and style="" attributes.
  out = out.replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi, (_m, open, css, close) =>
    open + rewriteCss(css, base) + close
  );
  out = out.replace(/(\sstyle\s*=\s*)(["'])([^"']*url\([^"']*)\2/gi, (_m, lead, quote, css) =>
    `${lead}${quote}${rewriteCss(css, base)}${quote}`
  );

  // 4. A <base> so ordinary relative URLs resolve under the preview path too.
  //    Inserted after any existing <base>, which would otherwise win.
  const baseTag = `<base href="${base}">`;
  if (/<head\b[^>]*>/i.test(out)) {
    out = out.replace(/(<head\b[^>]*>)/i, `$1\n${baseTag}`);
  } else if (/<html\b[^>]*>/i.test(out)) {
    out = out.replace(/(<html\b[^>]*>)/i, `$1<head>${baseTag}</head>`);
  } else {
    out = baseTag + out;
  }

  return out;
}

/* ------------------------------------------------------------------ *
 * The proxy itself
 * ------------------------------------------------------------------ */
/*
 * Headers that must not cross in either direction.
 *
 * Nothing from the panel's own session may reach the site: it is the user's
 * code, and handing it an admin cookie would make a preview a way to act as
 * the administrator. Nothing the site sets may reach the panel's origin
 * either, for the same reason in reverse.
 *
 * The framing headers are dropped because removing them is the entire point,
 * and the site's CSP goes with them - a policy written for the site's own
 * origin does not describe this one, and keeping it only breaks the render.
 */
const STRIP_REQUEST = ['cookie', 'authorization', 'x-csrf-token'];
const STRIP_RESPONSE = [
  'set-cookie',
  'x-frame-options',
  'content-security-policy',
  'content-security-policy-report-only',
  'strict-transport-security',
  'content-length', // bodies are rewritten, so the original length is wrong
  'content-encoding', // asked for identity below; never claim otherwise
  /*
   * Transfer-Encoding is the upstream's framing decision, not ours. Passing a
   * chunked header through and then setting our own Content-Length produces a
   * response no client will parse - "Content-Length can't be present with
   * Transfer-Encoding" - and the frame goes blank again. Dropping both lets
   * Node frame the response it is actually sending.
   */
  'transfer-encoding',
  'connection',
];

const REWRITABLE = /^text\/html|^text\/css/i;
const MAX_REWRITE_BYTES = 8 * 1024 * 1024;

/**
 * Proxies one request to a site container and writes the answer back.
 *
 * `base` is the path the preview is mounted at, e.g. "/preview/3/".
 */
function proxy(req, res, { port, base, upstreamPath }) {
  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (STRIP_REQUEST.includes(name.toLowerCase())) continue;
    headers[name] = value;
  }
  // The upstream must not compress: the body may need rewriting, and
  // decompressing it here to do that would be work for no benefit.
  headers['accept-encoding'] = 'identity';
  headers.host = `127.0.0.1:${port}`;
  // So a site can tell a preview from a real visit if it wants to.
  headers['x-hostpanel-preview'] = '1';

  const upstream = http.request(
    { host: '127.0.0.1', port, path: upstreamPath, method: req.method, headers, timeout: 15000 },
    (up) => {
      const out = {};
      for (const [name, value] of Object.entries(up.headers)) {
        if (STRIP_RESPONSE.includes(name.toLowerCase())) continue;
        out[name] = value;
      }

      // A redirect to "/somewhere" would leave the preview and land on the
      // panel's own routes, so it is kept inside the preview instead.
      if (out.location && isRootRelative(out.location)) {
        out.location = prefixUrl(out.location, base);
      }

      const type = String(up.headers['content-type'] || '');
      const declared = parseInt(up.headers['content-length'] || '0', 10);

      if (!REWRITABLE.test(type) || declared > MAX_REWRITE_BYTES) {
        res.writeHead(up.statusCode || 200, out);
        up.pipe(res);
        return;
      }

      const chunks = [];
      let size = 0;
      let tooBig = false;
      up.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_REWRITE_BYTES) { tooBig = true; return; }
        chunks.push(chunk);
      });
      up.on('end', () => {
        if (tooBig) {
          // Rather than truncate a page, say so plainly.
          res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('This page is too large to show in the preview. Open it in a new tab.');
          return;
        }
        const body = Buffer.concat(chunks).toString('utf8');
        const rewritten = /^text\/css/i.test(type)
          ? rewriteCss(body, base)
          : rewriteHtml(body, base);
        const buffer = Buffer.from(rewritten, 'utf8');
        out['content-length'] = String(buffer.length);
        res.writeHead(up.statusCode || 200, out);
        res.end(buffer);
      });
      up.on('error', () => {
        if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('The site stopped responding while the page was loading.');
      });
    }
  );

  upstream.on('timeout', () => upstream.destroy(new Error('timed out')));
  upstream.on('error', (err) => {
    if (res.headersSent) return res.end();
    res.writeHead(502, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(
      '<!doctype html><meta charset="utf-8">' +
        '<body style="font:15px system-ui;padding:2rem;color:#444">' +
        '<h2 style="margin:0 0 .5rem">This site is not answering</h2>' +
        `<p>Nothing responded on port ${port}. ` +
        'Check the Logs tab, or start the site if it is stopped.</p>' +
        `<p style="color:#888;font-size:13px">${String(err.message || 'connection failed')}</p>`
    );
  });

  req.pipe(upstream);
}

module.exports = {
  proxy,
  rewriteHtml,
  rewriteCss,
  rewriteSrcset,
  prefixUrl,
  isRootRelative,
};
