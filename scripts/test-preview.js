#!/usr/bin/env node
'use strict';
/*
 * Exercises the preview proxy: URL rewriting, and a real proxied request
 * against a real HTTP server.
 *
 * The preview is served through the panel so that no framing header, mixed
 * content rule or closed port can blank it out. That only holds if the
 * rewriting is right - a page whose stylesheet 404s looks just as broken as one
 * that never loaded - and if the proxy strips the headers that would otherwise
 * carry the panel's session to the site, or the site's cookies to the panel.
 *
 * Run with: npm run test:preview
 */

const http = require('http');
const preview = require('../src/preview');

let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`); }
}

const BASE = '/preview/7/';

console.log('\nwhich URLs get rewritten');
{
  check('a root-relative path is rewritten',
    preview.prefixUrl('/style.css', BASE) === '/preview/7/style.css');
  check('a protocol-relative URL is left alone',
    preview.prefixUrl('//cdn.example.com/x.js', BASE) === '//cdn.example.com/x.js');
  check('an absolute URL is left alone',
    preview.prefixUrl('https://example.com/x.js', BASE) === 'https://example.com/x.js');
  check('a relative path is left alone (the <base> tag handles it)',
    preview.prefixUrl('assets/app.js', BASE) === 'assets/app.js');
  check('a fragment is left alone', preview.prefixUrl('#main', BASE) === '#main');
  check('a data: URL is left alone',
    preview.prefixUrl('data:image/png;base64,AAA', BASE).startsWith('data:'));
  check('a mailto: link is left alone',
    preview.prefixUrl('mailto:a@b.c', BASE) === 'mailto:a@b.c');
}

console.log('\nHTML rewriting');
{
  const html = [
    '<!doctype html><html><head>',
    '<link rel="stylesheet" href="/css/app.css">',
    '<script src="//cdn.tailwindcss.com"></script>',
    '<style>body { background: url(/img/bg.png); }</style>',
    '</head><body>',
    '<img src="/logo.png" srcset="/logo.png 1x, /logo@2x.png 2x" alt="">',
    '<a href="/about">About</a>',
    '<a href="https://example.com">Out</a>',
    '<a href="contact.html">Relative</a>',
    '<form action="/search"><input name="q"></form>',
    '<div style="background:url(/img/hero.jpg)"></div>',
    '</body></html>',
  ].join('\n');

  const out = preview.rewriteHtml(html, BASE);

  check('a stylesheet href is prefixed', out.includes('href="/preview/7/css/app.css"'));
  check('an image src is prefixed', out.includes('src="/preview/7/logo.png"'));
  check('a link href is prefixed', out.includes('href="/preview/7/about"'));
  check('a form action is prefixed', out.includes('action="/preview/7/search"'));
  check('both srcset entries are prefixed',
    out.includes('/preview/7/logo.png 1x') && out.includes('/preview/7/logo@2x.png 2x'));
  check('url() in a <style> block is prefixed', out.includes('url(/preview/7/img/bg.png)'));
  check('url() in a style attribute is prefixed', out.includes('url(/preview/7/img/hero.jpg)'));

  check('a CDN script is untouched', out.includes('src="//cdn.tailwindcss.com"'));
  check('an external link is untouched', out.includes('href="https://example.com"'));
  check('a relative link is untouched', out.includes('href="contact.html"'));

  check('a <base> is injected', out.includes(`<base href="${BASE}">`));
  check('and it is inside the head',
    out.indexOf('<base') > out.indexOf('<head') && out.indexOf('<base') < out.indexOf('</head'));
  check('nothing is prefixed twice', !out.includes('/preview/7/preview/7/'));
}

console.log('\nHTML that is not well formed');
{
  // Real pages are templating output, not textbook HTML. The rewriter must
  // never throw and never drop content.
  const fragments = [
    '<div><img src="/a.png"></div>',
    '<p>unclosed',
    '<html><body><a href="/x">x</a>',
    "<a href='/single'>quoted</a>",
    '<IMG SRC="/CAPS.png">',
    '',
  ];
  let threw = null;
  let out = [];
  try {
    out = fragments.map((f) => preview.rewriteHtml(f, BASE));
  } catch (err) { threw = err; }

  check('never throws', !threw, threw && threw.message);
  check('a fragment with no head still gets a base', out[0].includes('<base'));
  check('single quotes are handled', out[3].includes("href='/preview/7/single'"));
  check('attribute case is handled', out[4].includes('SRC="/preview/7/CAPS.png"'));
  check('empty input is fine', typeof out[5] === 'string');
}

console.log('\nCSS rewriting');
{
  const css = `
    @font-face { src: url(/fonts/x.woff2) format('woff2'); }
    .a { background: url("/img/a.png"); }
    .b { background: url('/img/b.png'); }
    .c { background: url(https://cdn.example.com/c.png); }
    .d { background: url(rel/d.png); }
  `;
  const out = preview.rewriteCss(css, BASE);
  check('an unquoted url is prefixed', out.includes('url(/preview/7/fonts/x.woff2)'));
  check('a double-quoted url is prefixed', out.includes('url("/preview/7/img/a.png")'));
  check("a single-quoted url is prefixed", out.includes("url('/preview/7/img/b.png')"));
  check('an absolute url is untouched', out.includes('url(https://cdn.example.com/c.png)'));
  check('a relative url is untouched', out.includes('url(rel/d.png)'));
}

/* ------------------------------------------------- a real proxied request -- */
(async () => {
  console.log('\nproxying a real server');

  // A site that behaves like the awkward ones: framing headers, a cookie, a
  // redirect, and a page full of root-relative URLs.
  const site = http.createServer((req, res) => {
    if (req.url === '/redirect') {
      res.writeHead(302, { Location: '/landed' });
      return res.end();
    }
    if (req.url === '/echo-headers') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(req.headers));
    }
    if (req.url === '/app.css') {
      res.writeHead(200, { 'content-type': 'text/css' });
      return res.end('.x { background: url(/img/x.png); }');
    }
    if (req.url === '/binary.png') {
      res.writeHead(200, { 'content-type': 'image/png' });
      return res.end(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    }
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'x-frame-options': 'SAMEORIGIN',
      'content-security-policy': "frame-ancestors 'none'",
      'set-cookie': 'sitesession=abc; Path=/',
    });
    return res.end('<html><head></head><body><img src="/logo.png"></body></html>');
  });
  await new Promise((resolve) => site.listen(0, '127.0.0.1', resolve));
  const sitePort = site.address().port;

  // The panel side: one route that proxies everything under /preview/7/.
  const panel = http.createServer((req, res) => {
    const base = '/preview/7/';
    const rest = req.url.slice(base.length - 1) || '/';
    preview.proxy(req, res, {
      port: sitePort,
      base,
      upstreamPath: rest.startsWith('/') ? rest : `/${rest}`,
    });
  });
  await new Promise((resolve) => panel.listen(0, '127.0.0.1', resolve));
  const panelPort = panel.address().port;

  const get = (path, headers) =>
    new Promise((resolve, reject) => {
      const req = http.request(
        { host: '127.0.0.1', port: panelPort, path, method: 'GET', headers: headers || {} },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () =>
            resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) })
          );
        }
      );
      req.on('error', reject);
      req.end();
    });

  const page = await get('/preview/7/');
  check('the page comes back', page.status === 200, `HTTP ${page.status}`);
  check('the framing header is stripped', !page.headers['x-frame-options'],
    String(page.headers['x-frame-options']));
  check("the site's CSP is stripped", !page.headers['content-security-policy']);
  check('the URLs in it are rewritten', page.body.toString().includes('src="/preview/7/logo.png"'));

  // The site must never be able to set a cookie on the panel's origin.
  check('Set-Cookie is stripped', !page.headers['set-cookie'],
    JSON.stringify(page.headers['set-cookie']));

  // And the panel's session must never reach the site.
  const echoed = await get('/preview/7/echo-headers', {
    cookie: 'hostpanel.sid=secret',
    authorization: 'Bearer secret',
    'x-csrf-token': 'secret',
  });
  const seen = JSON.parse(echoed.body.toString());
  check('the panel session cookie does not reach the site', !seen.cookie, seen.cookie);
  check('nor does the Authorization header', !seen.authorization);
  check('nor the CSRF token', !seen['x-csrf-token']);
  check('the site is told this is a preview', seen['x-hostpanel-preview'] === '1');

  const redirect = await get('/preview/7/redirect');
  check('a redirect stays inside the preview',
    redirect.headers.location === '/preview/7/landed', redirect.headers.location);

  const css = await get('/preview/7/app.css');
  check('CSS is rewritten too', css.body.toString().includes('url(/preview/7/img/x.png)'));

  const png = await get('/preview/7/binary.png');
  check('binary files pass through unchanged',
    png.body.equals(Buffer.from([0x89, 0x50, 0x4e, 0x47])), png.body.toString('hex'));
  check('and keep their content type', /image\/png/.test(png.headers['content-type']));

  site.close();

  // With the site gone, the proxy must explain rather than hang.
  const down = await get('/preview/7/');
  check('a stopped site produces a readable page, not a blank frame',
    down.status === 502 && /not answering/i.test(down.body.toString()),
    `HTTP ${down.status}`);

  panel.close();

  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
