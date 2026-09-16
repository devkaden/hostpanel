#!/usr/bin/env node
'use strict';
/*
 * Security regression tests that run without the runtime dependencies:
 * script-context escaping, redirect validation, path traversal and zip-slip.
 *
 * Run with: npm run test:security
 */

const path = require('path');
const fs = require('fs');
const os = require('os');

let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`); }
}

/* ------------------------------------------------- 1. script escaping ---- */
// Mirrors jsonForScript() in src/index.js.
function jsonForScript(value) {
  return JSON.stringify(value === undefined ? null : value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

console.log('\nembedding untrusted data in a <script> block');
{
  const evil = { command: '</script><img src=x onerror=alert(1)>' };
  const out = jsonForScript(evil);
  check('no literal </script> survives', !/<\/script/i.test(out), out);
  check('no raw angle brackets at all', !/[<>]/.test(out), out);
  check('still parses back to the original', JSON.parse(out).command === evil.command);

  const seps = jsonForScript('line\u2028sep\u2029para');
  check('escapes U+2028 / U+2029', !/[\u2028\u2029]/.test(seps), seps);

  // Verify the source actually uses the helper, not bare JSON.stringify.
  const views = path.join(__dirname, '..', 'src', 'views');
  let bare = [];
  for (const file of fs.readdirSync(views)) {
    if (!file.endsWith('.ejs')) continue;
    const src = fs.readFileSync(path.join(views, file), 'utf8');
    if (/<%-\s*JSON\.stringify/.test(src)) bare.push(file);
  }
  check('no view uses <%- JSON.stringify %>', bare.length === 0, bare.join(', '));
}

/* --------------------------------------------------- 2. safe redirect ---- */
// Mirrors safeNext() in src/routes/auth.js.
function safeNext(value) {
  if (typeof value !== 'string' || !value.startsWith('/')) return '/';
  if (value.startsWith('//') || value.startsWith('/\\')) return '/';
  if (/[\r\n]/.test(value)) return '/';
  return value;
}

console.log('\npost-login redirect target');
{
  check('rejects //evil.com', safeNext('//evil.com') === '/');
  check('rejects /\\evil.com', safeNext('/\\evil.com') === '/');
  check('rejects an absolute URL', safeNext('https://evil.com') === '/');
  check('rejects a header-injection newline', safeNext('/ok\r\nSet-Cookie: x=1') === '/');
  check('rejects a non-string', safeNext(undefined) === '/');
  check('allows a normal path', safeNext('/sites/3/files') === '/sites/3/files');
}

/* ------------------------------------------------- 3. path containment --- */
console.log('\nfile manager path containment');
{
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-sec-'));
  const secret = path.join(os.tmpdir(), 'hp-outside-secret.txt');
  fs.writeFileSync(secret, 'do not read me');
  fs.mkdirSync(path.join(root, 'app'), { recursive: true });

  // Mirrors the containment logic in src/filemanager.js resolveSafe().
  function resolveSafe(relPath) {
    const rootReal = fs.realpathSync(root);
    const cleaned = String(relPath || '').replace(/\\/g, '/').replace(/^\/+/, '');
    const target = path.resolve(rootReal, cleaned);
    const rel = path.relative(rootReal, target);
    if (rel.startsWith('..') || path.isAbsolute(rel)) throw new Error('outside');
    if (fs.existsSync(target)) {
      const relReal = path.relative(rootReal, fs.realpathSync(target));
      if (relReal.startsWith('..') || path.isAbsolute(relReal)) throw new Error('outside');
    }
    return target;
  }

  const blocked = (p) => {
    try { resolveSafe(p); return false; } catch (_) { return true; }
  };

  check('blocks ../../etc/passwd', blocked('../../etc/passwd'));
  check('blocks a backslash traversal', blocked('..\\..\\etc\\passwd'));
  check('blocks a nested traversal', blocked('app/../../../etc/passwd'));
  check('allows a normal path', !blocked('app/index.html'));

  // A leading slash is stripped rather than rejected, so "/etc/passwd" must
  // land inside the site root and never touch the real /etc/passwd.
  const abs = resolveSafe('/etc/passwd');
  check(
    'an absolute path is confined to the site root',
    abs.startsWith(fs.realpathSync(root) + path.sep) && abs !== '/etc/passwd',
    abs
  );

  // A symlink pointing outside the root must not be followable.
  const link = path.join(root, 'app', 'escape');
  try {
    fs.symlinkSync(secret, link);
    check('blocks a symlink escaping the root', blocked('app/escape'));
  } catch (_) {
    console.log('  SKIP  symlink escape (cannot create symlinks here)');
  }

  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(secret, { force: true });
}

/* ------------------------------------------------------- 4. zip slip ----- */
console.log('\nzip extraction containment');
{
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hp-zip-')));
  const destDir = path.join(root, 'app');
  fs.mkdirSync(destDir, { recursive: true });

  // Mirrors the guard in src/filemanager.js extractZip().
  function entryAllowed(entryName) {
    const outPath = path.resolve(destDir, entryName);
    const rel = path.relative(root, outPath);
    return !(rel.startsWith('..') || path.isAbsolute(rel));
  }

  check('rejects ../../../etc/cron.d/evil', !entryAllowed('../../../etc/cron.d/evil'));
  check('rejects an absolute entry', !entryAllowed('/etc/passwd'));
  check('accepts a normal entry', entryAllowed('assets/app.js'));

  fs.rmSync(root, { recursive: true, force: true });
}

/* ------------------------------------------ 5. upload path safety -------- */
console.log('\nnested upload paths (dropped folders)');
{
  // Mirrors the per-segment validation in saveUploadNested().
  function segmentsOk(relativePath) {
    const segments = String(relativePath || '')
      .replace(/\\/g, '/')
      .split('/')
      .filter((seg) => seg && seg !== '.');
    if (!segments.length) return false;
    for (const seg of segments) {
      if (seg === '..') return false;
      if (seg === '.') return false;
      if (/[\/\\\0]/.test(seg)) return false;
      if (seg.length > 255) return false;
    }
    return true;
  }

  check('accepts a normal nested path', segmentsOk('assets/css/app.css'));
  check('accepts a bare file name', segmentsOk('index.html'));
  check('rejects a traversal segment', !segmentsOk('../../etc/passwd'));
  check('rejects a traversal in the middle', !segmentsOk('assets/../../../etc/passwd'));
  check('rejects a backslash traversal', !segmentsOk('..\\..\\etc\\passwd'));
  check('rejects an empty path', !segmentsOk(''));
  check('rejects a path of only dots', !segmentsOk('./././'));
}

console.log('\nmoving files inside a site');
{
  // Mirrors the containment rules in filemanager.move().
  function moveAllowed(sourceRel, destRel) {
    if (sourceRel === '') return false;              // never move the root
    if (destRel === sourceRel) return false;         // into itself
    if (destRel.startsWith(sourceRel + '/')) return false; // into its own child
    return true;
  }

  check('allows a normal move', moveAllowed('app/index.html', 'app/pages'));
  check('allows moving up a level', moveAllowed('app/pages/a.html', 'app'));
  check('refuses to move the site root', !moveAllowed('', 'app'));
  check('refuses to move a folder into itself', !moveAllowed('app', 'app'));
  check('refuses to move a folder into its own child', !moveAllowed('app', 'app/pages'));
  check('allows a sibling with a shared prefix', moveAllowed('app', 'application'));
}

console.log('\nupload transport');
{
  const routes = fs.readFileSync(path.join(__dirname, '..', 'src', 'routes', 'files.js'), 'utf8');
  const view = fs.readFileSync(path.join(__dirname, '..', 'src', 'views', 'files.ejs'), 'utf8');
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));

  // Multipart parsing is what produced "Unexpected end of form"; it must be gone.
  check('no multipart parser is a dependency', !pkg.dependencies.multer);
  check('routes do not require multer', !/require\(['"]multer['"]\)/.test(routes));
  check('a raw PUT upload route exists', /files\/raw/.test(routes));
  check('the route enforces the size limit', /maxUploadBytes/.test(routes));
  check('the client uploads with PUT', /xhr\.open\('PUT'/.test(view));
  check('the client sends the CSRF token on uploads', /X-CSRF-Token/.test(view));

  // Answering before the body is read leaves it queued on a keep-alive socket,
  // where the next request reads it as headers and that connection hangs.
  check('an early rejection closes the connection',
    /rejectEarly/.test(routes) && /'Connection', 'close'/.test(routes));
  check('a failed upload closes it too',
    (routes.match(/'Connection', 'close'/g) || []).length >= 2);

  // A per-socket timeout outlives the request on a keep-alive connection, so
  // the timer keeps running against the *next* upload.
  const routesCode = routes
    .replace(/\/\/[^\n]*/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');
  check('the idle timeout is not set on the socket',
    !/req\.setTimeout\(/.test(routesCode),
    'req.setTimeout() leaks across keep-alive requests');
  check('the server logs an upload on arrival, not only on failure',
    /<- start/.test(routes));
  check('a failure says how many bytes actually arrived',
    /of \$\{declared/.test(routes));
}

console.log('\ndropped-folder file handles');
{
  const view = fs.readFileSync(path.join(__dirname, '..', 'src', 'views', 'files.ejs'), 'utf8');

  // Chrome only keeps a dropped folder readable for a short window. Past it,
  // entry.file() either fails (the upload aborts mid-body) or never calls back
  // at all (the upload never starts). Both were observed. So: traverse without
  // touching entry.file(), then read the bytes up front, with every read
  // guarded by a timeout so nothing can hang.
  const traversal = view
    .slice(view.indexOf('function readEntry'), view.indexOf('function entryToFile'))
    // Comments explain why this must not happen; only real code counts.
    .replace(/\/\/[^\n]*/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');
  check('traversal does not capture File objects',
    !/entry\.file\s*\(/.test(traversal),
    'readEntry still calls entry.file() during traversal');
  check('traversal keeps the entry instead',
    /entry:\s*entry/.test(traversal));

  // Comments discuss entry.file() at length; only real code counts.
  const viewCode = view
    .replace(/\/\/[^\n]*/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');
  check('every entry.file() call is timeout-guarded',
    /function entryToFile/.test(view) &&
      (viewCode.match(/entry\.file\s*\(/g) || []).length === 1,
    'entry.file() is called outside entryToFile()');
  check('entryToFile rejects rather than hanging',
    /timed out reading the file handle/.test(view));
  check('bytes are read before any upload starts',
    /function materialise/.test(view) && /await readPhase\(/.test(view));
  check('the read is bounded so a big folder cannot exhaust the tab',
    /MATERIALISE_MAX_FILE/.test(view) && /MATERIALISE_BUDGET/.test(view));
  check('the upload asks for a body rather than passing a file handle',
    /await bodyFor\(item\)/.test(view));
  check('a failed upload is retried through a different browser API',
    /function fetchFile/.test(view) && /retrying with fetch/.test(view));
  check('an upload that sends nothing is abandoned rather than left hanging',
    /stalled at/.test(view) && /lastMovedAt/.test(view));
  // Safari fires a progress event with loaded = 0 and then stalls, so an event
  // arriving must not count as movement - only the byte counter going up.
  check('the stall guard tracks bytes, not events',
    /e\.loaded > lastLoaded/.test(view));
  // A disk-backed File handed to XHR is what Safari never starts sending.
  check('file bytes are read into memory before the request',
    /function readBytes/.test(view) && /readAsArrayBuffer/.test(view));
  check('the read can be abandoned',
    /reader\.abort\(\)/.test(view));
  check('a picked file is read into memory before it is sent',
    /return await readBytes\(file, 30000\);/.test(view));

  // Resetting an <input type="file"> revokes the File objects it produced, so
  // clearing it while the upload is still running makes those files unreadable
  // mid-flight - WebKit reports NotReadableError and nothing is ever sent.
  const picker = view.slice(view.indexOf('function pickFrom'), view.indexOf('pickFrom(fileInput'));
  check('a file input is cleared only after the upload finishes',
    /await uploadFiles\(picked\);/.test(picker) &&
      /finally \{\s*input\.value = '';/.test(picker),
    'the input is reset while the upload is still reading from it');
  check('no handler clears a file input synchronously',
    !/\.files\.length\) uploadFiles/.test(view));
  check('but not one too large to hold',
    /READ_INTO_MEMORY_MAX/.test(view));
  check('the bytes are released once the file is sent',
    /item\.blob = null/.test(view));
  check('an unreadable file fails with an explanation, not a timeout',
    /Could not read "/.test(view) && /iCloud/.test(view));
  check('the deleted late resolver is really gone',
    !/resolveFile/.test(view));
}

console.log('\nbrowser requests carry the session');
{
  // A fetch() that omits cookies reaches the panel as a brand new session, so
  // its CSRF token cannot match and every write gets a 403 - while XHR uploads
  // on the same page keep working, because XHR always sent cookies. Relying on
  // the default is what allows that split-brain, so it is set explicitly.
  const views = path.join(__dirname, '..', 'src', 'views');
  const offenders = [];
  const check1 = (name, src) => {
    const re = /fetch\(/g;
    let m;
    while ((m = re.exec(src))) {
      // Look ahead far enough to cover the options object on the next line.
      const window_ = src.slice(m.index, m.index + 400);
      const end = window_.indexOf(');');
      const call = end > 0 ? window_.slice(0, end) : window_;
      if (!/credentials/.test(call)) offenders.push(`${name}:${src.slice(0, m.index).split('\n').length}`);
    }
  };
  for (const file of fs.readdirSync(views)) {
    if (!file.endsWith('.ejs')) continue;
    // Comments discuss fetch() by name; only real calls count.
    const src = fs
      .readFileSync(path.join(views, file), 'utf8')
      .replace(/\/\/[^\n]*/g, '')
      .replace(/\/\*[\s\S]*?\*\//g, '');
    check1(file, src);
  }
  // app.js routes everything through one helper, so the options object is what
  // matters there rather than each call site.
  const appSrc = fs
    .readFileSync(path.join(__dirname, '..', 'src', 'public', 'js', 'app.js'), 'utf8')
    .replace(/\/\/[^\n]*/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');
  check('the shared api() helper sends the session cookie',
    /method: 'POST', credentials: 'same-origin'/.test(appSrc));
  check1('app.js', appSrc.replace(/fetch\(url, opts\)/g, 'fetch(url, opts /* credentials */)'));
  check('every fetch sends the session cookie explicitly', offenders.length === 0,
    offenders.join(', '));
  check('a failed API call names itself in the console',
    /\[api\]/.test(fs.readFileSync(path.join(__dirname, '..', 'src', 'public', 'js', 'app.js'), 'utf8')));
}

console.log('\nin-app dialogs replace the browser ones');
{
  const app = fs.readFileSync(path.join(__dirname, '..', 'src', 'public', 'js', 'app.js'), 'utf8');
  check('HP.confirm exists', /confirm: confirmDialog/.test(app));
  check('HP.alert exists', /alert: alertDialog/.test(app));
  check('HP.prompt exists', /prompt: promptDialog/.test(app));

  const views = path.join(__dirname, '..', 'src', 'views');
  const offenders = [];
  for (const file of fs.readdirSync(views)) {
    if (!file.endsWith('.ejs')) continue;
    const src = fs.readFileSync(path.join(views, file), 'utf8');
    // A bare confirm(/alert(/prompt( not reached through HP.
    const re = /(^|[^.\w])(confirm|alert|prompt)\s*\(/g;
    let m;
    while ((m = re.exec(src))) {
      const before = src.slice(Math.max(0, m.index - 4), m.index + 1);
      if (!before.includes('HP.')) offenders.push(file + ': ' + m[2]);
    }
  }
  check('no view calls a browser dialog directly', offenders.length === 0, offenders.join(', '));
}

/* --------------------------------------------- 5. security headers set --- */
console.log('\ncache headers do not break downloads');
{
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8');
  // Safari's download manager hands the *cached* response to the downloader,
  // so no-store makes every file download fail silently. no-cache still forces
  // revalidation, which is all the panel needs.
  check('panel responses are not marked no-store',
    !/Cache-Control['"]?,\s*['"][^'"]*no-store/.test(src),
    'no-store on panel responses breaks downloads in Safari');
  check('but they still must revalidate',
    /Cache-Control', 'no-cache, must-revalidate, private'/.test(src));
  check('static assets are versioned so an update is a new URL',
    /ASSET_VERSION/.test(src));
}

console.log('\nsecurity headers declared in src/index.js');
{
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8');
  for (const header of [
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Referrer-Policy',
    'Content-Security-Policy',
    "frame-ancestors 'none'",
    "object-src 'none'",
  ]) {
    check(`sets ${header}`, src.includes(header));
  }
  // Safari applies CSP to the internal blob load that backs a file upload, so a
  // policy without blob: refuses to read the file at all - reported as
  // NotReadableError and "WebKitBlobResource error 4", neither of which
  // mentions CSP. This cost a very long debugging session.
  for (const directive of [
    "default-src 'self' blob:",
    "connect-src 'self' blob: ws: wss:",
    "img-src 'self' data: blob:",
  ]) {
    check(`CSP allows blob resources: ${directive}`, src.includes(directive));
  }
  check('the CSP can be turned off to test whether it is the cause',
    /disableCsp/.test(src) && /DISABLE_CSP/.test(
      fs.readFileSync(path.join(__dirname, '..', 'src', 'config.js'), 'utf8')
    ));
  check('trust proxy is opt-in', /TRUST_PROXY === 'true'/.test(
    fs.readFileSync(path.join(__dirname, '..', 'src', 'config.js'), 'utf8')
  ));
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
