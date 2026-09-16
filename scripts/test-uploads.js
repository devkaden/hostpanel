#!/usr/bin/env node
'use strict';
/*
 * Exercises the browser-side upload read path for real.
 *
 * The bug this guards against was never in the server: Chrome hands out a
 * directory handle when a folder is dropped and takes it back shortly
 * afterwards. Past that point entry.file() either fails or - worse - never
 * calls back at all, and the upload queue waits forever. Both happened.
 *
 * The functions under test are lifted straight out of src/views/files.ejs, so
 * this cannot drift from the shipped code, and run against a fake entries API
 * that reproduces each failure mode.
 *
 * Run with: npm run test:uploads
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`); }
}

/* ---------------------------------------- lift the code out of the view -- */
const view = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'views', 'files.ejs'),
  'utf8'
);
const start = view.indexOf('  /** entry.file() can hang');
const end = view.indexOf('  // Junk that is rebuilt on the server');
if (start < 0 || end < 0 || end <= start) {
  console.error('Could not locate the upload read helpers in files.ejs.');
  process.exit(1);
}
const source = view.slice(start, end);

for (const fn of ['entryToFile', 'materialise', 'bodyFor']) {
  if (!new RegExp('function ' + fn + '\\b').test(source)) {
    console.error(`The extracted block is missing ${fn}(). Adjust the markers.`);
    process.exit(1);
  }
}

const sandbox = { Blob, Error, Promise, setTimeout, clearTimeout, console };
vm.createContext(sandbox);
vm.runInContext(
  source + '\n;this.__api = { entryToFile, materialise, bodyFor, ' +
    'MATERIALISE_MAX_FILE, MATERIALISE_BUDGET };',
  sandbox
);
const { entryToFile, materialise, bodyFor, MATERIALISE_MAX_FILE } = sandbox.__api;

/* ------------------------------------------------- fake entries API ------ */
// mode: 'ok' | 'error' | 'hang', and it can change part-way through a run,
// which is exactly what Chrome does when it releases the dropped folder.
function fakeEntry(name, bytes, state) {
  return {
    name,
    file(onOk, onErr) {
      if (state.mode === 'hang') return;               // never calls back
      if (state.mode === 'error') return onErr(new Error('NotFoundError'));
      return onOk({
        name,
        size: bytes.length,
        type: '',
        arrayBuffer: async () => bytes.buffer.slice(
          bytes.byteOffset, bytes.byteOffset + bytes.byteLength
        ),
      });
    },
  };
}

const noop = () => {};
const bodyBytes = async (body) => {
  if (body && typeof body.arrayBuffer === 'function') {
    return Buffer.from(await body.arrayBuffer());
  }
  throw new Error('body is not readable');
};

(async () => {
  console.log('\nentryToFile()');
  {
    const state = { mode: 'ok' };
    const file = await entryToFile(fakeEntry('a.txt', Buffer.from('hi'), state), 500);
    check('resolves a readable handle', file.size === 2);

    state.mode = 'error';
    let err = null;
    try { await entryToFile(fakeEntry('b.txt', Buffer.alloc(0), state), 500); }
    catch (e) { err = e; }
    check('rejects when the browser refuses', !!err && /refused/.test(err.message));

    state.mode = 'hang';
    const began = Date.now();
    err = null;
    try { await entryToFile(fakeEntry('c.txt', Buffer.alloc(0), state), 300); }
    catch (e) { err = e; }
    const took = Date.now() - began;
    check('a handle that never calls back times out instead of hanging',
      !!err && /timed out/.test(err.message), err && err.message);
    check('the timeout actually fires on schedule', took >= 250 && took < 2000, took + 'ms');
  }

  console.log('\nmaterialise() reads while access is alive');
  {
    const state = { mode: 'ok' };
    const items = [
      { path: 'index.html', entry: fakeEntry('index.html', Buffer.from('<h1>hi</h1>'), state) },
      { path: 'app/main.js', entry: fakeEntry('main.js', Buffer.from('console.log(1)'), state) },
    ];
    const seen = [];
    await materialise(items, (i, n, name) => seen.push(`${i}/${n} ${name}`));

    check('every file ends up with bytes in hand', items.every((i) => !!i.blob));
    check('progress is reported per file', seen.length === 2 && seen[0] === '0/2 index.html',
      seen.join(' | '));

    // The whole point: access goes away, and the upload still works.
    state.mode = 'hang';
    const body = await bodyFor(items[0], false);
    check('a materialised file uploads after access is released', !!body);
    check('and the bytes are the right ones',
      (await bodyBytes(body)).toString() === '<h1>hi</h1>');

    const began = Date.now();
    await bodyFor(items[1], true);
    check('even a retry does not wait on the dead handle', Date.now() - began < 200);
  }

  console.log('\nfiles that cannot be read');
  {
    const state = { mode: 'hang' };
    const item = { path: 'photos/big.raw', entry: fakeEntry('big.raw', Buffer.alloc(0), state) };
    await materialise([item], noop);
    check('the failure is recorded on the item', !!item.readError, item.readError);
    check('no bytes are claimed', !item.blob && !item.file);

    let err = null;
    try { await bodyFor(item, false); } catch (e) { err = e; }
    check('bodyFor explains it rather than throwing something cryptic',
      !!err && /Could not read/.test(err.message) && /iCloud/.test(err.message),
      err && err.message);
  }

  console.log('\npicked files (no entry) still work');
  {
    const item = { path: 'notes.txt', file: { name: 'notes.txt', size: 5 } };
    const body = await bodyFor(item, false);
    check('a File from the file picker is used as-is', body === item.file);

    // materialise must not touch it or report it as unread.
    await materialise([item], noop);
    check('materialise leaves picked files alone', !item.readError && !item.blob);
  }

  console.log('\nmemory bounds');
  {
    const state = { mode: 'ok' };
    const big = Buffer.alloc(MATERIALISE_MAX_FILE + 1);
    const item = { path: 'huge.bin', entry: fakeEntry('huge.bin', big, state) };
    await materialise([item], noop);
    check('a file over the per-file cap is not held in memory', !item.blob);
    check('but its handle is kept as a fallback', !!item.file);
    check('the cap is a sane size', MATERIALISE_MAX_FILE >= 4 * 1024 * 1024);
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
