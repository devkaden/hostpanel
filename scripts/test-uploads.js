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

for (const fn of ['entryToFile', 'materialise', 'bodyFor', 'readBytes']) {
  if (!new RegExp('function ' + fn + '\\b').test(source)) {
    console.error(`The extracted block is missing ${fn}(). Adjust the markers.`);
    process.exit(1);
  }
}

// No FileReader here, which is deliberate: readBytes() has to work through its
// arrayBuffer() fallback too, and that is the path this exercises. ulog is the
// page's console helper, stubbed so the extracted code runs unmodified.
const sandbox = {
  Blob, Error, Promise, setTimeout, clearTimeout, console,
  ulog: () => {},
};
vm.createContext(sandbox);
vm.runInContext(
  source + '\n;this.__api = { entryToFile, materialise, bodyFor, readBytes, ' +
    'MATERIALISE_MAX_FILE, MATERIALISE_BUDGET, READ_INTO_MEMORY_MAX };',
  sandbox
);
const {
  entryToFile, materialise, bodyFor, readBytes,
  MATERIALISE_MAX_FILE, READ_INTO_MEMORY_MAX,
} = sandbox.__api;

/* ------------------------------------------------- fake entries API ------ */
// mode: 'ok' | 'error' | 'hang', and it can change part-way through a run,
// which is exactly what Chrome does when it releases the dropped folder.
function fakeFile(name, bytes) {
  return {
    name,
    size: bytes.length,
    type: '',
    arrayBuffer: async () => bytes.buffer.slice(
      bytes.byteOffset, bytes.byteOffset + bytes.byteLength
    ),
  };
}

function fakeEntry(name, bytes, state) {
  return {
    name,
    file(onOk, onErr) {
      if (state.mode === 'hang') return;               // never calls back
      if (state.mode === 'error') return onErr(new Error('NotFoundError'));
      return onOk(fakeFile(name, bytes));
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
    const body = await bodyFor(items[0]);
    check('a materialised file uploads after access is released', !!body);
    check('and the bytes are the right ones',
      (await bodyBytes(body)).toString() === '<h1>hi</h1>');

    const began = Date.now();
    await bodyFor(items[1]);
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
    try { await bodyFor(item); } catch (e) { err = e; }
    check('bodyFor explains it rather than throwing something cryptic',
      !!err && /Could not read/.test(err.message) && /iCloud/.test(err.message),
      err && err.message);
  }

  console.log('\npicked files (no entry)');
  {
    const bytes = Buffer.from('hello');
    const item = { path: 'notes.txt', file: fakeFile('notes.txt', bytes) };

    // The Safari bug: a disk-backed File handed to the request never sends.
    // bodyFor must turn it into bytes rather than passing the handle along.
    const body = await bodyFor(item);
    check('a picked file is read into memory, not passed as a handle',
      body !== item.file);
    check('and the bytes survive the trip', (await bodyBytes(body)).toString() === 'hello');

    // Reading happens per file at send time, so a big selection is never all
    // in memory at once - materialise is only for dropped entries.
    const fresh = { path: 'notes.txt', file: fakeFile('notes.txt', bytes) };
    await materialise([fresh], noop);
    check('materialise leaves picked files for later', !fresh.readError && !fresh.blob);
  }

  console.log('\nfiles too large to hold in memory');
  {
    const huge = fakeFile('video.mov', Buffer.alloc(8));
    huge.size = READ_INTO_MEMORY_MAX + 1; // lie about the size; nothing reads it
    const item = { path: 'video.mov', file: huge };
    const body = await bodyFor(item);
    check('a very large file is passed through rather than buffered',
      body === huge);
  }

  console.log('\nreadBytes gives up rather than hanging');
  {
    const stuck = {
      name: 'evicted.psd',
      size: 10,
      type: '',
      arrayBuffer: () => new Promise(() => {}), // never settles
    };
    const began = Date.now();
    let err = null;
    try { await readBytes(stuck, 300); } catch (e) { err = e; }
    check('a read that never returns times out', !!err && /timed out/.test(err.message),
      err && err.message);
    check('and it gives up on schedule', Date.now() - began < 2000);

    // bodyFor must not fail the upload over it: the handle is still worth a try.
    const item = { path: 'evicted.psd', file: stuck };
    const body = await bodyFor(item);
    check('an unreadable file still falls back to its handle', body === stuck);
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
