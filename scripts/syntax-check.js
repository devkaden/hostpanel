#!/usr/bin/env node
'use strict';

/**
 * Parses every .js and .ejs file under src/ without executing it, so a typo is
 * caught before the service restarts. Run with: npm run check
 *
 * Uses the real ejs compiler when it is installed, and falls back to a small
 * built-in transpiler otherwise, so this works before `npm install` too.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

let ejs = null;
try {
  // eslint-disable-next-line global-require
  ejs = require('ejs');
} catch (_) {
  ejs = null;
}

const root = path.join(__dirname, '..', 'src');
let failures = 0;
let checked = 0;
const ejsFiles = [];

/** Minimal EJS -> JS transpiler, good enough to surface syntax errors. */
function ejsToJs(src) {
  let out = 'function __tpl(locals){ var __o=[]; with(locals||{}){\n';
  let i = 0;
  while (i < src.length) {
    const open = src.indexOf('<%', i);
    if (open === -1) {
      out += `__o.push(${JSON.stringify(src.slice(i))});\n`;
      break;
    }
    if (open > i) out += `__o.push(${JSON.stringify(src.slice(i, open))});\n`;
    const close = src.indexOf('%>', open + 2);
    if (close === -1) throw new Error(`unclosed <% tag at offset ${open}`);

    let tag = src.slice(open + 2, close);
    let kind = '';
    if (['=', '-', '#', '_'].includes(tag[0])) {
      kind = tag[0];
      tag = tag.slice(1);
    }
    if (tag.endsWith('-') || tag.endsWith('_')) tag = tag.slice(0, -1);

    if (kind === '#') {
      /* comment, nothing to emit */
    } else if (kind === '=' || kind === '-') {
      out += `__o.push(${tag.trim() === '' ? '""' : `(${tag})`});\n`;
    } else {
      out += `${tag}\n`;
    }
    i = close + 2;
  }
  out += '} return __o.join(""); }';
  return out;
}

function check(file, fn) {
  checked += 1;
  try {
    fn();
  } catch (err) {
    failures += 1;
    console.error(`FAIL ${path.relative(process.cwd(), file)}\n     ${err.message}\n`);
  }
}

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
    } else if (entry.name.endsWith('.js')) {
      check(full, () => new vm.Script(fs.readFileSync(full, 'utf8'), { filename: full }));
    } else if (entry.name.endsWith('.ejs')) {
      ejsFiles.push(full);
      check(full, () => {
        const src = fs.readFileSync(full, 'utf8');
        if (ejs) ejs.compile(src, { filename: full });
        else new vm.Script(ejsToJs(src), { filename: full });
      });
    }
  }
}

walk(root);

// Every include target must exist, whichever compiler was used.
for (const file of ejsFiles) {
  const src = fs.readFileSync(file, 'utf8');
  const re = /include\(\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(src))) {
    const target = path.resolve(
      path.dirname(file),
      m[1].endsWith('.ejs') ? m[1] : `${m[1]}.ejs`
    );
    if (!fs.existsSync(target)) {
      failures += 1;
      console.error(`FAIL ${path.relative(process.cwd(), file)}\n     missing include: ${m[1]}\n`);
    }
  }
}

// Every res.render() target must exist as a view.
const viewNames = new Set(
  fs
    .readdirSync(path.join(root, 'views'))
    .filter((f) => f.endsWith('.ejs'))
    .map((f) => f.slice(0, -4))
);
for (const file of fs.readdirSync(path.join(root, 'routes'))) {
  const src = fs.readFileSync(path.join(root, 'routes', file), 'utf8');
  const re = /res\.(?:status\(\d+\)\.)?render\(\s*['"]([\w-]+)['"]/g;
  let m;
  while ((m = re.exec(src))) {
    if (!viewNames.has(m[1])) {
      failures += 1;
      console.error(`FAIL routes/${file}\n     renders a missing view: ${m[1]}\n`);
    }
  }
}

if (failures) {
  console.error(`${failures} problem(s) across ${checked} files.`);
  process.exit(1);
}
console.log(
  `All ${checked} files parsed cleanly${ejs ? '' : ' (built-in EJS parser; install deps for the real one)'}.`
);
