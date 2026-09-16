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
// The helper scripts ship too, and a broken one is only discovered when
// someone runs it at the exact moment they need it to work.
walk(__dirname);

/**
 * The body of every inline <script> in a document, found by scanning.
 *
 * Deliberately not a regular expression. Every regex for "an HTML tag" is
 * wrong in some case - an attribute value containing ">", a closing tag
 * written "</script >", a mixture of cases - and each of those made this
 * checker skip a block in silence, which for a syntax checker means the same
 * thing as passing. Scanning with indexOf has none of those edges: find the
 * next "<script", the ">" that ends the opening tag, then the next "</script".
 *
 * Scripts with a src attribute are skipped, since their body is elsewhere.
 */
function scriptBlocks(src) {
  const lower = src.toLowerCase();
  const out = [];
  let at = 0;

  for (;;) {
    const open = lower.indexOf('<script', at);
    if (open === -1) break;

    const openEnd = lower.indexOf('>', open);
    if (openEnd === -1) break;

    const close = lower.indexOf('</script', openEnd);
    if (close === -1) break;

    // A space or quote before src=, so that data-src= does not count as one.
    const openTag = lower.slice(open, openEnd + 1);
    const hasSrc = [' src=', ' src =', '"src=', "'src="].some((f) => openTag.includes(f));
    if (!hasSrc) out.push(src.slice(openEnd + 1, close));

    const closeEnd = lower.indexOf('>', close);
    at = closeEnd === -1 ? close + 8 : closeEnd + 1;
  }
  return out;
}

/*
 * The JavaScript inside a template's <script> blocks is opaque to the EJS
 * compiler - it is just text. That leaves hundreds of lines unchecked, so
 * parse them here with the EJS tags stubbed out.
 */
let inlineScripts = 0;

for (const file of ejsFiles) {
  const src = fs.readFileSync(file, 'utf8');
  const blocks = scriptBlocks(src);

  inlineScripts += blocks.length;

  blocks.forEach((block, index) => {
    const body = block
      // Output tags become a literal; control tags carry JS that stays.
      .replace(/<%[-=]\s*([\s\S]*?)\s*-?%>/g, '0')
      .replace(/<%_?\s*([\s\S]*?)\s*_?%>/g, '$1');

    checked += 1;
    try {
      new vm.Script(body, { filename: `${file} <script #${index + 1}>` });
    } catch (err) {
      failures += 1;
      console.error(
        `FAIL ${path.relative(process.cwd(), file)} (inline script #${index + 1})\n     ${err.message}\n`
      );
    }
  });
}

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

/*
 * A checker that quietly stopped finding anything reports success, which is
 * the worst possible failure mode for a checker. The views have inline scripts
 * in them; if none were found, the scanner is broken.
 */
if (ejsFiles.length && inlineScripts === 0) {
  console.error('FAIL no inline <script> blocks were found in any view - the scanner is broken.\n');
  failures += 1;
}

if (failures) {
  console.error(`${failures} problem(s) across ${checked} files.`);
  process.exit(1);
}
console.log(
  `All ${checked} files parsed cleanly, including ${inlineScripts} inline scripts` +
    `${ejs ? '' : ' (built-in EJS parser; install deps for the real one)'}.`
);
