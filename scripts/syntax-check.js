#!/usr/bin/env node
'use strict';

/**
 * Parses every .js and .ejs file in src/ without executing it, so a typo is
 * caught before the service restarts. Run with: npm run check
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ejs = require('ejs');

const root = path.join(__dirname, '..', 'src');
let failures = 0;
let checked = 0;

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue;
      walk(full);
    } else if (entry.name.endsWith('.js')) {
      check(full, () => new vm.Script(fs.readFileSync(full, 'utf8'), { filename: full }));
    } else if (entry.name.endsWith('.ejs')) {
      check(full, () => ejs.compile(fs.readFileSync(full, 'utf8'), { filename: full }));
    }
  }
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

walk(root);

if (failures) {
  console.error(`${failures} of ${checked} files failed to parse.`);
  process.exit(1);
}
console.log(`All ${checked} files parsed cleanly.`);
