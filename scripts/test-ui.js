#!/usr/bin/env node
'use strict';
/*
 * Invariants for the interface itself.
 *
 * None of this needs a browser, and all of it is the kind of mistake that a
 * page renders happily around: an icon name with a typo renders nothing at
 * all, a card class that was renamed in the markup but not the stylesheet
 * gives an unstyled block, and a search box wired to attributes that are no
 * longer written filters everything away.
 *
 * Run with: npm run test:ui
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

let pass = 0;
let fail = 0;
function check(name, cond, detail) {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`); }
}

const viewsDir = path.join(ROOT, 'src', 'views');
function everyView() {
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.ejs')) out.push(full);
    }
  };
  walk(viewsDir);
  return out;
}

/* ------------------------------------------------------------- icons ---- */
console.log('\nevery icon a view asks for exists');
{
  const { PATHS } = require('../src/icons');
  const missing = [];
  for (const file of everyView()) {
    const src = fs.readFileSync(file, 'utf8');
    // icon('name') and icon('name', 'extra'), but not icon(variable).
    for (const match of src.matchAll(/\bicon\(\s*'([a-zA-Z0-9_]+)'/g)) {
      if (!PATHS[match[1]]) missing.push(`${path.basename(file)}: ${match[1]}`);
    }
  }
  check('no view names an icon that does not exist', missing.length === 0, missing.join('\n        '));
  check('the icon set is not empty', Object.keys(PATHS).length > 20);
}

/* --------------------------------------------------------------- nav ---- */
console.log('\nthe top bar');
{
  const nav = read('src/views/partials/nav.ejs');
  // Creating a site belongs on the page listing sites, not beside the account
  // menu where it competes with navigation.
  check('there is no New Site button in the top bar', !/\/sites\/new/.test(nav));
  check('the security badge links to the security page', /href="\/security"/.test(nav));
  check('and only administrators see it',
    /u\.role === 'admin'[\s\S]{0,400}alert-bell/.test(nav));
  check('a missing alert count cannot break the render',
    /typeof alertCount !== 'undefined'/.test(nav),
    'the error page renders before the per-request locals are set');

  const dashboard = read('src/views/dashboard.ejs');
  check('the Sites page still has its own New Site button', /href="\/sites\/new"/.test(dashboard));
}

/* -------------------------------------------------------- site search --- */
console.log('\nsearching the site list');
{
  const dashboard = read('src/views/dashboard.ejs');
  check('there is a search box', /id="site-search"/.test(dashboard));
  check('every card carries the text it is matched against',
    // Not [^>]* - an EJS tag inside the attribute list contains ">".
    /<article class="site-card"[\s\S]{0,120}?data-search="/.test(dashboard));
  check('the haystack is lower-cased when it is built',
    /haystack[\s\S]{0,120}toLowerCase\(\)/.test(dashboard),
    'the query is lower-cased, so the haystack has to be too or nothing matches');
  check('the haystack covers name, type, owner, port and domains',
    /haystack = \[s\.name, typeLabel, s\.owner_name, s\.port\]\.concat\(s\.domains\)/.test(dashboard));
  check('there is something to show when nothing matches',
    /id="site-search-empty"/.test(dashboard));
  check('"/" focuses the box', /e\.key !== '\/'/.test(dashboard));
  check('and it is ignored while typing in another field',
    /tag === 'INPUT' \|\| tag === 'TEXTAREA'/.test(dashboard));
}

/* --------------------------------------------------------- site cards --- */
console.log('\nthe site cards');
{
  const dashboard = read('src/views/dashboard.ejs');
  const css = read('src/public/css/app.css');

  for (const cls of ['site-card-head', 'site-card-name', 'site-card-domain',
    'site-card-facts', 'site-card-links', 'site-search']) {
    check(`.${cls} is styled`, css.includes(`.${cls}`), 'markup class with no stylesheet rule');
  }

  check('the card no longer stacks two grey meta rows',
    !/class="meta"/.test(dashboard),
    'they gave a port number the same weight as the domain');
  check('the live status pill is still there', /data-state/.test(dashboard));
  check('the card links are down to three',
    (dashboard.match(/class="site-card-links"[\s\S]*?<\/div>/) || [''])[0]
      .split('<a ').length - 1 === 3,
    'Shell and Cron are one click further in, on the site page itself');
  check('port and owner only show in advanced mode',
    /<span class="adv">Port/.test(dashboard) && /class="adv"><%= s\.owner_name/.test(dashboard));
  check('a hidden card is actually hidden', /\.site-card\[hidden\] \{ display: none/.test(css),
    'display:flex beats the hidden attribute unless this rule exists');
}

/* ----------------------------------------------------- security page ---- */
console.log('\nthe security page');
{
  const view = read('src/views/security.ejs');
  check('it lists alerts', /alert-row/.test(view));
  check('clearing an alert is a POST with a CSRF token',
    /action="\/security\/acknowledge"[\s\S]{0,200}name="_csrf"/.test(view));
  check('there is a clear-all', /value="all"/.test(view));
  check('cleared alerts can still be looked at', /showAll/.test(view));
  check('it says when two-factor is optional', /Two-factor authentication is optional/.test(view));
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
