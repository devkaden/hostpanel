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

/* ------------------------------------------------- state in the header -- */
console.log('\nwhere the live state is shown');
{
  const tabs = read('src/views/partials/site-tabs.ejs');
  const status = read('src/views/partials/site-status.ejs');
  const css = read('src/public/css/app.css');

  check('the tab bar no longer carries the status reading',
    !/data-state-pill/.test(tabs),
    'a reading sitting among Start/Stop/Restart reads as one more button');
  check('the status partial has the pill and the uptime', /data-state-pill/.test(status) && /data-state-detail/.test(status));
  for (const view of ['site', 'files', 'logs', 'cron']) {
    check(`${view} shows it beside the site name`,
      new RegExp('page-title-row[\\s\\S]{0,300}site-status').test(read(`src/views/${view}.ejs`)));
  }
  check('the host shell, which has no site, does not',
    /!isHostShell[\s\S]{0,80}site-status/.test(read('src/views/terminal.ejs')));
  check('.page-title-row is styled', css.includes('.page-title-row'));

  const js = read('src/public/js/app.js');
  check('the poll writes to the header element, not inside the button bar',
    /document\.querySelector\('\[data-site-status\]'\)/.test(js));
}

/* ------------------------------------------------------- capitalisation - */
console.log('\ncapitalisation');
{
  const css = read('src/public/css/app.css');
  check('state pills are capitalised in one place',
    /\.pill \{[\s\S]{0,400}text-transform: capitalize/.test(css),
    'Docker reports "running"; the panel shows "Running"');

  // Headings, buttons and field labels start with a capital.
  const bad = [];
  for (const file of everyView()) {
    const src = fs.readFileSync(file, 'utf8');
    const patterns = [
      /<h[123]\b[^>]*>\s*([a-z][a-zA-Z ]{2,40})</g,
      /<label\b[^>]*>\s*([a-z][a-zA-Z ]{2,40})</g,
      /<th\b[^>]*>\s*([a-z][a-zA-Z ]{2,40})</g,
      /<dt>\s*([a-z][a-zA-Z ]{2,40})</g,
    ];
    for (const re of patterns) {
      for (const m of src.matchAll(re)) bad.push(`${path.basename(file)}: "${m[1].trim()}"`);
    }
  }
  check('no heading, label, column or field name starts lower case',
    bad.length === 0, bad.join('\n        '));
}

/* ------------------------------------------------ proxy check and fix --- */
console.log('\nchecking and fixing proxy hosts');
{
  const site = read('src/views/site.ejs');
  const settings = read('src/views/settings.ejs');
  const routes = read('src/routes/sites.js');
  const settingsRoutes = read('src/routes/settings.js');

  check('the site page has a Check & Fix button', /id="proxy-repair"/.test(site));
  check('it reports what changed rather than just reloading',
    /Proxy host repaired/.test(site));
  check('the framing choice is a per-site checkbox', /id="allow_framing"/.test(site));
  check('and it says the preview does not need it',
    /does not need it - that is served back through the panel/.test(site));
  check('problems found are listed on the page', /proxyIssues/.test(site));

  check('there is a repair route', /'\/sites\/:id\/proxy\/repair'/.test(routes));
  check('and a read-only check route', /'\/api\/sites\/:id\/proxy\/check'/.test(routes));
  check('both are behind the site access check',
    (routes.match(/proxy\/(repair|check)'[\s\S]{0,60}loadSite/g) || []).length === 2);

  check('settings can check every site at once', /'\/api\/npmplus\/check-all'/.test(settingsRoutes));
  check('and that is administrators only',
    /'\/api\/npmplus\/check-all',\s*\n\s*auth\.requireAdmin/.test(settingsRoutes));
  check('one site failing does not stop the rest',
    /catch \(err\)[\s\S]{0,300}results\.push/.test(settingsRoutes));
  check('the settings page has both buttons',
    /id="proxy-check-all"/.test(settings) && /id="proxy-fix-all"/.test(settings));
  check('fixing them all asks first', /HP\.confirm\([\s\S]{0,200}Fix every proxy host/.test(settings));

  // The framing checkbox posts one field to the settings endpoint. Every field
  // that form owns has to read "absent" as unchanged, or saving one thing
  // erases the rest - and a cleared domain is not obvious until the site stops
  // answering.
  check('a partial settings save cannot clear the domain',
    /body\.domain !== undefined \? body\.domain : site\.domain/.test(routes),
    'body.domain || "" would delete it');
  check('nor the extra domains',
    /body\.extra_domains !== undefined \? body\.extra_domains : site\.extra_domains/.test(routes));

  check('changing the port or domain fixes the proxy without being asked',
    /const moved =[\s\S]{0,400}npmplus\.repairProxy/.test(routes));
  check('but only a proxy host the panel already owns',
    /moved && site\.npm_proxy_id && npmplus\.isEnabled\(\)/.test(routes),
    'adopting someone else\'s host is a decision, not a side effect');
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
