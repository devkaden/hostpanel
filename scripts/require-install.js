'use strict';

/**
 * Guard for scripts that touch the live panel.
 *
 * These have to run from the installed copy, not from a git checkout: the
 * dependencies are installed there, and more importantly the database, the
 * .env and the sites all belong to that directory. Running from a checkout
 * fails on a missing module, which is a stack trace about `better-sqlite3`
 * rather than the actual mistake - and the actual mistake is easy to make,
 * because a checkout is exactly where you are standing right after a git pull.
 *
 * Call this before requiring anything from ../src.
 */

const fs = require('fs');
const path = require('path');

const APP_DIR = path.join(__dirname, '..');
const INSTALL_DIR = process.env.HOSTPANEL_APP_DIR || '/opt/hostpanel/app';

module.exports = function requireInstall(scriptName) {
  if (fs.existsSync(path.join(APP_DIR, 'node_modules', 'better-sqlite3'))) return;

  const installed = fs.existsSync(path.join(INSTALL_DIR, 'node_modules', 'better-sqlite3'));
  const here = path.resolve(APP_DIR);

  const lines = [
    '',
    `  This is the source checkout at ${here}, which has no dependencies`,
    '  installed and is not the copy the panel actually runs.',
    '',
  ];

  if (installed && path.resolve(INSTALL_DIR) !== here) {
    lines.push('  Run it from the installed copy instead:', '');
    lines.push(`    cd ${INSTALL_DIR} && npm run ${scriptName}`, '');
  } else {
    lines.push('  Install the panel first:', '', '    sudo ./install.sh', '');
  }

  process.stderr.write(lines.join('\n'));
  process.exit(1);
};
