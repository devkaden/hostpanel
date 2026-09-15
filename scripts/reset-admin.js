#!/usr/bin/env node
'use strict';

/**
 * Emergency access recovery. Run on the panel host:
 *
 *   cd /opt/hostpanel/app && npm run reset-admin            # resets "admin"
 *   cd /opt/hostpanel/app && npm run reset-admin -- kaden   # resets that user
 *
 * Prints a new random password and forces a change at next login. If the named
 * user does not exist it is created as an administrator.
 */

const { db } = require('../src/db');
const auth = require('../src/auth');

const username = process.argv[2] || 'admin';
const password = auth.randomPassword();
const hash = auth.hashPassword(password);

const existing = auth.findUserByUsername(username);

if (existing) {
  db.prepare(
    "UPDATE users SET password_hash = ?, must_change_pw = 1, active = 1, role = 'admin' WHERE id = ?"
  ).run(hash, existing.id);
  console.log(`Reset ${username} (promoted to administrator and re-enabled).`);
} else {
  db.prepare(
    "INSERT INTO users (username, password_hash, role, must_change_pw) VALUES (?,?,'admin',1)"
  ).run(username, hash);
  console.log(`Created administrator ${username}.`);
}

// Drop every live session so the old credentials stop working immediately.
db.prepare('DELETE FROM sessions').run();

console.log(`\n  username: ${username}`);
console.log(`  password: ${password}\n`);
console.log('You will be asked to change this at first login.');
