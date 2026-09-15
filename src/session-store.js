'use strict';

/**
 * Minimal express-session store backed by the same better-sqlite3 handle the
 * rest of the panel uses, so we don't pull in a second native sqlite driver.
 */
const session = require('express-session');
const { db } = require('./db');

class SqliteStore extends session.Store {
  constructor(options = {}) {
    super(options);
    this.ttlMs = options.ttlMs || 12 * 60 * 60 * 1000;
    this.get_ = db.prepare('SELECT data, expires FROM sessions WHERE sid = ?');
    this.set_ = db.prepare(
      'INSERT INTO sessions (sid, expires, data) VALUES (?,?,?) ' +
        'ON CONFLICT(sid) DO UPDATE SET expires = excluded.expires, data = excluded.data'
    );
    this.del_ = db.prepare('DELETE FROM sessions WHERE sid = ?');
    this.touch_ = db.prepare('UPDATE sessions SET expires = ? WHERE sid = ?');
    this.reap_ = db.prepare('DELETE FROM sessions WHERE expires < ?');

    this.reaper = setInterval(() => {
      try {
        this.reap_.run(Date.now());
      } catch (_) {
        /* ignore */
      }
    }, 10 * 60 * 1000);
    if (this.reaper.unref) this.reaper.unref();
  }

  expiryFor(sess) {
    if (sess && sess.cookie && sess.cookie.expires) {
      return new Date(sess.cookie.expires).getTime();
    }
    return Date.now() + this.ttlMs;
  }

  get(sid, cb) {
    try {
      const row = this.get_.get(sid);
      if (!row) return cb(null, null);
      if (row.expires < Date.now()) {
        this.del_.run(sid);
        return cb(null, null);
      }
      return cb(null, JSON.parse(row.data));
    } catch (err) {
      return cb(err);
    }
  }

  set(sid, sess, cb) {
    try {
      this.set_.run(sid, this.expiryFor(sess), JSON.stringify(sess));
      return cb && cb(null);
    } catch (err) {
      return cb && cb(err);
    }
  }

  destroy(sid, cb) {
    try {
      this.del_.run(sid);
      return cb && cb(null);
    } catch (err) {
      return cb && cb(err);
    }
  }

  touch(sid, sess, cb) {
    try {
      this.touch_.run(this.expiryFor(sess), sid);
      return cb && cb(null);
    } catch (err) {
      return cb && cb(err);
    }
  }

  destroyForUser(userId) {
    return destroySessionsForUser(userId);
  }
}

/**
 * Kills every stored session belonging to one user, leaving everyone else
 * signed in. Exported standalone so routes do not need the store instance.
 */
function destroySessionsForUser(userId) {
  const del = db.prepare('DELETE FROM sessions WHERE sid = ?');
  let removed = 0;
  for (const row of db.prepare('SELECT sid, data FROM sessions').all()) {
    try {
      const parsed = JSON.parse(row.data);
      if (parsed && parsed.user && parsed.user.id === userId) {
        del.run(row.sid);
        removed += 1;
      }
    } catch (_) {
      /* ignore malformed rows */
    }
  }
  return removed;
}

module.exports = SqliteStore;
module.exports.destroySessionsForUser = destroySessionsForUser;
