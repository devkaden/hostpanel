'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');
const express = require('express');

const config = require('../config');
const { audit } = require('../db');
const fm = require('../filemanager');
const sites = require('../sites');
const { loadSite, wrap } = require('../middleware');

const router = express.Router();

/* ------------------------------------------------------------------ *
 * File manager page
 * ------------------------------------------------------------------ */
router.get(
  '/sites/:id/files',
  loadSite,
  wrap(async (req, res) => {
    const rel = String(req.query.path || '');
    // A site whose provisioning failed may have no directories yet.
    const dirs = sites.siteDirs(req.site);
    for (const dir of [dirs.root, dirs.app, dirs.logs, dirs.conf]) {
      await fsp.mkdir(dir, { recursive: true }).catch(() => {});
    }
    let listing;
    try {
      listing = await fm.list(req.site, rel);
    } catch (_) {
      listing = await fm.list(req.site, '');
    }
    res.render('files', {
      title: `${req.site.name} - files`,
      site: req.site,
      listing,
      dirs: sites.siteDirs(req.site),
      maxUploadMb: Math.round(config.maxUploadBytes / 1024 / 1024),
    });
  })
);

/* ------------------------------------------------------------------ *
 * JSON API
 * ------------------------------------------------------------------ */
router.get(
  '/api/sites/:id/files',
  loadSite,
  wrap(async (req, res) => {
    res.json(await fm.list(req.site, req.query.path || ''));
  })
);

router.get(
  '/api/sites/:id/files/read',
  loadSite,
  wrap(async (req, res) => {
    res.json(await fm.readFile(req.site, req.query.path || ''));
  })
);

router.post(
  '/api/sites/:id/files/write',
  loadSite,
  wrap(async (req, res) => {
    const { path: rel, content } = req.body;
    if (typeof rel !== 'string' || typeof content !== 'string') {
      return res.status(400).json({ error: 'path and content are required' });
    }
    await fm.writeFile(req.site, rel, content);
    audit(req, 'files.write', req.site.name, rel);
    return res.json({ ok: true });
  })
);

router.post(
  '/api/sites/:id/files/mkdir',
  loadSite,
  wrap(async (req, res) => {
    await fm.mkdir(req.site, req.body.path || '', req.body.name);
    audit(req, 'files.mkdir', req.site.name, `${req.body.path || ''}/${req.body.name}`);
    res.json({ ok: true });
  })
);

router.post(
  '/api/sites/:id/files/touch',
  loadSite,
  wrap(async (req, res) => {
    await fm.createFile(req.site, req.body.path || '', req.body.name);
    audit(req, 'files.create', req.site.name, `${req.body.path || ''}/${req.body.name}`);
    res.json({ ok: true });
  })
);

router.post(
  '/api/sites/:id/files/rename',
  loadSite,
  wrap(async (req, res) => {
    await fm.rename(req.site, req.body.path, req.body.name);
    audit(req, 'files.rename', req.site.name, `${req.body.path} -> ${req.body.name}`);
    res.json({ ok: true });
  })
);

router.post(
  '/api/sites/:id/files/delete',
  loadSite,
  wrap(async (req, res) => {
    const removed = await fm.remove(req.site, req.body.paths || req.body.path);
    audit(req, 'files.delete', req.site.name, removed.join(', ').slice(0, 500));
    res.json({ ok: true, removed });
  })
);

router.post(
  '/api/sites/:id/files/chmod',
  loadSite,
  wrap(async (req, res) => {
    await fm.chmod(req.site, req.body.path, req.body.mode);
    audit(req, 'files.chmod', req.site.name, `${req.body.path} ${req.body.mode}`);
    res.json({ ok: true });
  })
);

router.post(
  '/api/sites/:id/files/extract',
  loadSite,
  wrap(async (req, res) => {
    const count = await fm.extractZip(req.site, req.body.path);
    audit(req, 'files.extract', req.site.name, `${req.body.path} (${count} files)`);
    res.json({ ok: true, files: count });
  })
);

router.post(
  '/api/sites/:id/files/move',
  loadSite,
  wrap(async (req, res) => {
    const moved = await fm.move(req.site, req.body.paths || req.body.path, req.body.to);
    audit(req, 'files.move', req.site.name, moved.map((m) => `${m.from} -> ${m.to}`).join(', ').slice(0, 500));
    res.json({ ok: true, moved });
  })
);

/**
 * Uploads one file as a raw request body.
 *
 * Deliberately not multipart. A multipart parser sat in this path, and any
 * limit it hit tore down the stream mid-flight and surfaced as "Unexpected
 * end of form" - an error that named neither the file nor the cause. A raw
 * PUT has no form to end unexpectedly: the body is the file, the destination
 * is in the query string, and a failure is about one known file.
 */
router.put(
  '/api/sites/:id/files/raw',
  loadSite,
  wrap(async (req, res) => {
    const relative = String(req.query.path || '');
    const destDir = String(req.query.dir || '');

    // Logged on arrival, not only on failure. A successful small upload used to
    // log nothing at all, which made "no log lines" ambiguous: it could mean
    // the request never arrived, or that it sailed through. That ambiguity cost
    // more debugging time than the logging costs.
    const tag = `[upload] ${req.site ? req.site.name : '?'}: ${relative || '(no name)'}`;
    console.log(`${tag} <- start (${req.get('content-length') || 'unknown'} bytes declared)`);

    if (!relative) return res.status(400).json({ error: 'No file name was supplied' });

    const mb = Math.round(config.maxUploadBytes / 1024 / 1024);
    const declared = parseInt(req.get('content-length') || '0', 10);
    if (declared && declared > config.maxUploadBytes) {
      return res.status(413).json({
        error: `"${relative}" is ${Math.round(declared / 1024 / 1024)} MB, over the ${mb} MB limit.`,
      });
    }

    await fsp.mkdir(config.tmpDir, { recursive: true });
    const tmp = path.join(config.tmpDir, `up-${crypto.randomBytes(10).toString('hex')}`);

    let written = 0;
    let tooBig = false;
    let lastChunkAt = Date.now();

    // Counting in a Transform rather than a 'data' listener. Attaching 'data'
    // puts the request into flowing mode, which fights pipe()'s backpressure
    // when the disk is slower than the socket.
    const counter = new Transform({
      transform(chunk, _enc, cb) {
        written += chunk.length;
        lastChunkAt = Date.now();
        if (written > config.maxUploadBytes) {
          tooBig = true;
          return cb(new Error(`"${relative}" is over the ${mb} MB limit.`));
        }
        return cb(null, chunk);
      },
    });

    // A stalled upload must never hold the request open forever: the browser
    // waits on a response that never comes, the socket stays tied up, and
    // later uploads queue behind it against the browser's per-host connection
    // limit.
    //
    // Deliberately NOT req.setTimeout(). That sets the timeout on the *socket*,
    // which outlives this request - with keep-alive the browser reuses the
    // connection, so the timer keeps running against the next upload and the
    // callback still holds a reference to this one. An idle keep-alive
    // connection would then be reported as a file that timed out.
    //
    // This watches the bytes instead, and says what it actually saw, which is
    // the difference between "the upload stalled" and "the browser opened a
    // request and then sent nothing at all".
    const IDLE_MS = 60000;
    const watchdog = setInterval(() => {
      if (Date.now() - lastChunkAt < IDLE_MS) return;
      clearInterval(watchdog);
      req.destroy(
        new Error(
          `no data for ${IDLE_MS / 1000}s - received ${written} of ` +
            `${declared || 'an unknown number of'} bytes`
        )
      );
    }, 5000);
    if (watchdog.unref) watchdog.unref();

    const started = Date.now();
    try {
      await pipeline(req, counter, fs.createWriteStream(tmp));
      await fm.saveUploadNested(req.site, destDir, relative, tmp);

      clearInterval(watchdog);
      const ms = Date.now() - started;
      console.log(`${tag} -> ok, ${written} bytes in ${Math.round(ms / 100) / 10}s`);
      return res.json({ ok: true, path: relative, bytes: written });
    } catch (err) {
      clearInterval(watchdog);
      await fsp.unlink(tmp).catch(() => {});
      const stalled = err.code === 'ECONNRESET' || /timeout|no data|aborted/i.test(err.message || '');
      console.error(
        `${tag} -> FAILED after ${written} of ${declared || '?'} bytes: ${err.message}` +
          (err.code ? ` (${err.code})` : '')
      );
      return res.status(tooBig ? 413 : 400).json({
        error: stalled
          ? `The browser stopped sending "${relative}" after ${written} of ` +
            `${declared || 'an unknown number of'} bytes.`
          : err.message,
        path: relative,
      });
    }
  })
);

router.get(
  '/api/sites/:id/files/download',
  loadSite,
  wrap(async (req, res) => {
    const rel = String(req.query.path || '');
    const { abs } = fm.resolveSafe(req.site, rel);
    const stat = fs.statSync(abs);

    if (stat.isDirectory() || req.query.zip === '1') {
      const zipped = await fm.zipPath(req.site, rel);
      audit(req, 'files.download_zip', req.site.name, rel);
      return res.download(zipped.path, zipped.name, () => {
        fs.unlink(zipped.path, () => {});
      });
    }
    audit(req, 'files.download', req.site.name, rel);
    return res.download(abs, path.basename(abs));
  })
);

module.exports = router;
