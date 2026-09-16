'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const express = require('express');
const multer = require('multer');

const config = require('../config');
const { audit } = require('../db');
const fm = require('../filemanager');
const sites = require('../sites');
const { loadSite, wrap } = require('../middleware');

const router = express.Router();

// The browser uploads in batches, so one request never carries a huge number
// of files. The ceiling here is generous enough that a batch never trips it.
const MAX_FILES_PER_REQUEST = 200;

const upload = multer({
  dest: config.tmpDir,
  limits: {
    fileSize: config.maxUploadBytes,
    files: MAX_FILES_PER_REQUEST,
    // relpaths is one JSON string listing every file in the batch.
    fieldSize: 2 * 1024 * 1024,
    parts: MAX_FILES_PER_REQUEST + 20,
  },
});

/**
 * Turns multer and busboy failures into something a person can act on.
 *
 * When a limit is hit, multer tears down the request stream while the browser
 * is still sending, and busboy then reports "Unexpected end of form" - which
 * says nothing about the actual cause. These messages name it.
 */
function uploadFiles(req, res, next) {
  upload.array('files', MAX_FILES_PER_REQUEST)(req, res, (err) => {
    if (!err) return next();

    const mb = Math.round(config.maxUploadBytes / 1024 / 1024);
    const messages = {
      LIMIT_FILE_SIZE: `That file is larger than the ${mb} MB limit. Raise MAX_UPLOAD_MB in .env if you need more.`,
      LIMIT_FILE_COUNT: `Too many files in one request (the limit is ${MAX_FILES_PER_REQUEST}). Upload in smaller batches.`,
      LIMIT_PART_COUNT: 'Too many parts in one request. Upload in smaller batches.',
      LIMIT_FIELD_VALUE: 'The upload metadata was too large. Upload in smaller batches.',
      LIMIT_UNEXPECTED_FILE: 'The upload contained an unexpected field.',
    };

    if (err.code && messages[err.code]) {
      return res.status(413).json({ error: messages[err.code], code: err.code });
    }
    if (/unexpected end of form/i.test(err.message || '')) {
      return res.status(400).json({
        error:
          'The upload was cut off before it finished. This usually means the browser ' +
          'stopped sending - try fewer files at once, or check the connection.',
        code: 'UPLOAD_TRUNCATED',
      });
    }
    return next(err);
  });
}

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

router.post(
  '/api/sites/:id/files/upload',
  loadSite,
  uploadFiles,
  wrap(async (req, res) => {
    const dest = String(req.body.path || '');
    // A dropped folder sends one relative path per file, in the same order.
    let relPaths = req.body.relpaths;
    if (typeof relPaths === 'string') {
      try {
        relPaths = JSON.parse(relPaths);
      } catch (_) {
        relPaths = null;
      }
    }

    const saved = [];
    const failed = [];
    const files = req.files || [];

    for (let i = 0; i < files.length; i += 1) {
      const file = files[i];
      const relative = Array.isArray(relPaths) && relPaths[i] ? relPaths[i] : file.originalname;
      try {
        await fm.saveUploadNested(req.site, dest, relative, file.path);
        saved.push(relative);
      } catch (err) {
        failed.push({ name: relative, error: err.message });
        await fsp.unlink(file.path).catch(() => {});
      }
    }

    audit(req, 'files.upload', req.site.name, saved.join(', ').slice(0, 500));
    res.json({ ok: true, saved, failed });
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
