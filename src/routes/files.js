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

const upload = multer({
  dest: config.tmpDir,
  limits: { fileSize: config.maxUploadBytes, files: 50 },
});

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
  '/api/sites/:id/files/upload',
  loadSite,
  upload.array('files', 50),
  wrap(async (req, res) => {
    const dest = String(req.body.path || '');
    const saved = [];
    for (const file of req.files || []) {
      await fm.saveUpload(req.site, dest, file.path, file.originalname);
      saved.push(file.originalname);
    }
    audit(req, 'files.upload', req.site.name, saved.join(', ').slice(0, 500));
    res.json({ ok: true, saved });
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
