'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
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
    if (!relative) return res.status(400).json({ error: 'No file name was supplied' });

    const declared = parseInt(req.get('content-length') || '0', 10);
    const mb = Math.round(config.maxUploadBytes / 1024 / 1024);
    if (declared && declared > config.maxUploadBytes) {
      return res.status(413).json({
        error: `"${relative}" is ${Math.round(declared / 1024 / 1024)} MB, over the ${mb} MB limit.`,
      });
    }

    await fsp.mkdir(config.tmpDir, { recursive: true });
    const tmp = path.join(config.tmpDir, `up-${crypto.randomBytes(10).toString('hex')}`);
    const out = fs.createWriteStream(tmp);

    let written = 0;
    let tooBig = false;

    try {
      await new Promise((resolve, reject) => {
        req.on('data', (chunk) => {
          written += chunk.length;
          if (written > config.maxUploadBytes && !tooBig) {
            tooBig = true;
            req.destroy();
            out.destroy();
            reject(new Error(`"${relative}" is over the ${mb} MB limit.`));
          }
        });
        req.on('aborted', () => reject(new Error('The upload was cancelled')));
        req.on('error', reject);
        out.on('error', reject);
        out.on('finish', resolve);
        req.pipe(out);
      });

      await fm.saveUploadNested(req.site, destDir, relative, tmp);
      return res.json({ ok: true, path: relative, bytes: written });
    } catch (err) {
      await fsp.unlink(tmp).catch(() => {});
      return res.status(tooBig ? 413 : 400).json({ error: err.message, path: relative });
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
