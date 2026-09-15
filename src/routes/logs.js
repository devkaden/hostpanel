'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const express = require('express');

const docker = require('../docker');
const sites = require('../sites');
const tpl = require('../site-templates');
const { loadSite, wrap } = require('../middleware');

const router = express.Router();

/** Which log sources exist for a given site type. */
function sourcesFor(site) {
  const list = [{ id: 'container', label: 'Container output (stdout/stderr)' }];
  if (site.type === 'static') {
    list.push({ id: 'access.log', label: 'nginx access log' });
    list.push({ id: 'error.log', label: 'nginx error log' });
  }
  if (site.type === 'php' || site.type === 'wordpress') {
    list.push({ id: 'access.log', label: 'Apache access log' });
    list.push({ id: 'error.log', label: 'Apache error log' });
    list.push({ id: 'other_vhosts_access.log', label: 'Apache vhost access log' });
  }
  if (site.type === 'wordpress') {
    list.push({ id: 'database', label: 'Database container output' });
  }
  list.push({ id: 'provision', label: 'Provisioning / build output' });
  return list;
}

router.get(
  '/sites/:id/logs',
  loadSite,
  wrap(async (req, res) => {
    res.render('logs', {
      title: `${req.site.name} - logs`,
      site: req.site,
      sources: sourcesFor(req.site),
      selected: req.query.source || 'container',
    });
  })
);

router.get(
  '/api/sites/:id/logs',
  loadSite,
  wrap(async (req, res) => {
    const source = String(req.query.source || 'container');
    const tail = Math.min(parseInt(req.query.tail || '400', 10) || 400, 5000);
    const site = req.site;

    if (source === 'container') {
      return res.json({ text: await docker.logs(tpl.containerName(site), { tail }) });
    }
    if (source === 'database') {
      if (site.type !== 'wordpress') return res.status(400).json({ error: 'No database container' });
      return res.json({ text: await docker.logs(tpl.dbContainerName(site), { tail }) });
    }
    if (source === 'provision') {
      const lines = sites
        .getProgress(site.id)
        .map((l) => `[${new Date(l.at).toLocaleTimeString()}] ${l.line}`);
      return res.json({ text: lines.join('\n') || '(no provisioning output recorded)' });
    }

    // File-backed log inside the site's logs directory.
    if (!/^[a-z0-9_.-]+\.log$/i.test(source)) {
      return res.status(400).json({ error: 'Unknown log source' });
    }
    const file = path.join(sites.siteDirs(site).logs, source);
    if (!fs.existsSync(file)) {
      return res.json({ text: `(${source} has not been written yet)` });
    }
    const text = await tailFile(file, tail);
    return res.json({ text });
  })
);

/** Streams new container output over SSE. */
router.get(
  '/sites/:id/logs/stream',
  loadSite,
  wrap(async (req, res) => {
    const source = String(req.query.source || 'container');
    const name =
      source === 'database' ? tpl.dbContainerName(req.site) : tpl.containerName(req.site);

    res.set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.flushHeaders();

    let raw;
    let text;
    try {
      const result = await docker.logStream(name, 100);
      raw = result.stream;
      text = result.text;
    } catch (err) {
      res.write(`event: error\ndata: ${JSON.stringify({ error: err.message })}\n\n`);
      return res.end();
    }

    // Buffer partial lines so a chunk boundary never splits one in the UI.
    let carry = '';
    text.on('data', (chunk) => {
      carry += chunk.toString('utf8');
      const lines = carry.split(/\r?\n/);
      carry = lines.pop();
      for (const line of lines) res.write(`data: ${JSON.stringify(line)}\n\n`);
    });
    text.on('error', () => res.end());
    text.on('end', () => {
      if (carry) res.write(`data: ${JSON.stringify(carry)}\n\n`);
      res.end();
    });

    const heartbeat = setInterval(() => res.write(': ping\n\n'), 20000);
    req.on('close', () => {
      clearInterval(heartbeat);
      try {
        raw.destroy();
      } catch (_) {
        /* ignore */
      }
    });
    return undefined;
  })
);

router.post(
  '/api/sites/:id/logs/clear',
  loadSite,
  wrap(async (req, res) => {
    const source = String(req.body.source || '');
    if (!/^[a-z0-9_.-]+\.log$/i.test(source)) {
      return res.status(400).json({ error: 'Only file-backed logs can be cleared' });
    }
    const file = path.join(sites.siteDirs(req.site).logs, source);
    if (fs.existsSync(file)) await fsp.truncate(file, 0);
    return res.json({ ok: true });
  })
);

/** Reads roughly the last N lines of a file without loading the whole thing. */
async function tailFile(file, lines) {
  const stat = await fsp.stat(file);
  const chunkSize = Math.min(stat.size, Math.max(64 * 1024, lines * 200));
  const start = Math.max(0, stat.size - chunkSize);
  const handle = await fsp.open(file, 'r');
  try {
    const buf = Buffer.alloc(chunkSize);
    await handle.read(buf, 0, chunkSize, start);
    const text = buf.toString('utf8');
    const all = text.split(/\r?\n/);
    if (start > 0) all.shift(); // drop the partial first line
    return all.slice(-lines).join('\n');
  } finally {
    await handle.close();
  }
}

module.exports = router;
