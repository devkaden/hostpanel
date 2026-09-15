'use strict';

const parser = require('cron-parser');
const { db } = require('./db');
const docker = require('./docker');
const tpl = require('./site-templates');

const TICK_MS = 30 * 1000;
const nextRuns = new Map(); // jobId -> epoch ms
let timer = null;
let running = new Set();

function validateSchedule(expr) {
  try {
    parser.parseExpression(String(expr || '').trim());
    return null;
  } catch (err) {
    return err.message || 'Invalid cron expression';
  }
}

function describeSchedule(expr) {
  try {
    const it = parser.parseExpression(String(expr).trim());
    return it.next().toDate();
  } catch (_) {
    return null;
  }
}

function listJobs(siteId) {
  const rows = db
    .prepare('SELECT * FROM cron_jobs WHERE site_id = ? ORDER BY id')
    .all(siteId);
  return rows.map((row) => ({
    ...row,
    next_run: nextRuns.has(row.id) ? new Date(nextRuns.get(row.id)).toISOString() : null,
    next_run_calc: row.enabled ? describeSchedule(row.schedule) : null,
  }));
}

function getJob(id) {
  return db.prepare('SELECT * FROM cron_jobs WHERE id = ?').get(id);
}

function createJob(siteId, { name, schedule, command, enabled = 1 }) {
  const scheduleError = validateSchedule(schedule);
  if (scheduleError) throw new Error(`Invalid schedule: ${scheduleError}`);
  if (!String(command || '').trim()) throw new Error('A command is required');
  const info = db
    .prepare(
      'INSERT INTO cron_jobs (site_id, name, schedule, command, enabled) VALUES (?,?,?,?,?)'
    )
    .run(
      siteId,
      String(name || 'Job').trim().slice(0, 80),
      String(schedule).trim(),
      String(command).trim(),
      enabled ? 1 : 0
    );
  scheduleNext(info.lastInsertRowid);
  return getJob(info.lastInsertRowid);
}

function updateJob(id, { name, schedule, command, enabled }) {
  const job = getJob(id);
  if (!job) throw new Error('Job not found');
  if (schedule !== undefined) {
    const scheduleError = validateSchedule(schedule);
    if (scheduleError) throw new Error(`Invalid schedule: ${scheduleError}`);
  }
  db.prepare(
    'UPDATE cron_jobs SET name = ?, schedule = ?, command = ?, enabled = ? WHERE id = ?'
  ).run(
    name !== undefined ? String(name).trim().slice(0, 80) : job.name,
    schedule !== undefined ? String(schedule).trim() : job.schedule,
    command !== undefined ? String(command).trim() : job.command,
    enabled !== undefined ? (enabled ? 1 : 0) : job.enabled,
    id
  );
  scheduleNext(id);
  return getJob(id);
}

function deleteJob(id) {
  db.prepare('DELETE FROM cron_jobs WHERE id = ?').run(id);
  nextRuns.delete(id);
  return true;
}

function scheduleNext(jobId, from = new Date()) {
  const job = getJob(jobId);
  if (!job || !job.enabled) {
    nextRuns.delete(jobId);
    return null;
  }
  try {
    const it = parser.parseExpression(job.schedule, { currentDate: from });
    const next = it.next().getTime();
    nextRuns.set(jobId, next);
    return next;
  } catch (_) {
    nextRuns.delete(jobId);
    return null;
  }
}

async function runJob(jobId, { manual = false } = {}) {
  if (running.has(jobId)) {
    return { skipped: true, reason: 'Job is already running' };
  }
  const job = getJob(jobId);
  if (!job) throw new Error('Job not found');
  const site = db.prepare('SELECT * FROM sites WHERE id = ?').get(job.site_id);
  if (!site) throw new Error('Site not found');

  running.add(jobId);
  const started = Date.now();
  let exitCode = -1;
  let output = '';

  try {
    const containerName = tpl.containerName(site);
    const state = await docker.containerState(containerName);
    if (state !== 'running') {
      exitCode = -1;
      output = `Container is ${state}; the job was not run.`;
    } else {
      const workdir = site.type === 'node' ? '/app' : site.type === 'static' ? '/usr/share/nginx/html' : '/var/www/html';
      const user = site.type === 'php' || site.type === 'wordpress' ? 'www-data' : undefined;
      const res = await docker.exec(containerName, ['sh', '-lc', job.command], { workdir, user });
      exitCode = res.exitCode;
      output = res.output;
    }
  } catch (err) {
    exitCode = -1;
    output = `Error: ${err.message}`;
  } finally {
    running.delete(jobId);
  }

  const duration = Math.round((Date.now() - started) / 100) / 10;
  const stored = `[${new Date().toISOString()}] ${manual ? 'manual run' : 'scheduled run'} - exit ${exitCode} in ${duration}s\n${output}`;
  db.prepare(
    "UPDATE cron_jobs SET last_run = datetime('now'), last_exit = ?, last_output = ? WHERE id = ?"
  ).run(exitCode, stored.slice(-16000), jobId);

  if (!manual) scheduleNext(jobId);
  return { exitCode, output, duration };
}

async function tick() {
  const now = Date.now();
  const jobs = db.prepare('SELECT id FROM cron_jobs WHERE enabled = 1').all();
  for (const { id } of jobs) {
    if (!nextRuns.has(id)) {
      scheduleNext(id);
      continue;
    }
    if (nextRuns.get(id) <= now) {
      nextRuns.delete(id);
      runJob(id).catch((err) => console.error(`[cron] job ${id} failed:`, err.message));
    }
  }
  // Drop schedules for jobs that no longer exist or were disabled.
  const live = new Set(jobs.map((j) => j.id));
  for (const id of [...nextRuns.keys()]) {
    if (!live.has(id)) nextRuns.delete(id);
  }
}

function start() {
  if (timer) return;
  for (const { id } of db.prepare('SELECT id FROM cron_jobs WHERE enabled = 1').all()) {
    scheduleNext(id);
  }
  timer = setInterval(() => {
    tick().catch((err) => console.error('[cron] tick failed:', err.message));
  }, TICK_MS);
  if (timer.unref) timer.unref();
  console.log('[cron] scheduler started');
}

function stop() {
  if (timer) clearInterval(timer);
  timer = null;
}

module.exports = {
  start,
  stop,
  listJobs,
  getJob,
  createJob,
  updateJob,
  deleteJob,
  runJob,
  validateSchedule,
  describeSchedule,
};
