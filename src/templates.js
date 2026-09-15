'use strict';

/**
 * Site presets. A template stores the parts of a site's configuration that are
 * worth reusing - never its name, domain, port or database credentials, which
 * must be unique per site.
 */

const { db } = require('./db');

const REUSABLE_FIELDS = [
  'type',
  'runtime_version',
  'install_command',
  'start_command',
  'app_port',
  'env_json',
  'memory_mb',
  'cpu_limit',
  'custom_image',
  'extra_volumes',
  'extra_labels',
  'docker_network',
];

function list() {
  return db.prepare('SELECT * FROM templates ORDER BY name').all();
}

function get(id) {
  return db.prepare('SELECT * FROM templates WHERE id = ?').get(id);
}

/** The reusable slice of a site, as a plain object. */
function configFromSite(site) {
  const config = {};
  for (const field of REUSABLE_FIELDS) {
    if (site[field] !== undefined && site[field] !== null) config[field] = site[field];
  }
  return config;
}

function createFromSite(site, { name, description }, userId) {
  const clean = String(name || '').trim();
  if (!clean) throw new Error('Give the preset a name.');
  if (clean.length > 60) throw new Error('That name is too long.');
  if (db.prepare('SELECT id FROM templates WHERE lower(name) = lower(?)').get(clean)) {
    throw new Error(`A preset called "${clean}" already exists.`);
  }

  const info = db
    .prepare(
      'INSERT INTO templates (name, description, type, config_json, created_by) VALUES (?,?,?,?,?)'
    )
    .run(
      clean,
      String(description || '').trim().slice(0, 200),
      site.type,
      JSON.stringify(configFromSite(site)),
      userId || null
    );
  return get(info.lastInsertRowid);
}

function remove(id) {
  db.prepare('DELETE FROM templates WHERE id = ?').run(id);
  return true;
}

/** Merges a template's stored config into new-site form input. */
function applyTo(input, templateId) {
  const template = get(parseInt(templateId, 10));
  if (!template) return input;

  let config = {};
  try {
    config = JSON.parse(template.config_json || '{}');
  } catch (_) {
    config = {};
  }

  const merged = { ...input };
  for (const [key, value] of Object.entries(config)) {
    // Anything the user actually typed wins over the preset.
    const supplied = merged[key];
    const isBlank = supplied === undefined || supplied === null || String(supplied).trim() === '';
    if (isBlank) merged[key] = value;
  }
  // The preset decides the type unless the form chose one explicitly.
  if (!String(input.type || '').trim()) merged.type = template.type;
  return merged;
}

module.exports = { list, get, createFromSite, remove, applyTo, configFromSite, REUSABLE_FIELDS };
