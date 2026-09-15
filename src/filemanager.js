'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const AdmZip = require('adm-zip');

const config = require('./config');
const sites = require('./sites');

const TEXT_EXTENSIONS = new Set([
  '.txt', '.md', '.markdown', '.html', '.htm', '.css', '.scss', '.less', '.js', '.mjs', '.cjs',
  '.ts', '.tsx', '.jsx', '.json', '.jsonc', '.xml', '.yml', '.yaml', '.toml', '.ini', '.conf',
  '.cfg', '.env', '.php', '.py', '.rb', '.sh', '.bash', '.sql', '.log', '.csv', '.tsv',
  '.htaccess', '.gitignore', '.dockerignore', '.svg', '.vue', '.svelte', '.lock',
]);

const EDITABLE_NAMES = new Set([
  'Dockerfile', 'Makefile', 'LICENSE', 'README', 'CHANGELOG', '.env', '.htaccess', '.gitignore',
]);

function isTextFile(name, size) {
  if (size > config.maxEditableBytes) return false;
  const ext = path.extname(name).toLowerCase();
  if (TEXT_EXTENSIONS.has(ext)) return true;
  return EDITABLE_NAMES.has(name) || (!ext && size < 200 * 1024);
}

/**
 * Resolves a user-supplied relative path against the site root and refuses
 * anything that escapes it (traversal, absolute paths, symlink escapes).
 */
function resolveSafe(site, relPath = '') {
  const root = sites.siteDirs(site).root;
  const rootReal = fs.existsSync(root) ? fs.realpathSync(root) : root;
  const cleaned = String(relPath || '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '');
  const target = path.resolve(rootReal, cleaned);

  const rel = path.relative(rootReal, target);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error('Path is outside the site directory');
  }

  // The live MySQL data directory must not be browsable or writable: editing
  // it under a running server corrupts the database.
  const relPosix = rel.split(path.sep).join('/');
  if (site.type === 'wordpress' && (relPosix === 'db' || relPosix.startsWith('db/'))) {
    throw new Error('The database directory is managed by the database container and is not editable here.');
  }

  // If the path already exists, make sure its real location is still inside.
  if (fs.existsSync(target)) {
    const real = fs.realpathSync(target);
    const relReal = path.relative(rootReal, real);
    if (relReal.startsWith('..') || path.isAbsolute(relReal)) {
      throw new Error('Path resolves outside the site directory');
    }
  }
  return { abs: target, rel: rel.split(path.sep).join('/'), root: rootReal };
}

async function list(site, relPath = '') {
  const { abs, rel, root } = resolveSafe(site, relPath);
  const st = await fsp.stat(abs);
  if (!st.isDirectory()) throw new Error('Not a directory');

  const entries = await fsp.readdir(abs, { withFileTypes: true });
  const items = [];
  for (const entry of entries) {
    if (site.type === 'wordpress' && rel === '' && entry.name === 'db') continue;
    const full = path.join(abs, entry.name);
    let stat = null;
    try {
      stat = await fsp.lstat(full);
    } catch (_) {
      continue;
    }
    const isDir = entry.isDirectory() || (entry.isSymbolicLink() && safeIsDir(full));
    items.push({
      name: entry.name,
      path: rel ? `${rel}/${entry.name}` : entry.name,
      type: isDir ? 'dir' : 'file',
      symlink: entry.isSymbolicLink(),
      size: stat.size,
      mtime: stat.mtime.toISOString(),
      mode: (stat.mode & 0o777).toString(8).padStart(3, '0'),
      editable: !isDir && isTextFile(entry.name, stat.size),
    });
  }

  items.sort((a, b) => {
    if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
    return a.name.localeCompare(b.name, undefined, { numeric: true });
  });

  const parent = rel ? rel.split('/').slice(0, -1).join('/') : null;
  return { path: rel, parent, root, items };
}

function safeIsDir(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch (_) {
    return false;
  }
}

async function readFile(site, relPath) {
  const { abs } = resolveSafe(site, relPath);
  const st = await fsp.stat(abs);
  if (st.isDirectory()) throw new Error('That is a directory');
  if (st.size > config.maxEditableBytes) {
    throw new Error(
      `File is too large to edit in the browser (${Math.round(st.size / 1024)} KB). Download it instead.`
    );
  }
  const content = await fsp.readFile(abs, 'utf8');
  return { content, size: st.size, path: relPath };
}

async function writeFile(site, relPath, content) {
  const { abs } = resolveSafe(site, relPath);
  await fsp.mkdir(path.dirname(abs), { recursive: true });
  await fsp.writeFile(abs, content, 'utf8');
  await applyOwnership(site, abs);
  return true;
}

async function mkdir(site, relPath, name) {
  validateName(name);
  const { abs } = resolveSafe(site, path.posix.join(relPath || '', name));
  await fsp.mkdir(abs, { recursive: true });
  await applyOwnership(site, abs);
  return true;
}

async function createFile(site, relPath, name) {
  validateName(name);
  const { abs } = resolveSafe(site, path.posix.join(relPath || '', name));
  if (fs.existsSync(abs)) throw new Error('A file with that name already exists');
  await fsp.mkdir(path.dirname(abs), { recursive: true });
  await fsp.writeFile(abs, '');
  await applyOwnership(site, abs);
  return true;
}

async function rename(site, relPath, newName) {
  validateName(newName);
  const { abs } = resolveSafe(site, relPath);
  const target = resolveSafe(site, path.posix.join(path.posix.dirname(relPath), newName));
  if (fs.existsSync(target.abs)) throw new Error('A file with that name already exists');
  await fsp.rename(abs, target.abs);
  return true;
}

async function remove(site, relPaths) {
  const list_ = Array.isArray(relPaths) ? relPaths : [relPaths];
  const removed = [];
  for (const rel of list_) {
    if (!rel) continue;
    const { abs, rel: safeRel } = resolveSafe(site, rel);
    if (safeRel === '') throw new Error('Refusing to delete the site root');
    await fsp.rm(abs, { recursive: true, force: true });
    removed.push(safeRel);
  }
  return removed;
}

async function chmod(site, relPath, mode) {
  const parsed = parseInt(String(mode), 8);
  if (Number.isNaN(parsed) || parsed < 0 || parsed > 0o777) throw new Error('Invalid mode');
  const { abs } = resolveSafe(site, relPath);
  await fsp.chmod(abs, parsed);
  return true;
}

async function saveUpload(site, relPath, tmpFile, originalName) {
  validateName(originalName);
  const { abs } = resolveSafe(site, path.posix.join(relPath || '', originalName));
  await fsp.mkdir(path.dirname(abs), { recursive: true });
  await fsp.rename(tmpFile, abs).catch(async () => {
    await fsp.copyFile(tmpFile, abs);
    await fsp.unlink(tmpFile).catch(() => {});
  });
  await applyOwnership(site, abs);
  return abs;
}

async function extractZip(site, relPath) {
  const { abs } = resolveSafe(site, relPath);
  if (!/\.zip$/i.test(abs)) throw new Error('Only .zip archives can be extracted');
  const destDir = path.dirname(abs);
  const rootReal = fs.realpathSync(sites.siteDirs(site).root);

  const zip = new AdmZip(abs);
  let count = 0;
  for (const entry of zip.getEntries()) {
    // Guard against zip-slip.
    const outPath = path.resolve(destDir, entry.entryName);
    const rel = path.relative(rootReal, outPath);
    if (rel.startsWith('..') || path.isAbsolute(rel)) {
      throw new Error(`Archive contains an unsafe path: ${entry.entryName}`);
    }
    if (entry.isDirectory) {
      await fsp.mkdir(outPath, { recursive: true });
    } else {
      await fsp.mkdir(path.dirname(outPath), { recursive: true });
      await fsp.writeFile(outPath, entry.getData());
      count += 1;
    }
  }
  await applyOwnership(site, destDir, true);
  return count;
}

async function zipPath(site, relPath) {
  const { abs, rel } = resolveSafe(site, relPath);
  const zip = new AdmZip();
  const st = await fsp.stat(abs);
  if (st.isDirectory()) zip.addLocalFolder(abs);
  else zip.addLocalFile(abs);
  const outName = `${(rel || site.name).replace(/[\/]/g, '_') || site.name}.zip`;
  const outPath = path.join(config.tmpDir, `${Date.now()}-${outName}`);
  zip.writeZip(outPath);
  return { path: outPath, name: outName };
}

function validateName(name) {
  const n = String(name || '').trim();
  if (!n) throw new Error('A name is required');
  if (n === '.' || n === '..') throw new Error('Invalid name');
  if (/[\/\\\0]/.test(n)) throw new Error('Name cannot contain slashes');
  if (n.length > 255) throw new Error('Name is too long');
  return n;
}

async function applyOwnership(site, target, recursive = false) {
  const owner = sites.ownerUid(site.type);
  if (!owner) return;
  if (process.platform !== 'linux' || process.getuid() !== 0) return;
  if (recursive) {
    await sites.chownRecursive(target, owner.uid, owner.gid);
  } else {
    await fsp.chown(target, owner.uid, owner.gid).catch(() => {});
  }
}

module.exports = {
  resolveSafe,
  list,
  readFile,
  writeFile,
  mkdir,
  createFile,
  rename,
  remove,
  chmod,
  saveUpload,
  extractZip,
  zipPath,
  isTextFile,
  validateName,
};
