'use strict';

const { PassThrough } = require('stream');
const Docker = require('dockerode');
const config = require('./config');

let docker = null;
try {
  docker = new Docker({ socketPath: config.dockerSocket });
} catch (err) {
  console.error('[docker] could not initialise client:', err.message);
}

let lastPing = { ok: false, at: 0, error: 'not checked yet' };

async function ping(force = false) {
  if (!force && Date.now() - lastPing.at < 5000) return lastPing;
  if (!docker) {
    lastPing = { ok: false, at: Date.now(), error: 'Docker client unavailable' };
    return lastPing;
  }
  try {
    await docker.ping();
    lastPing = { ok: true, at: Date.now(), error: null };
  } catch (err) {
    lastPing = { ok: false, at: Date.now(), error: err.message };
  }
  return lastPing;
}

function client() {
  if (!docker) throw new Error('Docker is not available on this host');
  return docker;
}

async function getContainer(idOrName) {
  if (!idOrName) return null;
  try {
    const c = client().getContainer(idOrName);
    await c.inspect();
    return c;
  } catch (_) {
    return null;
  }
}

async function inspect(idOrName) {
  const c = await getContainer(idOrName);
  if (!c) return null;
  try {
    return await c.inspect();
  } catch (_) {
    return null;
  }
}

async function containerState(idOrName) {
  const info = await inspect(idOrName);
  if (!info) return 'missing';
  if (info.State.Running) return info.State.Health ? info.State.Health.Status : 'running';
  if (info.State.Restarting) return 'restarting';
  return info.State.Status || 'stopped';
}

/** Pull an image, resolving only once the pull stream completes. */
function pullImage(image, onProgress) {
  return new Promise((resolve, reject) => {
    client().pull(image, (err, stream) => {
      if (err) return reject(err);
      client().modem.followProgress(
        stream,
        (doneErr, output) => (doneErr ? reject(doneErr) : resolve(output)),
        (event) => {
          if (onProgress && event && event.status) {
            onProgress(`${event.status}${event.id ? ' ' + event.id : ''}`);
          }
        }
      );
    });
  });
}

async function imageExists(image) {
  try {
    await client().getImage(image).inspect();
    return true;
  } catch (_) {
    return false;
  }
}

async function ensureImage(image, onProgress) {
  if (await imageExists(image)) return false;
  if (onProgress) onProgress(`Pulling ${image} ...`);
  await pullImage(image, onProgress);
  return true;
}

async function ensureNetwork(name) {
  const nets = await client().listNetworks({ filters: { name: [name] } });
  const exact = nets.find((n) => n.Name === name);
  if (exact) return client().getNetwork(exact.Id);
  return client().createNetwork({ Name: name, Driver: 'bridge' });
}

async function removeNetwork(name) {
  try {
    const net = client().getNetwork(name);
    await net.remove();
  } catch (_) {
    /* already gone */
  }
}

async function removeContainer(idOrName, { force = true, removeVolumes = false } = {}) {
  const c = await getContainer(idOrName);
  if (!c) return false;
  try {
    await c.remove({ force, v: removeVolumes });
    return true;
  } catch (err) {
    if (/no such container/i.test(err.message)) return false;
    throw err;
  }
}

async function startContainer(idOrName) {
  const c = await getContainer(idOrName);
  if (!c) throw new Error('Container does not exist');
  const info = await c.inspect();
  if (info.State.Running) return info;
  await c.start();
  return c.inspect();
}

async function stopContainer(idOrName, timeout = 10) {
  const c = await getContainer(idOrName);
  if (!c) return false;
  const info = await c.inspect();
  if (!info.State.Running) return true;
  await c.stop({ t: timeout });
  return true;
}

async function restartContainer(idOrName, timeout = 10) {
  const c = await getContainer(idOrName);
  if (!c) throw new Error('Container does not exist');
  await c.restart({ t: timeout });
  return true;
}

async function logs(idOrName, { tail = 400, timestamps = false } = {}) {
  const c = await getContainer(idOrName);
  if (!c) return '';
  const buf = await c.logs({ stdout: true, stderr: true, tail, timestamps });
  return demuxToString(buf);
}

/**
 * Returns a still-open, already de-multiplexed text stream for SSE forwarding.
 * Demuxing frame-by-frame in the consumer would mangle output whenever a chunk
 * boundary lands inside Docker's 8-byte frame header, so it is done here with
 * dockerode's own demuxer.
 */
async function logStream(idOrName, tail = 200) {
  const c = await getContainer(idOrName);
  if (!c) throw new Error('Container does not exist');
  const info = await c.inspect();
  const raw = await c.logs({ stdout: true, stderr: true, tail, follow: true, timestamps: false });

  if (info.Config.Tty) return { stream: raw, text: raw };

  const text = new PassThrough();
  client().modem.demuxStream(raw, text, text);
  raw.on('end', () => text.end());
  raw.on('error', (err) => text.emit('error', err));
  return { stream: raw, text };
}

/**
 * Runs a command in a throwaway container that shares the site's bind mounts.
 * Used for install steps, so a crash-looping application container can never
 * stop dependencies from being installed.
 */
async function runOneShot(image, cmd, { binds = [], workdir, env, network, onProgress } = {}) {
  await ensureImage(image, onProgress);
  const container = await client().createContainer({
    Image: image,
    Cmd: cmd,
    WorkingDir: workdir || undefined,
    Env: env || undefined,
    Labels: { 'hostpanel.managed': 'true', 'hostpanel.role': 'oneshot' },
    HostConfig: {
      Binds: binds,
      AutoRemove: false,
      NetworkMode: network || 'bridge',
    },
  });

  try {
    await container.start();
    const result = await container.wait();
    const buf = await container.logs({ stdout: true, stderr: true, tail: 2000 });
    return { exitCode: result.StatusCode, output: demuxToString(buf) };
  } finally {
    await container.remove({ force: true }).catch(() => {});
  }
}

/**
 * Builds a site image with extra OS packages baked in, and returns its tag.
 *
 * The official node and php images are deliberately minimal, so an app that
 * shells out to ffmpeg, yt-dlp or imagemagick finds nothing there. Installing
 * into a running container is not enough: the container is recreated on every
 * rebuild and the packages vanish with it. Committing the install to a
 * site-specific image makes it survive, and keeps the base image untouched for
 * every other site.
 *
 * Done with run-and-commit rather than a Dockerfile so no build context has to
 * be written to disk, and so the output streams back live.
 */
async function buildImageWithPackages(baseImage, packages, tag, onProgress) {
  await ensureImage(baseImage, onProgress);

  const list = packages.join(' ');
  const say = onProgress || (() => {});
  say(`Installing system packages: ${list}`);

  // pip is the route for yt-dlp: the Debian package lags badly, and YouTube
  // changes often enough that a stale copy is a broken one.
  const aptNames = packages.filter((p) => p !== 'yt-dlp');
  const wantsYtDlp = packages.includes('yt-dlp');

  const steps = ['set -e', 'export DEBIAN_FRONTEND=noninteractive', 'apt-get update'];
  if (aptNames.length) {
    steps.push(`apt-get install -y --no-install-recommends ${aptNames.join(' ')}`);
  }
  if (wantsYtDlp) {
    steps.push('apt-get install -y --no-install-recommends curl ca-certificates');
    steps.push(
      'curl -fsSL https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp ' +
        '-o /usr/local/bin/yt-dlp && chmod 0755 /usr/local/bin/yt-dlp'
    );
  }
  steps.push('rm -rf /var/lib/apt/lists/*');

  const container = await client().createContainer({
    Image: baseImage,
    Cmd: ['sh', '-lc', steps.join(' && ')],
    Labels: { 'hostpanel.managed': 'true', 'hostpanel.role': 'imagebuild' },
    HostConfig: { NetworkMode: 'bridge' },
  });

  try {
    await container.start();
    const logs = await container.logs({ stdout: true, stderr: true, follow: true });
    await new Promise((resolve) => {
      logs.on('data', (chunk) => {
        const text = demuxToString(chunk).trim();
        if (text) say(text.split('\n').slice(-4).join('\n'));
      });
      logs.on('end', resolve);
      logs.on('error', resolve);
    });

    const result = await container.wait();
    if (result.StatusCode !== 0) {
      const buf = await container.logs({ stdout: true, stderr: true, tail: 60 });
      throw new Error(
        `installing system packages failed (exit ${result.StatusCode}). ` +
          `Last output: ${demuxToString(buf).trim().slice(-500)}`
      );
    }

    const [repo, version] = tag.split(':');
    await container.commit({ repo, tag: version || 'latest' });
    say(`Built ${tag}`);
    return tag;
  } finally {
    await container.remove({ force: true }).catch(() => {});
  }
}

/**
 * Starts a throwaway container with a terminal attached.
 *
 * For getting a shell when the site's own container will not stay up. A Node
 * app with no dependencies installed exits the moment it starts, and exec needs
 * a running container - so the one moment a shell is most needed is the one
 * moment the normal route cannot provide it. This mounts the same files into a
 * fresh container that just runs a shell, which cannot exit on its own.
 */
async function runInteractive(image, cmd, { binds = [], workdir, env, onProgress } = {}) {
  await ensureImage(image, onProgress);
  const container = await client().createContainer({
    Image: image,
    Cmd: cmd,
    WorkingDir: workdir || undefined,
    Env: env || undefined,
    Tty: true,
    OpenStdin: true,
    StdinOnce: false,
    Labels: { 'hostpanel.managed': 'true', 'hostpanel.role': 'rescue' },
    HostConfig: {
      Binds: binds,
      AutoRemove: false,
      NetworkMode: 'bridge',
    },
  });

  const stream = await container.attach({
    stream: true,
    stdin: true,
    stdout: true,
    stderr: true,
    hijack: true,
  });
  await container.start();
  return { container, stream };
}

/**
 * Docker multiplexes stdout/stderr with an 8-byte header per frame when the
 * container has no TTY. Strip those headers so the text is readable.
 */
function demuxToString(buffer) {
  if (!buffer || !buffer.length) return '';
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  // Heuristic: a valid frame header starts with a stream byte of 0-2 and three zero bytes.
  if (!(buf.length > 8 && buf[0] <= 2 && buf[1] === 0 && buf[2] === 0 && buf[3] === 0)) {
    return buf.toString('utf8');
  }
  const chunks = [];
  let offset = 0;
  while (offset + 8 <= buf.length) {
    const size = buf.readUInt32BE(offset + 4);
    chunks.push(buf.slice(offset + 8, offset + 8 + size));
    offset += 8 + size;
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Runs a one-shot command inside a container and collects its output. */
async function exec(idOrName, cmd, { user, workdir, env } = {}) {
  const c = await getContainer(idOrName);
  if (!c) throw new Error('Container does not exist');
  const e = await c.exec({
    Cmd: cmd,
    AttachStdout: true,
    AttachStderr: true,
    Tty: false,
    User: user || undefined,
    WorkingDir: workdir || undefined,
    Env: env || undefined,
  });
  const stream = await e.start({ hijack: true, stdin: false });
  const chunks = [];
  await new Promise((resolve, reject) => {
    stream.on('data', (d) => chunks.push(d));
    stream.on('end', resolve);
    stream.on('error', reject);
  });
  const info = await e.inspect();
  return { exitCode: info.ExitCode, output: demuxToString(Buffer.concat(chunks)) };
}

/** Interactive exec used by the web terminal. */
async function execInteractive(idOrName, cmd) {
  const c = await getContainer(idOrName);
  if (!c) throw new Error('Container does not exist');
  const e = await c.exec({
    Cmd: cmd,
    AttachStdin: true,
    AttachStdout: true,
    AttachStderr: true,
    Tty: true,
  });
  const stream = await e.start({ hijack: true, stdin: true });
  return { exec: e, stream };
}

async function stats(idOrName) {
  const c = await getContainer(idOrName);
  if (!c) return null;
  try {
    const s = await c.stats({ stream: false });
    const cpuDelta = s.cpu_stats.cpu_usage.total_usage - s.precpu_stats.cpu_usage.total_usage;
    const sysDelta = s.cpu_stats.system_cpu_usage - s.precpu_stats.system_cpu_usage;
    const cpus = s.cpu_stats.online_cpus || 1;
    const cpuPercent = sysDelta > 0 && cpuDelta > 0 ? (cpuDelta / sysDelta) * cpus * 100 : 0;
    const memUsage = (s.memory_stats.usage || 0) - ((s.memory_stats.stats || {}).cache || 0);
    return {
      cpuPercent: Math.round(cpuPercent * 10) / 10,
      memoryBytes: memUsage,
      memoryLimit: s.memory_stats.limit || 0,
    };
  } catch (_) {
    return null;
  }
}

async function systemInfo() {
  try {
    const [info, df] = await Promise.all([client().info(), client().df().catch(() => null)]);
    return {
      containers: info.Containers,
      running: info.ContainersRunning,
      images: info.Images,
      version: info.ServerVersion,
      memTotal: info.MemTotal,
      cpus: info.NCPU,
      layersSize: df ? df.LayersSize : null,
    };
  } catch (err) {
    return { error: err.message };
  }
}

module.exports = {
  ping,
  client,
  getContainer,
  inspect,
  containerState,
  ensureImage,
  pullImage,
  imageExists,
  ensureNetwork,
  removeNetwork,
  removeContainer,
  startContainer,
  stopContainer,
  restartContainer,
  logs,
  logStream,
  exec,
  execInteractive,
  buildImageWithPackages,
  runInteractive,
  runOneShot,
  demuxToString,
  stats,
  systemInfo,
};
