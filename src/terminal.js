'use strict';

/**
 * Browser terminal.
 *
 * Two kinds of session:
 *   - site shell  : `docker exec` into the site's container (always available)
 *   - host shell  : a real PTY on the panel host (admins only, requires the
 *                   optional node-pty dependency)
 *
 * Wire protocol over the websocket:
 *   binary frames  -> raw keystrokes from the browser / raw output to it
 *   text frames    -> JSON control messages, currently only {type:'resize',cols,rows}
 */

const { WebSocketServer } = require('ws');
const url = require('url');

const docker = require('./docker');
const tpl = require('./site-templates');
const sites = require('./sites');
const { getSetting, audit } = require('./db');

let pty = null;
try {
  // eslint-disable-next-line global-require, import/no-extraneous-dependencies
  pty = require('node-pty');
} catch (_) {
  pty = null;
}

function hostShellAvailable() {
  return Boolean(pty) && getSetting('allow_host_shell', '1') === '1';
}

const PICK_SHELL = 'if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi';

function workdirFor(site) {
  if (site.type === 'node') return '/app';
  if (site.type === 'static') return '/usr/share/nginx/html';
  return '/var/www/html';
}

function attach(server, sessionMiddleware) {
  const wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', (req, socket, head) => {
    const { pathname, query } = url.parse(req.url, true);
    if (pathname !== '/ws/terminal') {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }

    const fakeRes = {
      getHeader: () => undefined,
      setHeader: () => {},
      writeHead: () => {},
      end: () => {},
      on: () => {},
      once: () => {},
      emit: () => {},
    };

    sessionMiddleware(req, fakeRes, () => {
      if (!req.session || !req.session.user) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => {
        handleConnection(ws, req, query).catch((err) => {
          try {
            ws.send(`\r\n\x1b[31m${err.message}\x1b[0m\r\n`);
            ws.close();
          } catch (_) {
            /* socket already gone */
          }
        });
      });
    });
  });

  return wss;
}

async function handleConnection(ws, req, query) {
  const user = req.session.user;
  const say = (text) => {
    try {
      ws.send(text);
    } catch (_) {
      /* ignore */
    }
  };

  if (query.host === '1') {
    if (user.role !== 'admin') throw new Error('Host shell is restricted to administrators.');
    if (!hostShellAvailable()) {
      throw new Error(
        pty
          ? 'The host shell is disabled in Settings.'
          : 'The host shell needs the optional node-pty package. Run: npm install node-pty'
      );
    }
    return attachHostShell(ws, req, say);
  }

  const site = sites.getSite(parseInt(query.site, 10));
  if (!site) throw new Error('Site not found.');
  if (!sites.canAccess({ id: user.id, role: user.role }, site)) {
    throw new Error('You do not have access to that site.');
  }

  const containerName =
    query.target === 'db' && site.type === 'wordpress'
      ? tpl.dbContainerName(site)
      : tpl.containerName(site);

  const state = await docker.containerState(containerName);
  if (state === 'missing') throw new Error('The container does not exist yet. Provision the site first.');

  audit(req, 'terminal.open', site.name, containerName);

  let exec = null;
  let stream = null;
  let rescue = null;

  if (state === 'running') {
    say(`\x1b[2m--- connected to ${containerName} ---\x1b[0m\r\n`);
    ({ exec, stream } = await docker.execInteractive(containerName, [
      '/bin/sh',
      '-c',
      `cd ${workdirFor(site)} 2>/dev/null; ${PICK_SHELL}`,
    ]));
  } else {
    // The container is down, which used to end the session: exec needs a
    // running container, so the one moment a shell is most wanted - an app
    // that will not stay up - was the one moment there was no way in. A
    // throwaway container with the same files mounted gives a shell that
    // cannot exit on its own, and is where "npm install" belongs anyway.
    const dirs = sites.siteDirs(site);
    const spec = tpl.buildSpec(site, dirs);
    const workdir = workdirFor(site);

    say(`\x1b[2m--- ${containerName} is ${state}; opened a temporary shell on the same files ---\x1b[0m\r\n`);
    say('\x1b[2m--- changes here are kept; the site itself is still stopped ---\x1b[0m\r\n');

    rescue = await docker.runInteractive(
      spec.image,
      ['/bin/sh', '-c', `cd ${workdir} 2>/dev/null; ${PICK_SHELL}`],
      { binds: [`${dirs.app}:${workdir}`], workdir, env: (spec.create || {}).Env }
    );
    stream = rescue.stream;
  }

  let closed = false;
  const shutdown = () => {
    if (closed) return;
    closed = true;
    try {
      stream.end();
    } catch (_) {
      /* ignore */
    }
    if (rescue) {
      // Nothing else will reap it: the shell was the only process in it.
      rescue.container.remove({ force: true }).catch(() => {});
    }
    try {
      ws.close();
    } catch (_) {
      /* ignore */
    }
  };

  stream.on('data', (chunk) => {
    if (ws.readyState === ws.OPEN) ws.send(chunk);
  });
  stream.on('end', () => {
    say('\r\n\x1b[2m--- session ended ---\x1b[0m\r\n');
    shutdown();
  });
  stream.on('error', () => shutdown());

  ws.on('message', (data, isBinary) => {
    if (!isBinary) {
      let msg = null;
      try {
        msg = JSON.parse(data.toString());
      } catch (_) {
        msg = null;
      }
      if (msg && msg.type === 'resize') {
        const size = { h: Math.max(4, msg.rows | 0), w: Math.max(10, msg.cols | 0) };
        const target = exec || (rescue && rescue.container);
        if (target) target.resize(size).catch(() => {});
        return;
      }
      if (msg && msg.type === 'ping') return;
      // Non-JSON text frames are treated as input too.
      try {
        stream.write(data.toString());
      } catch (_) {
        /* ignore */
      }
      return;
    }
    try {
      stream.write(data);
    } catch (_) {
      /* ignore */
    }
  });

  ws.on('close', shutdown);
  ws.on('error', shutdown);
  return true;
}

function attachHostShell(ws, req, say) {
  audit(req, 'terminal.host_open', 'host');
  say('\x1b[2m--- host shell ---\x1b[0m\r\n');

  const shell = process.env.SHELL || '/bin/bash';
  const term = pty.spawn(shell, ['-l'], {
    name: 'xterm-256color',
    cols: 100,
    rows: 30,
    cwd: process.env.HOME || '/root',
    env: process.env,
  });

  term.onData((data) => {
    if (ws.readyState === ws.OPEN) ws.send(Buffer.from(data, 'utf8'));
  });
  term.onExit(() => {
    say('\r\n\x1b[2m--- session ended ---\x1b[0m\r\n');
    try {
      ws.close();
    } catch (_) {
      /* ignore */
    }
  });

  ws.on('message', (data, isBinary) => {
    if (!isBinary) {
      let msg = null;
      try {
        msg = JSON.parse(data.toString());
      } catch (_) {
        msg = null;
      }
      if (msg && msg.type === 'resize') {
        try {
          term.resize(Math.max(10, msg.cols | 0), Math.max(4, msg.rows | 0));
        } catch (_) {
          /* ignore */
        }
        return;
      }
      if (msg && msg.type === 'ping') return;
      term.write(data.toString());
      return;
    }
    term.write(data.toString('utf8'));
  });

  const kill = () => {
    try {
      term.kill();
    } catch (_) {
      /* ignore */
    }
  };
  ws.on('close', kill);
  ws.on('error', kill);
  return true;
}

module.exports = { attach, hostShellAvailable };
