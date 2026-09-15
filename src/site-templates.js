'use strict';

const path = require('path');
const config = require('./config');

/**
 * Builds the dockerode container-creation payload for a site.
 * Every site type maps onto one HTTP-speaking container whose port 80 (or the
 * app port, for Node) is published on the site's allocated host port. NPMplus
 * then proxies the public domain at that host port.
 */

function baseLabels(site) {
  return {
    'hostpanel.managed': 'true',
    'hostpanel.site': site.name,
    'hostpanel.site_id': String(site.id),
    'hostpanel.type': site.type,
  };
}

function hostConfigCommon(site, binds, portBindings, networkName) {
  const hc = {
    Binds: binds,
    PortBindings: portBindings,
    RestartPolicy: { Name: 'unless-stopped' },
    NetworkMode: networkName,
    LogConfig: { Type: 'json-file', Config: { 'max-size': '10m', 'max-file': '3' } },
  };
  if (site.memory_mb && site.memory_mb > 0) {
    hc.Memory = site.memory_mb * 1024 * 1024;
    hc.MemorySwap = site.memory_mb * 1024 * 1024;
  }
  if (site.cpu_limit && site.cpu_limit > 0) {
    hc.NanoCpus = Math.round(site.cpu_limit * 1e9);
  }
  return hc;
}

function envArray(site, extra = {}) {
  let parsed = {};
  try {
    parsed = JSON.parse(site.env_json || '{}');
  } catch (_) {
    parsed = {};
  }
  const merged = { ...extra, ...parsed };
  return Object.entries(merged).map(([k, v]) => `${k}=${v}`);
}

function imageFor(site) {
  switch (site.type) {
    case 'static':
      return 'nginx:alpine';
    case 'php':
      return `php:${site.runtime_version || '8.3'}-apache`;
    case 'wordpress':
      return `wordpress:php${site.runtime_version || '8.3'}-apache`;
    case 'node':
      return `node:${site.runtime_version || '22'}-bookworm-slim`;
    default:
      throw new Error(`Unknown site type: ${site.type}`);
  }
}

function containerName(site) {
  return `${config.containerPrefix}${site.name}`;
}

function dbContainerName(site) {
  return `${config.containerPrefix}${site.name}-db`;
}

function networkName(site) {
  return `${config.networkPrefix}${site.id}`;
}

function buildSpec(site, dirs) {
  const name = containerName(site);
  const net = networkName(site);
  const labels = baseLabels(site);
  const bindHost = process.env.PUBLISH_ADDRESS || '0.0.0.0';

  if (site.type === 'static') {
    const binds = [
      `${dirs.app}:/usr/share/nginx/html:ro`,
      `${dirs.logs}:/var/log/nginx`,
      `${path.join(dirs.conf, 'nginx-site.conf')}:/etc/nginx/conf.d/default.conf:ro`,
    ];
    return {
      name,
      image: imageFor(site),
      create: {
        name,
        Image: imageFor(site),
        Labels: labels,
        Env: envArray(site),
        ExposedPorts: { '80/tcp': {} },
        HostConfig: hostConfigCommon(
          site,
          binds,
          { '80/tcp': [{ HostIp: bindHost, HostPort: String(site.port) }] },
          net
        ),
      },
    };
  }

  if (site.type === 'php') {
    const binds = [
      `${dirs.app}:/var/www/html`,
      `${dirs.logs}:/var/log/apache2`,
      `${path.join(dirs.conf, 'php-custom.ini')}:/usr/local/etc/php/conf.d/zz-hostpanel.ini:ro`,
    ];
    return {
      name,
      image: imageFor(site),
      create: {
        name,
        Image: imageFor(site),
        Labels: labels,
        Env: envArray(site),
        Cmd: [
          'sh',
          '-c',
          'a2enmod rewrite remoteip >/dev/null 2>&1 || true; exec apache2-foreground',
        ],
        ExposedPorts: { '80/tcp': {} },
        HostConfig: hostConfigCommon(
          site,
          binds,
          { '80/tcp': [{ HostIp: bindHost, HostPort: String(site.port) }] },
          net
        ),
      },
    };
  }

  if (site.type === 'wordpress') {
    const dbName = dbContainerName(site);
    const siteUrl = site.domain ? `https://${site.domain}` : '';
    const configExtra = [
      "if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') { $_SERVER['HTTPS'] = 'on'; }",
      "if (isset($_SERVER['HTTP_X_FORWARDED_HOST'])) { $_SERVER['HTTP_HOST'] = $_SERVER['HTTP_X_FORWARDED_HOST']; }",
      siteUrl ? `define('WP_HOME', '${siteUrl}');` : '',
      siteUrl ? `define('WP_SITEURL', '${siteUrl}');` : '',
      "define('FS_METHOD', 'direct');",
    ]
      .filter(Boolean)
      .join('\n');

    const appBinds = [
      `${dirs.app}:/var/www/html`,
      `${dirs.logs}:/var/log/apache2`,
      `${path.join(dirs.conf, 'php-custom.ini')}:/usr/local/etc/php/conf.d/zz-hostpanel.ini:ro`,
    ];

    return {
      name,
      image: imageFor(site),
      dbName,
      dbImage: config.mariadbImage,
      dbCreate: {
        name: dbName,
        Image: config.mariadbImage,
        Labels: { ...labels, 'hostpanel.role': 'database' },
        Env: [
          `MARIADB_DATABASE=${site.db_name}`,
          `MARIADB_USER=${site.db_user}`,
          `MARIADB_PASSWORD=${site.db_password}`,
          `MARIADB_ROOT_PASSWORD=${site.db_password}root`,
        ],
        HostConfig: {
          Binds: [`${dirs.db}:/var/lib/mysql`],
          RestartPolicy: { Name: 'unless-stopped' },
          NetworkMode: net,
          LogConfig: { Type: 'json-file', Config: { 'max-size': '10m', 'max-file': '2' } },
        },
      },
      create: {
        name,
        Image: imageFor(site),
        Labels: labels,
        Env: envArray(site, {
          WORDPRESS_DB_HOST: `${dbName}:3306`,
          WORDPRESS_DB_NAME: site.db_name,
          WORDPRESS_DB_USER: site.db_user,
          WORDPRESS_DB_PASSWORD: site.db_password,
          WORDPRESS_CONFIG_EXTRA: configExtra,
        }),
        // No Cmd override here on purpose: the WordPress entrypoint only runs
        // its first-boot setup when argv[0] starts with "apache2", and the
        // official image already enables mod_rewrite and mod_remoteip.
        ExposedPorts: { '80/tcp': {} },
        HostConfig: hostConfigCommon(
          site,
          appBinds,
          { '80/tcp': [{ HostIp: bindHost, HostPort: String(site.port) }] },
          net
        ),
      },
    };
  }

  if (site.type === 'node') {
    const appPort = site.app_port || 3000;
    const start = (site.start_command || 'npm start').trim();
    const binds = [`${dirs.app}:/app`, `${dirs.logs}:/var/log/app`];
    return {
      name,
      image: imageFor(site),
      create: {
        name,
        Image: imageFor(site),
        Labels: labels,
        WorkingDir: '/app',
        Env: envArray(site, { PORT: String(appPort), NODE_ENV: 'production', HOST: '0.0.0.0' }),
        Cmd: ['sh', '-c', start],
        ExposedPorts: { [`${appPort}/tcp`]: {} },
        HostConfig: hostConfigCommon(
          site,
          binds,
          { [`${appPort}/tcp`]: [{ HostIp: bindHost, HostPort: String(site.port) }] },
          net
        ),
      },
    };
  }

  throw new Error(`Unknown site type: ${site.type}`);
}

/* ------------------------------------------------------------------ *
 * Seed files written into a brand new site directory
 * ------------------------------------------------------------------ */
const DEFAULT_NGINX_CONF = `server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html index.htm;

    # Serve the file, then the directory, then fall back to index.html so
    # client-side routed single page apps work out of the box.
    location / {
        try_files $uri $uri/ /index.html;
    }

    location ~* \\.(?:css|js|woff2?|ttf|eot|svg|png|jpe?g|gif|webp|avif|ico)$ {
        expires 7d;
        add_header Cache-Control "public";
        try_files $uri =404;
    }

    access_log /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log warn;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml image/svg+xml;
}
`;

const DEFAULT_PHP_INI = `; Managed by HostPanel - edit here, then restart the site.
upload_max_filesize = 128M
post_max_size = 128M
memory_limit = 512M
max_execution_time = 300
max_input_vars = 3000
date.timezone = UTC
expose_php = Off
`;

function seedIndexHtml(site) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${site.name}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
         display:grid; place-items:center; min-height:100vh; margin:0; background:#0f1115; color:#e6e8ec; }
  .card { text-align:center; padding:3rem 2.5rem; border:1px solid #262a33; border-radius:14px; background:#161a21; }
  h1 { margin:0 0 .5rem; font-size:1.6rem; }
  p { margin:.25rem 0; color:#9aa3b2; font-size:.95rem; }
  code { background:#0f1115; padding:.15rem .4rem; border-radius:5px; color:#8ab4f8; }
</style>
</head>
<body>
  <div class="card">
    <h1>${site.name} is live</h1>
    <p>Served by HostPanel.</p>
    <p>Replace this file at <code>/index.html</code> using the file manager.</p>
  </div>
</body>
</html>
`;
}

function seedIndexPhp(site) {
  return `<?php
// Managed by HostPanel - replace this with your application.
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${site.name}</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; display:grid; place-items:center;
         min-height:100vh; margin:0; background:#0f1115; color:#e6e8ec; }
  .card { text-align:center; padding:3rem 2.5rem; border:1px solid #262a33; border-radius:14px; background:#161a21; }
  code { background:#0f1115; padding:.15rem .4rem; border-radius:5px; color:#8ab4f8; }
</style>
</head>
<body>
  <div class="card">
    <h1>${site.name}</h1>
    <p>PHP <?= PHP_VERSION ?> is running.</p>
    <p>Upload your application to <code>/</code> using the file manager.</p>
  </div>
</body>
</html>
`;
}

function seedNodeApp(site) {
  const appPort = site.app_port || 3000;
  return {
    'package.json': JSON.stringify(
      {
        name: site.name.replace(/[^a-z0-9-]/gi, '-').toLowerCase(),
        version: '1.0.0',
        private: true,
        main: 'server.js',
        scripts: { start: 'node server.js' },
      },
      null,
      2
    ),
    'server.js': `const http = require('http');

const port = process.env.PORT || ${appPort};

http
  .createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(
      '<!doctype html><meta charset="utf-8"><title>${site.name}</title>' +
        '<body style="font-family:system-ui;background:#0f1115;color:#e6e8ec;display:grid;place-items:center;min-height:100vh;margin:0">' +
        '<div style="text-align:center;padding:3rem;border:1px solid #262a33;border-radius:14px;background:#161a21">' +
        '<h1>${site.name}</h1><p>Node ' + process.version + ' is running on port ' + port + '.</p>' +
        '<p>Replace server.js, then restart the site.</p></div>'
    );
  })
  .listen(port, '0.0.0.0', () => console.log('listening on ' + port));
`,
  };
}

module.exports = {
  buildSpec,
  imageFor,
  containerName,
  dbContainerName,
  networkName,
  envArray,
  DEFAULT_NGINX_CONF,
  DEFAULT_PHP_INI,
  seedIndexHtml,
  seedIndexPhp,
  seedNodeApp,
};
