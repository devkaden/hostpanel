<p align="center">
  <img src="src/public/logo.svg" width="72" height="72" alt="HostPanel">
</p>

<h1 align="center">HostPanel</h1>

<p align="center">
  A self-hosted web hosting control panel for a homelab.<br>
  Every site is its own Docker container, with reverse proxy and HTTPS handled for you.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/node-22%2B-3a63e0" alt="Node 22+">
  <img src="https://img.shields.io/badge/license-MIT-3a63e0" alt="MIT">
  <img src="https://img.shields.io/badge/tests-578-3fbf7f" alt="578 tests">
</p>

---

Create a site, give it a domain, and HostPanel builds the container, publishes
it on a host port, and asks **NPMplus** (or Nginx Proxy Manager) to reverse
proxy the domain and issue the Let's Encrypt certificate — in one step.

**Site types:** static/HTML · PHP · WordPress (with its own MariaDB) · Node.js

## Features

- **File manager** — drag-and-drop uploads including whole folders, an editor
  with syntax highlighting, image preview, zip extraction, drag-to-move
- **Browser shell** into any container, which still works when the site is down
- **Live logs** — container output plus the site's own access and error logs
- **Scheduled tasks** per site, with the last run's output kept
- **Rename a site** — the container, the folder and the image follow; the port
  and domain stay, so the reverse proxy needs no change
- **Multi-user** — administrators see everything, standard users see their own
  sites, with per-user site quotas
- **Two-factor authentication** — TOTP, optional or required by role, with
  single-use recovery codes
- **Security alerts** — repeated failed sign-ins, lockouts, sign-ins from a new
  address and account changes, raised once per pattern rather than once per event
- **Node.js that just works** — dependencies install themselves on first start,
  and extra programs like `ffmpeg` or `yt-dlp` are a field in the site settings
- **Built to hand to someone else** — a first-run setup guide, a Simple/Advanced
  toggle that hides Docker internals, inline help, light and dark themes, and a
  configurable name, logo and accent colour

## Install

On a fresh Debian 12/13 or Ubuntu 22.04+ LXC or VM:

```bash
git clone https://github.com/devkaden/hostpanel.git
cd hostpanel
sudo ./install.sh
```

The installer sets up Node.js 22, Docker Engine, the panel and a systemd unit,
then shows the generated admin password. It is written to
`/opt/hostpanel/data/initial-admin-password.txt` (mode `0600`) and never to the
service log - delete that file once you have signed in and changed it.

Open `http://<host-ip>:8890` and sign in.

> **Proxmox LXC:** Docker inside an unprivileged container needs `nesting=1` and
> `keyctl=1` (Options → Features). A VM avoids the issue entirely.

### Updating

```bash
cd ~/hostpanel && git pull && ./install.sh
```

Your database, `.env` and site files are untouched. The service restarts itself.

## How it fits together

```
     internet
        │
        ▼
   ┌─────────┐   http://<host-ip>:21000   ┌──────────────────┐
   │ NPMplus │ ─────────────────────────▶ │ hp-mysite        │  ← Docker
   │  :443   │   proxy host + LE cert     │ nginx/php/node   │
   └─────────┘                            └──────────────────┘
        ▲                                          ▲
        │ REST API                                 │ Docker socket
        └────────────── HostPanel :8890 ───────────┘
```

Each site gets its own directory:

```
/opt/hostpanel/data/sites/<name>/
  app/    your files — the container's web root or /app
  conf/   nginx-site.conf or php-custom.ini, editable, never overwritten
  logs/   access.log and error.log from inside the container
  db/     MariaDB data (WordPress only)
```

Host ports come from 21000–21999. State lives in
`/opt/hostpanel/data/hostpanel.db` (SQLite).

| Type | Image | Notes |
|---|---|---|
| Static | `nginx:alpine` | SPA-friendly `try_files`, gzip, cache headers |
| PHP | `php:8.1–8.4-apache` | `mod_rewrite` on, `php-custom.ini` editable |
| WordPress | `wordpress:php8.3-apache` + `mariadb:11` | Credentials generated, HTTPS-behind-proxy handled |
| Node.js | `node:20/22/24-bookworm-slim` | Your install and start commands, `PORT` injected |

## Connecting NPMplus

Settings → Reverse Proxy. Fill in the URL, an admin login, and the **Host IP**
NPMplus should forward traffic to — that last one is the field people get
wrong. It must be an address the NPMplus host can reach *this* host on, so if
NPMplus runs on the same machine it is the LAN IP, not `127.0.0.1`.

**Test connection** probes in three steps and names the one that failed.

Tick **Manage reverse proxy hosts automatically** and creating a site with a
domain will, in one go: build the container, create the proxy host, request a
certificate, and re-attach it with SSL forced and websockets allowed.

### Keeping proxy hosts in step

Proxy hosts drift: a site's port changes, a domain is added here but never
there, somebody disables a host while debugging. The symptom always arrives
later, as "the domain stopped working".

- **Check & Fix** on a site's page compares that site against its proxy host,
  says in words what does not match, and corrects it.
- **Settings → Reverse Proxy → Check & Fix All** does the same for every site
  in one pass.
- Changing a site's port or domains fixes its proxy host automatically, so the
  drift mostly stops happening.
- **HTTPS** on a site's page is a single on/off choice. Turning it off detaches
  the certificate but keeps it, so it can go back on without issuing a new one.

Anything hand-written in a host's advanced config is kept: the panel only ever
rewrites its own marked block. A proxy host the panel did not create is never
repointed without being told to take it over.

**Let other pages embed this site in a frame** (per site) clears the
`X-Frame-Options` header NPMplus adds. The panel's own preview does not need
it — previews are served back through the panel — so this is only for embedding
a site somewhere else.

<details>
<summary>NPMplus authentication differs from classic NPM</summary>

NPMplus 2.15+ does not return a JWT and does not accept `Authorization: Bearer`.
`POST /api/tokens` answers `{"expires": "…"}` and puts the token in an httpOnly
`__Host-Http-token` cookie. The panel keeps a cookie jar and replays it.

Older builds returned `{"token": "…"}` and took a Bearer header; that path still
works and is chosen automatically.

Certificate requests differ too: NPMplus takes the ACME email from its own
configuration and rejects `letsencrypt_email`, while classic NPM requires it.
The panel sends whichever shape matches and falls back on rejection.

Two account types the panel cannot use: one with TOTP enabled (use a dedicated
API account), and an OIDC-only account with no local password.

</details>

## Node.js sites

**Dependencies install themselves.** Uploading a project without `node_modules`
is the normal way to deploy, so starting a Node site with a `package.json` and
no `node_modules` runs the install first. Without it the site is a dead end: the
container exits with `Cannot find module`, and you cannot open a shell into a
container that is not running.

**Extra programs.** Node and PHP images are minimal, so an app that shells out
to `ffmpeg`, `yt-dlp`, `imagemagick` or `git` finds nothing. The site's settings
have an **Extra Programs** field; pressing Apply Changes bakes them into an
image of that site's own. `yt-dlp` comes from its own releases rather than apt,
and the build runs `yt-dlp --version` before committing, so "installed" means
"runs".

**Bind to `0.0.0.0`.** Inside a container, `localhost` means "this container
only" and nothing outside can reach it:

```js
app.listen(process.env.PORT || 3000, '0.0.0.0')
```

## Security

The panel reaches the Docker socket, which is equivalent to root on the host.
Give administrator only to people you would give root to; everyone else gets a
standard account.

| Area | What is in place |
|---|---|
| Passwords | bcrypt, cost 12, constant-time comparison, configurable minimum length |
| Two-factor | TOTP (RFC 6238), optional or required by role, single-use recovery codes |
| Sessions | httpOnly, SameSite=Lax, server-side store; invalidated on any credential change |
| Throttling | 8 failures per user+IP, 20 per account, 30 per IP, persisted so a restart does not clear it |
| Rate limiting | Every request capped per account (per address before sign-in), in three buckets, tunable in Settings |
| CSRF | Double-submit token on every state-changing request |
| Files | Path traversal, zip-slip and symlink escapes rejected; every path resolved against the site root |
| Headers | CSP, `nosniff`, `frame-ancestors 'none'`, no referrer |
| Secrets | Database `0600`, data directory `0750`, `.env` `0600` |
| Alerting | Repeated failures, sign-ins from new addresses and account changes surface on a Security page |

The two-factor flow is worth describing because the failure modes are subtle:
the password step never creates a signed-in session, so there is no
half-authenticated state to walk through; the code step is rate limited exactly
like the password step; recovery codes are single use and stored hashed; and
nothing is switched on until a code from the app checks out, so a mistyped key
cannot lock anyone out. `npm run test:totp` checks the implementation against
the RFC 4226 and RFC 6238 test vectors.

**Settings → Security** lists how the install actually stands — secure cookies,
session secret, `TRUST_PROXY` correctness, host shell, and which administrators
have not set up two-factor.

**Security** (the shield in the top bar, administrators only) shows what has
been tried against the panel: a burst of failed sign-ins from one address, a
lockout, a sign-in from an address an account has not used before, a recovery
code being spent, two-factor being turned off, a new administrator. Alerts are
raised once per pattern rather than once per attempt — an attack that produced
fifty notifications would only teach you to ignore them — and the page also
groups the last day's failures by address.

### Exposing the panel to the internet

Behind a reverse proxy, set both of these in `/opt/hostpanel/app/.env`:

```bash
SECURE_COOKIES=true   # session cookies never sent over plain HTTP
TRUST_PROXY=true      # believe X-Forwarded-For, so throttling counts the real client
```

`TRUST_PROXY=true` is only correct if the panel is reachable *exclusively*
through your proxy. If port 8890 is also open, anyone can forge the address the
rate limiter counts against.

An honest caveat: this panel has not had the adversarial attention that
CloudPanel or Plesk have. Two-factor, throttling and session invalidation raise
the bar considerably, but keeping the panel behind a VPN removes the whole
category of problem, and costs nothing.

## Troubleshooting

<details>
<summary>The site preview is blank</summary>

The preview is not a frame pointed at your site. The panel fetches the site's
pages itself and serves them back under `/preview/<id>/`, rewriting
root-relative URLs on the way, so the frame is same-origin with the panel. That
removes the three things that used to produce an identical white rectangle with
nothing in the console: a framing header from the site or from NPMplus, a
plain-HTTP frame inside an HTTPS page, and a port your browser cannot reach even
though the server can. None of them apply to a same-origin frame, and there is
nothing to configure in your reverse proxy.

What is left, and what it looks like:

- **The site is not answering.** The preview shows "This site is not answering"
  with the port, rather than nothing. Usually the app bound `127.0.0.1` instead
  of `0.0.0.0`, or listens on a different port than **Internal port** says. The
  Logs tab prints the address the app chose.
- **The page is very large.** Pages over 8 MB are not rewritten; the preview
  says so and suggests opening it in a tab.

If the frame is blank with a console message about `frame-ancestors`, the policy
naming it is the one to look at: the panel sends `frame-ancestors 'self'` on
`/preview/` and `'none'` everywhere else, so a `'none'` on a preview response is
coming from something in front of the panel.

**Why the preview URL has a token in it.** The frame is sandboxed without
`allow-same-origin`, which is what keeps a previewed site walled off from the
panel around it — and it also gives that document an opaque origin, so the
browser treats everything it asks for as cross-site and withholds the
`SameSite=Lax` session cookie. The page arrived and every image in it came back
as a redirect to the sign-in form. The preview carries a short-lived token in
its path instead, minted when the site page is rendered; the `<base>` tag and
the URL rewriting put it in front of every path the page resolves. A token
grants one thing: looking at one site, for two hours.

</details>

<details>
<summary>Uploads hang or fail</summary>

Every transfer is logged, not only failures:

```bash
journalctl -u hostpanel -f | grep upload
```

A failure reports how many of the declared bytes arrived. `0 of 4211` means the
browser sent nothing — browser side. `4000 of 4211` means the connection died
in flight.

To take the browser out of the picture entirely:

```bash
cd /opt/hostpanel/app && npm run test:upload-live
```

That uploads five real files and downloads one over the real HTTP port, with no
browser involved. If it passes, the server is fine.

Files are read into memory before sending rather than handed over as file
handles. Safari will accept a request with a disk-backed `File` body and then
never send it, and the browser reports `NotReadableError` with no further
explanation.

</details>

<details>
<summary>Something breaks in one browser only</summary>

Try turning the Content-Security-Policy off:

```bash
echo 'DISABLE_CSP=true' >> /opt/hostpanel/app/.env
systemctl restart hostpanel
```

If the problem disappears, the policy is the cause. This is worth knowing
because a CSP refusal does not announce itself: Safari reports it as
`NotReadableError` or `WebKitBlobResource error 4`, which reads exactly like
the operating system denying the browser access to your files. Put the setting
back once you have your answer.

</details>

<details>
<summary>Docker is not responding</summary>

```bash
systemctl status docker
```

In an LXC container, Docker also needs nesting enabled on the container itself.

</details>

<details>
<summary>Locked out of the panel</summary>

```bash
cd /opt/hostpanel/app && npm run reset-admin
```

Generates a new password for `admin`, or for a named user with
`npm run reset-admin -- username`.

</details>

## Configuration

`/opt/hostpanel/app/.env` — restart the service after editing. Everything here
can also be set in Settings, which takes precedence.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8890` | Panel HTTP port |
| `BIND_ADDRESS` | `0.0.0.0` | Interface the panel listens on |
| `SESSION_SECRET` | generated | Signs session cookies |
| `SESSION_HOURS` | `12` | Session lifetime |
| `SECURE_COOKIES` | `false` | Set `true` when served over HTTPS |
| `TRUST_PROXY` | `false` | Believe `X-Forwarded-For` |
| `HOSTPANEL_DATA` | `/opt/hostpanel/data` | Database and site directories |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Docker endpoint |
| `PORT_RANGE_START` / `_END` | `21000` / `21999` | Host ports for sites |
| `PUBLISH_ADDRESS` | `0.0.0.0` | Interface site containers publish on |
| `HOST_IP` | auto-detected | Address NPMplus forwards to |
| `MAX_UPLOAD_MB` | `512` | Largest single upload |
| `DISABLE_CSP` | `false` | Debugging only |

## Development

```bash
npm install
npm run dev     # node --watch
npm test        # everything below
```

| Command | What it covers |
|---|---|
| `npm run check` | Parses every `.js`, `.ejs` and inline `<script>` |
| `npm run test:security` | Escaping, redirects, traversal, zip-slip, auth flow |
| `npm run test:totp` | TOTP against the RFC 4226 and RFC 6238 vectors |
| `npm run test:npmplus` | The NPMplus client against a simulated API |
| `npm run test:config` | Ports, container specs, managed config files |
| `npm run test:uploads` | The browser-side upload path against fake file APIs |
| `npm run test:preview` | URL rewriting and a real proxied request |
| `npm run test:alerts` | Alert thresholds, de-duplication and the wiring |
| `npm run test:ui` | Icon names, card markup and stylesheet agreement |
| `npm run test:ratelimit` | The limiter's buckets and keys, and the rest of the scan findings |
| `npm run test:upload-live` | Real uploads and downloads against a running panel |

Everything except `test:upload-live` runs with no dependencies installed and
without touching Docker or a real NPMplus.

```
src/
  index.js          express app, security headers, template locals
  auth.js           passwords, sessions, throttling, 2FA policy
  totp.js           RFC 6238, no dependencies
  db.js             schema, migrations, settings
  docker.js         container lifecycle via dockerode
  sites.js          provisioning, lifecycle, probes
  site-templates.js per-type images, container specs, config files
  npmplus.js        proxy hosts and certificates
  filemanager.js    path containment, uploads, zips
  terminal.js       websocket shells
  cron.js           scheduled tasks
  icons.js          inline SVG icon set
  routes/           one file per area
  views/            EJS, no build step
```

## License

MIT
