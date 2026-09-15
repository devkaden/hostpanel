# HostPanel

A self-hosted web hosting control panel in the spirit of CloudPanel, built for a
homelab that already runs **NPMplus**. Every site is its own Docker container;
the panel creates it, publishes it on a host port, and asks NPMplus to reverse
proxy your domain at that port and issue the Let's Encrypt certificate.

**Site types:** static/HTML, PHP, WordPress (with its own MariaDB), Node.js.

**Included:** multi-user logins with roles, a file manager with uploads and an
inline editor, a browser shell into any container, live logs, per-site scheduled
tasks, and full NPMplus proxy + SSL automation.

**Built to hand to someone else:** a guided first-run setup, a Simple/Advanced
toggle that hides Docker internals until they are wanted, inline help on every
non-obvious field, light and dark themes, and a configurable name, logo and
accent colour.

**Repository:** <https://github.com/devkaden/hostpanel>

---

## Install

On a fresh Debian 12/13 (or Ubuntu 22.04+) LXC or VM:

```bash
git clone https://github.com/devkaden/hostpanel.git
cd hostpanel
sudo ./install.sh     # already root? just ./install.sh
```

The installer sets up Node.js 22, Docker Engine, the panel and a systemd unit,
then prints the generated admin password (also written to
`/opt/hostpanel/data/initial-admin-password.txt`). Open
`http://<vm-ip>:8890`, sign in, and change the password when prompted.

> **Proxmox LXC note:** running Docker inside an unprivileged container needs
> `nesting=1` and `keyctl=1` on the container. In the Proxmox UI that is
> Options → Features. A VM avoids the issue entirely and is the safer choice if
> you have the RAM.

### Connect NPMplus

Go to **Settings** and fill in:

| Field | Value |
|---|---|
| NPMplus URL | e.g. `https://npm.kjserver.net:81` — the admin UI, no trailing slash |
| Admin email | the NPMplus login you use |
| Admin password | that login's password |
| Let's Encrypt email | where expiry notices go |
| Host IP | the address NPMplus should forward traffic to |

Press **Test connection**. It probes in three steps and tells you which one
failed:

1. **Reaching the API** — `GET /api` should return `{"status":"OK", …}`
2. **Signing in** — `POST /api/tokens`
3. **Reading proxy hosts** — `GET /api/nginx/proxy-hosts`

### A note on NPMplus authentication

Current NPMplus (2.15.x and later) does **not** return a JWT in the response
body and does **not** accept an `Authorization: Bearer` header. `POST
/api/tokens` answers `{"expires": "…"}` and puts the signed token in an
httpOnly cookie named `__Host-Http-token`. The panel keeps a cookie jar and
replays it on every call.

Older NPM and NPMplus builds returned `{"token": "…"}` and took a Bearer
header. That path still works and is used automatically when a token is present
in the body, so the panel handles both generations.

The `meta` object on a certificate request differs too: NPMplus accepts only
`dns_challenge` (plus DNS-provider keys) and takes the ACME account email from
its own configuration, while classic NPM requires `letsencrypt_agree` and the
email per request. The panel sends the shape that matches whichever it is
talking to, and falls back to the other if the first is rejected. The
**Let's Encrypt email** field in Settings is therefore only used by classic NPM.

Two accounts the panel cannot use:

- **TOTP enabled** — sign-in returns `{"requiresTotp": true}` and a challenge
  cookie that needs a six-digit code. Use a dedicated API account without TOTP.
- **OIDC-only** — if `GET /api` reports `"password": false` and `"oidc": true`,
  there is no local password to authenticate with.

If NPMplus sits behind another reverse proxy, that proxy must not strip
`Set-Cookie` or the panel never receives a session.

You can exercise the whole client against a simulated NPMplus without touching
your real one:

```bash
npm run test:npmplus
```

**Host IP** is the one people get wrong. It must be an address the NPMplus host
can reach this panel's host on. If NPMplus runs on the same machine, the LAN IP
is right (not `127.0.0.1`, since NPMplus is itself in a container). The Detect
button guesses it from the network interfaces.

Tick **Manage reverse proxy hosts automatically** and creating a site with a
domain will, in one step: create the container, create the NPMplus proxy host
pointing at `http://<host-ip>:<site-port>`, request a certificate for the
domains, and re-attach it with SSL forced and websockets allowed.

---

## How it fits together

```
     internet
        │
        ▼
   ┌─────────┐   http://<host-ip>:21000   ┌──────────────────┐
   │ NPMplus │ ─────────────────────────▶ │ hp-myapp         │  ← Docker
   │  :443   │   proxy host + LE cert     │ nginx/php/node   │
   └─────────┘                            └──────────────────┘
        ▲                                          ▲
        │ REST API (tokens, proxy-hosts, certs)    │ Docker socket
        └────────────── HostPanel :8890 ───────────┘
```

Each site gets:

```
/opt/hostpanel/data/sites/<name>/
  app/    ← your files (the container's web root or /app)
  conf/   ← nginx-site.conf or php-custom.ini, editable, never overwritten
  logs/   ← access.log / error.log from inside the container
  db/     ← MariaDB data, WordPress only (hidden from the file manager)
```

Host ports are allocated from 21000–21999. The panel keeps state in
`/opt/hostpanel/data/hostpanel.db` (SQLite).

### What each site type runs

| Type | Image | Notes |
|---|---|---|
| Static | `nginx:alpine` | SPA-friendly `try_files`, gzip, cache headers preconfigured |
| PHP | `php:8.4/8.3/8.2/8.1-apache` | `mod_rewrite` on, `php-custom.ini` editable |
| WordPress | `wordpress:php8.3-apache` + `mariadb:11` | DB credentials generated; HTTPS-behind-proxy handled in `WORDPRESS_CONFIG_EXTRA` |
| Node.js | `node:24/22/20-bookworm-slim` | Your install and start commands; `PORT` injected |

Node dependency installs run in a throwaway container sharing the same `/app`
mount, so an app that crashes on start can still have its dependencies
installed.

---

## Using it

**Creating a site.** Name, type, domain, done. Watch the build output stream
live on the site page. Without a domain the site is still reachable at
`http://<host-ip>:<port>` for testing.

**Files.** Browse, drag-and-drop upload, edit text files in place (Ctrl+S
saves), extract zips, download a folder as a zip, rename, chmod, bulk delete.
Paths are resolved against the site root and symlink escapes are rejected.

**Shell.** A real terminal into the container — `docker exec` behind a
websocket, with resize, full-screen programs and tab completion. WordPress
sites can also open a shell in the database container.

The **host shell** (admins only) is a login shell on the panel host. It needs
the optional `node-pty` package; if it did not build during install, container
shells still work. Turn it off entirely in Settings.

**Logs.** Container stdout/stderr, plus the nginx or Apache access and error
logs. "Follow" streams new lines live.

**Cron.** Five-field cron expressions in UTC. Jobs run with `sh -lc` inside the
site container on the panel's own scheduler — no host crontab is touched. Run
any job manually and see its output immediately.

For WordPress, disable the built-in pseudo-cron in `wp-config.php`:

```php
define('DISABLE_WP_CRON', true);
```

then schedule `php /var/www/html/wp-cron.php` every 5 minutes.

**Users.** Admins see and manage everything. Standard users only see the sites
they own, with an optional site limit. New and reset passwords must be changed
at first login, and resetting a password ends that user's sessions immediately.

**Settings that need a rebuild.** Domain and notes apply immediately. Runtime
version, ports, environment variables and resource limits change the container
definition, so hit **Apply changes** after saving. It recreates the container and
keeps every file.

---

## Making it yours

**Simple and Advanced.** The toggle in the top bar switches between the two.
Simple hides container names, images, resource limits, environment variables and
the advanced Docker options; Advanced shows everything. The choice is per person
and remembered in their browser. Set the default for new visitors under
Settings → Appearance.

**Inline help.** The small `?` next to a field explains it in one sentence, on
hover or keyboard focus.

**Setup guide.** A new install sends the first administrator through a
three-step wizard: this server's address, the reverse proxy, and a first site.
Re-run it any time from Settings → Setup guide.

**Theme and branding.** Light, dark, or match the device. The panel name, a logo
and the accent colour are all configurable.

**Preferences follow the person, not the browser.** The theme and Simple/Advanced
toggles are saved against the signed-in account, so they survive a refresh, a
different device and the next login. The administrator's setting is the default
for anyone who has not chosen for themselves.

**Live preview.** Each site page embeds the running site, with desktop, tablet
and phone widths. The preview hits the container directly by port, so it works
before DNS or the reverse proxy exist, and always shows *that* site rather than
whatever the domain currently resolves to.

### Ports

Everything is adjustable, and nothing has to be:

| Port | Where | Notes |
|---|---|---|
| The panel's own | Settings → Panel | Overrides `.env`. Restart to apply. |
| The pool for new sites | Settings → Panel | Defaults to 21000-21999. |
| A site's host port | Site → Settings (Advanced) | Checked live against other sites *and* anything already listening. Apply changes afterwards, and update your proxy. |
| A site's internal port | Site → Settings (Advanced) | The port the server inside the container listens on. Node apps get it as `PORT`; nginx and Apache have it written into their config. |

### Advanced container options

Per site, under Advanced:

- **Custom image** — replaces the default image for that site type
- **Extra folders** — one per line as `folder:/path/in/container`, restricted to
  paths inside that site's own directory
- **Container labels** — JSON, for Watchtower, Traefik and similar. Labels
  cannot overwrite the `hostpanel.*` ones the panel relies on.
- **Docker network** — blank gives the site its own private network; name an
  existing one to place it alongside other containers. A network the panel did
  not create is never deleted.

### Presets

**Save as preset** on any site stores its runtime, commands, limits, environment
variables and container options. The next site can start from it. Names,
domains, ports and database credentials are never included, since those must be
unique. Manage presets under Settings.

### Generated config files

The nginx and Apache configs in each site's `conf/` folder are generated, then
yours. The panel keeps a hash of what it wrote and only rewrites a file while it
still matches — the moment you edit one, it stops touching it. Config files that
predate this tracking are adopted as yours and never overwritten.

---

## Security notes, honestly

**The panel runs as root.** It needs the Docker socket, and it chowns site files
to the uids the site containers run as. Docker socket access is already
equivalent to root on the host, so a separate service user would give the
appearance of isolation without the substance. What this means in practice:

- Put the panel on a LAN-only port, or behind NPMplus with its own domain and
  an access list. Do not expose `:8890` to the internet.
- The 21000–21999 site ports should be reachable from NPMplus and nothing else.
  If NPMplus is on the same host, set `PUBLISH_ADDRESS` in `.env` to the LAN IP
  or `127.0.0.1` so the ports are not bound on every interface.
- Only give admin to people you would give root to. A standard user is confined
  to their own sites, but a shell inside a container is still a shell.

### What is hardened

| Area | Measure |
|---|---|
| Passwords | bcrypt, cost 12; forced change at first login; dummy hash on unknown users so timing does not reveal which accounts exist |
| Sessions | httpOnly, SameSite=Lax, regenerated on login (no session fixation); killed on disable or password reset |
| CSRF | Token on every mutating request, compared in constant time |
| Brute force | Two buckets — 8 tries per username+IP and 20 per username across all IPs — over a 10-minute window |
| XSS | All template output escaped; data embedded in `<script>` blocks is escaped so `</script>` in a cron command or job output cannot break out |
| Redirects | The post-login `next` parameter must be a same-origin path; `//evil.com` and `/\evil.com` are rejected |
| Files | Traversal, symlink-escape and zip-slip guards; downloads always served as attachments |
| Headers | CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, HSTS when `SECURE_COOKIES=true` |
| Secrets | Database `0600`, data directory `0750`, `.env` `0600` |
| Generated passwords | `crypto.randomBytes` with rejection sampling (no modulo bias) |
| Audit | Every action logged with user, target and IP |

Run the checks yourself:

```bash
npm test            # syntax, NPMplus client, security, ports and container specs
npm run test:security
npm run test:npmplus
npm run test:config
```

All of it runs without dependencies installed and without touching Docker or
your real NPMplus.

### Known limitations

These are deliberate trade-offs, not oversights:

- **Cron commands and the terminal execute arbitrary code inside a site's
  container.** That is the feature. Anyone with access to a site can run
  anything as root *in that container*.
- **`TRUST_PROXY` defaults to `false`.** If the panel sits behind a reverse
  proxy, set it to `true` so the lockout sees real client IPs — but only if the
  panel is *not* also reachable directly, or a spoofed `X-Forwarded-For` would
  defeat the lockout.
- **The NPMplus password is stored in plaintext** in the panel's database. It
  has to be replayed on every API call, so it cannot be hashed. Use a dedicated
  NPMplus account rather than your personal admin login.
- **The CSP allows `'unsafe-inline'` for scripts,** because the pages use inline
  scripts. It still blocks framing, objects, foreign form posts and base-tag
  injection.
- **No 2FA on the panel itself.** Put it behind an NPMplus access list if you
  need a second factor.

If you put the panel itself behind NPMplus, set `SECURE_COOKIES=true` in
`.env`. Websockets must be allowed on that proxy host for the terminal to work.

---

## Operating it

```bash
systemctl status hostpanel
systemctl restart hostpanel
journalctl -u hostpanel -f
```

Locked out? On the host:

```bash
cd /opt/hostpanel/app
npm run reset-admin            # resets "admin"
npm run reset-admin -- kaden   # resets that user, creating it if needed
```

Check the code parses before restarting after a manual edit:

```bash
npm run check
```

**Backups.** Everything that matters is `/opt/hostpanel/data` — the SQLite
database and every site directory. For WordPress, stop the site first or take a
`mariadb-dump` from its shell rather than copying `db/` live.

### Updating

From your clone on the panel host:

```bash
cd ~/hostpanel
git pull
sudo ./install.sh     # already root? just ./install.sh
```

Re-running the installer is the update path. It rsyncs the new code over
`/opt/hostpanel/app`, keeps your `.env` and everything in
`/opt/hostpanel/data`, reinstalls dependencies and restarts the service.
Running sites are untouched — their containers keep serving throughout.

If you do not have a clone on the host (the panel is installed but the source
is not), create one next to it:

```bash
cd ~
git clone https://github.com/devkaden/hostpanel.git
cd hostpanel
sudo ./install.sh
```

Check it came back up:

```bash
systemctl status hostpanel
curl -s localhost:8890/healthz
```

To verify the new code before installing it:

```bash
npm test
```

---

## Configuration reference

`/opt/hostpanel/app/.env` — restart the service after editing.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8890` | Panel HTTP port |
| `BIND_ADDRESS` | `0.0.0.0` | Interface the panel listens on |
| `SESSION_SECRET` | generated | Signs session cookies |
| `SESSION_HOURS` | `12` | Session lifetime |
| `SECURE_COOKIES` | `false` | Set `true` when the panel is served over HTTPS |
| `HOSTPANEL_DATA` | `/opt/hostpanel/data` | Database and site directories |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Docker endpoint |
| `PORT_RANGE_START` / `_END` | `21000` / `21999` | Host ports for sites |
| `PUBLISH_ADDRESS` | `0.0.0.0` | Interface site containers publish on |
| `HOST_IP` | auto-detected | Address NPMplus forwards to |
| `MAX_UPLOAD_MB` | `512` | Largest single upload |

---

## Troubleshooting

**apt 404s on `.deb` files during install** — the package index is stale and
points at filenames a Debian point release has already replaced. The installer
now retries this automatically; to clear it by hand:

```bash
rm -rf /var/lib/apt/lists/* && apt-get clean && apt-get update
```

Then re-run `./install.sh` — it is safe to re-run at any point.

**"Docker is not reachable"** — `systemctl status docker`. In an LXC, check
nesting is enabled.

**Certificate request fails** — the domain's DNS must already resolve to
NPMplus and port 80 must reach it, because HTTP-01 validation happens there.
The proxy host is still created and the site works over HTTP; use **Re-sync
proxy + SSL** once DNS has propagated.

**"Host IP is not set"** — fill it in under Settings. See the table above.

**NPMplus test connection fails** — the message names the step. Failing at
step 1 means the URL is not reaching the API (the admin interface is on port 81
over HTTPS by default). Step 2 is the credentials, or one of the account
limitations in the authentication note above. To see the raw exchange:

```bash
curl -sk https://<npmplus-host>/api
curl -sk -i -X POST https://<npmplus-host>/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"identity":"you@example.com","secret":"yourpassword"}'
```

A healthy sign-in is a `200` whose body is `{"expires": "…"}` with a
`set-cookie: __Host-Http-token=…` header. Note that `/api/tokens` is rate
limited to 10 attempts per 5 minutes.

**Site shows nginx's default page or a 502** — check the container is running
on the site page, then read the container log. For Node, confirm the app binds
`0.0.0.0` on `process.env.PORT` rather than `localhost`.

**WordPress redirect loop** — usually a stale `WP_HOME`/`WP_SITEURL`. The panel
sets both from the domain at container creation, so set the domain first and
then rebuild.

**Terminal won't connect** — if the panel is behind a proxy, that proxy must
allow websocket upgrades. In NPMplus that is the "Websockets Support" toggle.
