#!/usr/bin/env bash
#
# HostPanel installer for Debian 12 / 13 (and Ubuntu 22.04+).
#
#   curl -fsSL https://.../install.sh | bash        # from a release
#   sudo ./install.sh                               # from a clone
#
# Installs Node.js, Docker, the panel itself and a systemd unit, then prints
# the generated administrator password.

set -euo pipefail

APP_DIR="/opt/hostpanel/app"
DATA_DIR="/opt/hostpanel/data"
SERVICE="hostpanel"
NODE_MAJOR="22"
PANEL_PORT="${PANEL_PORT:-8890}"

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'

say()  { echo "${BOLD}==>${RESET} $*"; }
ok()   { echo "  ${GREEN}ok${RESET}  $*"; }
warn() { echo "  ${YELLOW}!!${RESET}  $*"; }
die()  { echo "${RED}error:${RESET} $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this with sudo or as root."

if ! command -v apt-get >/dev/null 2>&1; then
  die "This installer targets Debian/Ubuntu. On another distro, install Node 20+ and Docker yourself, then run 'npm ci --omit=dev' in the app directory."
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --------------------------------------------------------------- packages ---
say "Installing base packages"
export DEBIAN_FRONTEND=noninteractive

# A stale package index points at filenames the mirror has already replaced
# (a Debian point release moves them), which surfaces as 404s on .deb files.
# Refreshing the lists from scratch is the fix, so do it automatically.
refresh_apt_lists() {
  rm -rf /var/lib/apt/lists/*
  apt-get clean
  apt-get update -qq
}

BASE_PACKAGES="ca-certificates curl gnupg rsync build-essential python3 unzip"

apt-get update -qq || refresh_apt_lists
if ! apt-get install -y -qq $BASE_PACKAGES >/dev/null 2>&1; then
  warn "package index looked stale, refreshing it and retrying"
  refresh_apt_lists
  apt-get install -y -qq $BASE_PACKAGES >/dev/null \
    || die "Could not install base packages. Run 'apt-get update' manually and check the output."
fi
ok "base packages ready"

# git is handy to have but nothing in this installer needs it.
apt-get install -y -qq git >/dev/null 2>&1 || warn "git could not be installed, continuing without it"

# ------------------------------------------------------------------- node ---
if command -v node >/dev/null 2>&1 && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 20 ]; then
  ok "node $(node -v) already installed"
else
  say "Installing Node.js ${NODE_MAJOR}.x"
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  chmod a+r /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  apt-get update -qq
  apt-get install -y -qq nodejs >/dev/null
  ok "node $(node -v) installed"
fi

# ----------------------------------------------------------------- docker ---
if command -v docker >/dev/null 2>&1; then
  ok "docker $(docker --version | awk '{print $3}' | tr -d ,) already installed"
else
  say "Installing Docker Engine"
  install -d -m 0755 /etc/apt/keyrings
  DISTRO_ID="$(. /etc/os-release && echo "$ID")"
  DISTRO_CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-bookworm}")"
  [ "$DISTRO_ID" = "debian" ] || [ "$DISTRO_ID" = "ubuntu" ] || DISTRO_ID="debian"

  curl -fsSL "https://download.docker.com/linux/${DISTRO_ID}/gpg" \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  write_docker_repo() {
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DISTRO_ID} $1 stable" \
      > /etc/apt/sources.list.d/docker.list
  }

  # Docker occasionally lags a new Debian release; fall back to the previous
  # stable codename rather than failing the whole install.
  FALLBACK_CODENAME="bookworm"
  [ "$DISTRO_ID" = "ubuntu" ] && FALLBACK_CODENAME="jammy"

  write_docker_repo "$DISTRO_CODENAME"
  if ! apt-get update -qq -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/docker.list \
        -o Dir::Etc::sourceparts=/dev/null -o APT::Get::List-Cleanup=0 2>/dev/null; then
    warn "no Docker packages for '${DISTRO_CODENAME}', falling back to '${FALLBACK_CODENAME}'"
    write_docker_repo "$FALLBACK_CODENAME"
  fi

  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
  systemctl enable --now docker
  ok "docker installed and running"
fi

docker info >/dev/null 2>&1 || die "Docker is installed but not responding. Check 'systemctl status docker'."

# -------------------------------------------------------------- app files ---
say "Installing the panel into ${APP_DIR}"
mkdir -p "$APP_DIR" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

if [ "$SOURCE_DIR" != "$APP_DIR" ]; then
  rsync -a --delete \
    --exclude node_modules --exclude .git --exclude data --exclude .env \
    "$SOURCE_DIR"/ "$APP_DIR"/
fi
ok "files copied"

say "Installing npm dependencies (this takes a minute)"
cd "$APP_DIR"
if [ -f package-lock.json ]; then
  npm ci --omit=dev --no-audit --no-fund
else
  npm install --omit=dev --no-audit --no-fund
fi
ok "dependencies installed"

# node-pty is optional and powers the host shell; a failure here is harmless.
if npm ls node-pty >/dev/null 2>&1; then
  ok "node-pty present (host shell available)"
else
  warn "node-pty not built - container shells still work, the host shell will not"
fi

# ------------------------------------------------------------------- .env ---
if [ ! -f "$APP_DIR/.env" ]; then
  say "Writing ${APP_DIR}/.env"
  SECRET="$(head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c 48)"
  cat > "$APP_DIR/.env" <<EOF
# HostPanel configuration - restart the service after editing.
PORT=${PANEL_PORT}
BIND_ADDRESS=0.0.0.0
SESSION_SECRET=${SECRET}
HOSTPANEL_DATA=${DATA_DIR}
DOCKER_SOCKET=/var/run/docker.sock

# Site containers publish their ports in this range on the host.
PORT_RANGE_START=21000
PORT_RANGE_END=21999

# Set to true only once the panel itself is served over HTTPS.
SECURE_COOKIES=false

# Largest single file the file manager accepts, in MB.
MAX_UPLOAD_MB=512
EOF
  chmod 0600 "$APP_DIR/.env"
  ok ".env created"
else
  ok ".env already exists, leaving it alone"
fi

# ---------------------------------------------------------------- systemd ---
say "Installing the systemd unit"
cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=HostPanel - web hosting control panel
Documentation=file://${APP_DIR}/README.md
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=/usr/bin/node ${APP_DIR}/src/index.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hostpanel

# The panel needs the Docker socket and must chown site files to the uids the
# site containers run as, so it runs as root. Docker socket access is already
# root-equivalent, so a separate service user would not add isolation.
NoNewPrivileges=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null

# Remember the credentials file's state before boot, so an update never prints
# the password from the original install as if it were new.
CREDS="${DATA_DIR}/initial-admin-password.txt"
CREDS_BEFORE=""
[ -f "$CREDS" ] && CREDS_BEFORE="$(stat -c %Y "$CREDS" 2>/dev/null || echo)"

systemctl restart "$SERVICE"
ok "service enabled and started"

sleep 3
if ! systemctl is-active --quiet "$SERVICE"; then
  echo
  die "The service failed to start. Logs:
$(journalctl -u "$SERVICE" -n 40 --no-pager)"
fi

# ------------------------------------------------------------------ done ----
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

CREDS_AFTER=""
[ -f "$CREDS" ] && CREDS_AFTER="$(stat -c %Y "$CREDS" 2>/dev/null || echo)"
FRESH_ADMIN=false
[ -n "$CREDS_AFTER" ] && [ "$CREDS_AFTER" != "$CREDS_BEFORE" ] && FRESH_ADMIN=true

echo
echo "${GREEN}${BOLD}HostPanel is running.${RESET}"
echo
echo "  URL       http://${HOST_IP:-<this-host>}:${PANEL_PORT}"
if [ "$FRESH_ADMIN" = true ]; then
  echo "  Login     $(grep -m1 username "$CREDS" | cut -d' ' -f2-)"
  echo "  Password  $(grep -m1 password "$CREDS" | cut -d' ' -f2-)"
  echo "            ${DIM}(also saved in ${CREDS}; you must change it at first login)${RESET}"
  echo
  echo "  ${BOLD}Next steps${RESET}"
  echo "   1. Sign in and change the password."
  echo "   2. Settings -> NPMplus: paste your NPMplus URL, admin email and password, then Test connection."
  echo "   3. Settings -> Host IP: confirm the address NPMplus should forward traffic to."
  echo "   4. Create your first site."
else
  echo "  Login     your existing account (no new password was generated)"
  echo
  echo "  ${BOLD}Updated.${RESET} Your sites, users and settings are unchanged."
  echo "   ${DIM}Forgot the password? Run: cd ${APP_DIR} && npm run reset-admin${RESET}"
fi
echo
echo "  ${DIM}logs:    journalctl -u ${SERVICE} -f${RESET}"
echo "  ${DIM}restart: systemctl restart ${SERVICE}${RESET}"
echo "  ${DIM}data:    ${DATA_DIR}${RESET}"
echo
if [ -n "${HOST_IP:-}" ]; then
  echo "  ${YELLOW}Firewall note:${RESET} site containers publish on ports 21000-21999."
  echo "  Allow NPMplus to reach those ports on ${HOST_IP}, and keep them off the public internet."
  echo
fi
