#!/usr/bin/env bash
# funaibuddy-lab — one-command setup for a fresh Ubuntu 24.04 server.
#
#   curl -fsSL https://raw.githubusercontent.com/psachdev/funaibuddy-lab/main/setup/bootstrap.sh | bash
#
# Safe to run again: every step checks before it changes anything.
# It asks for your domain, a connector token, an optional SSH public key, and your project secrets.
set -euo pipefail

REPO_URL="${LAB_REPO_URL:-https://github.com/psachdev/funaibuddy-lab.git}"
REPO_DIR=/opt/funaibuddy-lab
ENV_DIR=/etc/funaibuddy-lab
ENV_FILE=$ENV_DIR/lab.env
LAB_UID=10001

say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ask()  { local reply; read -r -p "$1" reply </dev/tty; printf '%s' "$reply"; }
asks() { local reply; read -r -s -p "$1" reply </dev/tty; echo >/dev/tty; printf '%s' "$reply"; }

[ "$(id -u)" -eq 0 ] || { echo "Run this as root."; exit 1; }
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || { echo "This script is written for Ubuntu (tested on 24.04)."; exit 1; }

# ---- 1. answers -------------------------------------------------------------
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
if [ -z "${LAB_DOMAIN:-}" ]; then
  LAB_DOMAIN=$(ask "Domain for the connector (for example lab.example.com): ")
fi
[[ "$LAB_DOMAIN" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || { echo "That does not look like a domain."; exit 1; }
GENERATED=""
if [ -z "${LAB_TOKEN:-}" ]; then
  LAB_TOKEN=$(asks "Connector token: paste one from your password manager (40+ characters), or press Enter to generate: ")
  if [ -z "$LAB_TOKEN" ]; then LAB_TOKEN=$(openssl rand -hex 32); GENERATED=1; fi
fi
[ "${#LAB_TOKEN}" -ge 32 ] || { echo "The token must be at least 32 characters."; exit 1; }
[[ "$LAB_TOKEN" =~ ^[A-Za-z0-9._~+-]+$ ]] || { echo "Use only letters, digits and . _ ~ + - in the token."; exit 1; }
LAB_ALLOWED_IPS="${LAB_ALLOWED_IPS:-160.79.104.0/21}"   # Anthropic's published outbound range
LAB_TZ="${LAB_TZ:-America/Los_Angeles}"
LAB_SSH="${LAB_SSH:-}"                                   # closed | keys
if [ -z "$LAB_SSH" ]; then
  echo "Emergency door. Paste an SSH PUBLIC key (one line starting with ssh-ed25519 or ssh-rsa) to keep" >/dev/tty
  echo "remote login open for that key only. Press Enter to close remote login completely" >/dev/tty
  echo "(then your host's browser console is the only way in, so check that it works for you first)." >/dev/tty
  LAB_SSH_PUBKEY=$(ask "Public key: ")
  if [ -n "$LAB_SSH_PUBKEY" ]; then
    [[ "$LAB_SSH_PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+)\ [A-Za-z0-9+/=]+ ]] || { echo "That is not a public key."; exit 1; }
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    grep -qxF "$LAB_SSH_PUBKEY" /root/.ssh/authorized_keys 2>/dev/null || echo "$LAB_SSH_PUBKEY" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    LAB_SSH=keys
  else
    LAB_SSH=closed
  fi
fi
if [ "$LAB_SSH" = "keys" ] && ! [ -s /root/.ssh/authorized_keys ]; then
  echo "LAB_SSH=keys but /root/.ssh/authorized_keys is empty: that would lock you out."; exit 1
fi

# ---- 2. system --------------------------------------------------------------
say "Updating Ubuntu and installing Docker, git and the firewall"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confold upgrade
apt-get -y -q install docker.io docker-compose-v2 git ufw curl ca-certificates openssl unattended-upgrades
timedatectl set-timezone "$LAB_TZ" || true

say "Turning on automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

if ! swapon --show | grep -q .; then
  say "Adding a 2 GB swap file (spare memory on disk)"
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap -q /swapfile && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

mkdir -p /etc/docker
[ -f /etc/docker/daemon.json ] || echo '{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"}}' > /etc/docker/daemon.json
systemctl enable --now docker >/dev/null
systemctl restart docker

# ---- 3. the lab --------------------------------------------------------------
say "Fetching funaibuddy-lab"
if [ -d "$REPO_DIR/.git" ]; then git -C "$REPO_DIR" pull --ff-only; else git clone "$REPO_URL" "$REPO_DIR"; fi

mkdir -p /srv/lab/{projects,secrets,logs} "$ENV_DIR"
[ -f /srv/lab/flows.yaml ] || cp "$REPO_DIR/flows.example.yaml" /srv/lab/flows.yaml
chown -R $LAB_UID:$LAB_UID /srv/lab/projects /srv/lab/logs /srv/lab/secrets
chmod 700 /srv/lab/secrets "$ENV_DIR"

umask 077
cat > "$ENV_FILE" <<EOF
LAB_DOMAIN=$LAB_DOMAIN
LAB_TOKEN=$LAB_TOKEN
LAB_ALLOWED_IPS="$LAB_ALLOWED_IPS"
LAB_TZ=$LAB_TZ
LAB_SSH=$LAB_SSH
EOF
umask 022
ln -sf "$REPO_DIR/maintenance/lab" /usr/local/bin/lab
chmod +x "$REPO_DIR/maintenance/lab"

say "Building and starting the connector (first build takes a few minutes)"
lab up

# ---- 4. projects --------------------------------------------------------------
for project in $(lab projects); do
  say "Project: $project"
  lab secrets "$project"
  lab project-setup "$project"
done
lab schedules

if [ -n "$GENERATED" ]; then
  cat <<EOF

  Your generated connector token. Save it in your password manager NOW,
  before the next step. ("lab rotate-token" makes a new one.)

      $LAB_TOKEN

EOF
  ask "Press Enter once the token is saved: " >/dev/null
fi

# ---- 5. lock the doors (last, so a dropped connection cannot strand the setup) ----
say "Locking down remote login (SSH): no passwords"
cat > /etc/ssh/sshd_config.d/00-funaibuddy-lab.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

say "Firewall: everything closed except the certificate port and Anthropic's addresses"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 80/tcp comment 'HTTPS certificate renewal' >/dev/null
for range in $LAB_ALLOWED_IPS; do
  ufw allow proto tcp from "$range" to any port 443 comment 'Claude connector' >/dev/null
done
[ "$LAB_SSH" = "keys" ] && ufw limit 22/tcp comment 'SSH, keys only' >/dev/null
ufw --force enable >/dev/null
ufw status verbose | sed 's/^/    /'


say "Done"
lab doctor || true
cat <<EOF

  Connector address :  https://$LAB_DOMAIN/mcp
  Request header    :  Authorization: Bearer <your connector token>
  Remote login      :  $LAB_SSH

  In Claude: Settings > Connectors > Add custom connector. Enter the address,
  choose "No sign in", and add the request header above.
EOF
