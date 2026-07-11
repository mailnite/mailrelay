#!/usr/bin/env bash
#
# Copyright 2022-present Mailnite LLC.
# SPDX-License-Identifier: Apache-2.0
#
# mailrelay installer — served at https://get.mailnite.com/relay
#
# One command on a fresh Linux VDS turns it into a mailnite relay:
#
#   curl -fsSL https://get.mailnite.com/relay | sudo bash -s -- --token <KEY>
#
# It downloads the mailrelay binary for this machine, verifies its sha256
# against the manifest on get.mailnite.com, installs it as a hardened systemd
# service that may bind ports below 1024 (via AmbientCapabilities — NOT setcap,
# which a binary update would silently strip), and starts it. Re-running the
# command upgrades in place and RESTARTS the service, so the fresh binary and
# any new --token/--transport/--bind take effect immediately (settings not
# repeated on the re-run are inherited from the existing install). A daily
# systemd timer keeps it up to date.
#
# Options (after `bash -s --`):
#   --token <KEY>      handshake key from the mailnite admin console (required
#                      on first install; MAILRELAY_TOKEN env works too)
#   --transport <t>    tcp | ws | quic          (default: tcp; all run under TLS)
#   --bind <addr>      relay control bind       (default: 0.0.0.0:8443)
#   --version <vX.Y.Z> install a specific version (default: stable channel)
#   --base <url>       manifest/download base   (default: https://get.mailnite.com)
#   --no-autoupdate    do not install the daily update timer
#   --update           timer mode: upgrade if the channel moved, else exit 0
#   --uninstall        stop and remove the service and binaries
#   --purge            with --uninstall: also remove the key and the user
#
set -euo pipefail

BASE="https://get.mailnite.com"
TOKEN="${MAILRELAY_TOKEN:-}"
TRANSPORT="${MAILRELAY_TRANSPORT:-}"
BIND="${MAILRELAY_BIND:-}"
WANT_VERSION=""
AUTOUPDATE=1
MODE="install"
PURGE=0

# MAILRELAY_DESTDIR stages the whole install under a prefix (tests, images).
DESTDIR="${MAILRELAY_DESTDIR:-}"
INSTALL_DIR="$DESTDIR/opt/mailrelay"
BIN="$INSTALL_DIR/bin/mailrelay"
ENV_DIR="$DESTDIR/etc/mailrelay"
ENV_FILE="$ENV_DIR/env"
UNIT="$DESTDIR/etc/systemd/system/mailrelay.service"
UPDATE_SH="$INSTALL_DIR/update.sh"
UPDATE_UNIT="$DESTDIR/etc/systemd/system/mailrelay-update.service"
UPDATE_TIMER="$DESTDIR/etc/systemd/system/mailrelay-update.timer"
SVC_USER="mailrelay"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --token)         TOKEN="${2:?--token needs a value}"; shift 2 ;;
    --transport)     TRANSPORT="${2:?--transport needs a value}"; shift 2 ;;
    --bind)          BIND="${2:?--bind needs a value}"; shift 2 ;;
    --version)       WANT_VERSION="${2:?--version needs a value}"; shift 2 ;;
    --base)          BASE="${2:?--base needs a value}"; shift 2 ;;
    --no-autoupdate) AUTOUPDATE=0; shift ;;
    --update)        MODE="update"; shift ;;
    --uninstall)     MODE="uninstall"; shift ;;
    --purge)         PURGE=1; shift ;;
    *) die "unknown option: $1 (see the comments at the top of this script)" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "this installer must run as root — pipe it to 'sudo bash' as shown in the admin console"
command -v systemctl >/dev/null 2>&1 || die "systemd is required (no systemctl found)"
command -v curl >/dev/null 2>&1 || die "curl is required"

# The default base is HTTPS-pinned. An explicit http:// --base (a local test
# server, an air-gapped mirror) is allowed, loudly.
CURL_PROTO="--proto =https"
case "$BASE" in
  http://*) CURL_PROTO=""; warn "using a plain-HTTP base ($BASE) — fine for a local test, never for production" ;;
esac
fetch() { # fetch <output|-> <url>
  if [ "$1" = "-" ]; then
    curl -fsSL $CURL_PROTO "$2"
  else
    curl -fSL $CURL_PROTO -o "$1" "$2"
  fi
}

os="$(uname -s)"; [ "$os" = "Linux" ] || die "the relay targets a Linux VDS (this is $os)"
case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "unsupported architecture $(uname -m) — mailrelay ships for amd64 and arm64" ;;
esac

# ----- uninstall -------------------------------------------------------------

if [ "$MODE" = "uninstall" ]; then
  log "stopping and removing mailrelay"
  systemctl disable --now mailrelay-update.timer 2>/dev/null || true
  systemctl disable --now mailrelay.service 2>/dev/null || true
  rm -f "$UNIT" "$UPDATE_UNIT" "$UPDATE_TIMER"
  systemctl daemon-reload
  rm -rf "$INSTALL_DIR"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$ENV_DIR"
    userdel "$SVC_USER" 2>/dev/null || true
    log "purged the key and the $SVC_USER user"
  else
    log "kept $ENV_FILE (the key) — pass --purge to remove it"
  fi
  log "uninstalled"
  exit 0
fi

# ----- resolve the version from the channel manifest ------------------------

# The manifest is deliberately plain text (key value per line) so a shell can
# read it without jq:
#   version v0.1.0
#   sha256_linux_amd64 <hex>
#   sha256_linux_arm64 <hex>
#   url_base https://get.mailnite.com/dl/mailrelay/v0.1.0
manifest="$(fetch - "$BASE/v1/mailrelay.txt")" \
  || die "cannot fetch $BASE/v1/mailrelay.txt — is the version manifest published?"

mf() { printf '%s\n' "$manifest" | awk -v k="$1" '$1 == k { print $2; exit }'; }

VERSION="${WANT_VERSION:-$(mf version)}"
[ -n "$VERSION" ] || die "the manifest has no version line"
SHA256="$(mf "sha256_linux_${ARCH}")"
URL_BASE="$(mf url_base)"
[ -n "$URL_BASE" ] || URL_BASE="$BASE/dl/mailrelay/$VERSION"
# An explicitly requested version downloads by convention (its manifest hash
# only covers the channel version).
if [ -n "$WANT_VERSION" ] && [ "$WANT_VERSION" != "$(mf version)" ]; then
  URL_BASE="$BASE/dl/mailrelay/$VERSION"
  SHA256=""
  warn "installing pinned $VERSION — no channel checksum for it, verification falls back to the release SHA256SUMS"
fi

current=""
[ -r "$INSTALL_DIR/version" ] && current="$(cat "$INSTALL_DIR/version")"

if [ "$MODE" = "update" ]; then
  [ -x "$BIN" ] || die "mailrelay is not installed; run the installer first"
  if [ "$current" = "$VERSION" ]; then
    exit 0 # already current — the timer's normal day
  fi
  log "updating mailrelay $current → $VERSION"
fi

# ----- download & verify ------------------------------------------------------

tmp="$(mktemp -d /tmp/mailrelay-install.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

tarball="mailrelay_linux_${ARCH}.tar.gz"
log "downloading $VERSION $tarball"
fetch "$tmp/$tarball" "$URL_BASE/$tarball" \
  || die "download failed: $URL_BASE/$tarball"

if [ -z "$SHA256" ]; then
  fetch "$tmp/SHA256SUMS" "$URL_BASE/SHA256SUMS" \
    || die "no channel checksum and no SHA256SUMS next to the artifact — refusing to install unverified"
  SHA256="$(awk -v f="$tarball" '$2 == f { print $1 }' "$tmp/SHA256SUMS")"
  [ -n "$SHA256" ] || die "SHA256SUMS does not list $tarball"
fi
got="$(sha256sum "$tmp/$tarball" | awk '{print $1}')"
[ "$got" = "$SHA256" ] || die "sha256 mismatch for $tarball
  expected $SHA256
  got      $got
A checksum that doesn't match is a binary you don't run."
log "sha256 verified"

tar -xzf "$tmp/$tarball" -C "$tmp" mailrelay || die "tarball does not contain the mailrelay binary"

# ----- install ----------------------------------------------------------------

mkdir -p "$INSTALL_DIR/bin"
install -m 0755 "$tmp/mailrelay" "$BIN.new"
mv -f "$BIN.new" "$BIN" # atomic on the same filesystem
printf '%s\n' "$VERSION" > "$INSTALL_DIR/version"

if [ "$MODE" = "update" ]; then
  systemctl try-restart mailrelay.service
  log "updated to $VERSION"
  exit 0
fi

if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/mailrelay --shell /usr/sbin/nologin "$SVC_USER"
fi

# The key (and any non-default transport/bind) lives in an environment file the
# service user can read but nobody else — never on the command line, so it does
# not show in `ps` or `systemctl cat`.
#
# A re-run may omit flags it passed the first time (the common case: rotating
# only the token), so inherit anything not overridden from the existing env
# file — a reinstall must never silently drop the transport/bind (or the key)
# the relay was running with.
mkdir -p "$ENV_DIR"
if [ -s "$ENV_FILE" ]; then
  [ -n "$TOKEN" ]     || TOKEN="$(sed -n 's/^MAILRELAY_TOKEN=//p' "$ENV_FILE" | tail -n 1)"
  [ -n "$TRANSPORT" ] || TRANSPORT="$(sed -n 's/^MAILRELAY_TRANSPORT=//p' "$ENV_FILE" | tail -n 1)"
  [ -n "$BIND" ]      || BIND="$(sed -n 's/^MAILRELAY_BIND=//p' "$ENV_FILE" | tail -n 1)"
fi
if [ -n "$TOKEN" ]; then
  umask 077
  {
    echo "MAILRELAY_TOKEN=$TOKEN"
    if [ -n "$TRANSPORT" ]; then echo "MAILRELAY_TRANSPORT=$TRANSPORT"; fi
    if [ -n "$BIND" ]; then echo "MAILRELAY_BIND=$BIND"; fi
  } > "$ENV_FILE"
  chown root:"$SVC_USER" "$ENV_FILE"
  chmod 0640 "$ENV_FILE"
  umask 022
else
  die "no --token given and no existing $ENV_FILE — generate the key in the mailnite admin console (Mail relay → step 1) and re-run with --token"
fi

# CAP_NET_BIND_SERVICE comes from the unit, not setcap: a file capability would
# vanish the moment the update timer replaces the binary.
mkdir -p "$(dirname "$UNIT")"
cat > "$UNIT" <<EOF
[Unit]
Description=Mailnite reverse relay
Documentation=https://github.com/mailnite/mailrelay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
EnvironmentFile=$ENV_FILE
ExecStart=$BIN serve
Restart=always
RestartSec=3
StateDirectory=mailrelay
WorkingDirectory=/var/lib/mailrelay
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

# ----- autoupdate (a fixed local script; only DATA comes from the network) ----
#
# The updater is written here once and never fetched again: the timer executes
# LOCAL code, and only the manifest + tarball come from the network, with the
# tarball verified against the manifest hash. A compromised download origin can
# therefore at worst ship a binary that runs as the unprivileged service user —
# it can never run arbitrary code as root the way piping a fetched script to
# bash on a timer would.

if [ "$AUTOUPDATE" = 1 ]; then
  cat > "$UPDATE_SH" <<EOF
#!/usr/bin/env bash
# mailrelay self-update — runs from mailrelay-update.timer. Fixed local code:
# fetches the channel manifest and, only when the version moved, downloads the
# tarball, verifies its sha256 against the manifest, swaps the binary
# atomically and restarts the service.
set -euo pipefail
BASE="$BASE"
ARCH="$ARCH"
BIN="$BIN"
INSTALL_DIR="$INSTALL_DIR"

manifest="\$(curl -fsSL $CURL_PROTO "\$BASE/v1/mailrelay.txt")" || exit 0 # manifest unreachable: try again tomorrow
mf() { printf '%s\n' "\$manifest" | awk -v k="\$1" '\$1 == k { print \$2; exit }'; }

version="\$(mf version)"
[ -n "\$version" ] || exit 0
current="\$(cat "\$INSTALL_DIR/version" 2>/dev/null || true)"
[ "\$version" = "\$current" ] && exit 0

sha256="\$(mf "sha256_linux_\${ARCH}")"
[ -n "\$sha256" ] || { echo "manifest has no sha256 for linux_\${ARCH}; skipping" >&2; exit 0; }
url_base="\$(mf url_base)"
[ -n "\$url_base" ] || url_base="\$BASE/dl/mailrelay/\$version"

tmp="\$(mktemp -d /tmp/mailrelay-update.XXXXXX)"
trap 'rm -rf "\$tmp"' EXIT
tarball="mailrelay_linux_\${ARCH}.tar.gz"
curl -fsSL $CURL_PROTO -o "\$tmp/\$tarball" "\$url_base/\$tarball"
got="\$(sha256sum "\$tmp/\$tarball" | awk '{print \$1}')"
if [ "\$got" != "\$sha256" ]; then
  echo "sha256 mismatch for \$version (expected \$sha256, got \$got) — refusing to update" >&2
  exit 1
fi
tar -xzf "\$tmp/\$tarball" -C "\$tmp" mailrelay
install -m 0755 "\$tmp/mailrelay" "\$BIN.new"
mv -f "\$BIN.new" "\$BIN"
printf '%s\n' "\$version" > "\$INSTALL_DIR/version"
systemctl try-restart mailrelay.service
echo "mailrelay updated \$current → \$version"
EOF
  chmod 0755 "$UPDATE_SH"

  cat > "$UPDATE_UNIT" <<EOF
[Unit]
Description=Mailnite relay self-update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATE_SH
EOF

  cat > "$UPDATE_TIMER" <<'EOF'
[Unit]
Description=Daily mailnite relay self-update

[Timer]
OnCalendar=daily
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
EOF
fi

systemctl daemon-reload
# enable + restart, NOT `enable --now`: --now is a no-op on a service that is
# already running, so a re-run of this installer would leave the OLD process
# serving with the OLD binary and env. restart hands over in every case (and
# plain-starts a fresh install). Same for the timer, so a changed schedule or
# updater script takes effect on re-runs.
systemctl enable mailrelay.service
systemctl restart mailrelay.service
if [ "$AUTOUPDATE" = 1 ]; then
  systemctl enable mailrelay-update.timer
  systemctl restart mailrelay-update.timer
else
  # An explicit --no-autoupdate on a re-run must also switch OFF a timer a
  # previous install enabled.
  systemctl disable --now mailrelay-update.timer 2>/dev/null || true
fi

# ----- report ------------------------------------------------------------------

port="8443"
if [ -n "$BIND" ]; then port="${BIND##*:}"; fi
# The address lookup is best-effort reporting: under `set -euo pipefail` a
# missing iproute2 / no default route must not fail an install that already
# succeeded, hence the `|| true` guards.
ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
[ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
[ -n "$ip" ] || ip="<this-host>"

echo
log "mailrelay $VERSION is installed and running"
echo
echo "    Relay address to paste into the mailnite admin console (step 3):"
echo
echo "        $ip:$port"
echo
echo "    (a DNS name pointing at this VDS works too, and survives IP changes)"
echo
echo "    status:   systemctl status mailrelay"
echo "    logs:     journalctl -u mailrelay -f"
if [ "$AUTOUPDATE" = 1 ]; then
  echo "    updates:  daily via mailrelay-update.timer (this script --uninstall removes everything)"
fi
echo
