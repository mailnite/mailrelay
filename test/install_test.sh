#!/usr/bin/env bash
#
# Copyright 2022-present Karagatan LLC.
# SPDX-License-Identifier: Apache-2.0
#
# Behavioral test for install.sh: drives the REAL installer through
# fresh-install -> reinstall -> autoupdate against stubbed
# systemctl/curl/id/uname, staged under MAILRELAY_DESTDIR, and asserts the
# handover semantics:
#
#   - installing restarts the service (a re-run must replace a RUNNING relay);
#   - a re-run inherits env settings it does not override (token rotation must
#     not drop --transport/--bind);
#   - the autoupdater swaps the binary and try-restarts the service, and does
#     neither when the channel has not moved;
#   - --no-autoupdate on a re-run disables a previously enabled timer.
#
# Run it anywhere bash + tar + (sha256sum|shasum) exist: make test-install
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mailrelay-installtest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

STAGE="$WORK/stage"
STUBS="$WORK/stubs"
FIXTURES="$WORK/fixtures"
export SYSCTL_LOG="$WORK/systemctl.log"
export FIXTURES
mkdir -p "$STAGE" "$STUBS" "$FIXTURES"

sha256() {
  if command -v sha256sum > /dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# ----- stubs (simulate root on a systemd Linux host with the CDN reachable) ---
cat > "$STUBS/systemctl" <<'EOF'
#!/bin/bash
echo "systemctl $*" >> "$SYSCTL_LOG"
exit 0
EOF
cat > "$STUBS/curl" <<'EOF'
#!/bin/bash
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  */v1/mailrelay.txt) src="$FIXTURES/manifest.txt" ;;
  *.tar.gz)           src="$FIXTURES/mailrelay_linux_amd64.tar.gz" ;;
  *) echo "curl stub: unknown url $url" >&2; exit 22 ;;
esac
[ -f "$src" ] || { echo "curl stub: missing fixture $src" >&2; exit 22; }
if [ -n "$out" ]; then cp "$src" "$out"; else cat "$src"; fi
EOF
cat > "$STUBS/id" <<'EOF'
#!/bin/bash
echo 0
EOF
cat > "$STUBS/uname" <<'EOF'
#!/bin/bash
case "${1:-}" in -m) echo x86_64 ;; *) echo Linux ;; esac
EOF
cat > "$STUBS/useradd" <<'EOF'
#!/bin/bash
exit 0
EOF
cat > "$STUBS/chown" <<'EOF'
#!/bin/bash
exit 0
EOF
if ! command -v sha256sum > /dev/null 2>&1; then
  cat > "$STUBS/sha256sum" <<'EOF'
#!/bin/bash
exec shasum -a 256 "$@"
EOF
fi
chmod 0755 "$STUBS"/*
export PATH="$STUBS:$PATH"

# ----- release fixtures -------------------------------------------------------
make_release() { # make_release <version>
  local v="$1" dir
  dir="$(mktemp -d "$WORK/rel.XXXXXX")"
  printf 'RELAY BINARY %s\n' "$v" > "$dir/mailrelay"
  tar -czf "$FIXTURES/mailrelay_linux_amd64.tar.gz" -C "$dir" mailrelay
  local sha; sha="$(sha256 "$FIXTURES/mailrelay_linux_amd64.tar.gz" | awk '{print $1}')"
  cat > "$FIXTURES/manifest.txt" <<EOF
version $v
sha256_linux_amd64 $sha
url_base http://test.local/dl/mailrelay/$v
EOF
  rm -rf "$dir"
}

fail=0
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" > /dev/null 2>&1; then echo "PASS: $desc"; else echo "FAIL: $desc"; fail=1; fi
}
count_in_log() { grep -c -- "$1" "$SYSCTL_LOG" 2>/dev/null || true; }

BIN="$STAGE/opt/mailrelay/bin/mailrelay"
ENVF="$STAGE/etc/mailrelay/env"
VERF="$STAGE/opt/mailrelay/version"
UPD="$STAGE/opt/mailrelay/update.sh"

# ===== 1. fresh install (ws transport, token tok1) ============================
make_release v9.9.9
MAILRELAY_DESTDIR="$STAGE" bash "$REPO/install.sh" \
  --token tok1 --transport ws --base http://test.local > "$WORK/install1.log" 2>&1
check "install #1 exits 0" test $? -eq 0
check "binary staged"           grep -q "RELAY BINARY v9.9.9" "$BIN"
check "version recorded"        grep -qx "v9.9.9" "$VERF"
check "env has token tok1"      grep -qx "MAILRELAY_TOKEN=tok1" "$ENVF"
check "env has ws transport"    grep -qx "MAILRELAY_TRANSPORT=ws" "$ENVF"
check "service enabled"         grep -q "systemctl enable mailrelay.service" "$SYSCTL_LOG"
check "service restarted on install" grep -q "systemctl restart mailrelay.service" "$SYSCTL_LOG"
check "update timer enabled"    grep -q "systemctl enable mailrelay-update.timer" "$SYSCTL_LOG"
check "install report reached"  grep -q "installed and running" "$WORK/install1.log"
R1=$(count_in_log "systemctl restart mailrelay.service")

# ===== 2. reinstall: rotate ONLY the token ====================================
MAILRELAY_DESTDIR="$STAGE" bash "$REPO/install.sh" \
  --token tok2 --base http://test.local > "$WORK/install2.log" 2>&1
check "install #2 exits 0" test $? -eq 0
R2=$(count_in_log "systemctl restart mailrelay.service")
check "reinstall restarts the service again" test "$R2" -gt "$R1"
check "env rotated to tok2"        grep -qx "MAILRELAY_TOKEN=tok2" "$ENVF"
check "env inherited ws transport" grep -qx "MAILRELAY_TRANSPORT=ws" "$ENVF"

# ===== 3. autoupdate: channel moved ===========================================
make_release v9.9.10
bash "$UPD" > "$WORK/update1.log" 2>&1
check "update.sh exits 0" test $? -eq 0
check "binary swapped by autoupdate" grep -q "RELAY BINARY v9.9.10" "$BIN"
check "version bumped by autoupdate" grep -qx "v9.9.10" "$VERF"
check "service try-restarted after autoupdate" grep -q "systemctl try-restart mailrelay.service" "$SYSCTL_LOG"
T1=$(count_in_log "systemctl try-restart mailrelay.service")

# ===== 4. autoupdate no-op: channel unchanged =================================
bash "$UPD" > "$WORK/update2.log" 2>&1
check "update.sh no-op exits 0" test $? -eq 0
T2=$(count_in_log "systemctl try-restart mailrelay.service")
check "no restart when version unchanged" test "$T2" -eq "$T1"

# ===== 5. --no-autoupdate on a rerun disables the timer =======================
MAILRELAY_DESTDIR="$STAGE" bash "$REPO/install.sh" \
  --token tok3 --no-autoupdate --base http://test.local > "$WORK/install3.log" 2>&1
check "install #3 exits 0" test $? -eq 0
check "rerun with --no-autoupdate disables the timer" \
  grep -q "systemctl disable --now mailrelay-update.timer" "$SYSCTL_LOG"

echo
if [ "$fail" = 0 ]; then
  echo "install.sh: ALL CHECKS PASSED"
else
  echo "install.sh: CHECKS FAILED"
  exit 1
fi
