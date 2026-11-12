#!/bin/bash
# Install or remove Snapback on a macOS 13+ machine.
#   sudo ./install.sh              install (keeps an existing rules.json)
#   sudo ./install.sh --overwrite-rules
#   sudo ./install.sh --uninstall
set -euo pipefail

LABEL="com.example.snapback"
HOME_DIR="/Library/Application Support/Snapback"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
GUARD="$HOME_DIR/bin/snapback.py"
LOG="/var/log/snapback.jsonl"
SRC="$(cd "$(dirname "$0")" && pwd)"
PY=(/usr/bin/python3 -I)

die() { echo "error: $*" >&2; exit 1; }

# Stopping the daemon without this raises a tamper alert (by design).
authorize_stop() {
  if [[ -f "$GUARD" ]]; then
    "${PY[@]}" "$GUARD" stop --authorize-only >/dev/null 2>&1 || true
  fi
}

[[ $EUID -eq 0 ]] || die "run with sudo"
[[ "$(uname)" == "Darwin" ]] || die "macOS only"

if [[ "${1:-}" == "--uninstall" ]]; then
  authorize_stop
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  echo "Stopped and removed the LaunchDaemon."
  echo "Left in place for review: $HOME_DIR (vault, quarantine) and /var/log/snapback.*"
  exit 0
fi

major="$(sw_vers -productVersion | cut -d. -f1)"
(( major >= 13 )) || die "needs macOS 13 or later (for eslogger)"
[[ -x /usr/bin/eslogger ]] || die "/usr/bin/eslogger not found"
xcode-select -p >/dev/null 2>&1 || die "install the Command Line Tools first: xcode-select --install"
"${PY[@]}" -c 'import sys; assert sys.version_info >= (3, 7)' || die "/usr/bin/python3 is not usable"

authorize_stop
launchctl bootout "system/$LABEL" 2>/dev/null || true

# Everything root-only: the rules hold the webhook secret, and the control files
# (maintenance windows) would tell malware when brew is allowed to write.
install -d -o root -g wheel -m 0755 "$HOME_DIR" "$HOME_DIR/bin"
install -d -o root -g wheel -m 0700 "$HOME_DIR/control" "$HOME_DIR/vault" "$HOME_DIR/quarantine"
chmod 0700 "$HOME_DIR/control"   # tighten an older install
install -o root -g wheel -m 0755 "$SRC/snapback.py" "$GUARD"
install -o root -g wheel -m 0755 "$SRC/brew-guarded" "$HOME_DIR/bin/brew-guarded"
if [[ ! -f "$HOME_DIR/rules.json" || "${1:-}" == "--overwrite-rules" ]]; then
  install -o root -g wheel -m 0600 "$SRC/rules.json" "$HOME_DIR/rules.json"
fi
chown root:wheel "$HOME_DIR/rules.json"
chmod 0600 "$HOME_DIR/rules.json"
# Loads every rule and compiles every pattern, so a typo fails here, not at boot.
"${PY[@]}" "$GUARD" status >/dev/null || die "rules.json is not valid (see the error above)"
install -o root -g wheel -m 0644 "$SRC/$LABEL.plist" "$PLIST"
plutil -lint "$PLIST" >/dev/null
touch "$LOG"
# Root only: alerts include full command lines, and the developer account is the
# one an attacker would be using. Read it with sudo (see README).
chown root:wheel "$LOG"
chmod 0640 "$LOG"

echo "Taking the initial baseline (hashing protected files; can take a minute)..."
"${PY[@]}" "$GUARD" baseline

launchctl bootstrap system "$PLIST"
launchctl enable "system/$LABEL"
sleep 3

cat <<EOF

Installed. Mode is whatever rules.json says (ships as "audit": alert only).

One manual step: eslogger needs Full Disk Access for the process that launches it.
  System Settings > Privacy & Security > Full Disk Access > add the Python
  binary named in /var/log/snapback.err if eslogger reports it is not
  permitted, then: sudo launchctl kickstart -k system/$LABEL
  (On a managed fleet, push this as a PPPC profile from your MDM instead.)

Check it:   sudo tail -f $LOG
Test alert: sudo /usr/bin/python3 -I "$GUARD" test-alert
Use brew:   alias brew='$HOME_DIR/bin/brew-guarded'
Stop it:    sudo /usr/bin/python3 -I "$GUARD" stop   (anything else is reported as tampering)
EOF
