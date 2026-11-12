#!/bin/bash
# Reproduces the post-mortem's file operations against pyenv, with a harmless
# payload (a comment line), so you can confirm Snapback stops it.
# Run as your normal user, NOT with sudo, on a test machine.
#
#   ./simulate_attack.sh           run the attack (expect it to die with "Killed: 9")
#   ./simulate_attack.sh --check   confirm pyenv was restored
#   ./simulate_attack.sh --restore put the backup back if the watcher did not
set -u
LINK=/opt/homebrew/bin/pyenv
BACKUP=/tmp/snapback-sim.backup
MARK="Snapback simulation (harmless)"

realpath_py() { /usr/bin/python3 -I -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"; }
TARGET="$(realpath_py /opt/homebrew/opt/pyenv/libexec/pyenv)"
DIR="$(dirname "$TARGET")"
KEG="$(dirname "$DIR")"
LINK_TARGET_ORIG="$(readlink "$LINK" 2>/dev/null || true)"

[[ -f "$TARGET" ]] || { echo "pyenv not installed via Homebrew; nothing to test against"; exit 1; }

case "${1:-}" in
  --check)
    if grep -q "$MARK" "$TARGET"; then
      echo "FAIL: $TARGET still contains the simulated payload"
      exit 1
    fi
    [[ -f "$BACKUP" ]] && cmp -s "$BACKUP" "$TARGET" && echo "PASS: pyenv matches the pre-attack copy"
    echo "symlink: $LINK -> $(readlink "$LINK")"
    echo "Alerts: sudo tail -n 5 /var/log/snapback.jsonl"
    exit 0 ;;
  --restore)
    cp "$BACKUP" "$TARGET" && echo "restored $TARGET from $BACKUP"
    exit 0 ;;
esac

cp "$TARGET" "$BACKUP"
echo "[sim] backed up $TARGET to $BACKUP"
echo "[sim] CREATE  $DIR/pyenv_";        cp "$TARGET" "$DIR/pyenv_"
# Pause so you can see the script die at the first step. Remove it to test the
# real race: the watcher then catches and reverts the later steps instead.
sleep 1
echo "[sim] MODIFY  pyenv_";             printf '\n# %s\n' "$MARK" >> "$DIR/pyenv_"
echo "[sim] DELETE  $TARGET";            rm -f "$TARGET"
echo "[sim] RENAME  pyenv_ -> pyenv";    mv "$DIR/pyenv_" "$TARGET"
echo "[sim] DELETE  $LINK";              rm -f "$LINK"
echo "[sim] ln      $LINK";              ln -s "${LINK_TARGET_ORIG:-../Cellar/pyenv/$(basename "$KEG")/bin/pyenv}" "$LINK"
echo "[sim] spawn zsh";                  /bin/zsh -c 'echo "[sim] zsh ran"'
echo
echo "[sim] The script was NOT stopped. Is the watcher running in enforce mode?"
echo "[sim] Undo with: $0 --restore"
