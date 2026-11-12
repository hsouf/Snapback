# Snapback (prototype)

A root watcher for macOS 13+ aimed at the case where an attacker is already running code as a developer, through a malicious repo, package hook, extension or stolen session. It watches the things such an attacker goes after first and reacts within milliseconds:

- **Toolchain tampering** (Homebrew, pyenv, global npm and Python packages, PATH): kills the script's process tree, restores the files from a root-owned vault and quarantines what was written. A tampered binary that gets *run* before the revert lands is killed at exec.
- **Persistence** (launch agents and login items, shell, git, ssh and AI-tool config, Python startup hooks, cron, sudoers): alerts with a saved copy of the change.
- **Credential theft** (SSH keys, cloud CLI tokens, keychains, browser cookies and passwords, wallets): alerts when anything outside an allow list reads them.
- **Attack commands** (reverse shells, password-phishing dialogs, keychain dumps, disabling Gatekeeper, adding root certificates): kills the high-confidence ones, alerts on the rest.
- **System events** (SSH and screen-sharing logins, new users and admin-group changes, privacy permission grants, new background items, configuration profiles, XProtect detections, failed sudo): alerts.

It is a prototype for a test machine or a small pilot. Read [Limits](#limits) before relying on it. The most important one is that it **reacts, it does not block**: macOS only lets a process deny an operation in advance if it holds Apple's Endpoint Security entitlement.

## Background

[Binance's initial report on its 29 October 2026 incident](https://x.com/binance/status/2117626126214504729) describes an engineer running a fake job-interview "assignment" repository whose setup step swapped a Homebrew-installed `pyenv` for a trojan that ran commands and talked to an attacker's server. Their endpoint security did not detect it. The report lists the file operations:

```
CREATE  /opt/homebrew/Cellar/pyenv/2.8.0/libexec/pyenv_
MODIFY  pyenv_ -> 3,414 B
DELETE  .../libexec/pyenv  (3,344 B)    <- remove the valid pyenv
RENAME  pyenv_ -> pyenv  (3,414 B)      <- replace it with a malicious version
DELETE  /opt/homebrew/bin/pyenv
ln (create a new symlink)  +  spawn zsh
```

On Apple Silicon, `/opt/homebrew` is owned by the developer's own account, so any script they run can rewrite it without sudo. Snapback treats every write there as a violation unless brew makes it, started from the `brew-guarded` wrapper during a maintenance window. It matches on file paths, kernel-attested process identity and the process tree, not malware signatures, so obfuscating the script does not hide these steps. `simulate_attack.sh` replays the sequence with a harmless payload, and `test_snapback.py` checks the kill, the restore and the quarantine.

## Files

| File | Purpose |
|---|---|
| `snapback.py` | The watcher and its CLI (Python 3.7+, standard library only) |
| `rules.json` | What to protect, what to detect, who is allowed. Ships in `audit` mode |
| `com.example.snapback.plist` | LaunchDaemon: runs as root, restarted by launchd if it dies |
| `brew-guarded` | `brew` wrapper that opens a maintenance window bound to itself |
| `install.sh` | Installs, baselines and starts it (`--uninstall` removes it) |
| `simulate_attack.sh` | Replays the post-mortem steps with a harmless payload |
| `test_snapback.py` | 153 automated checks with synthetic events and real processes (no root needed) |
| `log-viewer.html` | Opens the alert log in a browser: incidents and edit history. Ships with sample data |

## How it works

```mermaid
flowchart LR
    subgraph kernel["macOS"]
        ES["Endpoint Security<br/>(eslogger)"]
    end
    subgraph daemon["snapback.py run (root LaunchDaemon)"]
        F["Prefilter<br/>(raw line, no JSON parse)"]
        P["Event loop<br/>process table + rules"]
        V[("Vault<br/>known-good copies")]
        HK["Housekeeping thread<br/>heartbeat, windows,<br/>re-baseline, scans, watchdog"]
    end
    R["rules.json"] --> P
    ES -- "JSON lines" --> F --> P
    P -- "violation" --> K["Freeze + kill the<br/>script's process tree"]
    P -- "violation" --> RV["Quarantine, restore<br/>(symlink-safe)"]
    RV <--> V
    HK <--> V
    C["control/ (root 0700)<br/>window.json · stop.json<br/>rebaseline.request"] --> HK
    BW["brew-guarded<br/>sudo window open --pid"] --> C
    P --> LOG["/var/log/snapback.jsonl<br/>+ syslog + signed webhook"]
    HK --> LOG
    LOG --> UI["log-viewer.html"]
```

**Events in.** The daemon starts Apple's `/usr/bin/eslogger` and reads its JSON lines. It subscribes to process events (`exec`, `fork`, `exit`, `signal`), file events (`create`, `rename`, `unlink`, `link`, `close`, `clone`, `copyfile`, `exchangedata`, `setmode`, `setowner`, `truncate`, `utimes`, `open`) and whatever system events the rules name. Most events on a dev machine have nothing to do with the rules, so a prefilter decides from the raw line whether an event is worth parsing. That cuts the cost of an irrelevant event from about 19 µs to under 5 µs, and it fails open: anything it can't classify gets parsed. A gap in eslogger's `global_seq_num` means events were dropped, and that raises an alert and triggers an immediate scan. If no events arrive for 60 s, the stream is assumed suspended and eslogger is restarted.

**Who is allowed: kernel-attested facts only.** Allow rules match the executable path and the *script* path the kernel reports for each exec (for `#!` scripts), the code-signing identity (`TEAMID:signing.id`, or `platform:` for Apple's own binaries), and the platform-binary flag. Command lines are never used for an allow decision, because any process can set its own argv. A process the watcher only knows from `ps` is never trusted. An allowed tool started with code-injecting environment variables (`BASH_ENV`, `BASH_FUNC_*`, `DYLD_*`, `NODE_OPTIONS`, `PYTHONPATH`, a `PYENV_HOOK_PATH` outside protected directories, and so on) is not trusted either.

Outside maintenance windows, only the allowed tool itself may write, or an Apple non-interpreter helper it runs directly (`cp`, `ln`, `mkdir`). Arbitrary descendants may not, so `PATH=/tmp/evil:$PATH pyenv rehash` doesn't hand the attacker's fake `rm` pyenv's permission.

**Rules.** There are three kinds in `rules.json`:

| `type` | Matches | Typical actions |
|---|---|---|
| `files` (default) | File events under `paths`, filtered by `include` / `exclude` globs. `"access": "read"` matches any `open` (for credential stores) | `kill`, `revert`, `alert`, `snapshot` |
| `exec` | Exec events whose `executable`, `script` or `args` match regexes in `match` (and none in `exclude_match`) | `kill`, `alert` |
| `event` | System events listed in `events`, optionally filtered by `match` on fields of the event | `alert` |

`allow` takes `users`, `ancestor_paths` / `ancestor_regex` (matched against executable and script paths), `signing_ids`, `platform_binaries` (`"all"` or `"non_tools"`, which excludes general-purpose tools like `cat`, `cp`, `curl`, `osascript` and interpreters), `protected_images` (binaries, or scripts run by an interpreter, that sit in a protected tree and match the vault), `only_during_window`, and `helpers`. Each rule can set its own `mode` (`audit` or `enforce`) and `kill_scope` (`script`, `session` or `process`).

**On a violation.**
1. *Kill.* Starting at the process that acted, the watcher walks up through interpreters (`sh`, `node`, `npm`, `python` and so on) to find the script running it, stopping below your terminal or editor session. It flags and SIGSTOPs that tree, re-scans for children until no new ones appear, then SIGKILLs all of it. Anything a flagged process forks or execs later is killed as it appears. If the chain comes in over SSH, the whole remote session's shell is killed, because remote logins to a dev laptop are rare and an attacker's shell shouldn't survive (`kill_remote_sessions`).
2. *Revert.* Whatever is at the path is moved to quarantine (root-owned, never executable). The known-good file, symlink or directory is restored from the vault with its mode and owner. A protected directory that was renamed away is moved back. A file not in the baseline (like `pyenv_`) is quarantined and nothing is restored.
3. *Alert.* One JSON record with the rule, the paths, the process chain (with signing identity and script for each process) and every action taken. Repeated events from an already-killed process are logged as `followup` and not re-sent.

In `audit` mode the same record says `would_kill` / `would_revert` and nothing is touched.

**Exec-time integrity.** Whenever a file under a `revert` rule is executed, as a binary or as a `#!` script, it is checked against the vault: a stat comparison, plus a hash if the stat differs. A modified or unknown file is killed and restored before it gets far. This covers the gap between a tampering write and its revert, and anything the event stream missed.

**Symlink-safe repairs.** The daemon runs as root but repairs files inside directories the developer can write to. Every repair resolves the path one directory at a time with `O_NOFOLLOW` and then acts through directory descriptors, with temporary names that are random and opened `O_EXCL`. A symlink planted anywhere in the path makes the operation fail instead of landing elsewhere. Hashing reads through the same `O_NOFOLLOW` descriptor it checked. Quarantine doesn't chmod a file that has other hard links.

**The vault.** `/Library/Application Support/Snapback/vault` (root only) holds a manifest of every protected path: type, mode, owner, size, mtime, **ctime**, inode, SHA-256 and symlink target. It also keeps a content-addressed copy of every protected file up to 5 MB. ctime can't be set from user space, so restoring the mtime with `touch -r` after an in-place edit doesn't fool the fast scan. Larger files can be detected but not restored; the alert then says which formula to reinstall.

**The baseline changes only on purpose.**
- *Maintenance window.* `brew-guarded` runs `sudo snapback.py window open --pid $$` before a changing brew command. Only processes descended from that wrapper, with brew in their attested chain, may write. The window closes the moment the wrapper exits, even if the terminal is closed mid-upgrade. When it closes, only the paths brew was seen touching are accepted, and the next scan reverts anything else. If events were dropped during the window, everything under the window's rules is accepted (so a real upgrade isn't broken) and a warning lists the files accepted without attribution. Scans of other rules keep running during a window.
- *Allowed tools outside a window* (such as `pyenv rehash`). Only the exact paths they touched are re-baselined, a few seconds after they go quiet.
- *`sudo snapback.py baseline`* accepts the current state of everything.

Every re-baseline writes a `rebaselined` record listing the files it added, changed and removed, what triggered it, and which command made the change.

**Housekeeping.** A thread wakes every second. It writes a heartbeat (with event, skip and drop counters and the age of the last event), notices windows closing, runs re-baselines that are due, watches the event stream, and every 120 s compares the protected trees with the vault, re-hashing everything on every 10th scan. A scan also runs at startup.

**Protecting itself.** It runs as root under launchd with `KeepAlive`, so the developer's account can't kill it, and launchd restarts it if root does. Rules, control files and the log are root-only: malware running as the developer can't read the webhook secret, see when a window is open, or edit alerts. `snapback.py stop` is the only quiet way to stop it. Any other SIGTERM sends a `stopped` alert, flushed to the webhook before exit, and leaves a marker. On restart, a marker from the current boot is reported as a critical tamper (killed or stopped), while one from before the boot is just a reboot. Signals and `kill` / `launchctl` commands aimed at it are reported as `tamper_attempt`.

**The log.** `/var/log/snapback.jsonl` (root:wheel 0640) holds one JSON object per line. Records also go to syslog, and to `webhook_url` if set, from a worker thread with retries. With `webhook_secret` set, each POST carries `X-Snapback-Signature: sha256=<HMAC of the body>` so the receiver can reject forgeries. Have the receiver alert when heartbeats stop: that is the only way to notice a watcher that root has removed.

| `type` | Written when |
|---|---|
| `violation` | A rule was broken. `rule_type` says `files`, `exec` or `event`; includes the process chain and actions |
| `drift` | A scan found a change; no process attribution |
| `tamper_attempt` | A signal or command aimed at the watcher, a stalled event stream, or a restart after an unauthorized stop |
| `warning` / `error` | Dropped events, unattributed window changes, eslogger exited or lacks an event type, a handler failed |
| `window` | A maintenance window opened or closed, by whom, bound to which pid |
| `rebaselined` / `baselined` | Changes accepted into the baseline, with the files involved |
| `started` / `stopped` / `stop_authorized` / `started_after_reboot` / `heartbeat` | Lifecycle and liveness |

**Example: the attack.** Say the repo's setup ran from `npm install`. The script creates `/opt/homebrew/Cellar/pyenv/2.8.0/libexec/pyenv_`. No window is open and brew isn't in its chain, so this is a violation. The script, its shell and `npm` are frozen and killed, `pyenv_` is quarantined, and any later steps that already landed are reverted. If the trojan had been swapped in faster than that, the shell init that runs `pyenv` would be killed at exec, because the file no longer matches the vault. `log-viewer.html` ships with this scenario as its sample data.

## Install and test

```bash
sudo bash install.sh
sudo tail -f /var/log/snapback.jsonl      # watch for "started" and heartbeats
sudo /usr/bin/python3 -I "/Library/Application Support/Snapback/bin/snapback.py" test-alert
```

eslogger needs Full Disk Access for the process that starts it. If `/var/log/snapback.err` shows eslogger exiting with a permission error, grant Full Disk Access to the Python binary it names, then `sudo launchctl kickstart -k system/com.example.snapback`. On a fleet, push a PPPC profile from MDM instead.

To prove it works, set `"mode": "enforce"` in `/Library/Application Support/Snapback/rules.json`, restart it with the `kickstart` command above, then as your normal user:

```bash
bash simulate_attack.sh            # should stop with "Killed: 9" right after the CREATE step
bash simulate_attack.sh --check    # PASS: pyenv matches the pre-attack copy
```

The automated tests need no root and run on macOS or Linux:

```bash
python3 test_snapback.py
```

They cover the post-mortem sequence, windows, the scan backstop, argv spoofing, PATH and env injection, symlink and hard-link tricks, renamed directories, exec-time integrity, the prefilter (including its cost), dropped events, every shipped exec and event rule (positive and benign cases), credential reads, stop authorization and webhook signatures. On macOS they also check that every event the rules need exists in the local `eslogger`.

`com.example.snapback` is a placeholder launchd label. To change it, edit the plist filename and `Label`, `LABEL` in `install.sh`, and `settings.label` plus the self-protection path in `rules.json`.

## Rollout and tuning

Run in `audit` mode first (alerts say `would_kill` / `would_revert` and nothing is touched). After a week of reviewing alerts and adding `exclude` or `allow` entries for legitimate tools, switch to `enforce`. A rule can opt in or out on its own with `"mode"`.

What to expect in audit mode:
- **credential-access** is the noisiest. Every unlisted reader of a key, token or cookie store alerts: your own boto3 scripts, a Python-based CLI from a cask, a backup agent. Allow tools by signing identity (`"TEAMID:signing.id"`, see `codesign -dv <binary>`) or by path when they live in a protected tree. Don't allow an interpreter by itself (`python`, `node`, an Electron app's helper): that allows every script it runs, including a malicious VS Code extension.
- **developer-tool-hooks** fires when you edit your git, ssh, npm or AI-tool config yourself. That's expected; it only alerts.
- **python-startup-hooks** fires when `pip` installs a package that ships a `.pth` file.
- **exec rules** match command lines, so expect the odd hit from install scripts (`curl … | bash`) and from your own use of `xattr -d com.apple.quarantine`.

Things that `enforce` mode will stop until you adjust for them: `npm install -g` while npm's prefix is in `/opt/homebrew` (use `npm config set prefix ~/.npm-global`), `pip install --break-system-packages` into Homebrew's Python, brew run outside `brew-guarded` (including `brew autoupdate` from launchd), and any manual edits under the protected paths.

## Day-to-day use

Homebrew's own changes are only accepted inside a maintenance window, which needs sudo, so a background script can't open one. The wrapper handles this:

```bash
alias brew='/Library/Application\ Support/Snapback/bin/brew-guarded'
```

Other commands (all need sudo; run them as `sudo /usr/bin/python3 -I "/Library/Application Support/Snapback/bin/snapback.py" …`):

```bash
snapback.py window open 30 --pid <pid>   # manual window, bound to a process
snapback.py window close                 # accept what changed, re-baseline
snapback.py baseline                     # accept the current state (e.g. after a reinstall)
snapback.py verify                       # report drift without changing anything; exit 1 if any
snapback.py status                       # mode, window, rules, events subscribed
snapback.py test-alert                   # check the log, syslog and webhook path
snapback.py stop                         # stop without a tamper alert
```

To review alerts, copy the log out (`sudo cp /var/log/snapback.jsonl ~/Desktop/`) and open `log-viewer.html` in a browser. The page makes no network requests and shows log content as plain text only. Each incident lists what was killed, restored and quarantined, the process chain, where the evidence was saved, and what to do next.

## What "can't be killed" means here

Against the developer's account, and malware running as it, the watcher can't be killed or reconfigured: it runs as root, and its rules and control files are root-only. Against an admin using sudo, it can be stopped, but not quietly. An unauthorized stop is alerted (flushed to the webhook before exit), launchd restarts it within about five seconds, the restart is reported as critical, a startup scan reverts anything changed meanwhile, and a stopped heartbeat is visible to whoever collects it. `launchctl bootout` can still remove it for good; only the missing heartbeat shows that.

Making it unkillable even by root requires Apple's Endpoint Security entitlement: an ES system extension can deny signals aimed at itself, and MDM can mark it non-removable. Commercial EDRs and Santa protect themselves that way, and a script can't.

## Limits

**It reacts; it does not block.** eslogger only reports events after they happen. The watcher kills and reverts within milliseconds, and kills a tampered binary when it runs, but the first malicious write always succeeds. So does anything the script does outside the protected paths before its first violation, such as reading a token. Credential reads are *alerted*, not prevented, and by then the data has been read.

To deny operations up front, add an Endpoint Security AUTH client. The practical choice is [Santa](https://northpole.dev) with File Access Authorization rules, deployed by MDM. The same ideas carry over: allow writes under `/opt/homebrew` only by brew's Ruby, allow reads of `~/.ssh/id_*` only by `platform:com.apple.ssh*`, and deny everything else. A starting point to check against Santa's FAA documentation for your version:

```xml
<key>WatchItems</key>
<dict>
  <key>SSHKeys</key>
  <dict>
    <key>Paths</key>
    <array><dict><key>Path</key><string>/Users/*/.ssh/id_*</string><key>IsPrefix</key><false/></dict></array>
    <key>Options</key>
    <dict>
      <key>AllowReadAccess</key><false/>
      <key>AuditOnly</key><true/>   <!-- flip to false once the allow list is right -->
      <key>RuleType</key><string>PathsWithAllowedProcesses</string>
    </dict>
    <key>Processes</key>
    <array>
      <dict><key>SigningID</key><string>com.apple.ssh</string><key>PlatformBinary</key><true/></dict>
      <dict><key>SigningID</key><string>com.apple.ssh-agent</string><key>PlatformBinary</key><true/></dict>
      <dict><key>SigningID</key><string>com.apple.ssh-add</string><key>PlatformBinary</key><true/></dict>
    </array>
  </dict>
</dict>
```

Keep Snapback alongside it for what Santa doesn't do here: reverting and quarantining, exec-time integrity against a known-good vault, and the alert history.

**Allowing script tools is still the weak point.** Allow decisions use kernel-attested identity, pid-bound windows and environment checks, but brew and pyenv are scripts that read configuration the developer controls. A malicious formula, tap or brew environment file runs as brew. The robust fix is to make `/opt/homebrew` unwritable by the developer: a dedicated `brew` account, which the rules already allow if it exists.

**The sudo prompt itself is a target.** An attacker who can edit `~/.zshrc` (alert-only) can alias `brew` to a fake wrapper that phishes the sudo password. If the developer is an admin, a cached sudo timestamp in the same terminal is also usable by a script. Treat any `shell-startup-files` alert as serious, and consider standard (non-admin) accounts with privilege elevation on request.

**Exec rules match command lines, which attackers control.** They catch common tooling (stealers, copy-pasted reverse shells) and are trivial to evade for someone who expects them. Treat them as tripwires, not a boundary.

**Interpreters launder identity.** A credential read by Homebrew's `python3` running the AWS CLI looks the same as one by `python3` running a stealer, unless the script itself sits in a protected tree. Expect to allow some tools by path and to review the rest.

**The first baseline trusts the machine as it is.** Install on a machine you have reason to believe is clean, or reinstall Homebrew first.

**Not covered:** network connections (macOS has no notify event for them; use a Network Extension firewall), clipboard and screen access beyond the TCC-grant event, pyc poisoning of Python packages in `__pycache__` (alert-only under Homebrew because Python writes these lazily), and anything outside the configured paths.

**eslogger's JSON format is not a stable API**, and Apple says so. The parser is tolerant and the prefilter falls back to full parsing, but after macOS upgrades check `sudo eslogger rename | head -n 1`, and run the test suite, which verifies the event names. Granting Full Disk Access to Apple's shared Python also grants it to any other launchd job using the same interpreter. For anything beyond a pilot, ship the watcher as a signed binary or, better, as an ES system extension, and grant access to that alone.

## License

MIT. See [LICENSE](LICENSE). This is a prototype provided as is, without warranty. Run it on a test machine first.
