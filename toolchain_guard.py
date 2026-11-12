#!/usr/bin/env python3
"""toolchain-guard: a root watcher for macOS that detects, stops and undoes what an
attacker running as the developer does to a dev machine: tampering with toolchains
(Homebrew, pyenv, PATH), persistence (launch agents, login items, shell and AI-tool
startup files), credential theft, and well-known attack commands.

How it works
  * Reads Endpoint Security events from Apple's `eslogger` (macOS 13+).
  * Matches file events, exec events and system events (login items, TCC grants,
    account changes, remote logins...) against rules.json.
  * On a violation it can freeze and kill the offending script's process tree,
    restore touched files from a root-owned vault of known-good copies, quarantine
    whatever the attacker wrote, and raise an alert (log, syslog, signed webhook).
  * Executables under protected trees are checked against the vault when they run,
    so a tampered binary is killed even if it runs before the revert lands.
  * A periodic scan compares the protected trees with the vault, as a backstop for
    anything the event stream missed. Dropped events trigger an immediate scan.

Security properties this code relies on
  * Allow decisions use kernel-attested facts only: the executable and script paths
    from exec events, code-signing identity, platform-binary flag. Never argv.
  * Every file operation in a user-writable directory goes through directory file
    descriptors with O_NOFOLLOW, so planted symlinks cannot redirect root writes.

What it cannot do (see README.md)
  * eslogger only *notifies*; it cannot deny an operation. Kill-and-revert happens
    milliseconds after the fact. Denying up front needs an Endpoint Security AUTH
    client (Santa, an EDR, or your own signed system extension).
  * It runs as root, so the developer's account cannot stop it; root can, and that
    is reported but cannot be prevented without Apple's ES entitlement.

Standard library only, Python 3.7+. Never run it with a Python or tools from
/opt/homebrew: that is exactly what it is guarding.
"""

import argparse
import errno
import fnmatch
import hashlib
import hmac
import json
import os
import pwd
import queue
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.request

try:
    import syslog
except ImportError:  # pragma: no cover
    syslog = None

HOME_DIR = "/Library/Application Support/ToolchainGuard"
DEFAULT_RULES = os.path.join(HOME_DIR, "rules.json")
DATA_VOLUME = "/System/Volumes/Data"

FILE_EVENTS = ["create", "rename", "unlink", "link", "close", "clone", "copyfile",
               "exchangedata", "setmode", "setowner", "truncate", "utimes", "open"]
PROCESS_EVENTS = ["exec", "fork", "exit", "signal"]
FWRITE = 0x2  # kernel FFLAGS bit in open events

# Process families treated as "part of the script" when deciding what to kill.
INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "fish", "python",
                "perl", "ruby", "node", "bun", "deno", "php", "lua", "tclsh", "expect",
                "osascript", "env", "xargs", "nohup", "timeout", "npm", "npx", "pnpm",
                "yarn", "pip", "pipx", "uv", "poetry", "make", "java", "swift", "go",
                "cargo", "git", "awk", "gawk", "pwsh", "julia", "rscript", "gem",
                "bundle", "rake"}
# General-purpose platform tools that read or ship arbitrary files. A platform
# binary is "trusted" for credential reads only if it is not one of these.
TOOLS = INTERPRETERS | {
    "cat", "cp", "mv", "ditto", "zip", "unzip", "tar", "bsdtar", "gzip", "bzip", "xz",
    "rsync", "scp", "sftp", "ftp", "curl", "wget", "nc", "ncat", "socat", "base",
    "openssl", "sqlite", "dd", "head", "tail", "less", "more", "vi", "vim", "nano",
    "strings", "xxd", "hexdump", "od", "plutil", "defaults", "security", "pbcopy",
    "grep", "egrep", "fgrep", "sed", "find", "tee", "mail", "split", "cpio", "pax",
    "hdiutil", "textutil", "lldb", "ln", "install", "rm", "chmod", "chown", "touch",
    "mkdir", "screencapture", "file", "diff", "cmp", "shasum", "md", "cksum"}
# A shell whose parent's name contains one of these is the user's own terminal
# session. The kill walk stops below it and never kills it (unless the rule or a
# remote session asks for session scope).
SESSION_PARENTS = ("login", "sshd", "terminal", "iterm", "tmux", "screen",
                   "code helper", "cursor helper", "warp", "wezterm",
                   "alacritty", "kitty", "ghostty", "hyper", "tabby")
NEVER_KILL = {"launchd", "kernel_task", "loginwindow", "windowserver", "login",
              "sshd", "sshd-session", "terminal", "iterm2", "finder", "dock",
              "systemuiserver", "securityd", "opendirectoryd", "logind", "configd"}

# Environment variables that inject code into the named interpreter family. An
# allowed tool started with one of these is not trusted (it may run attacker code).
TAINT_ALWAYS = {"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
                "LD_PRELOAD", "LD_LIBRARY_PATH"}
TAINT_SHELL = {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND", "ZDOTDIR"}
TAINT_BY_FAMILY = {
    "python": {"PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE"},
    "perl": {"PERL5OPT", "PERL5LIB", "PERLLIB"},
    "ruby": {"RUBYOPT", "RUBYLIB"},
    "node": {"NODE_OPTIONS", "NODE_PATH"},
}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "fish", "env"}
SYSTEM_HOOK_DIRS = ("/usr/local/etc/pyenv.d", "/etc/pyenv.d", "/private/etc/pyenv.d",
                    "/usr/lib/pyenv/hooks")

O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


# --------------------------------------------------------------------------- helpers

def norm(path):
    """Normalise an ES path: drop the Data-volume firmlink prefix."""
    if path.startswith(DATA_VOLUME + "/"):
        path = path[len(DATA_VOLUME):]
    return os.path.normpath(path)


def under(path, root):
    return path == root or path.startswith(root + "/")


def short_name(info):
    exe = (info or {}).get("path") or ""
    args = (info or {}).get("args") or []
    name = os.path.basename(exe) or (os.path.basename(args[0]) if args else "")
    return name.lstrip("-")


def family(name):
    """'python3.9' -> 'python', 'perl5.30' -> 'perl'."""
    return re.sub(r"[\d.]+$", "", (name or "").lower())


def iso_now():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def local_users():
    seen, users = set(), []
    for pw in pwd.getpwall():
        if (pw.pw_uid >= 500 and pw.pw_name not in seen
                and pw.pw_dir.startswith("/Users/") and os.path.isdir(pw.pw_dir)):
            seen.add(pw.pw_name)
            users.append(pw)
    return users


def expand_home(items, users):
    out = []
    for item in items:
        if item.startswith("~/"):
            out.extend(os.path.join(u.pw_dir, item[2:]) for u in users)
        else:
            out.append(item)
    return out


def real_parent(path):
    """Resolve symlinks in the parent of `path` but keep the leaf, the way ES
    reports paths (/etc/zshrc -> /private/etc/zshrc, /var/x -> /private/var/x)."""
    path = norm(path)
    parent = os.path.dirname(path)
    if parent in ("", "/"):
        return path
    return os.path.join(os.path.realpath(parent), os.path.basename(path))


def compile_globs(patterns):
    """One regex for a list of fnmatch globs (None for an empty list)."""
    patterns = list(patterns)
    if not patterns:
        return None
    return re.compile("|".join("(?:%s)" % fnmatch.translate(p) for p in patterns))


def ancestors(path):
    out, p = [], os.path.dirname(path)
    while p not in ("", "/"):
        out.append(p)
        p = os.path.dirname(p)
    return out


PATH_PAIRS = (("filename", "dir"), ("target_filename", "target_dir"), ("target_name", "target_dir"))


def extract_paths(obj, out):
    """Collect every path named in an eslogger event payload.

    Handles {"path": ...} file objects and {"dir": {...}, "filename": ...} style
    new-path objects wherever they are nested, so it does not depend on the exact
    layout of each event type."""
    if isinstance(obj, dict):
        p = obj.get("path")
        if isinstance(p, str) and p.startswith("/"):
            out.add(norm(p))
        skip = {"stat", "audit_token", "parent_dir"}  # parent dirs are context, not targets
        for fkey, dkey in PATH_PAIRS:
            fn, d = obj.get(fkey), obj.get(dkey)
            if isinstance(fn, str) and isinstance(d, dict) and isinstance(d.get("path"), str):
                out.add(norm(os.path.join(d["path"], fn)))
                skip.add(dkey)
        for k, v in obj.items():
            if k not in skip:
                extract_paths(v, out)
    elif isinstance(obj, list):
        for v in obj:
            extract_paths(v, out)
    return out


def replaces_existing(rename_payload):
    """True when a rename lands on top of a file that already existed."""
    dt = rename_payload.get("destination_type")
    if dt is not None:
        return dt == 0  # ES_DESTINATION_TYPE_EXISTING_FILE
    return "existing_file" in (rename_payload.get("destination") or {})


def rename_paths(payload):
    """(source, destination) of a rename event."""
    src = (payload.get("source") or {}).get("path")
    dest = payload.get("destination") or {}
    dst = (dest.get("existing_file") or {}).get("path")
    if not dst:
        np = dest.get("new_path") or {}
        d, fn = (np.get("dir") or {}).get("path"), np.get("filename")
        if d and fn:
            dst = os.path.join(d, fn)
    return (norm(src) if src else None), (norm(dst) if dst else None)


def proc_info(p):
    """Kernel-attested fields from an eslogger process object."""
    p = p or {}
    tok = p.get("audit_token") or {}
    ptok = p.get("parent_audit_token") or {}
    exe = (p.get("executable") or {}).get("path") or ""
    plat = p.get("is_platform_binary")
    return {
        "pid": tok.get("pid", p.get("pid")),
        "ppid": ptok.get("pid", p.get("ppid")),
        "oppid": p.get("original_ppid"),
        "euid": tok.get("euid", p.get("euid")),
        "path": norm(exe) if exe else "",
        "platform": bool(plat) if plat is not None else None,
        "signing_id": p.get("signing_id") or None,
        "team_id": p.get("team_id") or None,
    }


def diff_entries(old, new, limit=200):
    """What a rebaseline accepted: paths added, changed and removed, for the
    edit history in the log. Lists are capped at `limit`; counts are exact."""
    def sig(e):
        return (e.get("t"), e.get("sha"), e.get("link"), e.get("mode"), e.get("uid"), e.get("gid"))
    lists = {"added": sorted(p for p in new if p not in old),
             "changed": sorted(p for p in new if p in old and sig(new[p]) != sig(old[p])),
             "removed": sorted(p for p in old if p not in new)}
    out = {k: v[:limit] for k, v in lists.items()}
    out["counts"] = {k: len(v) for k, v in lists.items()}
    out["truncated"] = any(len(v) > limit for v in lists.values())
    return out


def reinstall_hint(path):
    if "/Cellar/" in path:
        formula = path.split("/Cellar/", 1)[1].split("/", 1)[0]
        return f"no vault copy; run: brew reinstall {formula}"
    return "no vault copy; reinstall the tool that owns this file"


def pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (TypeError, ValueError, OSError):
        return False


def boot_time():
    try:
        out = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.boottime"], capture_output=True,
                             text=True, timeout=5).stdout
        m = re.search(r"sec\s*=\s*(\d+)", out)
        if m:
            return float(m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except OSError:
        pass
    return None


DROP_KEYS = {"stat", "audit_token", "parent_audit_token", "responsible_audit_token",
             "cdhash", "codesigning_flags", "start_time", "thread", "tty"}


def flatten(obj, prefix="", out=None, depth=0):
    """{"a": {"b": True}} -> {"a.b": "true"}, for matching event rules."""
    out = {} if out is None else out
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k not in DROP_KEYS:
                flatten(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            flatten(v, f"{prefix}.{i}", out, depth + 1)
    elif isinstance(obj, bool):
        out[prefix] = "true" if obj else "false"
    elif obj is not None:
        out[prefix] = str(obj)
    return out


def summarize_payload(obj, depth=0):
    """A compact copy of an event payload for an alert record."""
    if depth > 5:
        return "..."
    if isinstance(obj, dict):
        return {k: summarize_payload(v, depth + 1) for k, v in obj.items() if k not in DROP_KEYS}
    if isinstance(obj, list):
        return [summarize_payload(v, depth + 1) for v in obj[:20]]
    if isinstance(obj, str) and len(obj) > 300:
        return obj[:300] + "..."
    return obj


# --------------------------------------------------------------------------- safe file operations
#
# The daemon runs as root and repairs files inside directories the developer
# (and so the attacker) can write to. Every operation there resolves the parent
# directory one component at a time with O_NOFOLLOW and then acts relative to
# that directory descriptor, so a planted symlink anywhere in the path makes the
# operation fail instead of landing somewhere else.

class UnsafePath(OSError):
    """A path component is a symlink (or not a directory) where a real directory
    was expected."""


def _open_dir_chain(parts):
    fd = os.open("/", os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    try:
        walked = ""
        for comp in parts:
            walked += "/" + comp
            try:
                nfd = os.open(comp, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                              dir_fd=fd)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                    raise UnsafePath(e.errno, "not a real directory", walked)
                raise
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


class ParentDir:
    """with ParentDir(path) as pd: act on pd.name relative to pd.fd."""

    def __init__(self, path):
        path = os.path.normpath(path)
        if not path.startswith("/") or path == "/":
            raise ValueError(f"not an absolute file path: {path!r}")
        parts = path.strip("/").split("/")
        self.name = parts[-1]
        self.parts = parts[:-1]
        self.fd = None

    def __enter__(self):
        self.fd = _open_dir_chain(self.parts)
        return self

    def __exit__(self, *exc):
        os.close(self.fd)


def safe_lstat(path):
    with ParentDir(path) as pd:
        return os.stat(pd.name, dir_fd=pd.fd, follow_symlinks=False)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _open_nofollow_at(dir_fd, name, want_dir=False):
    flags = os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (O_DIRECTORY if want_dir else 0)
    return os.open(name, flags, dir_fd=dir_fd)


def safe_walk(root, prune=None):
    """Yield (path, dir_fd, name, lstat) for root and everything below it.
    Never follows symlinks, never blocks on FIFOs. dir_fd is valid only until the
    generator is advanced."""
    try:
        pd = ParentDir(root).__enter__()
    except (OSError, ValueError):
        return
    try:
        try:
            st = os.stat(pd.name, dir_fd=pd.fd, follow_symlinks=False)
        except OSError:
            return
        yield root, pd.fd, pd.name, st
        if stat.S_ISDIR(st.st_mode):
            yield from _walk_dir(pd.fd, pd.name, root, st, prune)
    finally:
        os.close(pd.fd)


def _walk_dir(parent_fd, name, path, st, prune):
    try:
        fd = _open_nofollow_at(parent_fd, name, want_dir=True)
    except OSError:
        return
    try:
        fst = os.fstat(fd)
        if (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            return  # swapped while we looked
        try:
            names = os.listdir(fd)
        except OSError:
            return
        for n in sorted(names):
            p = path + "/" + n
            if prune and prune(p):
                continue
            try:
                cst = os.stat(n, dir_fd=fd, follow_symlinks=False)
            except OSError:
                continue
            yield p, fd, n, cst
            if stat.S_ISDIR(cst.st_mode):
                yield from _walk_dir(fd, n, p, cst, prune)
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- config

class Allow:
    """Who may make a change. Every identity check uses kernel-attested data."""

    def __init__(self, raw, users):
        raw = raw or {}
        self.uids = set()
        for name in raw.get("users", []):
            try:
                self.uids.add(pwd.getpwnam(name).pw_uid)
            except KeyError:
                pass  # e.g. the dedicated "brew" account isn't set up on this machine
        self.paths = [norm(p) for p in expand_home(raw.get("ancestor_paths", []), users)]
        self.regex = [re.compile(r) for r in raw.get("ancestor_regex", [])]
        self.signing = []
        for item in raw.get("signing_ids", []):
            team, _, sid = item.partition(":")
            if team and sid:
                self.signing.append((team, sid))
        self.platform = raw.get("platform_binaries")  # None, "all" or "non_tools"
        self.protected_images = bool(raw.get("protected_images"))
        self.only_in_window = bool(raw.get("only_during_window"))
        self.helpers = bool(raw.get("helpers", True))
        self.has_identity = bool(self.paths or self.regex or self.signing or self.platform
                                 or self.protected_images)


class Rule:
    def __init__(self, raw, users, default_mode):
        self.id = raw["id"]
        self.type = raw.get("type", "files")
        self.description = raw.get("description", "")
        self.severity = raw.get("severity", "high")
        self.mode = raw.get("mode") or default_mode
        self.paths = [real_parent(p) for p in expand_home(raw.get("paths", []), users)]
        self.excludes = [norm(p) for p in expand_home(raw.get("exclude", []), users)]
        self.includes = list(expand_home(raw.get("include", []), users))
        self.actions = set(raw.get("actions", ["alert"]))
        self.access = raw.get("access", "write")  # "write" or "read" (any open)
        if self.type == "files":
            if self.access == "read":
                default = ["open"]
            elif self.reverts or "kill" in self.actions:
                default = FILE_EVENTS
            else:
                default = [e for e in FILE_EVENTS if e != "open"]
        else:
            default = []
        self.events = set(raw.get("events") or default)
        self.rename_over_existing_only = bool(raw.get("rename_over_existing_only"))
        self.kill_scope = raw.get("kill_scope", "script")
        self.exec_integrity = bool(raw.get("exec_integrity", True))
        self.allow = Allow(raw.get("allow"), users)
        self.match = {k: re.compile(v) for k, v in (raw.get("match") or {}).items()}
        self.exclude_match = {k: re.compile(v) for k, v in (raw.get("exclude_match") or {}).items()}
        self.root_ancestors = frozenset(a for p in self.paths for a in ancestors(p))
        self._roots = frozenset(self.paths)
        self._prefixes = tuple(self.paths)
        self._exclude_rx = compile_globs(self.excludes)
        self._include_rx = compile_globs(self.includes)

    @property
    def reverts(self):
        return "revert" in self.actions

    @property
    def enforce(self):
        return self.mode == "enforce"

    def excluded(self, path):
        return self._exclude_rx is not None and self._exclude_rx.match(path) is not None

    def _under_root(self, path):
        if not path.startswith(self._prefixes):
            return False
        p = path
        while p and p != "/":
            if p in self._roots:
                return True
            p = os.path.dirname(p)
        return False

    def covers(self, path):
        if not self._under_root(path) or self.excluded(path):
            return False
        return self._include_rx is None or self._include_rx.match(path) is not None

    # exec rules: keys executable / script / args, each a regex
    def exec_matches(self, exe, script, cmd):
        fields = {"executable": exe or "", "script": script or "", "args": cmd or ""}
        if not self.match:
            return False
        if not all(rx.search(fields.get(k, "")) for k, rx in self.match.items()):
            return False
        return not any(rx.search(fields.get(k, "")) for k, rx in self.exclude_match.items())

    # event rules: keys are dotted suffixes into the flattened payload
    @staticmethod
    def _field_hit(flat, key, rx):
        return any((k == key or k.endswith("." + key)) and rx.search(v) for k, v in flat.items())

    def event_matches(self, flat):
        if not all(self._field_hit(flat, k, rx) for k, rx in self.match.items()):
            return False
        return not any(self._field_hit(flat, k, rx) for k, rx in self.exclude_match.items())


class Config:
    def __init__(self, path):
        with open(path) as f:
            raw = json.load(f)
        s = raw.get("settings", {})
        self.path = path
        self.home = s.get("home_dir", HOME_DIR)
        self.vault_dir = os.path.join(self.home, "vault")
        self.quarantine_dir = os.path.join(self.home, "quarantine")
        self.control_dir = os.path.join(self.home, "control")
        self.mode = s.get("mode", "enforce")  # "enforce" or "audit"
        self.label = s.get("label", "com.example.toolchain-guard")
        self.log_file = s.get("log_file", "/var/log/toolchain-guard.jsonl")
        self.webhook_url = s.get("webhook_url") or None
        self.webhook_secret = s.get("webhook_secret") or None
        self.scan_interval = float(s.get("scan_interval_seconds", 120))
        self.deep_every = max(1, int(s.get("deep_scan_every", 10)))
        self.heartbeat_interval = float(s.get("heartbeat_seconds", 60))
        self.settle = float(s.get("rebaseline_settle_seconds", 5))
        self.max_store = int(s.get("vault_max_file_bytes", 5 * 1024 * 1024))
        self.eslogger = s.get("eslogger_path", "/usr/bin/eslogger")
        self.window_close_mode = s.get("window_close_rebaseline", "touched")  # or "full"
        self.stall_seconds = float(s.get("stream_stall_seconds", 60))
        self.kill_remote_sessions = bool(s.get("kill_remote_sessions", True))
        self.dedupe_seconds = float(s.get("alert_dedupe_seconds", 30))
        self.syslog = bool(s.get("syslog", True))
        users = local_users()
        self.rules = [Rule(r, users, self.mode) for r in raw.get("rules", [])]
        self.file_rules = [r for r in self.rules if r.type == "files"]
        self.exec_rules = [r for r in self.rules if r.type == "exec"]
        self.event_rules = [r for r in self.rules if r.type == "event"]
        self.file_event_names = set()
        for r in self.file_rules:
            self.file_event_names |= r.events
        self.event_rule_events = set()
        for r in self.event_rules:
            self.event_rule_events |= r.events
        explicit = s.get("eslogger_events")
        if explicit:
            self.events = list(explicit)
        else:
            wanted = PROCESS_EVENTS + [e for e in FILE_EVENTS if e in self.file_event_names]
            wanted += sorted(self.event_rule_events - set(wanted))
            self.events = wanted


# --------------------------------------------------------------------------- event prefilter

class Prefilter:
    """Decides from the raw JSON line whether an event is worth json.loads.

    Most events on a dev machine (file opens and closes in caches, browsers, IDE
    indexes) have nothing to do with the rules. Parsing each one in Python would
    make the watcher fall behind under load, and eslogger then drops events.
    Process events and system-event rules are always parsed. File events are
    parsed only if one of their target paths (not the process's own executable)
    falls under a protected root. Anything it cannot understand is parsed."""

    KEY_RE = re.compile(r'"event"\s*:\s*\{\s*"([a-z_]+)"')
    PATH_RE = re.compile(r'"path"\s*:\s*"((?:[^"\\]|\\.)*)"')
    EXE_RE = re.compile(r'"executable"\s*:\s*\{\s*$')
    UNMODIFIED_RE = re.compile(r'"modified"\s*:\s*false')
    MAPPED_RE = re.compile(r'"was_mapped_writable"\s*:\s*true')

    def __init__(self, roots, exact, always, file_events):
        """roots: [(root, include_globs)], where an empty include list means
        everything under the root counts."""
        merged = {}
        for root, inc in roots:
            if root in merged and (not merged[root] or not inc):
                merged[root] = []
            else:
                merged[root] = list(merged.get(root, [])) + list(inc)
        self.roots = {r: compile_globs(inc) for r, inc in merged.items()}
        self.prefixes = tuple(sorted(self.roots))
        self.exact = frozenset(exact)
        self.always = frozenset(always)
        self.file_events = frozenset(file_events)

    def _covered(self, s):
        p = s
        while p and p != "/":
            if p in self.roots:
                rx = self.roots[p]
                if rx is None or rx.match(s):
                    return True
            p = os.path.dirname(p)
        return False

    CREATES = frozenset(("create", "rename", "link", "clone", "copyfile"))

    def _hit(self, s, name):
        if "\\" in s:
            s = s.replace("\\/", "/")
            if "\\" in s:
                try:
                    s = json.loads('"' + s + '"')
                except ValueError:
                    return True
        if s.startswith(DATA_VOLUME + "/"):
            s = s[len(DATA_VOLUME):]
        if s in self.exact:
            return True
        if not s.startswith(self.prefixes):
            return False
        # inside a root: covered, or a directory whose new file's name is elsewhere
        return name in self.CREATES or self._covered(s)

    def wants(self, line):
        """Fast path: eslogger's compact JSON, scanned with str.find only."""
        i = line.find('"event":{"')
        if i < 0:
            return self._wants_slow(line)
        j = line.find('"', i + 10)
        name = line[i + 10:j]
        if name in self.always:
            return True
        if name not in self.file_events:
            return False
        if name == "close" and '"modified":false' in line and '"was_mapped_writable":true' not in line:
            return False
        pos = 0
        while True:
            k = line.find('"path":"', pos)
            if k < 0:
                return False
            start = k + 8
            end = line.find('"', start)
            if end < 0 or line[end - 1] == "\\":
                return self._wants_slow(line)  # escaped quote in a path: let the regex handle it
            pos = end + 1
            if line.endswith('"executable":{', 0, k):
                continue  # the acting process's own binary, not a target
            if self._hit(line[start:end], name):
                return True

    def _wants_slow(self, line):
        m = self.KEY_RE.search(line)
        if not m:
            return True
        name = m.group(1)
        if name in self.always:
            return True
        if name not in self.file_events:
            return False
        if name == "close" and self.UNMODIFIED_RE.search(line) and not self.MAPPED_RE.search(line):
            return False
        for pm in self.PATH_RE.finditer(line):
            if self.EXE_RE.search(line, max(0, pm.start() - 40), pm.start()):
                continue  # the acting process's own binary, not a target
            if self._hit(pm.group(1), name):
                return True
        return False


# --------------------------------------------------------------------------- processes

class ProcTable:
    """pid -> what we know about the process, built from ES events (attested) and
    ps (not attested: argv can be rewritten by the process itself)."""

    def __init__(self):
        self.procs = {}
        self.exited = {}
        self._last_ps = 0.0

    def _entry(self, pid):
        return self.procs.setdefault(pid, {
            "ppid": None, "oppid": None, "path": "", "script": None, "args": [], "euid": None,
            "platform": None, "signing_id": None, "team_id": None, "taint": None, "src": "ps"})

    def note_es(self, info):
        """Update from the `process` object of any ES event."""
        pid = info.get("pid")
        if pid is None:
            return
        e = self._entry(pid)
        if info.get("path") and e["src"] == "es" and e["path"] and info["path"] != e["path"]:
            e.update(script=None, args=[], taint=None)  # image changed; we missed the exec
        for k in ("ppid", "oppid", "euid", "platform", "signing_id", "team_id"):
            if info.get(k) is not None:
                e[k] = info[k]
        if info.get("path"):
            e["path"] = info["path"]
            e["src"] = "es"
        self.exited.pop(pid, None)

    def note_exec(self, info, script, args, taint):
        e = self._entry(info["pid"])
        for k in ("ppid", "oppid", "euid"):
            if info.get(k) is not None:
                e[k] = info[k]
        e.update(path=info.get("path") or e["path"], script=script,
                 args=args if args is not None else [], taint=taint,
                 platform=info.get("platform"), signing_id=info.get("signing_id"),
                 team_id=info.get("team_id"), src="es")
        self.exited.pop(info["pid"], None)

    def note_fork(self, child, parent_pid):
        cpid = child.get("pid")
        if cpid is None:
            return
        parent = self.procs.get(parent_pid) or {}
        e = self._entry(cpid)
        for k in ("path", "script", "args", "taint", "platform", "signing_id", "team_id", "src"):
            if k in parent:
                e[k] = parent[k]
        e["ppid"] = parent_pid
        e["oppid"] = child.get("oppid") or parent_pid
        if child.get("euid") is not None:
            e["euid"] = child["euid"]
        if child.get("path"):
            e["path"], e["src"] = child["path"], "es"
        self.exited.pop(cpid, None)

    def refresh(self, force=False):
        if not force and time.time() - self._last_ps < 0.5:
            return
        self._last_ps = time.time()
        try:
            out = subprocess.run(["/bin/ps", "-A", "-o", "pid=,ppid=,uid=,args="],
                                 capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return
        for line in out.splitlines():
            parts = line.split(None, 3)
            if len(parts) < 3:
                continue
            try:
                pid, ppid, uid = int(parts[0]), int(parts[1]), int(parts[2])
            except ValueError:
                continue
            args = parts[3].split() if len(parts) > 3 else []
            e = self.procs.get(pid)
            if e:
                e["ppid"] = ppid  # follow re-parenting; keep attested data
            else:
                e = self._entry(pid)
                e.update(ppid=ppid, path=args[0] if args else "", args=args, euid=uid)

    def get(self, pid):
        if pid not in self.procs:
            self.refresh()
        return self.procs.get(pid)

    def chain(self, pid, depth=16):
        out, seen = [], set()
        while pid and pid not in seen and len(out) < depth:
            seen.add(pid)
            info = self.get(pid)
            if not info:
                break
            out.append((pid, info))
            nxt = info.get("ppid")
            if (not nxt or nxt <= 1) and info.get("oppid") and info["oppid"] > 1:
                nxt = info["oppid"]  # daemonized: follow the original parent
            pid = nxt
        return out

    def descendants(self, roots):
        """Live and recently exited descendants, following both the current parent
        and the original parent (so double-forked daemons are still found)."""
        kids = {}
        for pid, info in self.procs.items():
            for parent in {info.get("ppid"), info.get("oppid")}:
                if parent:
                    kids.setdefault(parent, set()).add(pid)
        out, todo = set(), list(roots)
        while todo:
            for child in kids.get(todo.pop(), ()):
                if child not in out and child not in roots:
                    out.add(child)
                    todo.append(child)
        return out

    def exit(self, pid):
        if pid is not None:
            self.exited[pid] = time.time()

    def purge(self, age=120):
        cutoff = time.time() - age
        for pid, t in list(self.exited.items()):
            if t < cutoff:
                self.exited.pop(pid, None)
                self.procs.pop(pid, None)


# --------------------------------------------------------------------------- alerts

SYSLOG_PRIO = {"critical": "LOG_CRIT", "high": "LOG_ERR", "medium": "LOG_WARNING"}


class Alerter:
    """Writes every record to the local log synchronously; sends it to syslog and
    to the webhook from a worker thread with retries. flush() before exiting."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.RLock()  # re-entrant: the SIGTERM handler may emit mid-emit
        self.host = socket.gethostname()
        self.q = queue.Queue(maxsize=5000)
        self.dropped = 0
        self.failed = 0
        self._worker = None
        self.use_syslog = bool(syslog) and cfg.syslog
        if self.use_syslog:
            syslog.openlog("toolchain-guard", syslog.LOG_PID, syslog.LOG_AUTH)

    def emit(self, record, remote=True):
        record = dict(record)
        record.setdefault("ts", iso_now())
        record["host"] = self.host
        line = json.dumps(record, sort_keys=True, default=str)
        with self.lock:
            try:
                fd = os.open(self.cfg.log_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT | O_CLOEXEC, 0o640)
                with os.fdopen(fd, "a") as f:
                    f.write(line + "\n")
            except OSError as e:
                sys.stderr.write(f"toolchain-guard: cannot write log: {e}\n{line}\n")
        if not remote:
            return
        if self.use_syslog and record.get("type") != "heartbeat":
            prio = getattr(syslog, SYSLOG_PRIO.get(record.get("severity"), "LOG_NOTICE"))
            try:
                syslog.syslog(prio, line[:900])
            except (OSError, ValueError):
                pass
        if self.cfg.webhook_url:
            self._ensure_worker()
            try:
                self.q.put_nowait(line)
            except queue.Full:
                self.dropped += 1

    def _ensure_worker(self):
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(target=self._run, daemon=True)
            self._worker.start()

    def _run(self):
        while True:
            line = self.q.get()
            try:
                for attempt in range(3):
                    if self._post(line):
                        break
                    time.sleep(0.5 * (2 ** attempt))
                else:
                    self.failed += 1
            finally:
                self.q.task_done()

    def _post(self, line):
        body = line.encode()
        headers = {"Content-Type": "application/json", "X-ToolchainGuard-Host": self.host}
        if self.cfg.webhook_secret:
            mac = hmac.new(self.cfg.webhook_secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-ToolchainGuard-Signature"] = "sha256=" + mac
        try:
            req = urllib.request.Request(self.cfg.webhook_url, data=body, headers=headers)
            urllib.request.urlopen(req, timeout=5).close()
            return True
        except Exception:  # alerting must never take the watcher down
            return False

    def flush(self, timeout=5.0):
        deadline = time.time() + timeout
        while self.q.unfinished_tasks and time.time() < deadline:
            time.sleep(0.05)


# --------------------------------------------------------------------------- vault

class Vault:
    """Known-good copies of protected files, plus a manifest of what should exist."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.manifest_path = os.path.join(cfg.vault_dir, "manifest.json")
        self.objects = os.path.join(cfg.vault_dir, "objects")
        self.entries = {}
        self.dirty = False
        if os.path.exists(self.manifest_path):
            with open(self.manifest_path) as f:
                self.entries = json.load(f).get("entries", {})

        self._rules = [r for r in cfg.file_rules if r.reverts]
        roots = [(r.id, p) for r in self._rules for p in r.paths]
        self._overlap = any(a != b and (under(pa, pb) or under(pb, pa))
                            for a, pa in roots for b, pb in roots)

    def rules(self):
        return self._rules

    def rule_for(self, path):
        for r in self._rules:
            if r.covers(path):
                return r
        return None

    @staticmethod
    def same_stat(e, st):
        return (e.get("size") == st.st_size and e.get("mtime_ns") == st.st_mtime_ns
                and e.get("ctime_ns") == st.st_ctime_ns and e.get("ino") == st.st_ino)

    @staticmethod
    def _cache_stat(e, st):
        e.update(size=st.st_size, mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns, ino=st.st_ino)

    # ---- hashing and storing, always through an O_NOFOLLOW descriptor
    def hash_at(self, dir_fd, name, st=None, store=False):
        """(sha, stored, fstat) of a regular file, or None if it is not one."""
        try:
            f = _open_nofollow_at(dir_fd, name)
        except OSError:
            return None
        out, tmp = None, None
        try:
            fst = os.fstat(f)
            if not stat.S_ISREG(fst.st_mode):
                return None
            if st is not None and (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
                return None
            if store and fst.st_size <= self.cfg.max_store:
                os.makedirs(self.objects, mode=0o700, exist_ok=True)
                tmp = os.path.join(self.objects, ".tmp-" + secrets.token_hex(8))
                out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o400)
            h = hashlib.sha256()
            while True:
                chunk = os.read(f, 1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                if out is not None:
                    _write_all(out, chunk)
            sha = h.hexdigest()
            dest = os.path.join(self.objects, sha)
            if out is not None:
                os.close(out)
                out = None
                if os.path.exists(dest):
                    os.unlink(tmp)
                else:
                    os.replace(tmp, dest)
                tmp = None
            return sha, os.path.exists(dest), fst
        except OSError:
            return None
        finally:
            os.close(f)
            if out is not None:
                os.close(out)
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)

    def hash_path(self, p):
        try:
            with ParentDir(p) as pd:
                r = self.hash_at(pd.fd, pd.name)
                return r[0] if r else None
        except (OSError, ValueError):
            return None

    # ---- baseline
    def _walk(self, root, rule):
        if rule.excluded(root):
            return iter(())
        return safe_walk(root, prune=rule.excluded)

    def _describe_at(self, dir_fd, name, st, old=None, full=False):
        e = {"mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid}
        try:
            if stat.S_ISLNK(st.st_mode):
                e.update(t="l", link=os.readlink(name, dir_fd=dir_fd))
            elif stat.S_ISDIR(st.st_mode):
                e["t"] = "d"
            elif stat.S_ISREG(st.st_mode):
                e["t"] = "f"
                self._cache_stat(e, st)
                if not full and old and old.get("t") == "f" and self.same_stat(old, st):
                    e["sha"], e["stored"] = old["sha"], old.get("stored", False)
                else:
                    r = self.hash_at(dir_fd, name, st, store=True)
                    if r is None:
                        return None
                    e["sha"], e["stored"] = r[0], r[1]
            else:
                return None
        except OSError:
            return None
        return e

    def describe(self, p, old=None):
        try:
            with ParentDir(p) as pd:
                st = os.stat(pd.name, dir_fd=pd.fd, follow_symlinks=False)
                return self._describe_at(pd.fd, pd.name, st, old)
        except (OSError, ValueError):
            return None

    def baseline(self, full=False, rules=None):
        """Re-read the protected trees. With `rules`, only paths those rules cover
        are re-read; everything else in the manifest is kept."""
        rules = list(rules) if rules else self.rules()
        new = {p: e for p, e in self.entries.items() if not any(r.covers(p) for r in rules)}
        for rule in rules:
            for root in rule.paths:
                for p, fd, name, st in self._walk(root, rule):
                    if p in new or not rule.covers(p):
                        continue
                    e = self._describe_at(fd, name, st, self.entries.get(p), full)
                    if e:
                        new[p] = e
        self.entries = new
        self.save()
        return len(new)

    def accept(self, paths):
        """Re-baseline only the given paths (and their subtrees), so an allowed
        change is accepted without laundering unrelated drift."""
        n, last_dir = 0, None
        for p in sorted(paths):
            if last_dir and under(p, last_dir):
                continue  # already walked as part of an accepted directory
            rule = self.rule_for(p)
            if rule is None:
                continue
            try:
                st = safe_lstat(p)
            except FileNotFoundError:
                for k in [k for k in self.entries if under(k, p)]:
                    del self.entries[k]
                    n += 1
                continue
            except (OSError, ValueError):
                continue
            walked = set()
            for q, fd, name, qst in self._walk(p, rule):
                if not rule.covers(q):
                    continue
                walked.add(q)
                e = self._describe_at(fd, name, qst, self.entries.get(q))
                if e:
                    self.entries[q] = e
                    n += 1
            for k in [k for k in self.entries if under(k, p) and k not in walked]:
                del self.entries[k]
                n += 1
            if stat.S_ISDIR(st.st_mode):
                last_dir = p
            parent = os.path.dirname(p)
            while rule.covers(parent) and parent not in self.entries:
                e = self.describe(parent)
                if e:
                    self.entries[parent] = e
                parent = os.path.dirname(parent)
        self.save()
        return n

    def save(self):
        os.makedirs(self.cfg.vault_dir, mode=0o700, exist_ok=True)
        tmp = self.manifest_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"version": 2, "saved": iso_now(), "entries": self.entries}, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.manifest_path)
        self.dirty = False

    # ---- comparison
    def _content_drift_at(self, dir_fd, name, e, st, deep):
        t = e["t"]
        if t == "l":
            if not stat.S_ISLNK(st.st_mode):
                return True
            try:
                return os.readlink(name, dir_fd=dir_fd) != e["link"]
            except OSError:
                return True
        if t == "d":
            return not stat.S_ISDIR(st.st_mode)
        if not stat.S_ISREG(st.st_mode) or st.st_size != e["size"]:
            return True
        if not deep and self.same_stat(e, st):
            return False
        r = self.hash_at(dir_fd, name, st)
        if r is None or r[0] != e["sha"]:
            return True
        self._cache_stat(e, r[2])  # touched but identical: refresh the stat cache
        self.dirty = True
        return False

    @staticmethod
    def _meta_drift(e, st):
        if e["t"] == "l":
            return False
        return (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) != (e["mode"], e["uid"], e["gid"])

    def image_intact(self, p):
        """True if p is a baselined regular file whose content is unchanged."""
        e = self.entries.get(p)
        if not e or e.get("t") != "f":
            return False
        try:
            with ParentDir(p) as pd:
                st = os.stat(pd.name, dir_fd=pd.fd, follow_symlinks=False)
                return not self._content_drift_at(pd.fd, pd.name, e, st, deep=False)
        except (OSError, ValueError):
            return False

    # ---- repair
    def reconcile(self, p):
        """Make p match the baseline. Returns a list of action records."""
        if self.rule_for(p) is None:
            return []
        try:
            acts = self._ensure_parents(p)
            e = self.entries.get(p)
            with ParentDir(p) as pd:
                try:
                    st = os.stat(pd.name, dir_fd=pd.fd, follow_symlinks=False)
                except FileNotFoundError:
                    st = None
                drift = st is None or (e is not None and self._content_drift_at(pd.fd, pd.name, e, st, True))
            if e is None:
                return acts + ([self.quarantine(p, "not in baseline")] if st is not None else [])
            if not drift:
                if self._meta_drift(e, st):
                    acts.append(self.fix_meta(p, e))
                return acts
            if st is not None:
                acts.append(self.quarantine(p, "modified"))
            acts.append(self.restore(p, e))
            return acts
        except UnsafePath as err:
            return [{"action": "restore_failed", "path": p,
                     "error": f"unsafe path (symlink at {err.filename}); refusing to follow it"}]
        except (OSError, ValueError) as err:
            return [{"action": "restore_failed", "path": p, "error": str(err)}]

    def _ensure_parents(self, p):
        """Recreate missing or replaced directories between the rule root and p."""
        rule = self.rule_for(p)
        acts, ancs = [], []
        a = os.path.dirname(p)
        while a not in ("", "/") and rule and rule.covers(a):
            ancs.append(a)
            a = os.path.dirname(a)
        for a in reversed(ancs):
            try:
                st = safe_lstat(a)
            except FileNotFoundError:
                st = None
            if st is not None and stat.S_ISDIR(st.st_mode):
                continue
            if st is not None:
                acts.append(self.quarantine(a, "replaced a protected directory"))
            e = self.entries.get(a)
            if not e or e.get("t") != "d":
                pst = safe_lstat(os.path.dirname(a))
                e = {"t": "d", "mode": 0o755, "uid": pst.st_uid, "gid": pst.st_gid}
            acts.append(self.restore(a, e))
        return acts

    def _qpath(self, p, prefix=""):
        base = os.path.join(self.cfg.quarantine_dir, "%s%s-%s" % (
            prefix, time.strftime("%Y%m%dT%H%M%S"), p.strip("/").replace("/", "__")))
        dest, n = base, 1
        while os.path.lexists(dest):
            dest, n = f"{base}.{n}", n + 1
        return dest

    def quarantine(self, p, why):
        os.makedirs(self.cfg.quarantine_dir, mode=0o700, exist_ok=True)
        dest = self._qpath(p)
        rec = {"action": "quarantined", "path": p, "reason": why, "to": dest}
        try:
            with ParentDir(p) as pd:
                st = os.stat(pd.name, dir_fd=pd.fd, follow_symlinks=False)
                if stat.S_ISREG(st.st_mode):
                    r = self.hash_at(pd.fd, pd.name, st)
                    if r:
                        rec["sha256"] = r[0]
                try:
                    os.rename(pd.name, dest, src_dir_fd=pd.fd)
                except OSError as err:
                    if err.errno != errno.EXDEV or not stat.S_ISREG(st.st_mode):
                        raise
                    self._copy_out(pd.fd, pd.name, st, dest)
                    os.unlink(pd.name, dir_fd=pd.fd)
            self._lock_down(dest)
        except FileNotFoundError:
            rec.update(action="quarantine_skipped", error="already gone")
        except (OSError, ValueError) as err:
            rec.update(action="quarantine_failed", error=str(err))
        return rec

    def _copy_out(self, dir_fd, name, st, dest):
        src = _open_nofollow_at(dir_fd, name)
        try:
            if (os.fstat(src).st_ino, os.fstat(src).st_dev) != (st.st_ino, st.st_dev):
                raise OSError(errno.EAGAIN, "file changed while copying", name)
            out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o400)
            try:
                while True:
                    chunk = os.read(src, 1 << 20)
                    if not chunk:
                        break
                    _write_all(out, chunk)
            finally:
                os.close(out)
        finally:
            os.close(src)

    @staticmethod
    def _lock_down(dest):
        """Quarantined evidence: root-owned, never executable. Skips files with
        other hard links, so an attacker cannot make us chmod a file elsewhere."""
        try:
            st = os.lstat(dest)
            if stat.S_ISLNK(st.st_mode):
                os.chown(dest, 0, 0, follow_symlinks=False)
                return
            want_dir = stat.S_ISDIR(st.st_mode)
            fd = os.open(dest, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (O_DIRECTORY if want_dir else 0))
            try:
                fst = os.fstat(fd)
                if want_dir:
                    os.fchown(fd, 0, 0)
                    os.fchmod(fd, 0o700)
                elif stat.S_ISREG(fst.st_mode) and fst.st_nlink == 1:
                    os.fchmod(fd, 0o400)
                    os.fchown(fd, 0, 0)
            finally:
                os.close(fd)
        except OSError:
            pass

    def snapshot(self, p):
        """Copy (not move) a file for later diffing; used by alert-only rules."""
        try:
            with ParentDir(p) as pd:
                src = _open_nofollow_at(pd.fd, pd.name)
                try:
                    st = os.fstat(src)
                    if not stat.S_ISREG(st.st_mode):
                        return None
                    if st.st_size > self.cfg.max_store:
                        return {"action": "snapshot_skipped", "path": p, "reason": "too large",
                                "size": st.st_size}
                    os.makedirs(self.cfg.quarantine_dir, mode=0o700, exist_ok=True)
                    dest = self._qpath(p, "evidence-")
                    out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o400)
                    h = hashlib.sha256()
                    try:
                        while True:
                            chunk = os.read(src, 1 << 20)
                            if not chunk:
                                break
                            h.update(chunk)
                            _write_all(out, chunk)
                    finally:
                        os.close(out)
                    return {"action": "snapshot", "path": p, "to": dest, "sha256": h.hexdigest()}
                finally:
                    os.close(src)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as err:
            if getattr(err, "errno", None) == errno.ELOOP:
                return None  # the path itself is a symlink: nothing to copy
            return {"action": "snapshot_failed", "path": p, "error": str(err)}

    def fix_meta(self, p, e):
        try:
            with ParentDir(p) as pd:
                fd = _open_nofollow_at(pd.fd, pd.name, want_dir=e["t"] == "d")
                try:
                    st = os.fstat(fd)
                    if (e["t"] == "d") != stat.S_ISDIR(st.st_mode):
                        raise OSError(errno.EAGAIN, "type changed", p)
                    if (st.st_uid, st.st_gid) != (e["uid"], e["gid"]):
                        os.fchown(fd, e["uid"], e["gid"])
                    os.fchmod(fd, e["mode"])
                    if e["t"] == "f":
                        self._cache_stat(e, os.fstat(fd))
                        self.dirty = True
                finally:
                    os.close(fd)
            return {"action": "mode_restored", "path": p, "mode": oct(e["mode"]),
                    "owner": f"{e['uid']}:{e['gid']}"}
        except (OSError, ValueError) as err:
            return {"action": "mode_restore_failed", "path": p, "error": str(err)}

    def restore(self, p, e):
        rec = {"action": "restored", "path": p}
        try:
            with ParentDir(p) as pd:
                tmp = ".tg-restore-" + secrets.token_hex(8)
                if e["t"] == "d":
                    try:
                        os.mkdir(pd.name, 0o700, dir_fd=pd.fd)
                    except FileExistsError:
                        pass
                    fd = _open_nofollow_at(pd.fd, pd.name, want_dir=True)
                    try:
                        os.fchown(fd, e["uid"], e["gid"])
                        os.fchmod(fd, e["mode"])
                    finally:
                        os.close(fd)
                    return rec
                if e["t"] == "l":
                    os.symlink(e["link"], tmp, dir_fd=pd.fd)
                    try:
                        os.chown(tmp, e["uid"], e["gid"], dir_fd=pd.fd, follow_symlinks=False)
                    except OSError:
                        pass
                    os.rename(tmp, pd.name, src_dir_fd=pd.fd, dst_dir_fd=pd.fd)
                    return rec
                obj = os.path.join(self.objects, e["sha"])
                if not e.get("stored") or not os.path.exists(obj):
                    return {"action": "restore_impossible", "path": p, "hint": reinstall_hint(p)}
                out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                              0o600, dir_fd=pd.fd)
                try:
                    with open(obj, "rb") as src:
                        for chunk in iter(lambda: src.read(1 << 20), b""):
                            _write_all(out, chunk)
                    os.fchown(out, e["uid"], e["gid"])
                    os.fchmod(out, e["mode"])
                except BaseException:
                    os.close(out)
                    os.unlink(tmp, dir_fd=pd.fd)
                    raise
                os.close(out)
                os.rename(tmp, pd.name, src_dir_fd=pd.fd, dst_dir_fd=pd.fd)
                self._cache_stat(e, os.stat(pd.name, dir_fd=pd.fd, follow_symlinks=False))
                self.dirty = True
        except (OSError, ValueError) as err:
            rec = {"action": "restore_failed", "path": p, "error": str(err)}
        return rec

    def _protects(self, p):
        return p in self.entries or any(under(k, p) for k in self.entries)

    def undo_rename(self, src, dst):
        """Put a protected file or tree back after it was renamed away."""
        if not src or not dst or not self._protects(src):
            return []
        try:
            with ParentDir(dst) as d:
                dst_st = os.stat(d.name, dir_fd=d.fd, follow_symlinks=False)
        except (OSError, ValueError):
            return []
        e = self.entries.get(src)
        want = e["t"] if e else "d"  # not in the manifest itself: an ancestor directory
        m = dst_st.st_mode
        have = "l" if stat.S_ISLNK(m) else "d" if stat.S_ISDIR(m) else "f" if stat.S_ISREG(m) else "?"
        if want != have:
            return []
        acts = []
        try:
            try:
                safe_lstat(src)
                acts.append(self.quarantine(src, "took the place of a renamed protected path"))
            except FileNotFoundError:
                pass
            with ParentDir(dst) as d, ParentDir(src) as s:
                os.rename(d.name, s.name, src_dir_fd=d.fd, dst_dir_fd=s.fd)
            acts.append({"action": "rename_undone", "path": src, "from": dst})
        except (OSError, ValueError) as err:
            acts.append({"action": "rename_undo_failed", "path": src, "from": dst, "error": str(err)})
        return acts

    # ---- backstop scan
    def detect(self, deep=False, skip_rules=()):
        skip = {r.id for r in skip_rules}
        seen, drift = set(), set()
        for rule in self.rules():
            if rule.id in skip:
                continue
            for root in rule.paths:
                for p, fd, name, st in self._walk(root, rule):
                    if p in seen or not rule.covers(p):
                        continue
                    if self._overlap and self.rule_for(p) is not rule:
                        continue
                    seen.add(p)
                    e = self.entries.get(p)
                    if (e is None or self._content_drift_at(fd, name, e, st, deep)
                            or self._meta_drift(e, st)):
                        drift.add(p)
        for p in self.entries:
            if p not in seen:
                rule = self.rule_for(p)
                if rule and rule.id not in skip:
                    drift.add(p)  # missing, or hidden behind a symlinked parent
        return drift

    def scan(self, deep=False, skip_rules=(), enforce=None):
        """Compare protected trees with the baseline. Returns [(path, rule, actions)].
        Repeats (up to 3 passes) while repairs uncover more, e.g. the contents of
        a directory that had been swapped for a symlink."""
        results, done = [], set()
        for _ in range(3):
            drift = self.detect(deep=deep, skip_rules=skip_rules) - done
            if not drift:
                break
            repaired = False
            for p in sorted(drift):  # parents sort before their children
                rule = self.rule_for(p)
                if rule is None:
                    continue
                act = rule.enforce if enforce is None else enforce
                acts = self.reconcile(p) if act else []
                repaired = repaired or bool(acts)
                results.append((p, rule, acts))
                done.add(p)
            if not repaired:
                break
        if self.dirty:
            self.save()
        return results


# --------------------------------------------------------------------------- guard

class Guard:
    SEQ_RE = re.compile(r'"global_seq_num"\s*:\s*(\d+)')

    def __init__(self, cfg):
        self.cfg = cfg
        self.alerter = Alerter(cfg)
        self.vault = Vault(cfg)
        self.procs = ProcTable()
        self.lock = threading.RLock()
        self.flagged = {}  # pid -> time it was killed
        self.self_pids = {os.getpid()}
        self.prefixes = tuple(sorted({p for r in cfg.file_rules for p in r.paths}))
        self.ancestor_paths = frozenset(a for r in cfg.file_rules for a in r.root_ancestors)
        self.revert_prefixes = tuple(p for r in cfg.file_rules if r.reverts for p in r.paths)
        self.window_rules = [r for r in cfg.file_rules if r.allow.only_in_window]
        self.prefilter = Prefilter([(p, r.includes) for r in cfg.file_rules for p in r.paths],
                                   self.ancestor_paths,
                                   set(PROCESS_EVENTS) | cfg.event_rule_events, cfg.file_event_names)
        self.rebaseline_due = 0.0
        self.full_rebaseline = False  # admin request: accept everything
        self.window_closing = False
        self.window_dropped = False   # events were lost while a window was open
        self.accepted = set()         # paths touched by allowed processes
        self.accepted_by = set()      # the allowed commands that touched them
        self.rebaseline_trigger = ""
        self.window_was_open = False
        self._wcache = (0.0, None, None)
        self.next_scan = time.time() + cfg.scan_interval
        self.last_heartbeat = 0.0
        self.scans = 0
        self.stats = {"events": 0, "lines": 0, "skipped": 0, "violations": 0, "dropped_events": 0}
        self.last_seq = None
        self.last_line_t = time.time()
        self._last_drop_alert = 0.0
        self._recent = {}
        self._hook_cache = {}
        self.child = None
        self.running = True
        self.marker = os.path.join(cfg.control_dir, "running.pid")

    # ---- control files (root-owned 0700 directory; non-root users cannot write them)
    def _trusted(self, path):
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return False
        return os.geteuid() != 0 or (st.st_uid == 0 and not st.st_mode & 0o022)

    def _read_control(self, name):
        path = os.path.join(self.cfg.control_dir, name)
        try:
            if not self._trusted(path):
                return None
            with open(path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def window(self):
        """The open maintenance window as a dict, or None. A window bound to a pid
        (brew-guarded's shell) closes as soon as that process exits."""
        now = time.time()
        try:
            st = os.lstat(os.path.join(self.cfg.control_dir, "window.json"))
            sig = (st.st_ino, st.st_mtime_ns, st.st_size)
        except OSError:
            sig = None
        t, cached_sig, data = self._wcache
        if sig == cached_sig and now - t < 1.0:
            return data
        data = self._read_control("window.json")
        try:
            if not data or float(data.get("until", 0)) <= now:
                data = None
            elif data.get("pid") and not pid_alive(data["pid"]):
                data = None
        except (TypeError, ValueError):
            data = None
        self._wcache = (now, sig, data)
        return data

    def window_open(self):
        return bool(self.window())

    def _stop_authorized(self):
        data = self._read_control("stop.json")
        try:
            return bool(data) and float(data.get("until", 0)) > time.time()
        except (TypeError, ValueError):
            return False

    # ---- raw stream
    def feed_line(self, line):
        self.last_line_t = time.time()
        self.stats["lines"] += 1
        i = line.find('"global_seq_num"')
        if i >= 0:
            m = self.SEQ_RE.match(line, i)
            if m:
                self._check_seq(int(m.group(1)))
        if not self.prefilter.wants(line):
            self.stats["skipped"] += 1
            return
        try:
            ev = json.loads(line)
        except ValueError:
            return
        self.handle(ev)

    def _check_seq(self, seq):
        last, self.last_seq = self.last_seq, seq
        if last is None or seq <= last:
            return
        gap = seq - last - 1
        if gap <= 0:
            return
        self.stats["dropped_events"] += gap
        if self.window_open():
            self.window_dropped = True
        self.next_scan = min(self.next_scan, time.time() + 1)
        now = time.time()
        if now - self._last_drop_alert > 60:
            self._last_drop_alert = now
            self.alerter.emit({"type": "warning", "severity": "high",
                               "detail": f"eslogger dropped {gap} event(s); scanning protected paths now",
                               "dropped_total": self.stats["dropped_events"]})

    # ---- event handling
    def handle(self, ev):
        self.stats["events"] += 1
        body = ev.get("event")
        if not isinstance(body, dict) or not body:
            return
        name = next(iter(body))
        payload = body[name] if isinstance(body[name], dict) else {}
        info = proc_info(ev.get("process"))
        pid = info["pid"]

        if name == "fork":
            child = proc_info(payload.get("child"))
            self.procs.note_fork(child, pid)
            if pid in self.flagged:
                self._kill([child["pid"]], allow_session=True)
            return
        if name == "exec":
            self._on_exec(info, payload)
            return
        if name == "exit":
            self.procs.exit(pid)
            self.flagged.pop(pid, None)
            return

        self.procs.note_es(info)
        if name == "signal":
            self._check_signal(pid, payload)
            return
        if pid in self.self_pids:
            return  # our own restores and quarantines
        if name in self.cfg.event_rule_events:
            self._on_system_event(name, payload, pid, info)
        if name in self.cfg.file_event_names:
            self._on_file_event(name, payload, pid, info)

    def _on_file_event(self, name, payload, pid, info):
        if name == "close" and payload.get("modified") is False and not payload.get("was_mapped_writable"):
            return
        writing = True
        if name == "open":
            try:
                writing = bool(int(payload.get("fflag") or 0) & FWRITE)
            except (TypeError, ValueError):
                writing = True
        paths = {p for p in extract_paths(payload, set())
                 if p.startswith(self.prefixes) or p in self.ancestor_paths}
        if not paths:
            return
        over = name == "rename" and replaces_existing(payload)
        for rule in self.cfg.file_rules:
            if name not in rule.events:
                continue
            if name == "open" and rule.access == "write" and not writing:
                continue
            if rule.rename_over_existing_only and not over:
                continue
            hit = sorted(p for p in paths if rule.covers(p)
                         or (name in ("rename", "unlink") and p in rule.root_ancestors))
            if not hit:
                continue
            who = self._allowed(rule, pid, info["euid"])
            if who:
                if rule.reverts and writing:  # accept the change once activity settles
                    with self.lock:
                        self.accepted.update(hit)
                        if len(self.accepted_by) < 20:
                            self.accepted_by.add(who)
                        self.rebaseline_due = time.time() + self.cfg.settle
                continue
            extra = {}
            if name == "open":
                extra["access"] = "write" if writing else "read"
            self._violation(rule, name, hit, pid, over=over,
                            rename=rename_paths(payload) if name == "rename" else None, **extra)

    def _on_exec(self, info, payload):
        target = proc_info(payload.get("target"))
        pid = target["pid"] if target["pid"] is not None else info["pid"]
        target["pid"] = pid
        if target["ppid"] is None:
            target["ppid"] = info["ppid"]
        sc = payload.get("script")
        script = norm(sc["path"]) if isinstance(sc, dict) and isinstance(sc.get("path"), str) else None
        args = payload.get("args")
        args = [str(a) for a in args] if isinstance(args, list) else None
        prev = self.procs.procs.get(pid) or {}
        # `#!/usr/bin/env bash` scripts: the kernel attests the script on the env
        # exec; carry it to the interpreter env starts, if that interpreter is trusted.
        if (not script and prev.get("script") and prev.get("path") == "/usr/bin/env"
                and prev.get("src") == "es" and args and prev["script"] in args[1:3]
                and self._trusted_image(target)):
            script = prev["script"]
        taint = self._env_taint(target["path"], payload.get("env"))
        self.procs.note_exec(target, script, args, taint)
        if pid in self.flagged:
            self._kill([pid], allow_session=True)
            return
        if pid in self.self_pids:
            return
        if self._check_exec_integrity(pid, target, script):
            return
        self._check_exec_rules(pid, target, script, args)
        self._check_tamper_command(pid)

    def _trusted_image(self, info):
        if info.get("platform") is True:
            return True
        p = info.get("path") or ""
        return bool(p) and p.startswith(self.revert_prefixes) and self.vault.image_intact(p)

    def _hook_dir_ok(self, d):
        if not d or d.startswith(self.revert_prefixes) or d.startswith(SYSTEM_HOOK_DIRS) and self._root_dir(d):
            return True
        return False

    def _root_dir(self, d):
        now = time.time()
        hit = self._hook_cache.get(d)
        if hit and now - hit[0] < 60:
            return hit[1]
        try:
            st = os.stat(d)
            ok = st.st_uid == 0 and not st.st_mode & 0o022
        except FileNotFoundError:
            ok = True
        except OSError:
            ok = False
        self._hook_cache[d] = (now, ok)
        return ok

    def _env_taint(self, exe, env):
        if not isinstance(env, list):
            return None
        fam = family(os.path.basename(exe or ""))
        keys = set(TAINT_ALWAYS) | TAINT_BY_FAMILY.get(fam, set())
        if fam in SHELLS:
            keys |= TAINT_SHELL
        bad = set()
        for item in env:
            if not isinstance(item, str) or "=" not in item:
                continue
            k, v = item.split("=", 1)
            if k in keys and v:
                bad.add(k)
            elif fam in SHELLS and k.startswith("BASH_FUNC_"):
                bad.add("BASH_FUNC_*")
            elif k == "PYENV_HOOK_PATH" and any(not self._hook_dir_ok(d) for d in v.split(":") if d):
                bad.add(k)
        return sorted(bad) or None

    def _check_exec_integrity(self, pid, target, script):
        """Kill a process that runs a protected file which is modified or not in the
        baseline. Covers the window between a tampering write and its revert, and
        anything the event stream missed."""
        for p in (target.get("path"), script):
            if not p or not p.startswith(self.revert_prefixes):
                continue
            rule = self.vault.rule_for(p)
            if rule is None or not rule.exec_integrity:
                continue
            if self.vault.image_intact(p) or p in self.accepted:
                continue
            if self._allowed(rule, pid, target.get("euid")):
                continue
            self._violation(rule, "exec", [p], pid,
                            detail="ran a protected file that is modified or not in the baseline")
            return True
        return False

    def _check_exec_rules(self, pid, target, script, args):
        if not self.cfg.exec_rules:
            return
        cmd = " ".join(args or [])
        for rule in self.cfg.exec_rules:
            if not rule.exec_matches(target.get("path"), script, cmd):
                continue
            if self._allowed(rule, pid, target.get("euid")):
                continue
            self._violation(rule, "exec", [], pid, command=cmd[:1000])

    def _on_system_event(self, name, payload, pid, info):
        flat = None
        for rule in self.cfg.event_rules:
            if name not in rule.events:
                continue
            if flat is None:
                flat = flatten(payload)
            if not rule.event_matches(flat):
                continue
            if self._allowed(rule, pid, info["euid"]):
                continue
            self._violation(rule, name, [], pid, event_data=summarize_payload(payload))

    # ---- allow decisions (kernel-attested facts only)
    def _identity_ok(self, a, info):
        if info.get("src") != "es" or info.get("taint"):
            return False
        exe = info.get("path") or ""
        script = info.get("script") or ""
        images = [x for x in (exe, script) if x]
        if a.paths and any(x.startswith(pfx) for x in images for pfx in a.paths):
            return True
        if a.regex and any(rx.search(x) for x in images for rx in a.regex):
            return True
        if a.signing:
            team = "platform" if info.get("platform") else (info.get("team_id") or "")
            sid = info.get("signing_id") or ""
            if team and sid and any(t == team and fnmatch.fnmatchcase(sid, pat) for t, pat in a.signing):
                return True
        if a.platform and info.get("platform"):
            if a.platform == "all" or family(os.path.basename(exe)) not in TOOLS:
                return True
        if a.protected_images:
            interp = family(os.path.basename(exe)) in INTERPRETERS
            img = script if interp else exe
            if img and img.startswith(self.revert_prefixes) and self.vault.image_intact(img):
                return True
        return False

    def _is_helper(self, info):
        """A platform binary that is not an interpreter (cp, ln, mkdir...) run by an
        allowed tool. PATH tricks cannot fake this: the kernel attests both facts."""
        return (info.get("src") == "es" and info.get("platform") is True and not info.get("taint")
                and family(os.path.basename(info.get("path") or "")) not in INTERPRETERS)

    @staticmethod
    def _label(info):
        img = info.get("script") or info.get("path") or ""
        args = " ".join((info.get("args") or [])[1:6])
        return (img + (" " + args if args else ""))[:200]

    def _allowed(self, rule, pid, euid):
        """None if the change is not allowed, else a short note on what allowed it."""
        a = rule.allow
        if euid is not None and euid in a.uids:
            return f"uid {euid}"
        if not a.has_identity:
            return None
        chain = self.procs.chain(pid)
        if not chain:
            return None
        if a.only_in_window:
            w = self.window()
            if not w:
                return None
            if w.get("pid") and not any(p == w["pid"] for p, _ in chain):
                return None  # only brew started by the wrapper that opened the window
            for _, info in chain:
                if self._identity_ok(a, info):
                    return self._label(info)
            return None
        # Outside windows only the tool itself (or a platform helper it runs) may
        # write: descendants in general can be attacker code (PATH, hooks, env).
        writer = chain[0][1]
        if self._identity_ok(a, writer):
            return self._label(writer)
        if a.helpers and len(chain) > 1 and self._is_helper(writer) and self._identity_ok(a, chain[1][1]):
            return self._label(chain[1][1]) + " via " + short_name(writer)
        return None

    # ---- violations
    def _violation(self, rule, evname, paths, pid, over=False, rename=None, **extra):
        with self.lock:
            now = time.time()
            if not rule.reverts and "kill" not in rule.actions:
                key = (rule.id, pid, tuple(paths), extra.get("command"))
                t = self._recent.get(key)
                if t and now - t < self.cfg.dedupe_seconds:
                    return
                self._recent[key] = now
            followup = pid in self.flagged
            self.stats["violations"] += 1
            chain = self._describe_chain(pid)
            acts = []
            if "kill" in rule.actions and not followup:
                root, session = self._kill_root(pid, rule.kill_scope)
                if rule.enforce:
                    killed = self._kill([root], allow_session=session)
                    acts.append({"action": "killed" if killed else "kill_target_gone",
                                 "root_pid": root, "pids": killed,
                                 "scope": "session" if session else rule.kill_scope})
                else:
                    acts.append({"action": "would_kill", "root_pid": root})
            if rule.reverts and paths:
                if rule.enforce:
                    if rename:
                        acts.extend(self.vault.undo_rename(*rename))
                    for p in paths:
                        acts.extend(self.vault.reconcile(p))
                else:
                    acts.extend({"action": "would_revert", "path": p} for p in paths)
            elif "snapshot" in rule.actions:
                for p in paths:
                    snap = self.vault.snapshot(p)
                    if snap:
                        acts.append(snap)
            if self.vault.dirty:
                self.vault.save()
            if rule.reverts:  # sweep soon for anything else the process touched
                self.next_scan = min(self.next_scan, now + 2)
            rec = {"type": "violation", "rule": rule.id, "rule_type": rule.type,
                   "severity": rule.severity, "description": rule.description, "event": evname,
                   "paths": paths, "mode": rule.mode, "process_chain": chain, "actions": acts}
            if over:
                rec["rename_over_existing"] = True
            if followup:
                rec["followup"] = True
            rec.update(extra)
            self.alerter.emit(rec, remote=not followup)

    # ---- killing
    def _is_session_shell(self, pid):
        info = self.procs.get(pid) or {}
        args = info.get("args") or []
        if args and args[0].startswith("-"):
            return True  # login shell
        parent = self.procs.get(info.get("ppid")) or {}
        pname = short_name(parent).lower()
        return any(s in pname for s in SESSION_PARENTS)

    def _kill_root(self, pid, scope):
        """(root pid, session?) Walk up from the offender through interpreters to
        the script running it, stopping below the user's terminal session. In
        session scope (or when the chain comes in over SSH) include the session's
        shell too."""
        chain = self.procs.chain(pid)
        remote = self.cfg.kill_remote_sessions and any(
            short_name(i).lower() in ("sshd", "sshd-session") for _, i in chain[1:])
        if scope == "session" or (remote and scope != "process"):
            root = pid
            for p, info in chain[1:]:
                name = short_name(info).lower()
                if not p or p <= 1 or name in NEVER_KILL or any(s in name for s in SESSION_PARENTS):
                    break
                root = p
            return root, True
        root = pid
        if scope != "script":
            return root, False
        for _ in range(16):
            info = self.procs.get(root) or {}
            ppid = info.get("ppid")
            if not ppid or ppid <= 1:
                break
            pinfo = self.procs.get(ppid)
            if (not pinfo or family(short_name(pinfo)) not in INTERPRETERS
                    or self._is_session_shell(ppid)):
                break
            root = ppid
        return root, False

    def _killable(self, pid, allow_session=False):
        if not pid or pid <= 1 or pid in self.self_pids or pid in self.procs.exited:
            return False
        if short_name(self.procs.get(pid)).lower() in NEVER_KILL:
            return False
        return allow_session or not self._is_session_shell(pid)

    @staticmethod
    def _signal_all(pids, sig):
        """Signal each pid; return the ones that were actually signalled."""
        done = []
        for p in pids:
            try:
                os.kill(p, sig)
                done.append(p)
            except (ProcessLookupError, PermissionError):
                pass
        return done

    def _kill(self, roots, allow_session=False):
        """Flag, freeze, re-scan for children until none appear, then SIGKILL, so
        nothing can fork away between the snapshot of the tree and the kill."""
        targets = [p for p in dict.fromkeys(roots) if self._killable(p, allow_session)]
        if not targets:
            return []
        now = time.time()
        seen = set(targets)
        for p in targets:
            self.flagged[p] = now
        self._signal_all(targets, signal.SIGSTOP)
        for _ in range(5):
            self.procs.refresh(force=True)
            new = [c for c in sorted(self.procs.descendants(seen))
                   if c not in seen and self._killable(c, True)]
            if not new:
                break
            for p in new:
                self.flagged[p] = now
                seen.add(p)
            self._signal_all(new, signal.SIGSTOP)
            targets.extend(new)
        return self._signal_all(targets, signal.SIGKILL)

    def _describe_chain(self, pid):
        out = []
        for p, i in self.procs.chain(pid, depth=8):
            d = {"pid": p, "ppid": i.get("ppid"), "euid": i.get("euid"), "path": i.get("path"),
                 "args": (i.get("args") or [])[:8]}
            for k in ("script", "signing_id", "team_id", "taint"):
                if i.get(k):
                    d[k] = i[k]
            if i.get("platform"):
                d["platform"] = True
            if i.get("src") != "es":
                d["unverified"] = True  # learned from ps only
            out.append(d)
        return out

    # ---- self-protection signals
    def _check_tamper_command(self, pid):
        info = self.procs.procs.get(pid) or {}
        args = info.get("args") or []
        tool = os.path.basename(info.get("path") or (args[0] if args else ""))
        if tool not in ("launchctl", "kill", "pkill", "killall") or not args:
            return
        cmd = " ".join(args)
        targets_us = (self.cfg.label in cmd or "toolchain_guard" in cmd or "eslogger" in cmd
                      or any(str(p) in args for p in self.self_pids))
        if targets_us:
            self.alerter.emit({"type": "tamper_attempt", "severity": "high",
                               "detail": "command aimed at the watcher",
                               "process_chain": self._describe_chain(pid)})

    def _check_signal(self, sender, payload):
        target = proc_info(payload.get("target"))["pid"]
        if target in self.self_pids and sender not in self.self_pids:
            self.alerter.emit({"type": "tamper_attempt",
                               "severity": "info" if sender == 1 else "critical",
                               "detail": f"signal {payload.get('sig')} sent to watcher pid {target}",
                               "process_chain": self._describe_chain(sender)})

    # ---- periodic work
    def run_scan(self, reason="periodic"):
        self.scans += 1
        deep = self.scans % self.cfg.deep_every == 0
        skip = self.window_rules if self.window_open() else ()
        with self.lock:
            results = self.vault.scan(deep=deep, skip_rules=skip)
        for p, rule, acts in results:
            self.alerter.emit({"type": "drift", "rule": rule.id, "severity": rule.severity,
                               "path": p, "detected_by": f"{reason} scan",
                               "mode": rule.mode, "actions": acts,
                               "note": "found by scan, so no process attribution"})
        self.next_scan = time.time() + self.cfg.scan_interval
        return results

    def _rebaseline(self, now):
        with self.lock:
            before = dict(self.vault.entries)
            unattributed = None
            if self.full_rebaseline:
                n, kind, trigger = self.vault.baseline(), "full", self.rebaseline_trigger
            elif self.window_closing and (self.cfg.window_close_mode == "full" or self.window_dropped):
                self.vault.accept(self.accepted)
                touched = dict(self.vault.entries)
                n = self.vault.baseline(rules=self.window_rules)
                kind, trigger = "window rules", "maintenance window closed"
                unattributed = diff_entries(touched, self.vault.entries)
            elif self.window_closing:
                n, kind, trigger = self.vault.accept(self.accepted), "touched paths", "maintenance window closed"
            else:
                n, kind, trigger = self.vault.accept(self.accepted), "accepted paths", "allowed tool"
            changes = diff_entries(before, self.vault.entries)
            by = sorted(self.accepted_by)
            dropped = self.window_dropped
            self.accepted.clear()
            self.accepted_by.clear()
            self.rebaseline_due, self.full_rebaseline = 0.0, False
            closing, self.window_closing, self.window_dropped = self.window_closing, False, False
        if closing:
            self.next_scan = now + 1  # revert whatever the window did not account for
        self.alerter.emit({"type": "rebaselined", "kind": kind, "entries": n,
                           "trigger": trigger, "accepted_by": by, "changes": changes}, remote=False)
        if unattributed and any(unattributed["counts"].values()):
            self.alerter.emit({
                "type": "warning", "severity": "high" if dropped else "medium",
                "detail": ("events were dropped during the maintenance window, so every change "
                           "under its rules was accepted, including these with no attribution"
                           if dropped else "full window re-baseline accepted changes no allowed "
                                           "process was seen making"),
                "changes": unattributed})

    def _stream_watchdog(self, now):
        child = self.child
        if child is None or child.poll() is not None:
            return
        if now - self.last_line_t > self.cfg.stall_seconds:
            self.alerter.emit({"type": "tamper_attempt", "severity": "high",
                               "detail": f"no events from eslogger for {int(now - self.last_line_t)}s "
                                         "(suspended or hung); restarting it"})
            self.last_line_t = now
            try:
                child.kill()
            except OSError:
                pass

    def tick(self):
        now = time.time()
        if now - self.last_heartbeat >= self.cfg.heartbeat_interval:
            self.last_heartbeat = now
            self.alerter.emit(dict({
                "type": "heartbeat", "pid": os.getpid(), "mode": self.cfg.mode,
                "eslogger_pid": self.child.pid if self.child else None,
                "baseline_entries": len(self.vault.entries),
                "seconds_since_last_event": round(now - self.last_line_t, 1),
                "alerts_dropped": self.alerter.dropped, "webhook_failures": self.alerter.failed,
                "window_open": self.window_open()}, **self.stats))
        win = self.window_open()
        if self.window_was_open and not win:
            self.rebaseline_due, self.window_closing = now, True  # maintenance done
        self.window_was_open = win
        req = os.path.join(self.cfg.control_dir, "rebaseline.request")
        if os.path.lexists(req):
            ok = False
            try:
                ok = self._trusted(req)
                os.unlink(req)
            except OSError:
                pass
            if ok:
                self.rebaseline_due, self.full_rebaseline = now, True
                self.rebaseline_trigger = "baseline command"
        if self.rebaseline_due and now >= self.rebaseline_due and not win:
            self._rebaseline(now)
        elif now >= self.next_scan and not self.rebaseline_due:
            self.run_scan()
        self._stream_watchdog(now)
        for pid, t in list(self.flagged.items()):
            if now - t > 300:
                self.flagged.pop(pid, None)
        for k, t in list(self._recent.items()):
            if now - t > self.cfg.dedupe_seconds:
                self._recent.pop(k, None)
        self.procs.purge()

    def housekeeping(self):
        while self.running:
            time.sleep(1)
            try:
                self.tick()
            except Exception as err:
                self.alerter.emit({"type": "error", "where": "housekeeping", "error": repr(err)})

    # ---- lifecycle
    def _on_term(self, signum, frame):
        authorized = self._stop_authorized()
        self.running = False
        rec = {"type": "stopped", "signal": signum, "authorized": authorized}
        if not authorized:
            rec.update(severity="high", detail="stop signal without `toolchain_guard.py stop`: "
                                               "a system shutdown, or someone stopping the watcher")
        self.alerter.emit(rec)
        self.alerter.flush(5)
        if authorized:
            for path in (self.marker, os.path.join(self.cfg.control_dir, "stop.json")):
                try:
                    os.unlink(path)
                except OSError:
                    pass
        if self.child and self.child.poll() is None:
            self.child.terminate()
        sys.exit(0)

    def _report_previous_run(self):
        try:
            started = os.stat(self.marker).st_mtime
        except OSError:
            return
        boot = boot_time()
        if boot and started < boot:
            self.alerter.emit({"type": "started_after_reboot", "severity": "info",
                               "detail": "the previous instance was running when the machine shut down"},
                              remote=False)
        else:
            self.alerter.emit({"type": "tamper_attempt", "severity": "critical",
                               "detail": "previous watcher instance ended without a clean "
                                         "shutdown during this boot (killed, stopped or crashed); "
                                         "restarted"})

    def _supported_events(self):
        try:
            out = subprocess.run([self.cfg.eslogger, "--list-events"], capture_output=True,
                                 text=True, timeout=10).stdout.split()
        except (OSError, subprocess.SubprocessError):
            return self.cfg.events
        supported = set(out)
        if not supported:
            return self.cfg.events
        missing = [e for e in self.cfg.events if e not in supported]
        if missing:
            self.alerter.emit({"type": "warning", "detail": "eslogger lacks events", "events": missing})
        return [e for e in self.cfg.events if e in supported]

    def _stream_eslogger(self):
        cmd = [self.cfg.eslogger] + self._supported_events()
        try:
            self.child = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
        except OSError as err:
            self.alerter.emit({"type": "error", "severity": "critical",
                               "detail": f"cannot start eslogger: {err}"})
            return 0
        self.self_pids.add(self.child.pid)
        self.last_seq = None
        self.last_line_t = time.time()
        lines = 0
        for line in self.child.stdout:
            line = line.strip()
            if not line:
                continue
            lines += 1
            try:
                self.feed_line(line)
            except Exception as err:
                self.alerter.emit({"type": "error", "where": "handle", "error": repr(err)})
        rc = self.child.wait()
        self.self_pids.discard(self.child.pid)
        self.alerter.emit({"type": "error", "severity": "critical",
                           "detail": f"eslogger exited with code {rc}; protection is down until it restarts",
                           "hint": "eslogger needs root and Full Disk Access for this daemon"})
        return lines

    def run(self, replay=None):
        os.makedirs(self.cfg.control_dir, mode=0o700, exist_ok=True)
        if not replay:
            self._report_previous_run()
        with open(self.marker, "w") as f:
            f.write(str(os.getpid()))
        signal.signal(signal.SIGTERM, self._on_term)
        signal.signal(signal.SIGINT, self._on_term)
        if not self.vault.entries:
            n = self.vault.baseline()
            self.alerter.emit({"type": "baselined", "entries": n}, remote=False)
        self.procs.refresh(force=True)
        self.alerter.emit({"type": "started", "pid": os.getpid(), "mode": self.cfg.mode,
                           "rules": [r.id for r in self.cfg.rules],
                           "events": self.cfg.events,
                           "baseline_entries": len(self.vault.entries)})
        if replay:  # test harness: feed recorded/synthetic eslogger JSON lines
            with (sys.stdin if replay == "-" else open(replay)) as f:
                for line in f:
                    if line.strip():
                        self.feed_line(line.strip())
            self.alerter.flush(5)
            os.unlink(self.marker)
            return
        threading.Thread(target=self.housekeeping, daemon=True).start()
        self.run_scan("startup")  # catch anything changed while we were down
        backoff = 2
        while self.running:
            lines = self._stream_eslogger()
            if not self.running:
                break
            backoff = 2 if lines > 100 else min(backoff * 2, 60)
            time.sleep(backoff)
            self.run_scan("stream-restart")


# --------------------------------------------------------------------------- CLI

def daemon_running(cfg):
    try:
        with open(os.path.join(cfg.control_dir, "running.pid")) as f:
            os.kill(int(f.read().strip()), 0)
        return True
    except (OSError, ValueError):
        return False


def write_control(cfg, name, data):
    os.makedirs(cfg.control_dir, mode=0o700, exist_ok=True)
    path = os.path.join(cfg.control_dir, name)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def proc_uid(pid):
    try:
        out = subprocess.run(["/bin/ps", "-o", "uid=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=5).stdout.strip()
        return int(out) if out else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="toolchain_guard",
                                 description="Detect, stop and undo tampering on a developer machine.")
    ap.add_argument("--rules", default=DEFAULT_RULES, help="path to rules.json")
    ap.add_argument("--allow-nonroot", action="store_true", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="run the watcher (the LaunchDaemon uses this)")
    p_run.add_argument("--replay", help=argparse.SUPPRESS)
    p_base = sub.add_parser("baseline", help="accept the current state as known-good")
    p_base.add_argument("--full", action="store_true", help="re-hash every file")
    p_win = sub.add_parser("window", help="maintenance window for brew changes")
    p_win.add_argument("state", choices=["open", "close"])
    p_win.add_argument("minutes", nargs="?", type=float, default=30)
    p_win.add_argument("--pid", type=int, help="only descendants of this process are allowed; "
                                               "the window closes when it exits")
    p_stop = sub.add_parser("stop", help="stop the watcher without raising a tamper alert")
    p_stop.add_argument("--authorize-only", action="store_true",
                        help="only authorize the next stop (for scripts that bootout themselves)")
    sub.add_parser("verify", help="report drift from the baseline without changing anything")
    sub.add_parser("scan", help="one-shot scan that enforces the rules (daemon stopped)")
    sub.add_parser("status", help="show state")
    sub.add_parser("test-alert", help="send a test record to the log, syslog and webhook")
    args = ap.parse_args(argv)

    if os.geteuid() != 0 and not args.allow_nonroot:
        sys.exit("toolchain_guard: must run as root (use sudo)")
    cfg = Config(args.rules)
    alerter = Alerter(cfg)
    by = os.environ.get("SUDO_USER")
    rc = 0

    if args.cmd == "run":
        Guard(cfg).run(replay=args.replay)
    elif args.cmd == "baseline":
        if daemon_running(cfg) and not args.full:
            write_control(cfg, "rebaseline.request", {"at": time.time()})
            print("rebaseline requested from the running watcher")
        else:
            v = Vault(cfg)
            before = dict(v.entries)
            n = v.baseline(full=args.full)
            alerter.emit({"type": "rebaselined", "kind": "full", "entries": n,
                          "trigger": "baseline command", "by": by,
                          "changes": diff_entries(before, v.entries)}, remote=False)
            print(f"baseline: {n} entries")
    elif args.cmd == "window":
        rec = {"type": "window", "state": args.state, "by": by}
        if args.state == "open":
            if args.pid:
                if not pid_alive(args.pid):
                    sys.exit(f"window: pid {args.pid} is not running")
                sudo_uid = os.environ.get("SUDO_UID")
                owner = proc_uid(args.pid)
                if sudo_uid and owner is not None and str(owner) != sudo_uid:
                    sys.exit(f"window: pid {args.pid} does not belong to the user running sudo")
            until = time.time() + args.minutes * 60
            write_control(cfg, "window.json", {"until": until, "pid": args.pid, "by": by})
            rec.update(until=until, minutes=args.minutes, pid=args.pid)
            if not args.pid:
                rec.update(severity="medium", detail="window not bound to a process: any brew "
                                                     "started during it is allowed")
        else:
            write_control(cfg, "window.json", {"until": 0, "by": by})
            rec.update(until=0, minutes=None)
        alerter.emit(rec)
        if args.state == "close" and not daemon_running(cfg):
            v = Vault(cfg)
            before = dict(v.entries)
            n = v.baseline()
            alerter.emit({"type": "rebaselined", "kind": "full", "entries": n,
                          "trigger": "maintenance window closed", "by": by,
                          "changes": diff_entries(before, v.entries)}, remote=False)
            print(f"baseline: {n} entries")
        print(f"maintenance window {args.state}")
    elif args.cmd == "stop":
        write_control(cfg, "stop.json", {"until": time.time() + 120, "by": by})
        alerter.emit({"type": "stop_authorized", "severity": "medium", "by": by})
        if not args.authorize_only:
            r = subprocess.run(["/bin/launchctl", "bootout", f"system/{cfg.label}"])
            rc = r.returncode
            print("stopped" if rc == 0 else f"launchctl bootout failed ({rc})")
    elif args.cmd in ("verify", "scan"):
        if args.cmd == "scan" and daemon_running(cfg):
            sys.exit("the watcher is running; it scans on its own (use verify to report)")
        results = Vault(cfg).scan(deep=True, enforce=args.cmd == "scan")
        for p, rule, acts in results:
            print(f"[{rule.id}] {p}" + (f"  -> {acts}" if acts else ""))
            if args.cmd == "scan":
                alerter.emit({"type": "drift", "rule": rule.id, "severity": rule.severity,
                              "path": p, "detected_by": "manual scan", "actions": acts})
        print("no drift" if not results else f"{len(results)} drifted path(s)")
        rc = 1 if results and args.cmd == "verify" else 0
    elif args.cmd == "status":
        v = Vault(cfg)
        g = Guard(cfg)
        print(json.dumps({"daemon_running": daemon_running(cfg), "mode": cfg.mode,
                          "maintenance_window": g.window(),
                          "baseline_entries": len(v.entries),
                          "eslogger_events": cfg.events,
                          "rules": {r.id: {"type": r.type, "mode": r.mode} for r in cfg.rules}},
                         indent=2))
    elif args.cmd == "test-alert":
        alerter.emit({"type": "warning", "severity": "info", "detail": "test alert", "by": by})
        print("sent")
    alerter.flush(10)
    sys.exit(rc)


if __name__ == "__main__":
    main()
