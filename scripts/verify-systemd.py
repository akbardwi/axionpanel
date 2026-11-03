#!/usr/bin/env python3
"""Read-only deployment checks; systemd verification uses a disposable root.

No service management, real account creation, installation, or executable launch.
Executable placeholders only satisfy systemd-analyze's existence checks; they do
not establish application compatibility with the sandbox. Requires Python 3.10+
and systemd-analyze. TMPDIR must be writable; all temporary files stay there.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
UNIT_DIR = REPO / "deploy/systemd"
failures = []
checks = 0


def check(condition, label):
    global checks
    checks += 1
    if not condition:
        failures.append(label)
        print(f"FAIL: {label}")


def parse_unit(text):
    """Preserve repeated keys and distinguish absent from empty directives."""
    result = {}
    section = ""
    for line in text.replace("\\\n", " ").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line.strip("[]")
            continue
        name, sep, value = line.partition("=")
        if sep:
            result.setdefault((section, name.strip()), []).append(value.strip())
    return result


units = {}
for name, source in (("axionpanel", "panel"), ("axionpanel-agent", "agent")):
    path = UNIT_DIR / f"{name}.service"
    check(path.is_file(), f"{path.relative_to(REPO)} exists")
    if not path.is_file():
        continue
    text = path.read_text()
    data = parse_unit(text)
    units[name] = data
    get = lambda key: data.get(("Service", key), [None])[-1]
    command = get("ExecStart") or ""
    check(command.startswith(f"/usr/local/axionpanel/bin/{name} "), f"{name}: absolute binary path")
    flags = set(re.findall(r'(?:flag|fs)\.(?:String|Bool|Int)\("([a-z0-9-]+)"',
                           (REPO / f"cmd/{source}/main.go").read_text()))
    used_flags = set(re.findall(r'(?:^|\s)-([a-z][a-z0-9-]*)', command))
    check(bool(used_flags), f"{name}: CLI flags present")
    check(not used_flags - flags, f"{name}: unsupported flags {sorted(used_flags - flags)}")
    check(get("TimeoutStopSec") == "15s", f"{name}: TimeoutStopSec=15s outlasts internal drain")
    check("bootstrap-admin" not in used_flags and "version" not in used_flags,
          f"{name}: daemon ExecStart, not bootstrap/version")
    for key, value in {
        "Type": "simple", "Group": "axionpanel", "UMask": "0077",
        "ProtectSystem": "strict", "ProtectHome": "yes", "NoNewPrivileges": "yes",
        "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes", "ProtectControlGroups": "yes",
        "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
        "RestrictRealtime": "yes", "RestrictNamespaces": "yes",
        "SystemCallFilter": "@system-service", "SystemCallArchitectures": "native",
        "Restart": "on-failure",
    }.items():
        check(get(key) == value, f"{name}: {key}={value}")
    for key in ("ExecStartPre", "ExecStopPost", "NotifyAccess", "DynamicUser", "ProcSubset", "ProtectProc"):
        check(get(key) is None, f"{name}: no {key}")
    for key in ("InaccessiblePaths", "TemporaryFileSystem", "BindPaths", "BindReadOnlyPaths"):
        check("/proc" not in (get(key) or ""), f"{name}: {key} does not mask /proc")
    check("AF_UNIX" in (get("RestrictAddressFamilies") or "").split(), f"{name}: Unix sockets allowed")
    check(data.get(("Install", "WantedBy")) == ["multi-user.target"], f"{name}: manual enable target")
    if source == "agent":
        for key, value in {
            "User": "root", "WorkingDirectory": "/", "RuntimeDirectory": "axionpanel",
            "RuntimeDirectoryMode": "0750", "RuntimeDirectoryPreserve": "yes",
            "CapabilityBoundingSet": "CAP_CHOWN", "RestrictAddressFamilies": "AF_UNIX",
        }.items():
            check(get(key) == value, f"agent: {key}={value}")
        required = {"socket": "/run/axionpanel/agent.sock", "policy": "/etc/axionpanel/agent.toml",
                    "allow-uid": "axionpanel", "socket-gid": "axionpanel"}
    else:
        for key, value in {
            "User": "axionpanel", "WorkingDirectory": "/var/lib/axionpanel",
            "StateDirectory": "axionpanel", "StateDirectoryMode": "0700",
            "CapabilityBoundingSet": "", "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        }.items():
            check(get(key) == value, f"panel: {key}={value}")
        for key in ("After", "Wants"):
            check("axionpanel-agent.service" in " ".join(data.get(("Unit", key), [])), f"panel: {key} agent")
        required = {"addr": "127.0.0.1:7800", "origin": "http://127.0.0.1:7800",
                    "db": "/var/lib/axionpanel/panel.db", "secret-key": "/var/lib/axionpanel/secret.key",
                    "agent-socket": "/run/axionpanel/agent.sock"}
        check("insecure-loopback" in used_flags, "panel: explicit insecure loopback mode")
    for flag, value in required.items():
        check(bool(re.search(rf'(?:^|\s)-{flag}\s+{re.escape(value)}(?:\s|$)', command)),
              f"{name}: -{flag} {value}")

check(not list(UNIT_DIR.glob("*.socket")), "no socket-activation unit")
policy = UNIT_DIR / "agent.toml.example"
check(policy.is_file(), "owner-only policy example exists")
if policy.is_file():
    check(not any(line.split("#", 1)[0].strip() for line in policy.read_text().splitlines()),
          "policy example is empty/comment-only (deny-by-default)")
doc = REPO / "docs/deployment.md"
check(doc.is_file(), "deployment documentation exists")
if doc.is_file():
    content = doc.read_text()
    for needle in ("no TLS", "SSH tunnel", "not tested under PID1", "SIGTERM", "stale",
                   "0400", "getent group axionpanel", "useradd", "RuntimeDirectoryPreserve",
                   "-bootstrap-admin", "runuser", "umask 077", "parsed only", "not enforced",
                   "TimeoutStopSec=15s", "systemd-analyze verify"):
        check(needle in content, f"docs: {needle}")

# Documentation claims must reflect the code, not drift from it.
panel_src = (REPO / "cmd/panel/main.go").read_text()
agent_src = (REPO / "cmd/agent/main.go").read_text()
check("signal.NotifyContext" in panel_src and "Shutdown(" in panel_src,
      "panel source handles SIGTERM with http.Server.Shutdown")
check("signal.NotifyContext" in agent_src, "agent source handles signals")

if len(units) == 2:
    # Neither the real /etc/passwd nor /usr/local paths need to exist. These
    # files belong only to the disposable root, and no command executes them.
    with tempfile.TemporaryDirectory(prefix="axionpanel-systemd-") as tmp:
        root = Path(tmp)
        unit_dir = root / "etc/systemd/system"
        unit_dir.mkdir(parents=True)
        (root / "etc/passwd").write_text("root:x:0:0:root:/root:/usr/sbin/nologin\n"
                                         "axionpanel:x:999:999:AxionPanel:/var/lib/axionpanel:/usr/sbin/nologin\n")
        (root / "etc/group").write_text("root:x:0:\naxionpanel:x:999:\n")
        (root / "etc/nsswitch.conf").write_text("passwd: files\ngroup: files\n")
        # Minimal default dependencies for a synthetic root. Real hosts ship
        # these units. No-op stubs are parsed, never started.
        for target in ("sysinit", "basic", "shutdown", "multi-user"):
            (unit_dir / f"{target}.target").write_text(f"[Unit]\nDescription=Verification {target}\n")
        for name in units:
            (unit_dir / f"{name}.service").write_text((UNIT_DIR / f"{name}.service").read_text())
            binary = root / f"usr/local/axionpanel/bin/{name}"
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_text("#!/bin/sh\nexit 1\n")
            binary.chmod(0o755)
        command = ["systemd-analyze", f"--root={root}", "verify", "axionpanel.service", "axionpanel-agent.service"]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        output = (result.stdout + result.stderr).strip()
        print("systemd-analyze --root=<scratch> verify axionpanel.service axionpanel-agent.service")
        print(f"exit={result.returncode}; diagnostics={output or '(none)'}")
        check(result.returncode == 0 and not output, "systemd-analyze accepts both units without diagnostics")

print(f"{checks} assertions; {len(failures)} failures")
sys.exit(bool(failures))
