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
native_path = UNIT_DIR / "axionpanel-native.service.example"
check(native_path.is_file(), "axionpanel-native.service.example exists")
if native_path.is_file():
    native = parse_unit(native_path.read_text())
    nget = lambda key: native.get(("Service", key), [None])[-1]
    ncommand = nget("ExecStart") or ""
    nflags = set(re.findall(r"(?:flag|fs)\.(?:String|Bool|Int)\(\"([a-z0-9-]+)\"",
                            (REPO / "cmd/panel/main.go").read_text()))
    nused = set(re.findall(r"(?:^|\s)-([a-z][a-z0-9-]*)", ncommand))
    check(bool(nused), "native panel: CLI flags present")
    check(not nused - nflags, f"native panel: unsupported flags {sorted(nused - nflags)}")
    check(nget("User") == "axionpanel" and nget("Group") == "axionpanel", "native panel: service user/group")
    check(nget("WorkingDirectory") == "/var/lib/axionpanel", "native panel: state working directory")
    check(nget("StateDirectory") == "axionpanel" and nget("StateDirectoryMode") == "0700", "native panel: StateDirectory")
    check(nget("UMask") == "0077" and nget("Restart") == "on-failure" and nget("TimeoutStopSec") == "15s", "native panel: lifecycle basics")
    check(nget("NoNewPrivileges") == "yes" and nget("ProtectSystem") == "strict", "native panel: base sandboxing")
    check(nget("CapabilityBoundingSet") == "" and nget("AmbientCapabilities") == "", "native panel: no capabilities")
    check(nget("RestrictAddressFamilies") == "AF_UNIX AF_INET AF_INET6", "native panel: address families")
    check(nget("MemoryDenyWriteExecute") == "yes" and nget("SystemCallFilter") == "@system-service", "native panel: syscall/execmem guards")
    # Preserve every service sandbox/lifecycle directive from the loopback
    # profile; only its command is different. This catches future drift too.
    for (section, key), values in units.get("axionpanel", {}).items():
        if section == "Service" and key != "ExecStart":
            check(native.get((section, key)) == values, f"native panel: preserves {key}")
    for key in ("ExecStartPre", "ExecStartPost", "ExecStopPost", "ReadWritePaths", "EnvironmentFile"):
        check(nget(key) is None, f"native panel: no {key}")
    check(not nused & {"init-tls", "tls-host", "init-entrance", "bootstrap-admin", "bootstrap-out", "trusted-proxy"},
          "native panel: serving only, direct peer addresses")
    check(native.get(("Install", "WantedBy")) == ["multi-user.target"], "native panel: manual enable target")
    check(ncommand.startswith("/usr/local/axionpanel/bin/axionpanel "), "native panel: absolute trusted binary")
    check("network-online.target" in " ".join(native.get(("Unit", "After"), [])), "native panel: network-online ordering")
    check("network-online.target" in " ".join(native.get(("Unit", "Wants"), [])), "native panel: network-online dependency")
    check(not native.get(("Unit", "Requires")), "native panel: agent failure does not stop login")
    check(native.get(("Unit", "StartLimitIntervalSec")) == ["60"] and
          native.get(("Unit", "StartLimitBurst")) == ["3"], "native panel: restart rate limit")
    for key in ("InaccessiblePaths", "TemporaryFileSystem", "BindPaths", "BindReadOnlyPaths"):
        check(nget(key) is None, f"native panel: no extra {key}")
    allowed_service = {key for section, key in units.get("axionpanel", {}) if section == "Service"}
    check(not {key for section, key in native if section == "Service"} - allowed_service,
          "native panel: no unreviewed service directives")
    check("insecure-loopback" not in nused, "native panel: no insecure-loopback")
    check(native.get(("Unit", "After"), [""]) and "axionpanel-agent.service" in " ".join(native.get(("Unit", "After"), [])), "native panel: orders agent")
    check("axionpanel-agent.service" in " ".join(native.get(("Unit", "Wants"), [])), "native panel: wants agent")
    for flag, value in {
        "addr": "192.0.2.10:8443",
        "origin": "https://192.0.2.10:8443",
        "tls-cert": "/etc/axionpanel/tls/panel.crt",
        "tls-key": "/etc/axionpanel/tls/panel.key",
        "entrance-file": "/var/lib/axionpanel/entrance",
        "db": "/var/lib/axionpanel/panel.db",
        "secret-key": "/var/lib/axionpanel/secret.key",
        "agent-socket": "/run/axionpanel/agent.sock",
    }.items():
        check(bool(re.search(rf"(?:^|\s)-{flag}\s+{re.escape(value)}(?:\s|$)", ncommand)),
              f"native panel: -{flag} {value}")
    check("192.0.2.10" in ncommand and "192.0.2.10:8443" in ncommand, "native panel: documentation TEST-NET IP placeholder")
    tls_dir = UNIT_DIR / "axionpanel-tls.tmpfiles.conf.example"
    check(tls_dir.is_file(), "axionpanel-tls.tmpfiles.conf.example exists")
    if tls_dir.is_file():
        tls_lines = [l for l in tls_dir.read_text().splitlines() if l and not l.startswith(("#", ";"))]
        check(len(tls_lines) == 1 and tls_lines[0].startswith("d /etc/axionpanel/tls 0750 root axionpanel -"),
              "native tmpfiles: TLS directory exactly root:axionpanel 0750")
    doc_native = REPO / "docs/native-tls-systemd.md"
    check(doc_native.is_file(), "native-tls-systemd documentation exists")
    if doc_native.is_file():
        native_doc = doc_native.read_text()
        for needle in ("TEST-NET", "192.0.2.10", "-init-tls", "chgrp axionpanel", "chmod 0640",
                       "chown root:axionpanel", "umask 077", "runuser -u axionpanel",
                       "-init-entrance", "-bootstrap-out", "/var/lib/axionpanel/bootstrap.json",
                       "openssl x509 -noout -fingerprint -sha256", "systemd-analyze verify",
                       "curl --cacert", "--insecure", "self-signed", "no firewall", "TEST-NET",
                       "0750", "0640", "0600", "panel.crt", "panel.key", "axionpanel-native.service"):
            check(needle in native_doc, f"native-tls-systemd docs: {needle}")
        # The template must stay separate from the loopback unit and never
        # claim a live deployment was performed.
        check("not tested under PID1" in " ".join(native_doc.split()),
              "native-tls-systemd docs: static-verification caveat")
        check("does not open a public port" in native_doc or "does not open" in native_doc,
              "native-tls-systemd docs: no public-port claim in the static template")
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
                   "-bootstrap-admin", "runuser", "umask 077", "Policy is enforced on every operation", "no generic exec",
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

if native_path.is_file() and len(units) == 2:
    # Separate root: the two panel profiles are alternatives and must not be
    # installed as concurrent units. Static parsing still proves both names.
    with tempfile.TemporaryDirectory(prefix="axionpanel-native-systemd-") as tmp:
        root = Path(tmp)
        unit_dir = root / "etc/systemd/system"
        unit_dir.mkdir(parents=True)
        (root / "etc/passwd").write_text("root:x:0:0:root:/root:/usr/sbin/nologin\n"
                                         "axionpanel:x:999:999:AxionPanel:/var/lib/axionpanel:/usr/sbin/nologin\n")
        (root / "etc/group").write_text("root:x:0:\naxionpanel:x:999:\n")
        (root / "etc/nsswitch.conf").write_text("passwd: files\ngroup: files\n")
        for target in ("sysinit", "basic", "shutdown", "multi-user", "network-online"):
            (unit_dir / f"{target}.target").write_text(f"[Unit]\nDescription=Verification {target}\n")
        (unit_dir / "axionpanel.service").write_text(native_path.read_text())
        (unit_dir / "axionpanel-agent.service").write_text((UNIT_DIR / "axionpanel-agent.service").read_text())
        for name in ("axionpanel", "axionpanel-agent"):
            binary = root / f"usr/local/axionpanel/bin/{name}"
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_text("#!/bin/sh\nexit 1\n")
            binary.chmod(0o755)
        command = ["systemd-analyze", f"--root={root}", "verify",
                   "axionpanel.service", "axionpanel-agent.service"]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        output = (result.stdout + result.stderr).strip()
        print("systemd-analyze --root=<scratch> verify native axionpanel.service axionpanel-agent.service")
        print(f"exit={result.returncode}; diagnostics={output or '(none)'}")
        check(result.returncode == 0 and not output,
              "systemd-analyze accepts the native profile without diagnostics")

print(f"{checks} assertions; {len(failures)} failures")
sys.exit(bool(failures))
