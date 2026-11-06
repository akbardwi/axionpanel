#!/usr/bin/env bash
# AxionPanel installer foundation: authenticate, inspect, stage only.
# No host provisioning, account creation, unit install, firewall change or
# staged binary execution exists in this build.
set -euo pipefail
for argument in "$@"; do
    if [[ "$argument" == --apply ]]; then
        printf '%s\n' 'install: apply not implemented' >&2
        exit 1
    fi
done
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec python3 -I -B - "$SCRIPT_DIR" "$@" <<'PY'
import argparse
import gzip
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
os.umask(0o077)

MIB = 1024 * 1024
ARCHIVE_LIMIT = 256 * MIB
BINARY_LIMIT = 128 * MIB
TOTAL_LIMIT = 256 * MIB


class Refusal(Exception):
    pass


def fail(message):
    raise Refusal(message)


def absolute(value):
    path = Path(value)
    if not path.is_absolute():
        fail(f"absolute path required: {path.name}")
    if ".." in path.parts:
        fail("parent traversal in supplied path")
    return path


def open_dir(path, label="directory"):
    """Open a directory through FDs; a symlink ancestor is never followed."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute(path).parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except OSError:
        os.close(fd)
        fail(f"{label} missing or symlink ancestor refused")


def read_regular(path, limit):
    """Bounded read from a pinned regular file; path-controlled tar never used."""
    path = absolute(path)
    parent = open_dir(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except OSError:
        fail("required file missing or symlink refused")
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            fail("regular bounded input required")
        data = stream.read(limit + 1)
        if len(data) > limit:
            fail("input size limit exceeded")
        return data


def read_os_release(root):
    """Allow the standard relative /etc/os-release symlink inside the root."""
    path = root / "etc/os-release"
    try:
        info = os.lstat(path)
    except OSError:
        fail("required file missing: etc/os-release")
    if stat.S_ISLNK(info.st_mode):
        resolved = Path(os.path.realpath(path))
        boundary = os.path.realpath(root)
        if os.path.commonpath([str(resolved), boundary]) != boundary:
            fail("os-release symlink escapes inspection root")
        try:
            fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            fail("required file missing: etc/os-release")
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                fail("regular os-release required")
            data = stream.read(65537)
        if len(data) > 65536:
            fail("os-release too large")
        return data
    return read_regular(path, 65536)


def preflight(root, arch, fixture):
    data = read_os_release(root).decode("utf-8")
    values = {}
    # os-release is parsed as data. Never sourced, evaluated or interpolated.
    pattern = re.compile(r"""(ID|VERSION_ID)=(?:"([A-Za-z0-9_.-]+)"|'([A-Za-z0-9_.-]+)'|([A-Za-z0-9_.-]+))""")
    for line in data.splitlines():
        match = pattern.fullmatch(line)
        if match:
            key = match.group(1)
            if key in values:
                fail("ambiguous os-release")
            values[key] = next(value for value in match.groups()[1:] if value is not None)
    if (values.get("ID"), values.get("VERSION_ID")) not in {
        ("ubuntu", "24.04"), ("ubuntu", "26.04"), ("debian", "12"), ("debian", "13")
    }:
        fail("unsupported OS")
    for name in ("usr/bin/systemctl", "usr/lib/systemd/systemd"):
        read_regular(root / name, 32 * MIB)
    existing = [
        "opt/axionpanel", "usr/local/axionpanel", "var/lib/axionpanel",
        "etc/axionpanel", "run/axionpanel", "etc/sysusers.d/axionpanel.conf",
        "etc/tmpfiles.d/axionpanel.conf",
    ]
    units = ("axionpanel.service", "axionpanel-native.service", "axionpanel-agent.service")
    existing += [f"{prefix}/{unit}" for prefix in
                 ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system") for unit in units]
    for name in existing:
        if os.path.lexists(root / name):
            fail("existing AxionPanel state; inspection refuses adoption")
    for name in ("www/server/panel", "usr/local/cpanel", "usr/local/psa", "usr/local/hestia",
                 "usr/local/vesta", "usr/local/directadmin", "etc/webmin",
                 "usr/local/ispconfig", "etc/cyberpanel"):
        if os.path.lexists(root / name):
            fail("conflicting panel detected")
    for name in ("etc/passwd", "etc/group"):
        path = root / name
        if os.path.lexists(path):
            text = read_regular(path, 8 * MIB).decode("utf-8")
            if any(line.startswith("axionpanel:") for line in text.splitlines()):
                fail("existing AxionPanel state: service account")
    scope = "fixture inspection only; not evidence of a clean VPS" if fixture else "live read-only inspection; no PID1/runtime proof"
    print(f"Preflight passed ({arch}; euid {os.geteuid()}; {scope}).")


def read_public_key(path):
    """Read a bounded trust anchor from one validated descriptor."""
    parent = open_trusted_dir(path.parent, "public key parent")
    try:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=parent)
        except OSError:
            fail("public key missing or symlink refused")
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                fail("public key must be a regular file")
            if info.st_uid not in (0, os.geteuid()):
                fail("public key must be owned by caller or root")
            if info.st_mode & 0o022:
                fail("public key is group/other writable")
            if info.st_size > 16384:
                fail("public key too large")
            data = stream.read(16385)
        if len(data) > 16384:
            fail("public key too large")
        return data
    finally:
        os.close(parent)


def open_trusted_dir(path, label):
    """Open a directory chain, refusing writable or foreign-owned ancestors.

    Pinning the final descriptor prevents a later rename/replacement of the
    path from redirecting writes into an attacker-controlled directory.
    """
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute(path).parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                os.close(child)
                fail(f"{label} ancestor is writable or foreign-owned")
            os.close(fd)
            fd = child
        return fd
    except OSError:
        os.close(fd)
        fail(f"{label} missing or symlink ancestor refused")
    except Refusal:
        os.close(fd)
        raise


def open_stage_parent(stage):
    """Pin the immediate stage parent; it must be caller-owned and private."""
    parent = open_trusted_dir(stage.parent, "stage parent")
    if os.fstat(parent).st_uid != os.geteuid():
        os.close(parent)
        fail("stage parent must be caller-owned")
    return parent


def snapshot_inputs(source, public_key_bytes, snapshot, release, version):
    fd = open_dir(source)
    try:
        names = set(os.listdir(fd))
    finally:
        os.close(fd)
    archives = {release.archive_name(version, arch) for arch in release.ARCHES}
    if names != archives | {"SHA256SUMS", "SHA256SUMS.sig"}:
        fail("verification failed: missing, extra or unsigned development entry")
    for name, limit in [("SHA256SUMS", 4096), ("SHA256SUMS.sig", 64),
                        *((name, ARCHIVE_LIMIT) for name in sorted(archives))]:
        data = read_regular(source / name, limit)
        with (snapshot / name).open("xb") as output:
            output.write(data)
    with (snapshot / "trusted-public-key.pem").open("xb") as output:
        output.write(public_key_bytes)


def validate_archive(path, arch, allowed, binaries):
    """Parse USTAR headers directly; extension headers cannot hide members.

    Exact whitelist, bounded sizes, installer-selected modes. Return bounded
    bytes only after full validation; never extractall, chown or execute.
    """
    contents = {}
    total = 0
    with gzip.open(path, "rb") as archive:
        while True:
            block = archive.read(512)
            if len(block) != 512:
                fail("unsafe archive: truncated header")
            if block == b"\0" * 512:
                if archive.read(512) != b"\0" * 512:
                    fail("unsafe archive: invalid end marker")
                trailing = archive.read(10241)
                if len(trailing) > 10240 or any(trailing):
                    fail("unsafe archive: trailing data")
                break
            member = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
            name = member.name
            if block[257:263] != b"ustar\0":
                fail("unsafe archive: non-USTAR header")
            if (name not in allowed or name in contents
                    or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    or member.linkname or getattr(member, "sparse", None) is not None):
                fail("unsafe archive: unexpected, duplicate or nonregular member")
            limit = BINARY_LIMIT if name in binaries else MIB
            if member.mode != (0o755 if name in binaries else 0o644):
                fail("unsafe archive: unexpected mode")
            if not 0 < member.size <= limit or total + member.size > TOTAL_LIMIT:
                fail("unsafe archive: size limit exceeded")
            data = archive.read(member.size)
            if len(data) != member.size:
                fail("unsafe archive: truncated member")
            padding = (-member.size) % 512
            if archive.read(padding) != b"\0" * padding:
                fail("unsafe archive: invalid padding")
            if name in binaries:
                machine = 62 if arch == "amd64" else 183
                if (len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01"
                        or struct.unpack_from("<H", data, 16)[0] not in (2, 3)
                        or struct.unpack_from("<H", data, 18)[0] != machine):
                    fail("unsafe archive: wrong ELF class or architecture")
            contents[name] = data
            total += member.size
    if set(contents) != allowed or len(contents) != len(allowed):
        fail("unsafe archive: missing required members")
    return contents


def verify(snapshot, checkout, version, environment):
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(checkout / "scripts/release.py"), "verify",
         "--directory", str(snapshot), "--version", version,
         "--public-key", str(snapshot / "trusted-public-key.pem")],
        capture_output=True, env=environment, timeout=120)
    if result.returncode:
        fail("verification failed: signature or checksum validation refused")
    # Keep OpenSSL/release output private: only status is needed here.


def main():
    checkout = Path(sys.argv[1])
    parser = argparse.ArgumentParser(
        description="AxionPanel foundation: preflight/verify/stage only. Apply is not implemented.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight-only", action="store_true")
    mode.add_argument("--verify-only", action="store_true")
    parser.add_argument("--directory", required=True, type=absolute,
                        help="local release directory containing both architectures")
    parser.add_argument("--version", required=True)
    parser.add_argument("--public-key", required=True, type=absolute,
                        help="independently trusted Ed25519 public key")
    parser.add_argument("--stage-dir", type=absolute,
                        help="required new private 0700 workspace (removed after inspection)")
    # Required below with fail-closed diagnostic for all modes.
    parser.add_argument("--root", type=absolute, help="inspection-only fake root")
    parser.add_argument("--arch", help="inspection-only architecture override")
    args = parser.parse_args(sys.argv[2:])
    inspection = args.preflight_only or args.verify_only
    if not inspection and (args.root is not None or args.arch is not None):
        fail("--root and --arch are inspection-only")
    if args.stage_dir is None:
        fail("required: --stage-dir for private verification workspace")
    public_key_bytes = read_public_key(args.public_key)
    spec = importlib.util.spec_from_file_location("trusted_release", checkout / "scripts/release.py")
    if spec is None or spec.loader is None:
        fail("trusted checkout scripts/release.py required")
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    release.validate_version(args.version)
    arch = args.arch or {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, "")
    if arch not in release.ARCHES:
        fail("unsupported architecture")
    if args.preflight_only:
        preflight(args.root or Path("/"), arch, args.root is not None)

    owned = False
    keep = False
    parent_fd = None
    try:
        # All writes stay inside the explicit new private workspace. Verify
        # copied bytes, then inspect only those copies; never reuse sources.
        parent_fd = open_stage_parent(args.stage_dir)
        try:
            os.mkdir(args.stage_dir.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            fail("stage directory already exists; refusing overwrite")
        owned = True
        snapshot = args.stage_dir / "snapshot"
        snapshot.mkdir(mode=0o700)
        stage = args.stage_dir
        snapshot_inputs(args.directory, public_key_bytes, snapshot, release, args.version)
        environment = {**os.environ, "TMPDIR": str(args.stage_dir)}
        verify(snapshot, checkout, args.version, environment)
        allowed = set(release.PACKAGE_FILES) | set(release.BINARIES)
        selected = None
        for candidate in release.ARCHES:
            try:
                data = validate_archive(snapshot / release.archive_name(args.version, candidate),
                                        candidate, allowed, release.BINARIES)
            except (tarfile.TarError, gzip.BadGzipFile, OSError, EOFError, UnicodeError, ValueError) as exc:
                fail(f"unsafe archive: {type(exc).__name__}")
            if candidate == arch:
                selected = data
        if inspection:
            print("Signature, checksums and exact archive contents verified; nothing extracted or changed.")
        else:
            payload = stage / "payload"
            payload.mkdir(mode=0o700)
            for name, data in selected.items():
                target = payload / name
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with target.open("xb") as stream:
                    stream.write(data)
                target.chmod(0o755 if name in release.BINARIES else 0o644)
            for directory in payload.rglob("*"):
                if directory.is_dir():
                    directory.chmod(0o755)
            keep = True
            print(f"Authenticated {arch} payload staged at {payload}. Nothing executed or installed.")
    finally:
        if parent_fd is not None:
            if owned and not keep:
                shutil.rmtree(args.stage_dir.name, dir_fd=parent_fd)
            os.close(parent_fd)


try:
    main()
except (Refusal, OSError, ValueError, UnicodeError, subprocess.SubprocessError) as exc:
    print(f"install: {exc}", file=sys.stderr)
    sys.exit(1)
except Exception as exc:
    print(f"install: refused ({type(exc).__name__})", file=sys.stderr)
    sys.exit(1)
PY
