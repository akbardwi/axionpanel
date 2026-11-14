#!/usr/bin/env bash
# AxionPanel standalone bootstrap: authenticate, inspect, stage and install.
# No checkout is required; host mutation is explicit and fresh-host only.
set -euo pipefail
exec python3 -I -B - "$@" <<'PY'
import argparse
import contextlib
import gzip
import hashlib
import http.client
import ipaddress
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse

sys.dont_write_bytecode = True
os.umask(0o077)

MIB = 1024 * 1024
ARCHIVE_LIMIT = 256 * MIB
BINARY_LIMIT = 128 * MIB
TOTAL_LIMIT = 256 * MIB
MANIFEST_LIMIT = 4096
SIGNATURE_SIZE = 64
MAX_REDIRECTS = 3
DOWNLOAD_DEADLINE = 300
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

try:
    ARCHES = ("amd64", "arm64")
    BINARIES = ("axionpanel", "axionpanel-agent")
    PACKAGE_FILES = (
        "README.md",
        "deploy/nginx/axionpanel.conf.example",
        "deploy/systemd/agent.toml.example",
        "deploy/systemd/axionpanel-agent.service",
        "deploy/systemd/axionpanel-native.service.example",
        "deploy/systemd/axionpanel-tls.tmpfiles.conf.example",
        "deploy/systemd/axionpanel.service",
        "deploy/systemd/axionpanel.sysusers.conf",
        "deploy/systemd/axionpanel.tmpfiles.conf",
        "docs/agent.md",
        "docs/deployment.md",
        "docs/native-tls-systemd.md",
        "docs/public-access.md",
        "docs/secure-onboarding.md",
    )
except Exception:
    pass


class Refusal(Exception):
    pass


class DownloadDeadline(Refusal):
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
    pattern = re.compile(r"""(ID|VERSION_ID)=(?:"([A-Za-z0-9_.-]+)"|'([A-Za-z0-9_.-]+)|([A-Za-z0-9_.-]+))""")
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


def ed25519_public_key(data):
    """Refuse anything the immutable bytes do not prove is one Ed25519 key."""
    try:
        der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            input=data, check=True, capture_output=True, timeout=60,
            env={"PATH": "/usr/sbin:/usr/bin:/bin"}).stdout
    except (OSError, subprocess.SubprocessError):
        fail("public key must be a single Ed25519 PEM public key")
    if len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
        fail("public key must be Ed25519 (44-byte SPKI)")
    return data


def read_public_key(path):
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
        return ed25519_public_key(data)
    finally:
        os.close(parent)


def open_trusted_dir(path, label):
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
    parent = open_trusted_dir(stage.parent, "stage parent")
    if os.fstat(parent).st_uid != os.geteuid():
        os.close(parent)
        fail("stage parent must be caller-owned")
    return parent


def validate_version(version):
    core = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    suffix = r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    match = re.fullmatch(core + suffix, version, flags=re.ASCII)
    if not match or len(version) > 64:
        fail("version refused: SemVer without v prefix, whitespace or paths required")
    return version


def archive_name(version, arch):
    if arch not in ARCHES:
        fail("unsupported architecture")
    return f"axionpanel-{version}-linux-{arch}.tar.gz"


def expected_archives(version):
    return {archive_name(version, arch) for arch in ARCHES}


def snapshot_inputs(source, public_key_bytes, snapshot, version):
    fd = open_dir(source)
    try:
        names = set(os.listdir(fd))
    finally:
        os.close(fd)
    archives = expected_archives(version)
    if names != archives | {"SHA256SUMS", "SHA256SUMS.sig"}:
        fail("verification failed: missing, extra or unsigned development entry")
    for name, limit in [("SHA256SUMS", MANIFEST_LIMIT), ("SHA256SUMS.sig", SIGNATURE_SIZE),
                        *((name, ARCHIVE_LIMIT) for name in sorted(archives))]:
        data = read_regular(source / name, limit)
        with (snapshot / name).open("xb") as output:
            output.write(data)
    with (snapshot / "trusted-public-key.pem").open("xb") as output:
        output.write(public_key_bytes)


def validate_archive(path, arch, allowed, binaries):
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


def verify_manifest_signature(snapshot, manifest, signature):
    if len(signature) != SIGNATURE_SIZE:
        fail("verification failed: Ed25519 signature must be exactly 64 bytes")
    # Verify the bytes that were read, not a path another process could swap.
    checked_manifest = snapshot / "manifest.checked"
    checked_signature = snapshot / "signature.checked"
    with checked_manifest.open("xb") as stream:
        stream.write(manifest)
    with checked_signature.open("xb") as stream:
        stream.write(signature)
    try:
        subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-rawin",
             "-inkey", str(snapshot / "trusted-public-key.pem"),
             "-in", str(checked_manifest), "-sigfile", str(checked_signature)],
            check=True, capture_output=True, timeout=60,
            cwd=str(snapshot), env={"PATH": "/usr/sbin:/usr/bin:/bin"})
    except (OSError, subprocess.SubprocessError):
        fail("verification failed: manifest signature verification failed")


def verify_snapshot(snapshot, version):
    manifest_path = snapshot / "SHA256SUMS"
    signature_path = snapshot / "SHA256SUMS.sig"
    manifest = read_regular(manifest_path, MANIFEST_LIMIT)
    signature = read_regular(signature_path, SIGNATURE_SIZE)
    # Authenticate the bounded manifest before any filename or digest is parsed.
    verify_manifest_signature(snapshot, manifest, signature)
    expected = expected_archives(version)
    entries = {}
    for line in manifest.splitlines(keepends=True):
        match = re.fullmatch(rb"([0-9a-f]{64})  ([A-Za-z0-9_.+-]+\.tar\.gz)\n", line)
        if not match:
            fail("verification failed: malformed or unsafe manifest")
        digest, name = (value.decode("ascii") for value in match.groups())
        if name in entries or name not in expected:
            fail("verification failed: duplicate or unexpected manifest entry")
        entries[name] = digest
    if set(entries) != expected:
        fail("verification failed: missing manifest archive")
    for name in sorted(entries):
        data = read_regular(snapshot / name, ARCHIVE_LIMIT)
        digest = hashlib.sha256(data).hexdigest()
        if digest != entries[name]:
            fail("verification failed: archive digest mismatch")


def read_ca_file(path):
    parent = open_trusted_dir(path.parent, "CA file parent")
    try:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except OSError:
            fail("CA file missing or symlink refused")
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                fail("CA file must be a bounded regular file")
            if info.st_uid not in (0, os.geteuid()):
                fail("CA file must be owned by caller or root")
            if info.st_mode & 0o022:
                fail("CA file is group/other writable")
            data = stream.read(65537)
        if len(data) > 65536:
            fail("CA file must be a bounded regular file")
        return data
    finally:
        os.close(parent)


def ca_context(data):
    """Build the one TLS trust context from the already-validated CA bytes."""
    context = ssl.create_default_context()
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            context.load_verify_locations(cadata=data.decode("ascii"))
        else:
            context.load_verify_locations(cadata=data)
    except (UnicodeDecodeError, ssl.SSLError):
        fail("CA file must contain PEM certificates")
    return context


def validated_download_base(base):
    parsed = urllib.parse.urlsplit(base)
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.query
            or parsed.fragment or not parsed.hostname or ":" in parsed.hostname):
        fail("download base URL refused: HTTPS without credentials, query or fragment required")
    host = parsed.hostname
    port = parsed.port or 443
    path = parsed.path or "/"
    if not path.endswith("/"):
        path += "/"
    if len(path) > 2048 or any(part in (".", "..") for part in path.split("/")):
        fail("download base URL path refused")
    return host, port, path


@contextlib.contextmanager
def hard_deadline(seconds):
    """Absolute cancellation for one whole transfer.

    SIGALRM bounds DNS, connect, TLS, header parsing and body reads, none of
    which the cooperative monotonic checks can interrupt. Signals only exist on
    the main thread, so tests that execute the downloader in a worker thread
    keep the per-read fallback instead.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def expire(signum, frame):
        raise DownloadDeadline("download deadline exceeded")

    previous_handler = signal.signal(signal.SIGALRM, expire)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


def download_file(url, destination, limit, context):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.username or parsed.password
            or parsed.query or parsed.fragment or not parsed.hostname):
        fail("download URL refused")
    host = parsed.hostname
    port = parsed.port or 443
    request = parsed.path or "/"
    if parsed.query:
        request += "?" + parsed.query
    deadline = time.monotonic() + DOWNLOAD_DEADLINE
    redirects = 0
    with hard_deadline(DOWNLOAD_DEADLINE):
        while True:
            if time.monotonic() > deadline:
                fail("download deadline exceeded")
            connection = http.client.HTTPSConnection(host, port, context=context, timeout=30)
            try:
                connection.request("GET", request)
                response = connection.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    redirects += 1
                    if redirects > MAX_REDIRECTS:
                        fail("download redirect limit exceeded")
                    location = response.getheader("Location")
                    if not location:
                        fail("download redirect has no location")
                    url = urllib.parse.urljoin(url, location)
                    next_parsed = urllib.parse.urlsplit(url)
                    if next_parsed.scheme != "https" or next_parsed.username or next_parsed.password:
                        fail("download HTTPS redirect refused")
                    host = next_parsed.hostname or ""
                    port = next_parsed.port or 443
                    request = next_parsed.path or "/"
                    if next_parsed.query:
                        request += "?" + next_parsed.query
                    continue
                if response.status != 200:
                    fail(f"verification failed: download status {response.status}")
                length = response.getheader("Content-Length")
                if length and int(length) > limit:
                    fail("download exceeds size limit")
                received = 0
                with destination.open("xb") as output:
                    while True:
                        if time.monotonic() > deadline:
                            fail("download deadline exceeded")
                        # read1 returns after one buffered/socket read instead of
                        # waiting for a full MiB while a peer trickles forever.
                        chunk = response.read1(1024 * 1024)
                        if not chunk:
                            break
                        received += len(chunk)
                        if received > limit:
                            fail("download exceeds size limit")
                        output.write(chunk)
                return received
            finally:
                connection.close()


def acquire_sources(args, public_key_bytes, snapshot, version):
    host, port, base_path = validated_download_base(args.download_base_url)
    if args.ca_file is None:
        context = ssl.create_default_context()
    else:
        # Validate metadata and bytes once, then pin only those bytes.
        context = ca_context(read_ca_file(absolute(args.ca_file)))
    names = {
        "SHA256SUMS": MANIFEST_LIMIT,
        "SHA256SUMS.sig": SIGNATURE_SIZE,
        **{name: ARCHIVE_LIMIT for name in expected_archives(version)},
    }
    for name, limit in names.items():
        destination = snapshot / name
        download_file(f"https://{host}:{port}{base_path}{urllib.parse.quote(name)}",
                      destination, limit, context)
    with (snapshot / "trusted-public-key.pem").open("xb") as output:
        output.write(public_key_bytes)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="AxionPanel standalone bootstrap. Apply provisions a fresh host and is explicit-only.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--directory", type=absolute,
                       help="local release directory containing both architectures")
    source.add_argument("--download-base-url",
                       help="HTTPS release base URL; default is GitHub when omitted and no --directory")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--preflight-only", action="store_true")
    source.add_argument("--verify-only", action="store_true")
    # Apply is an inspection alternative too: silently ignoring --apply when an
    # inspection flag is present would look like a successful install.
    source.add_argument("--apply", action="store_true")
    parser.add_argument("--version", required=True)
    parser.add_argument("--public-key", required=True, type=absolute)
    parser.add_argument("--ca-file", type=absolute,
                        help="explicit trusted CA bundle for download TLS validation")
    parser.add_argument("--stage-dir", type=absolute,
                        help="required new private 0700 workspace; apply may default to a private /var/tmp directory")
    parser.add_argument("--root", type=absolute, help="inspection-only fake root")
    parser.add_argument("--arch", help="inspection-only architecture override")
    add_apply_arguments(parser)
    args = parser.parse_args(argv)
    return args


# BEGIN AXIONPANEL APPLY ENGINE
"""Self-contained fresh-host apply fragment. No downloads or trust bootstrap.

Keep all private symbols prefixed: this source is embedded verbatim into the
standalone installer as well as imported by its safe unit tests. There is no
alternate root, command injection hook, environment override, or reset mode.
"""
import contextlib as ap_contextlib
import fcntl as ap_fcntl
import grp as ap_grp
import hashlib as ap_hashlib
import http.client as ap_http
import http.cookies as ap_cookies
import ipaddress as ap_ipaddress
import json as ap_json
import os as ap_os
import pwd as ap_pwd
import re as ap_re
import socket as ap_socket
import ssl as ap_ssl
import stat as ap_stat
import subprocess as ap_subprocess
import time as ap_time


_AP_BINARY = '/usr/local/axionpanel/bin/axionpanel'
_AP_AGENT = '/usr/local/axionpanel/bin/axionpanel-agent'
_AP_STATE = '/var/lib/axionpanel'
_AP_CERT = '/etc/axionpanel/tls/panel.crt'
_AP_KEY = '/etc/axionpanel/tls/panel.key'
_AP_UNITS = ('axionpanel-agent.service', 'axionpanel.service')
_AP_MEMBERS = (
    'axionpanel', 'axionpanel-agent', 'README.md',
    'deploy/nginx/axionpanel.conf.example', 'deploy/systemd/agent.toml.example',
    'deploy/systemd/axionpanel-agent.service',
    'deploy/systemd/axionpanel-native.service.example',
    'deploy/systemd/axionpanel-tls.tmpfiles.conf.example',
    'deploy/systemd/axionpanel.service', 'deploy/systemd/axionpanel.sysusers.conf',
    'deploy/systemd/axionpanel.tmpfiles.conf', 'docs/agent.md',
    'docs/deployment.md', 'docs/native-tls-systemd.md', 'docs/public-access.md',
    'docs/secure-onboarding.md',
)
_AP_DESTINATIONS = (
    '/opt/axionpanel', '/usr/local/axionpanel', '/var/lib/axionpanel',
    '/etc/axionpanel', '/run/axionpanel', '/var/log/axionpanel',
    '/etc/sysusers.d/axionpanel.conf', '/etc/tmpfiles.d/axionpanel.conf',
    '/etc/tmpfiles.d/axionpanel-tls.conf',
)
_AP_CONFLICTS = (
    '/www/server/panel', '/usr/local/cpanel', '/usr/local/psa',
    '/usr/local/hestia', '/usr/local/vesta', '/usr/local/directadmin',
    '/etc/webmin', '/usr/local/ispconfig', '/etc/cyberpanel',
)
_AP_COMMANDS = (
    '/usr/bin/systemctl', '/usr/bin/systemd-sysusers',
    '/usr/bin/systemd-analyze', '/usr/sbin/runuser', '/usr/sbin/nologin',
)


def add_apply_arguments(parser):
    parser.add_argument('--yes', action='store_true', help='consent to fresh-host provisioning')
    parser.add_argument('--host', default='auto', help='auto (default route), an IP address, or 127.0.0.1')
    parser.add_argument('--open-firewall', action='store_true',
                        help='with --apply, add one ufw allow rule after the panel is ready')
    parser.add_argument('--port', type=int, default=8443, help='unprivileged native HTTPS port (not 7800)')
    parser.add_argument('--allow-public-listen', action='store_true', help='explicitly permit a non-loopback listener')
    parser.add_argument('--admin', default='admin', help='first administrator username')


_AP_UFW = '/usr/sbin/ufw'
_AP_PROBE = ('198.51.100.1', 53)
_AP_ADDRESS_ERROR = 'host must be a canonical unicast IP address'
_AP_UFW_AMBIGUOUS = 'ambiguous ufw rule; manage the firewall manually'
# A single port, a range or a comma-separated list of either.
_AP_UFW_PORTS = r'[0-9]+(?::[0-9]+)?(?:,[0-9]+(?::[0-9]+)?)*'


def _ap_canonical_address(value):
    try:
        ip = ap_ipaddress.ip_address(value)
    except ValueError:
        raise RuntimeError(_AP_ADDRESS_ERROR) from None
    # Require the canonical compressed IPv6 spelling and reject aliases.
    # A fixed listener identity must not be multicast, unspecified, reserved,
    # link-local or IPv4-mapped IPv6; loopback and private unicast are valid.
    if (str(ip) != value or '%' in value or ip.is_multicast or ip.is_unspecified or
            (ip.is_reserved and not ip.is_loopback) or ip.is_link_local or
            (ip.version == 6 and getattr(ip, 'ipv4_mapped', None) is not None)):
        raise RuntimeError(_AP_ADDRESS_ERROR)
    return ip


def _ap_detect_host():
    """Ask the kernel for the default-route IPv4 source address; send no traffic.

    A connected UDP socket resolves the routing decision without transmitting,
    querying DNS or contacting an external "what is my IP" service.
    """
    try:
        with ap_socket.socket(ap_socket.AF_INET, ap_socket.SOCK_DGRAM) as probe:
            probe.connect(_AP_PROBE)
            address = probe.getsockname()[0]
    except OSError:
        raise RuntimeError('no default route found; pass --host with an address, or --host 127.0.0.1') from None
    if _AP_PROBE[0] != address:
        return address
    raise RuntimeError('default route reports a probe address; pass --host explicitly')


def _ap_ufw_rule_ports(line):
    """Numeric port spans in a UFW status line's ``To`` field.

    ``None`` means the rule covers every port. Raises for any destination that
    is not plainly numeric: an app profile or interface policy must never be
    mistaken for the installer-owned rule during rollback.
    """
    tokens = line.split()
    index = next((i for i, token in enumerate(tokens)
                  if token in ('ALLOW', 'DENY', 'REJECT', 'LIMIT')), None)
    if index is None:
        raise RuntimeError(_AP_UFW_AMBIGUOUS)
    _ap_ufw_source(' '.join(tokens[index + 1:]))
    text = ' '.join(tokens[:index])
    if text.endswith(' (v6)'):
        text = text[:-len(' (v6)')]
    if text == 'Anywhere':
        return None
    if '/' in text:
        text, _, protocol = text.rpartition('/')
        if protocol not in ('tcp', 'udp'):
            raise RuntimeError(_AP_UFW_AMBIGUOUS)
    if not ap_re.fullmatch(_AP_UFW_PORTS, text, flags=ap_re.ASCII):
        raise RuntimeError(_AP_UFW_AMBIGUOUS)
    spans = []
    for part in text.split(','):
        low, _, high = part.partition(':')
        start, end = int(low), int(high) if high else int(low)
        if not 1 <= start <= end <= 65535:
            raise RuntimeError(_AP_UFW_AMBIGUOUS)
        spans.append((start, end))
    return spans


def _ap_ufw_source(text):
    """Validate a UFW ``From`` field: Anywhere, an address or a prefixed network."""
    if text.endswith(' (v6)'):
        text = text[:-len(' (v6)')]
    if text.startswith('(') and text.endswith(')'):
        # An interface-bound rule such as '(eth0)'.
        text = text[1:-1]
    source, _, interface = text.partition(' on ')
    if interface and not ap_re.fullmatch(r'[A-Za-z0-9_.:+-]+', interface, flags=ap_re.ASCII):
        raise RuntimeError(_AP_UFW_AMBIGUOUS)
    if interface and not source:
        raise RuntimeError(_AP_UFW_AMBIGUOUS)
    if source == 'Anywhere':
        return
    try:
        ap_ipaddress.ip_network(source, strict=False)
    except ValueError:
        raise RuntimeError(_AP_UFW_AMBIGUOUS) from None


def _ap_firewall_plan(args):
    return 'ufw allow %d/tcp' % args.port if args.open_firewall else 'unchanged'


def _ap_check_firewall(args):
    """Read-only UFW preconditions: active, unambiguous, no selected port rule."""
    if not args.open_firewall:
        return
    _ap_check_command(_AP_UFW)
    try:
        lines = _ap_run([_AP_UFW, 'status']).decode('ascii').splitlines()
    except UnicodeError:
        raise RuntimeError('ambiguous ufw status; manage the firewall manually') from None
    if not lines or lines[0] != 'Status: active':
        raise RuntimeError('--open-firewall requires an active ufw firewall; it is never enabled or reset')
    rest = [line.strip() for line in lines[1:] if line.strip()]
    if not rest:
        return
    if (len(rest) < 2 or rest[0].split() != ['To', 'Action', 'From'] or
            rest[1].split() != ['--', '------', '----']):
        raise RuntimeError('ambiguous ufw status; manage the firewall manually')
    # Any rule already covering the selected port is refused whatever its
    # action or protocol, and any destination that cannot be read as numeric
    # ports (app profile, interface, unparsable text) is treated as ambiguous.
    for line in rest[2:]:
        ports = _ap_ufw_rule_ports(line.split(' # ', 1)[0])
        if ports is None or any(low <= args.port <= high for low, high in ports):
            raise RuntimeError('ufw already has a rule for port %d; refusing adoption' % args.port)


def _ap_open_firewall(args):
    # Recheck immediately before publishing, not only during earlier validation.
    _ap_check_firewall(args)
    rule = '%d/tcp' % args.port
    comment = 'axionpanel-install-' + ap_os.urandom(16).hex()
    # The invocation-specific comment is part of UFW's rule identity.
    args._firewall_rule = rule
    args._firewall_comment = comment
    output = _ap_run([_AP_UFW, 'allow', rule, 'comment', comment])
    if output.splitlines() not in ([b'Rule added'], [b'Rule added', b'Rule added (v6)']):
        raise RuntimeError('ufw did not confirm a newly added rule; manual reconciliation required')


def _ap_rollback_firewall(args):
    rule = getattr(args, '_firewall_rule', None)
    if rule is None:
        return True
    comment = getattr(args, '_firewall_comment', None)
    if not comment:
        return False
    try:
        output = _ap_run([_AP_UFW, 'delete', 'allow', rule, 'comment', comment])
        if output.splitlines() not in ([b'Rule deleted'], [b'Rule deleted', b'Rule deleted (v6)']):
            return False
    except RuntimeError:
        return False
    args._firewall_rule = None
    args._firewall_comment = None
    return True


def _ap_options(args):
    if not args.apply:
        if args.open_firewall:
            raise RuntimeError('--open-firewall requires --apply')
        return
    if args.host == 'auto':
        detected = _ap_detect_host()
        try:
            ip = _ap_canonical_address(detected)
            if ip.version != 4 or ip.is_loopback:
                raise RuntimeError('unusable route')
        except RuntimeError:
            raise RuntimeError('unusable detected address; pass --host explicitly') from None
        args.host = detected
    ip = _ap_canonical_address(args.host)
    if not ip.is_loopback and not args.allow_public_listen:
        raise RuntimeError('non-loopback listener requires --allow-public-listen')
    if args.open_firewall and ip.is_loopback:
        raise RuntimeError('--open-firewall is not allowed for loopback')
    if getattr(args, 'root', None) is not None or getattr(args, 'arch', None) is not None:
        raise RuntimeError('--root and --arch are inspection-only')
    if isinstance(args.port, bool) or not isinstance(args.port, int) or not 1024 <= args.port <= 65535 or args.port == 7800:
        raise RuntimeError('port must be 1024..65535 and not 7800')
    if not ap_re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', args.admin, flags=ap_re.ASCII):
        raise RuntimeError('invalid administrator username')
    if ap_os.geteuid() != 0:
        raise RuntimeError('apply requires root')


def _ap_open_tty():
    # Text update mode requires seeking; terminals need independent streams.
    with ap_contextlib.ExitStack() as streams:
        try:
            reader = streams.enter_context(open('/dev/tty', 'r', errors='replace'))
            writer = streams.enter_context(open('/dev/tty', 'w', buffering=1, errors='replace'))
        except OSError:
            raise RuntimeError('apply requires --yes when no terminal is available') from None
        streams.pop_all()  # Both streams now belong to the confirmation caller.
        return reader, writer


def _ap_plan(args):
    local = not _ap_canonical_address(args.host).is_global
    return ('AxionPanel will be provisioned on this fresh host:\n'
            '  Listen: %s\n  Origin: https://%s%s\n  Administrator: %s\n'
            '  Firewall: %s\n'
            '  Native HTTPS, self-signed certificate; agent stays on a Unix socket.\n'
            '  Creates service account, binaries, private state and systemd units.\n'
            '  Starts and enables only the new AxionPanel services after readiness.\n'
            '  Failure preserves partial state for manual reconciliation.\n'
            '%s'
            % (_ap_hostport(args.host, args.port), _ap_authority(args),
               ' (LOCAL address)' if local else '', args.admin, _ap_firewall_plan(args),
               '  LOCAL address: external reachability is not guaranteed; provider routing and firewall rules still apply.\n'
               if local else '  External reachability is not guaranteed; provider routing and firewall rules still apply.\n'))


def _ap_confirm(args):
    """Read consent only from the controlling terminal, never installer stdin."""
    reader, writer = _ap_open_tty()
    with ap_contextlib.ExitStack() as streams:
        streams.callback(reader.close)
        streams.callback(writer.close)
        writer.write('\n' + _ap_plan(args) + 'Type INSTALL to continue: ')
        writer.flush()
        answer = reader.readline()
    if answer.strip() != 'INSTALL':
        raise RuntimeError('installation not confirmed')
    args.yes = True


def validate_apply(args):
    """Read-only; safe to call before any network access or provisioning."""
    _ap_options(args)
    if not args.apply:
        return
    if not args.yes:
        _ap_confirm(args)
    elif not getattr(args, '_plan_shown', False):
        print(_ap_plan(args), end='')
    args._plan_shown = True
    try:
        _ap_fresh_checks(args)
    except (OSError, ValueError, KeyError):
        raise RuntimeError('fresh-host prerequisites could not be checked') from None


def _ap_open_dir(path):
    """Pin a root-owned, non-writable, entirely non-symlink directory chain."""
    if not path.startswith('/') or '..' in path.split('/'):
        raise RuntimeError('trusted absolute directory required')
    fd = ap_os.open('/', ap_os.O_RDONLY | ap_os.O_DIRECTORY | ap_os.O_NOFOLLOW)
    try:
        for component in path.split('/')[1:]:
            if not component:
                continue
            child = ap_os.open(component, ap_os.O_RDONLY | ap_os.O_DIRECTORY | ap_os.O_NOFOLLOW, dir_fd=fd)
            ap_os.close(fd)
            fd = child
            info = ap_os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError('unsafe installation directory ownership or permissions')
        return fd
    except (OSError, RuntimeError):
        ap_os.close(fd)
        raise RuntimeError('unsafe or missing installation directory') from None


def _ap_read(path, limit, uid=0, private=False):
    parent, name = path.rsplit('/', 1)
    # State is intentionally user-owned; its root-controlled parent was pinned
    # during creation. Do not reuse the root-only walker for that final directory.
    base = _ap_open_dir('/var/lib' if parent == _AP_STATE else parent)
    try:
        if parent == _AP_STATE:
            child = ap_os.open('axionpanel', ap_os.O_RDONLY | ap_os.O_DIRECTORY | ap_os.O_NOFOLLOW, dir_fd=base)
            ap_os.close(base)
            base = child
            info = ap_os.fstat(base)
            if info.st_uid != uid or info.st_mode & 0o077:
                raise RuntimeError('unsafe private state directory')
        fd = ap_os.open(name, ap_os.O_RDONLY | ap_os.O_NOFOLLOW | ap_os.O_NONBLOCK, dir_fd=base)
        with ap_os.fdopen(fd, 'rb') as stream:
            info = ap_os.fstat(stream.fileno())
            if not ap_stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_mode & (0o077 if private else 0o022):
                raise RuntimeError('unsafe installation file')
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise RuntimeError('installation file exceeds size limit')
            return data
    except OSError:
        raise RuntimeError('installation file unavailable or unsafe') from None
    finally:
        ap_os.close(base)


def _ap_check_command(path):
    if path not in _AP_COMMANDS + (_AP_BINARY, _AP_AGENT, _AP_UFW, '/usr/bin/python3'):
        raise RuntimeError('untrusted installer command')
    # usrmerge may use fixed system executable symlinks. Resolve only these
    # trusted names, then validate every canonical ancestor and final inode.
    canonical = ap_os.path.realpath(path)
    parent, name = canonical.rsplit('/', 1)
    fd = _ap_open_dir(parent)
    try:
        command = ap_os.open(name, ap_os.O_RDONLY | ap_os.O_NOFOLLOW | ap_os.O_NONBLOCK, dir_fd=fd)
        try:
            info = ap_os.fstat(command)
            if not ap_stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111:
                raise RuntimeError('unsafe or unavailable installer command')
        finally:
            ap_os.close(command)
    except OSError:
        raise RuntimeError('required installer command unavailable') from None
    finally:
        ap_os.close(fd)
    # Also verify original ancestors, not just a possibly attacker-selected
    # resolved target. Fixed /usr/bin and /usr/sbin are canonical on supported OS.
    fd = _ap_open_dir(path.rsplit('/', 1)[0])
    ap_os.close(fd)


def _ap_run(command):
    _ap_check_command(command[0])
    if command[0] == _AP_UFW:
        # Supported distros ship UFW as a Python script, not an ELF. Isolated
        # mode blocks cwd/PYTHONPATH/user-site imports; no ambient interpreter.
        _ap_check_command('/usr/bin/python3')
        lines = _ap_read(_AP_UFW, 65536).splitlines()
        if not lines or lines[0].split() not in (
                [b'#!', b'/usr/bin/python3'], [b'#!/usr/bin/python3']):
            raise RuntimeError('unsupported ufw executable; manage firewall manually')
        command = ['/usr/bin/python3', '-I', '-B'] + list(command)
    try:
        result = ap_subprocess.run(command, stdin=ap_subprocess.DEVNULL,
            stdout=ap_subprocess.PIPE, stderr=ap_subprocess.DEVNULL,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'},
            cwd='/', timeout=90, check=False, umask=0o077)
    except (OSError, ap_subprocess.SubprocessError):
        raise RuntimeError('installer command failed; captured output suppressed') from None
    if result.returncode != 0:
        raise RuntimeError('installer command failed; captured output suppressed')
    return result.stdout


def _ap_check_pid1():
    try:
        executable = ap_os.readlink('/proc/1/exe')
        if executable not in ('/usr/lib/systemd/systemd', '/lib/systemd/systemd'):
            raise RuntimeError('apply requires real systemd PID1')
        info = ap_os.stat('/proc/1/exe')
        expected = ap_os.stat('/usr/lib/systemd/systemd')
        if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('apply requires real systemd PID1')
        fd = _ap_open_dir('/run/systemd/system')
        ap_os.close(fd)
    except OSError:
        raise RuntimeError('apply requires real systemd PID1') from None


def _ap_check_listener(host, port):
    family = ap_socket.AF_INET6 if ':' in host else ap_socket.AF_INET
    try:
        with ap_socket.socket(family, ap_socket.SOCK_STREAM) as listener:
            # Never SO_REUSEADDR: an occupied wildcard or non-listening bound
            # socket must fail too. The real daemon still owns final bind races.
            listener.bind((host, port))
    except OSError:
        raise RuntimeError('selected listener unavailable or occupied') from None


def _ap_check_os():
    # The distro-standard symlink is the only exception to no-follow reads.
    # Pin /etc first; never resolve an arbitrary symlink-selected path as root.
    etc = _ap_open_dir('/etc')
    try:
        info = ap_os.stat('os-release', dir_fd=etc, follow_symlinks=False)
        path = '/etc/os-release'
        if ap_stat.S_ISLNK(info.st_mode):
            if info.st_uid != 0 or ap_os.readlink('os-release', dir_fd=etc) not in (
                '/usr/lib/os-release', '../usr/lib/os-release'
            ):
                raise RuntimeError('unsafe os-release symlink')
            path = '/usr/lib/os-release'
    finally:
        ap_os.close(etc)
    try:
        data = _ap_read(path, 65536).decode('utf-8')
    except OSError:
        raise RuntimeError('os-release unavailable or unsafe') from None
    except UnicodeDecodeError:
        raise RuntimeError('malformed os-release') from None
    if any(ord(char) < 32 and char not in '\n\t\r' for char in data):
        raise RuntimeError('malformed os-release')
    values = {}
    # Parse data only, never source shell. Unknown fields may contain normal
    # distro display strings; every non-comment line must still be an assignment.
    assignment = ap_re.compile(r'[A-Z][A-Z0-9_]*=.*')
    pattern = ap_re.compile(r'''(ID|VERSION_ID)=(?:"([A-Za-z0-9_.-]+)"|'([A-Za-z0-9_.-]+)'|([A-Za-z0-9_.-]+))''')
    for line in data.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if not assignment.fullmatch(line):
            raise RuntimeError('malformed os-release')
        if line.split('=', 1)[0] in ('ID', 'VERSION_ID'):
            match = pattern.fullmatch(line)
            if match is None:
                raise RuntimeError('malformed os-release')
            key = match.group(1)
            if key in values:
                raise RuntimeError('ambiguous os-release')
            values[key] = next(value for value in match.groups()[1:] if value is not None)
    if (values.get('ID'), values.get('VERSION_ID')) not in {
        ('ubuntu', '24.04'), ('ubuntu', '26.04'), ('debian', '12'), ('debian', '13')
    }:
        raise RuntimeError('unsupported OS')


def _ap_fresh_checks(args):
    _ap_check_os()
    _ap_check_pid1()
    for command in _AP_COMMANDS:
        _ap_check_command(command)
    for path in ('/usr/local', '/var/lib', '/etc', '/etc/systemd/system', '/run'):
        fd = _ap_open_dir(path)
        ap_os.close(fd)
    # /etc/sysusers.d is an optional ancestor but its existence is still a
    # trusted-directory prerequisite; it is created later under the lock only.
    if ap_os.path.lexists('/etc/sysusers.d'):
        fd = _ap_open_dir('/etc/sysusers.d')
        ap_os.close(fd)
    for path in _AP_DESTINATIONS:
        if ap_os.path.lexists(path):
            raise RuntimeError('existing AxionPanel state; refusing adoption')
    for path in _AP_CONFLICTS:
        if ap_os.path.lexists(path):
            raise RuntimeError('conflicting panel detected')
    for path in ('/etc/passwd', '/etc/group'):
        if any(line.startswith(b'axionpanel:') for line in _ap_read(path, 8 * 1024 * 1024).splitlines()):
            raise RuntimeError('existing AxionPanel local account')
    for lookup in (ap_pwd.getpwnam, ap_grp.getgrnam):
        try:
            lookup('axionpanel')
        except KeyError:
            continue
        raise RuntimeError('existing AxionPanel NSS account')
    # Querying the manager catches vendor, generated, transient and alias units,
    # not only files in /etc. A preexisting unloaded drop-in also denies adoption.
    names = _AP_UNITS + ('axionpanel-native.service',)
    for directory in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system'):
        fd = _ap_open_dir(directory)
        try:
            for name in ap_os.listdir(fd):
                if name.startswith('axionpanel'):
                    raise RuntimeError('existing AxionPanel unit or drop-in')
        finally:
            ap_os.close(fd)
    for name in names:
        load = _ap_run(['/usr/bin/systemctl', '--system', 'show', '--property=LoadState', '--value', name]).strip()
        if load != b'not-found':
            raise RuntimeError('existing AxionPanel unit in systemd')
    _ap_check_listener(args.host, args.port)
    if args.open_firewall:
        _ap_check_command(_AP_UFW)
        _ap_check_firewall(args)


@ap_contextlib.contextmanager
def _ap_lock():
    parent = _ap_open_dir('/run')
    lock = None
    try:
        try:
            lock = ap_os.open('axionpanel-install.lock', ap_os.O_RDWR | ap_os.O_CREAT | ap_os.O_NOFOLLOW | ap_os.O_NONBLOCK,
                              0o600, dir_fd=parent)
            info = ap_os.fstat(lock)
            if not ap_stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or ap_stat.S_IMODE(info.st_mode) != 0o600:
                raise RuntimeError('unsafe installer lock')
            try:
                ap_fcntl.flock(lock, ap_fcntl.LOCK_EX | ap_fcntl.LOCK_NB)
            except OSError:
                raise RuntimeError('another installer holds the lock') from None
        except OSError:
            # Only acquisition errors are reported as a lock failure; an OSError
            # raised later inside the guarded provisioning must surface as itself.
            raise RuntimeError('installer lock unavailable or unsafe') from None
        yield
        # Keep inode: unlinking introduces a three-installer lock race.
    finally:
        if lock is not None:
            ap_os.close(lock)
        ap_os.close(parent)


def _ap_write_at(parent, name, data, mode):
    try:
        fd = ap_os.open(name, ap_os.O_WRONLY | ap_os.O_CREAT | ap_os.O_EXCL | ap_os.O_NOFOLLOW, mode, dir_fd=parent)
        with ap_os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            ap_os.fchmod(stream.fileno(), mode)
            ap_os.fsync(stream.fileno())
    except OSError:
        raise RuntimeError('exclusive installation write failed; refusing overwrite') from None


def _ap_write(path, data, mode):
    parent, name = path.rsplit('/', 1)
    fd = _ap_open_dir(parent)
    try:
        _ap_write_at(fd, name, data, mode)
    finally:
        ap_os.close(fd)


def _ap_mkdir(path, mode=0o755, uid=0, gid=0):
    parent, name = path.rsplit('/', 1)
    fd = _ap_open_dir(parent)
    try:
        ap_os.mkdir(name, mode, dir_fd=fd)
        child = ap_os.open(name, ap_os.O_RDONLY | ap_os.O_DIRECTORY | ap_os.O_NOFOLLOW, dir_fd=fd)
        try:
            ap_os.fchmod(child, mode)
            ap_os.fchown(child, uid, gid)
        finally:
            ap_os.close(child)
    except OSError:
        raise RuntimeError('exclusive installation directory creation failed') from None
    finally:
        ap_os.close(fd)


def _ap_hostport(host, port):
    return ('[' + host + ']' if ':' in host else host) + ':' + str(port)


def _ap_authority(args):
    """The same canonical address identifies bind, browser origin and certificate."""
    return _ap_hostport(args.host, args.port)


def _ap_serve_flags(args):
    return ['-addr', _ap_hostport(args.host, args.port), '-origin', 'https://' + _ap_authority(args),
            '-tls-cert', _AP_CERT, '-tls-key', _AP_KEY,
            '-entrance-file', _AP_STATE + '/entrance', '-db', _AP_STATE + '/panel.db',
            '-secret-key', _AP_STATE + '/secret.key', '-agent-socket', '/run/axionpanel/agent.sock']


def _ap_rollback_units(started):
    for unit in reversed(started):
        try:
            _ap_run(['/usr/bin/systemctl', '--system', 'stop', unit])
        except Exception:
            pass


def _ap_units(args):
    _ap_options(args)
    # Generate a closed set rather than executing arbitrary signed template
    # directives as root. No admin/password/entrance value enters a unit.
    shared = '''Type=simple
Group=axionpanel
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
UMask=0077
Restart=on-failure
RestartSec=3s
TimeoutStopSec=15s
StandardOutput=journal
StandardError=journal
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
'''
    panel = '''[Unit]
Description=AxionPanel control panel (native HTTPS)
After=network-online.target axionpanel-agent.service
Wants=network-online.target axionpanel-agent.service
StartLimitIntervalSec=60
StartLimitBurst=3
[Service]
User=axionpanel
WorkingDirectory=/var/lib/axionpanel
StateDirectory=axionpanel
StateDirectoryMode=0700
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ExecStart=''' + _AP_BINARY + ' ' + ' '.join(_ap_serve_flags(args)) + '\n' + shared
    agent = '''[Unit]
Description=AxionPanel read-only host agent
After=local-fs.target
StartLimitIntervalSec=60
StartLimitBurst=3
[Service]
User=root
WorkingDirectory=/
RuntimeDirectory=axionpanel
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
CapabilityBoundingSet=CAP_CHOWN
RestrictAddressFamilies=AF_UNIX
ExecStart=/usr/local/axionpanel/bin/axionpanel-agent -socket /run/axionpanel/agent.sock -allow-uid axionpanel -socket-gid axionpanel -policy /etc/axionpanel/agent.toml
''' + shared
    return tuple(unit + '[Install]\nWantedBy=multi-user.target\n' for unit in (panel, agent))


def _ap_probe_authenticated(request, bootstrap):
    code, _ = request('GET', bootstrap['entrance_path'])
    # The production request helper consumes only this exact 303, without
    # blindly following a server-controlled redirect or disclosing the path.
    if code != 303:
        raise RuntimeError('entrance readiness failed')
    code, body = request('GET', '/login')
    if code != 200 or b'<html' not in body.lower():
        raise RuntimeError('login UI readiness failed')
    code, body = request('GET', '/api/health')
    if code != 200 or not isinstance(body, dict) or body.get('status') != 'ok':
        raise RuntimeError('HTTPS health readiness failed')
    code, login = request('POST', '/api/v1/auth/login',
        {'username': bootstrap['username'], 'password': bootstrap['password']})
    if code != 200 or not isinstance(login, dict) or login.get('mfa_required') is not False or not login.get('csrf_token'):
        raise RuntimeError('authenticated readiness unavailable; complete MFA manually if required')
    try:
        code, info = request('GET', '/api/v1/system/info')
        if code != 200 or not isinstance(info, dict) or info.get('connected') is not True or not info.get('hostname'):
            raise RuntimeError('authenticated agent-backed system information readiness failed')
    finally:
        code, _ = request('POST', '/api/v1/auth/logout', {}, login['csrf_token'])
        if code != 200:
            raise RuntimeError('readiness session cleanup failed')


def _ap_readiness(args, uid):
    raw = _ap_read(_AP_STATE + '/bootstrap.json', 16384, uid, private=True)
    bootstrap = ap_json.loads(raw)
    origin = 'https://' + _ap_authority(args)
    host = args.host
    if (not isinstance(bootstrap, dict) or bootstrap.get('origin') != origin or
        bootstrap.get('username') != args.admin or not isinstance(bootstrap.get('password'), str) or
        not bootstrap['password'] or not ap_re.fullmatch(r'/[A-Za-z0-9_-]{12}', bootstrap.get('entrance_path', ''))):
        raise RuntimeError('private bootstrap artifact validation failed')
    certificate = _ap_read(_AP_CERT, 65536)
    # Trust exactly the locally generated self-signed certificate; still require
    # hostname validation. HTTPSConnection ignores ambient HTTP(S)_PROXY.
    context = ap_ssl.SSLContext(ap_ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=certificate.decode('ascii'))
    context.minimum_version = ap_ssl.TLSVersion.TLSv1_2
    expected = ap_ssl.PEM_cert_to_DER_cert(certificate.decode('ascii'))
    fingerprint = ap_hashlib.sha256(expected).hexdigest()
    jar = {}

    def request(method, path, body=None, csrf=None):
        connection = ap_http.HTTPSConnection(host, args.port, context=context, timeout=5)
        headers = {'Origin': origin, 'Host': _ap_authority(args), 'User-Agent': 'AxionPanel-installer-readiness'}
        if jar:
            headers['Cookie'] = '; '.join(name + '=' + value for name, value in jar.items())
        if csrf is not None:
            headers['X-CSRF-Token'] = csrf
        encoded = None
        if body is not None:
            encoded = ap_json.dumps(body).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        try:
            connection.connect()
            if connection.sock.getpeercert(binary_form=True) != expected:
                raise RuntimeError('TLS certificate pin mismatch')
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            for name, value in response.getheaders():
                if name.lower() == 'set-cookie':
                    cookies = ap_cookies.SimpleCookie()
                    cookies.load(value)
                    for key, morsel in cookies.items():
                        if key in ('axp_entrance', 'axp_session', 'axp_csrf', 'axp_mfa'):
                            if morsel['max-age'] == '-1' or not morsel.value:
                                jar.pop(key, None)
                            else:
                                jar[key] = morsel.value
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise RuntimeError('readiness response exceeds limit')
            if response.status == 303 and (path != bootstrap['entrance_path'] or response.getheader('Location') != '/login'):
                raise RuntimeError('unexpected readiness redirect')
            if path.startswith('/api/'):
                if response.status == 404:
                    # An undiscovered entrance answers every API path with a
                    # bare "Not Found" body; the readiness loop needs the
                    # status, so never parse a denial as JSON.
                    return response.status, None
                document = ap_json.loads(data)
                if not isinstance(document, dict):
                    raise RuntimeError('readiness document is not an object')
                return response.status, document
            return response.status, data
        finally:
            connection.close()

    # Retry transport readiness only, never password attempts or bootstrap.
    for attempt in range(30):
        try:
            code, _ = request('GET', '/api/health')
            if code == 404:
                break
            raise RuntimeError('undiscovered HTTPS health was not denied')
        except (OSError, ap_http.HTTPException):
            if attempt == 29:
                raise RuntimeError('native HTTPS listener did not become ready') from None
            ap_time.sleep(1)
    _ap_probe_authenticated(request, bootstrap)
    return fingerprint


def _ap_private_files(uid, directory, names):
    """Normalize panel-created state files to the documented private mode.

    ``runuser`` resets the umask to 0022, so files the panel creates under the
    0700 state directory can still land 0644 (SQLite database, secret key).
    """
    for name in names:
        path = directory + '/' + name
        if not ap_os.path.lexists(path):
            continue
        try:
            fd = ap_os.open(path, ap_os.O_RDONLY | ap_os.O_NOFOLLOW | ap_os.O_NONBLOCK)
        except OSError:
            raise RuntimeError('state file unavailable or unsafe') from None
        try:
            info = ap_os.fstat(fd)
            if not ap_stat.S_ISREG(info.st_mode) or info.st_uid != uid:
                raise RuntimeError('state file ownership verification failed')
            ap_os.fchmod(fd, 0o600)
        finally:
            ap_os.close(fd)


def _ap_provision(args, contents):
    panel_unit, agent_unit = _ap_units(args)
    _ap_mkdir('/usr/local/axionpanel')
    _ap_mkdir('/usr/local/axionpanel/bin')
    for name in ('axionpanel', 'axionpanel-agent'):
        _ap_write('/usr/local/axionpanel/bin/' + name, contents[name], 0o755)
    # Ship authenticated reference documentation/templates, never execute it.
    _ap_mkdir('/usr/local/axionpanel/share')
    for directory in ('deploy', 'deploy/nginx', 'deploy/systemd', 'docs'):
        _ap_mkdir('/usr/local/axionpanel/share/' + directory)
    for name in _AP_MEMBERS[2:]:
        _ap_write('/usr/local/axionpanel/share/' + name, contents[name], 0o644)
    if not ap_os.path.lexists('/etc/sysusers.d'):
        _ap_mkdir('/etc/sysusers.d')
    _ap_write('/etc/sysusers.d/axionpanel.conf',
              b'g axionpanel -\nu axionpanel - "AxionPanel service account" /var/lib/axionpanel /usr/sbin/nologin\n', 0o644)
    _ap_run(['/usr/bin/systemd-sysusers', '/etc/sysusers.d/axionpanel.conf'])
    user, group = ap_pwd.getpwnam('axionpanel'), ap_grp.getgrnam('axionpanel')
    if user.pw_uid == 0 or group.gr_gid == 0 or user.pw_gid != group.gr_gid or user.pw_dir != _AP_STATE or user.pw_shell != '/usr/sbin/nologin':
        raise RuntimeError('service account provisioning verification failed')
    uid, gid = user.pw_uid, group.gr_gid
    _ap_mkdir(_AP_STATE, 0o700, uid, gid)
    _ap_mkdir('/etc/axionpanel', 0o750, 0, gid)
    _ap_mkdir('/etc/axionpanel/tls', 0o750, 0, gid)
    _ap_write('/etc/axionpanel/agent.toml', b'# Deny-by-default: only built-in read-only operations are available.\n', 0o400)
    _ap_run([_AP_BINARY, '-init-tls', '-tls-host', args.host, '-tls-cert', _AP_CERT, '-tls-key', _AP_KEY])
    for path in (_AP_CERT, _AP_KEY):
        fd = ap_os.open(path, ap_os.O_RDONLY | ap_os.O_NOFOLLOW | ap_os.O_NONBLOCK)
        try:
            info = ap_os.fstat(fd)
            if not ap_stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
                raise RuntimeError('generated TLS file ownership verification failed')
            ap_os.fchown(fd, 0, gid)
            ap_os.fchmod(fd, 0o640)
        finally:
            ap_os.close(fd)
    _ap_run(['/usr/sbin/runuser', '-u', 'axionpanel', '--', _AP_BINARY,
             '-init-entrance', '-entrance-file', _AP_STATE + '/entrance'])
    _ap_run(['/usr/sbin/runuser', '-u', 'axionpanel', '--', _AP_BINARY] + _ap_serve_flags(args) +
             ['-bootstrap-admin', args.admin, '-bootstrap-out', _AP_STATE + '/bootstrap.json'])
    _ap_private_files(uid, _AP_STATE, ('panel.db', 'panel.db-wal', 'panel.db-shm',
                                       'secret.key', 'entrance', 'bootstrap.json'))
    _ap_read(_AP_STATE + '/bootstrap.json', 16384, uid, private=True)
    _ap_read(_AP_STATE + '/entrance', 64, uid, private=True)
    _ap_write('/etc/systemd/system/axionpanel-agent.service', agent_unit.encode(), 0o644)
    _ap_write('/etc/systemd/system/axionpanel.service', panel_unit.encode(), 0o644)
    _ap_run(['/usr/bin/systemd-analyze', 'verify', '/etc/systemd/system/axionpanel-agent.service',
             '/etc/systemd/system/axionpanel.service'])
    return uid


def apply_install(args, contents):
    """Provision authenticated bytes only; preserve partial state on any failure."""
    if not args.apply:
        raise RuntimeError('apply_install requires --apply')
    validate_apply(args)
    if set(contents) != set(_AP_MEMBERS) or any(not isinstance(value, bytes) for value in contents.values()):
        raise RuntimeError('authenticated exact installer payload required')
    try:
        with _ap_lock():
            started = []
            mutated = False
            try:
                # This is deliberately the same entire check as before authentication:
                # a second concurrent installer must not adopt the first one's state.
                _ap_options(args)
                _ap_fresh_checks(args)
                mutated = True
                uid = _ap_provision(args, contents)
                _ap_run(['/usr/bin/systemctl', '--system', 'daemon-reload'])
                for unit in _AP_UNITS:
                    # A start can time out after activating the unit. Record intent
                    # before the command so cleanup includes this ambiguous outcome.
                    started.append(unit)
                    _ap_run(['/usr/bin/systemctl', '--system', 'start', unit])
                    _ap_run(['/usr/bin/systemctl', '--system', 'is-active', '--quiet', unit])
                fingerprint = _ap_readiness(args, uid)
                if args.open_firewall:
                    # The port is published only after the panel answered locally;
                    # a later failure still removes the rule we asked for.
                    _ap_open_firewall(args)
                _ap_run(['/usr/bin/systemctl', '--system', 'enable', *_AP_UNITS])
                print('Firewall: ' + _ap_firewall_plan(args))
                print('Origin: https://' + _ap_authority(args) +
                      (' (LOCAL address; external reachability is not guaranteed)'
                       if not _ap_canonical_address(args.host).is_global else ''))
                print('Certificate SHA-256: ' + fingerprint)
                print('Bootstrap file: /var/lib/axionpanel/bootstrap.json')
                return {'origin': 'https://' + _ap_authority(args), 'certificate_sha256': fingerprint,
                        'bootstrap_file': _AP_STATE + '/bootstrap.json', 'authenticated_agent_ready': True}
            except (Exception, KeyboardInterrupt):
                # Rollback and service cleanup must finish before unlocking.
                firewall_removed = getattr(args, '_firewall_rule', None) is not None
                if mutated and not _ap_rollback_firewall(args):
                    _ap_rollback_units(started)
                    raise RuntimeError('installation failed; firewall rule %s was not removed; manual reconciliation required; owned comment: %s' % (
                        getattr(args, '_firewall_rule', None), getattr(args, '_firewall_comment', None))) from None
                _ap_rollback_units(started)
                if mutated:
                    suffix = '; firewall rule %d/tcp removed' % args.port if firewall_removed else ''
                    raise RuntimeError('installation failed; only newly started units were requested to stop; partial data preserved; manual reconciliation required' + suffix) from None
                raise RuntimeError('installation refused before provisioning; prerequisites or lock failed') from None
    except OSError:
        raise RuntimeError('installation refused before provisioning; prerequisites or lock failed') from None
# END AXIONPANEL APPLY ENGINE


def main():
    args = parse_args(sys.argv[1:])
    validate_version(args.version)
    arch = args.arch or {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, "")
    if arch not in ARCHES:
        fail("unsupported architecture")
    inspection = args.preflight_only or args.verify_only
    if not inspection and (args.root is not None or args.arch is not None):
        fail("--root and --arch are inspection-only")
    if args.stage_dir is None and not args.apply:
        fail("required: --stage-dir for private verification workspace")
    if args.download_base_url is not None:
        validated_download_base(args.download_base_url)
    # Read-only option validation guards every mode, not only apply; it must run
    # before the trusted key, network access or staging. Apply continues into
    # root, host and fresh-host checks inside the same call.
    validate_apply(args)
    if args.directory is None and args.download_base_url is None:
        args.download_base_url = f"https://github.com/akbardwi/axionpanel/releases/download/v{args.version}"
    public_key_bytes = read_public_key(args.public_key)
    if args.preflight_only:
        preflight(args.root or Path("/"), arch, args.root is not None)
    stage = args.stage_dir
    parent_fd = None
    keep = False
    if stage is None:
        stage = Path(tempfile.mkdtemp(prefix="axionpanel-install-", dir="/var/tmp"))
        info = os.lstat(stage)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            shutil.rmtree(stage)
            fail("apply staging directory is not private")
    else:
        parent_fd = open_stage_parent(stage)
        try:
            os.mkdir(stage.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            os.close(parent_fd)
            fail("stage directory already exists; refusing overwrite")
    try:
        snapshot = stage / "snapshot"
        snapshot.mkdir(mode=0o700)
        try:
            if args.directory is not None:
                snapshot_inputs(args.directory, public_key_bytes, snapshot, args.version)
            else:
                acquire_sources(args, public_key_bytes, snapshot, args.version)
            verify_snapshot(snapshot, args.version)
        except (OSError, ValueError, http.client.HTTPException, subprocess.SubprocessError):
            fail("verification failed: download, signature or checksum validation refused")
        allowed = set(PACKAGE_FILES) | set(BINARIES)
        selected = None
        for candidate in ARCHES:
            try:
                data = validate_archive(snapshot / archive_name(args.version, candidate),
                                        candidate, allowed, BINARIES)
            except (tarfile.TarError, gzip.BadGzipFile, OSError, EOFError, UnicodeError, ValueError) as exc:
                fail(f"unsafe archive: {type(exc).__name__}")
            if candidate == arch:
                selected = data
        if inspection:
            print("Signature, checksums and exact archive contents verified; nothing extracted or changed.")
            return
        payload = stage / "payload"
        payload.mkdir(mode=0o700)
        for name, data in selected.items():
            target = payload / name
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
            target.chmod(0o755 if name in BINARIES else 0o644)
        for directory in payload.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        if not args.apply:
            keep = True
            print(f"Authenticated {arch} payload staged at {payload}. Nothing executed or installed.")
            return
        apply_install(args, selected)
    finally:
        if parent_fd is not None:
            if not keep:
                shutil.rmtree(stage.name, dir_fd=parent_fd)
            os.close(parent_fd)
        elif not keep:
            shutil.rmtree(stage, ignore_errors=True)


try:
    main()
except Refusal as exc:
    print(f"install: {exc}", file=sys.stderr)
    sys.exit(1)
except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, RuntimeError) as exc:
    print(f"install: {exc}", file=sys.stderr)
    sys.exit(1)
except Exception as exc:
    print(f"install: refused ({type(exc).__name__})", file=sys.stderr)
    sys.exit(1)
PY
