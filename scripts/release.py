#!/usr/bin/env python3
"""Build allowlisted Linux archives and authenticate checksum manifests.

No installer, runtime mutation, key generation, key download or trust-on-first-use.
Only the supplied output directory is verification scope; no recursive discovery.
"""
import argparse
import gzip
import hashlib
from html.parser import HTMLParser
import io
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

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
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class ReleaseError(Exception):
    """Fail-closed release validation error."""


def run(args, **kwargs):
    try:
        return subprocess.run([str(a) for a in args], check=True, capture_output=True, **kwargs).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        # Never echo captured key material or arbitrary command output.
        raise ReleaseError(f"{args[0]} command failed") from exc


def validate_version(version):
    core = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    suffix = r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    match = re.fullmatch(core + suffix, version, flags=re.ASCII)
    if not match or len(version) > 64:
        raise ReleaseError("version must be SemVer without v prefix, whitespace or paths")
    prerelease = match.group(4)
    if prerelease and any(p.isdigit() and len(p) > 1 and p[0] == "0" for p in prerelease.split(".")):
        raise ReleaseError("numeric prerelease identifiers cannot have leading zeroes")
    return version


def archive_name(version, arch):
    validate_version(version)
    if arch not in ARCHES:
        raise ReleaseError("unsupported architecture")
    return f"axionpanel-{version}-linux-{arch}.tar.gz"


def regular(path):
    path = Path(path)
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise ReleaseError(f"regular file required: {path.name}")
        for parent in path.parents:
            if parent.is_symlink():
                raise ReleaseError("symlink parent refused")
    except OSError as exc:
        raise ReleaseError(f"required file missing: {path.name}") from exc
    return path


class AssetReferences(HTMLParser):
    def __init__(self):
        super().__init__()
        self.styles = []
        self.modules = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("type") == "module":
            self.modules.append(attrs.get("src", ""))
        if tag == "link" and attrs.get("rel") == "stylesheet":
            self.styles.append(attrs.get("href", ""))


def validate_web(repo):
    dist = Path(repo) / "web/dist"
    index = regular(dist / "index.html")
    parser = AssetReferences()
    parser.feed(index.read_text(encoding="utf-8"))
    if not parser.modules:
        raise ReleaseError("embedded UI missing module script/assets; run make web")
    for asset in parser.modules + parser.styles:
        relative = asset.removeprefix("/")
        if not re.fullmatch(r"assets/[A-Za-z0-9_.-]+", relative):
            raise ReleaseError("embedded UI has unsafe or external asset reference")
        if regular(dist / relative).stat().st_size == 0:
            raise ReleaseError("embedded UI asset empty")
    for module in parser.modules:
        if not module.removeprefix("/").lower().endswith((".js", ".mjs")):
            raise ReleaseError("embedded UI module script must reference a JavaScript asset")
    for path in dist.rglob("*"):
        if path.is_symlink():
            raise ReleaseError("embedded UI symlink refused")
    for path in sorted(dist.iterdir()):
        if path.name not in {"index.html", "assets", ".gitkeep"}:
            raise ReleaseError(f"unexpected embedded UI entry: {path.name}")
    placeholder = dist / ".gitkeep"
    if placeholder.exists() and regular(placeholder).stat().st_size:
        raise ReleaseError("embedded UI placeholder contains data")
    allowed_extensions = {".js", ".css", ".woff", ".woff2", ".ttf", ".otf", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".avif"}
    for path in sorted((dist / "assets").rglob("*")):
        regular(path)
        if (path.parent != dist / "assets"
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", path.name)
                or path.suffix.lower() not in allowed_extensions):
            raise ReleaseError(f"unexpected embedded UI asset: {path.name}")


def create_archive(repo, binaries, destination):
    repo, destination = Path(repo), Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ReleaseError("archive already exists; refusing overwrite")
    if set(binaries) != set(BINARIES):
        raise ReleaseError("exact panel and agent binaries required")
    tracked = set(run(["git", "-C", repo, "ls-files", "-z"]).decode().split("\0"))
    if not set(PACKAGE_FILES).issubset(tracked):
        raise ReleaseError("required deployment templates/docs are not tracked")
    sources = {name: regular(repo / name) for name in PACKAGE_FILES}
    sources.update({name: regular(path) for name, path in binaries.items()})
    try:
        with destination.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for name in sorted(sources):
                        data = sources[name].read_bytes()
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        info.mode = 0o755 if name in BINARIES else 0o644
                        info.uid = info.gid = info.mtime = 0
                        info.uname = info.gname = ""
                        archive.addfile(info, io.BytesIO(data))
    except FileExistsError as exc:
        raise ReleaseError("archive already exists; refusing overwrite") from exc


def ed25519_public(key, public=False):
    args = ["openssl", "pkey"]
    if public:
        args.append("-pubin")
    args += ["-in", key, "-pubout", "-outform", "DER"]
    der = run(args)
    if len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
        raise ReleaseError("Ed25519 key required")


def validate_signing_key(key):
    key = regular(key)
    metadata = key.stat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077 or not metadata.st_mode & 0o400:
        raise ReleaseError("signing key must be owner-private and owned by current user")
    ed25519_public(key)
    return key


def signing_mode(signing_key, unsigned_development):
    if bool(signing_key) == bool(unsigned_development):
        raise ReleaseError("choose --signing-key OR --unsigned-development explicitly")
    if signing_key:
        validate_signing_key(signing_key)


def checksum(path):
    digest = hashlib.sha256()
    with regular(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(directory, version, signing_key=None, unsigned_development=False):
    signing_mode(signing_key, unsigned_development)
    directory = Path(directory)
    names = [archive_name(version, arch) for arch in ARCHES]
    manifest = "".join(f"{checksum(directory / name)}  {name}\n" for name in names).encode("ascii")
    manifest_path = directory / "SHA256SUMS"
    signature_path = directory / "SHA256SUMS.sig"
    marker = directory / "SHA256SUMS.unsigned-development"
    if any(p.exists() or p.is_symlink() for p in (manifest_path, signature_path, marker)):
        raise ReleaseError("checksum output already exists; refusing overwrite")
    with manifest_path.open("xb") as stream:
        stream.write(manifest)
    if signing_key:
        # Reserve signature path exclusively; OpenSSL writes only this new file.
        with signature_path.open("xb"):
            pass
        run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", signing_key, "-in", manifest_path, "-out", signature_path])
    else:
        with marker.open("x") as stream:
            stream.write("UNSIGNED DEVELOPMENT ONLY. Not an authenticated release.\n")


def verify_release(directory, version, public_key):
    validate_version(version)
    directory = Path(directory)
    regular(public_key)
    ed25519_public(public_key, public=True)
    manifest_path = regular(directory / "SHA256SUMS")
    signature_path = regular(directory / "SHA256SUMS.sig")
    if manifest_path.stat().st_size > 4096 or signature_path.stat().st_size != 64:
        raise ReleaseError("signature or manifest size invalid")
    manifest, signature = manifest_path.read_bytes(), signature_path.read_bytes()
    # Authenticate the manifest before any digest or filename is trusted.
    with tempfile.TemporaryDirectory(prefix="axion-verify-") as temporary:
        snapshot = Path(temporary)
        (snapshot / "manifest").write_bytes(manifest)
        (snapshot / "signature").write_bytes(signature)
        try:
            run(["openssl", "pkeyutl", "-verify", "-pubin", "-rawin", "-inkey", public_key, "-in", snapshot / "manifest", "-sigfile", snapshot / "signature"])
        except ReleaseError as exc:
            raise ReleaseError("manifest signature verification failed") from exc
    expected = {archive_name(version, arch) for arch in ARCHES}
    entries = {}
    for line in manifest.splitlines(keepends=True):
        match = re.fullmatch(rb"([0-9a-f]{64})  ([A-Za-z0-9_.+-]+\.tar\.gz)\n", line)
        if not match:
            raise ReleaseError("malformed or unsafe manifest filename")
        digest, name = (value.decode("ascii") for value in match.groups())
        if name in entries or name not in expected:
            raise ReleaseError("duplicate or unexpected manifest filename")
        entries[name] = digest
    if set(entries) != expected:
        raise ReleaseError("missing manifest archive")
    actual = {p.name for p in directory.iterdir() if p.name.endswith(".tar.gz")}
    if actual != expected:
        raise ReleaseError("missing or extra archives in supplied directory")
    if (directory / "SHA256SUMS.unsigned-development").exists():
        raise ReleaseError("unsigned development marker present")
    for name, digest in entries.items():
        if checksum(directory / name) != digest:
            raise ReleaseError(f"archive digest mismatch: {name}")
    return entries


def build_release(repo, version, output, *, prebuilt_web=False, signing_key=None, unsigned_development=False):
    validate_version(version)
    signing_mode(signing_key, unsigned_development)
    repo, output = Path(repo).resolve(), Path(output)
    if output.exists() or output.is_symlink():
        raise ReleaseError("output directory exists; refusing overwrite")
    if not prebuilt_web:
        run(["make", "web"], cwd=repo)
    validate_web(repo)
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise ReleaseError("output directory exists; refusing overwrite") from exc
    with tempfile.TemporaryDirectory(prefix="axion-build-") as temporary:
        temporary = Path(temporary)
        for arch in ARCHES:
            binaries = {}
            env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0")
            for name, target in zip(BINARIES, ("./cmd/panel", "./cmd/agent")):
                path = temporary / f"{name}-{arch}"
                run(["go", "build", "-trimpath", "-ldflags", f"-s -w -X main.version={version}", "-o", path, target], cwd=repo, env=env)
                binaries[name] = path
            create_archive(repo, binaries, output / archive_name(version, arch))
    write_checksums(output, version, signing_key=signing_key, unsigned_development=unsigned_development)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build both Linux architectures into a NEW directory")
    build.add_argument("--version", required=True)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--prebuilt-web", action="store_true", help="validate existing web/dist instead of running make web")
    modes = build.add_mutually_exclusive_group(required=True)
    modes.add_argument("--signing-key", type=Path)
    modes.add_argument("--unsigned-development", action="store_true")
    verify = commands.add_parser("verify", help="authenticate signed manifest, then check exact archive set")
    verify.add_argument("--version", required=True)
    verify.add_argument("--directory", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path, help="independently trusted Ed25519 public key")
    args = parser.parse_args()
    try:
        if args.command == "build":
            output = build_release(Path(__file__).resolve().parents[1], args.version, args.output, prebuilt_web=args.prebuilt_web, signing_key=args.signing_key, unsigned_development=args.unsigned_development)
            print(f"Built {'UNSIGNED DEVELOPMENT' if args.unsigned_development else 'signed-checksum'} artifacts: {output}")
        else:
            for name, digest in verify_release(args.directory, args.version, args.public_key).items():
                print(f"{digest}  {name}")
            print("Signature and checksums verified. Not a provenance or reproducibility guarantee.")
    except (ReleaseError, OSError, UnicodeError) as exc:
        print(f"release: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
