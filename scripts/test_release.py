"""Release contract. Run: python3 -B -m unittest discover -s scripts -p test_release.py -v.

Contract: strict SemVer-safe versions; real embedded assets; exactly two Linux
archives containing binaries and explicit tracked docs/templates only; normalized
metadata; exclusive output; explicit development unsigned mode; Ed25519 manifest
verification with independently supplied public key before parsing any filenames.
Tests use fixture binary bytes only for archive layout; CLI integration builds
real Go executables separately. Ephemeral keys live in scratch, never repository.
"""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from typing import Any
import unittest

MODULE = Path(__file__).with_name("release.py")


def load_release():
    if not MODULE.exists():
        return None
    spec = importlib.util.spec_from_file_location("release_tool", MODULE)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release: Any = load_release()
SCRATCH = Path(tempfile.gettempdir())
SCRATCH.mkdir(parents=True, exist_ok=True)


class ReleaseContract(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(release, "release.py missing: release tooling contract unimplemented")
        self.tmp = tempfile.TemporaryDirectory(prefix="release-test-", dir=SCRATCH)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def run_openssl(self, *args):
        subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)

    def keypair(self, stem="test"):
        key, public = self.root / (stem + ".key"), self.root / (stem + ".pub")
        self.run_openssl("genpkey", "-algorithm", "ED25519", "-out", key)
        key.chmod(0o600)
        self.run_openssl("pkey", "-in", key, "-pubout", "-out", public)
        return key, public

    def signed(self):
        directory = self.root / "release"
        directory.mkdir()
        for arch in release.ARCHES:
            (directory / release.archive_name("1.2.3", arch)).write_bytes(arch.encode())
        key, public = self.keypair()
        release.write_checksums(directory, "1.2.3", signing_key=key)
        return directory, key, public

    def test_version_validation_blocks_path_and_ldflag_injection(self):
        for version in ("1.2.3", "0.0.0-dev", "1.2.3-rc.1+build.4"):
            self.assertEqual(release.validate_version(version), version)
        rejected = ("", "v1.2.3", "../1.2.3", "1.2.3 -X main.x=y", "1.2.3\n", "01.2.3", "1.2.3/evil", "1.2.3-01", "1.2.3+" + "x" * 80)
        # Reject versions too long for portable USTAR basenames too.
        for version in rejected:
            with self.subTest(version=version), self.assertRaises(release.ReleaseError):
                release.validate_version(version)

    def test_embedded_ui_rejects_placeholder_missing_assets_and_symlinks(self):
        dist = self.root / "web/dist"
        dist.mkdir(parents=True)
        (dist / ".gitkeep").touch()
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)
        (dist / "index.html").write_text('<html><script type="module" src="/assets/app.js"></script></html>')
        (dist / "assets").mkdir()
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)
        (dist / "assets/app.js").write_text("console.log('fixture')")
        (dist / "index.html").write_text('<html><script type="module" src="/assets/app.js"></script></html>')
        release.validate_web(self.root)
        (dist / "assets/app.js").unlink()
        (dist / "assets/app.js").symlink_to(dist / "index.html")
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)

    def test_archive_exact_whitelist_permissions_and_determinism(self):
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        for relative in release.PACKAGE_FILES:
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative + "\n")
            path.chmod(0o777)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        (repo / "secret.db").write_bytes(b"DO NOT PACKAGE")
        binaries = {}
        for name in release.BINARIES:
            binaries[name] = self.root / name
            binaries[name].write_bytes(b"fixture, not executable build")
        a, b = self.root / "a.tar.gz", self.root / "b.tar.gz"
        release.create_archive(repo, binaries, a)
        release.create_archive(repo, binaries, b)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        with tarfile.open(a) as archive:
            members = archive.getmembers()
            self.assertEqual({m.name for m in members}, set(release.PACKAGE_FILES) | set(release.BINARIES))
            for member in members:
                self.assertTrue(member.isfile())
                self.assertEqual((member.uid, member.gid, member.mtime, member.uname, member.gname), (0, 0, 0, "", ""))
                self.assertEqual(member.mode, 0o755 if member.name in release.BINARIES else 0o644)
        with self.assertRaises(release.ReleaseError):
            release.create_archive(repo, binaries, a)
        (repo / release.PACKAGE_FILES[0]).unlink()
        (repo / release.PACKAGE_FILES[0]).symlink_to(repo / "secret.db")
        with self.assertRaises(release.ReleaseError):
            release.create_archive(repo, binaries, self.root / "unsafe.tar.gz")

    def test_embedded_ui_requires_javascript_module_not_stylesheet_only(self):
        dist = self.root / "web/dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "assets/app.css").write_text("body{}")
        (dist / "index.html").write_text('<html><link rel="stylesheet" href="/assets/app.css"></html>')
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)

    def test_embedded_ui_rejects_non_javascript_module_target(self):
        dist = self.root / "web/dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "assets/app.css").write_text("body{}")
        (dist / "index.html").write_text('<script type="module" src="/assets/app.css"></script>')
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)

    def test_embedded_ui_refuses_extra_runtime_files(self):
        dist = self.root / "web/dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text('<script type="module" src="/assets/app.js"></script>')
        (dist / "assets/app.js").write_text("console.log('fixture')")
        (dist / "secret.db").write_bytes(b"runtime state")
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)
        (dist / "secret.db").unlink()
        (dist / "assets/secret.key").write_bytes(b"test fixture, not a key")
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)
        (dist / "assets/secret.key").unlink()
        (dist / "assets/state.db").write_bytes(b"runtime database")
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)
        (dist / "assets/state.db").unlink()
        (dist / "assets/extra.txt").write_text("unexpected extra")
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)
        (dist / "assets/extra.txt").unlink()
        (dist / "assets/extra").mkdir()
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)
        (dist / "assets/extra").rmdir()
        release.validate_web(self.root)

    def test_nonempty_embedded_placeholder_refused(self):
        dist = self.root / "web/dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text('<script type="module" src="/assets/app.js"></script>')
        (dist / "assets/app.js").write_text("console.log('fixture')")
        (dist / ".gitkeep").write_text("unexpected data")
        with self.assertRaises(release.ReleaseError):
            release.validate_web(self.root)

    def test_checksum_outputs_never_overwritten(self):
        directory, key, _ = self.signed()
        before = {p.name: p.read_bytes() for p in directory.iterdir()}
        with self.assertRaises(release.ReleaseError):
            release.write_checksums(directory, "1.2.3", signing_key=key)
        self.assertEqual(before, {p.name: p.read_bytes() for p in directory.iterdir()})
        key.unlink()
        (directory / "SHA256SUMS").unlink()
        (directory / "SHA256SUMS").symlink_to(directory / "target")
        with self.assertRaises(release.ReleaseError):
            release.write_checksums(directory, "1.2.3", unsigned_development=True)
        self.assertFalse((directory / "target").exists())

    def test_signing_key_rejects_directory_and_other_owner(self):
        with self.assertRaises(release.ReleaseError):
            release.validate_signing_key(self.root)
        if os.geteuid() == 0:
            key, _ = self.keypair()
            os.chown(key, 12345, 12345)
            with self.assertRaises(release.ReleaseError):
                release.validate_signing_key(key)

    def test_verify_rejects_archive_symlink(self):
        directory, _, public = self.signed()
        archive = directory / release.archive_name("1.2.3", "amd64")
        target = self.root / "outside"
        archive.rename(target)
        archive.symlink_to(target)
        with self.assertRaises(release.ReleaseError):
            release.verify_release(directory, "1.2.3", public)

    def test_output_no_overwrite_before_build(self):
        with self.assertRaises(release.ReleaseError):
            release.build_release(Path(__file__).resolve().parents[1], "1.2.3", self.root, prebuilt_web=True, unsigned_development=True)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_real_ed25519_round_trip_and_wrong_key(self):
        directory, _, public = self.signed()
        release.verify_release(directory, "1.2.3", public)
        _, wrong = self.keypair("wrong")
        with self.assertRaises(release.ReleaseError):
            release.verify_release(directory, "1.2.3", wrong)

    def test_archive_manifest_signature_tampering_refused(self):
        for target in ("archive", "manifest", "signature"):
            with self.subTest(target=target):
                case = self.root / target
                case.mkdir()
                directory, key, public = self.signed()
                file = directory / {"archive": release.archive_name("1.2.3", "arm64"), "manifest": "SHA256SUMS", "signature": "SHA256SUMS.sig"}[target]
                data = bytearray(file.read_bytes())
                data[len(data) // 2] ^= 1
                file.write_bytes(data)
                with self.assertRaises(release.ReleaseError):
                    release.verify_release(directory, "1.2.3", public)
                shutil.rmtree(directory)
                key.unlink()
                public.unlink()

    def test_signature_checked_before_manifest_parse(self):
        directory, _, public = self.signed()
        (directory / "SHA256SUMS").write_text("not a manifest\n")
        with self.assertRaisesRegex(release.ReleaseError, "signature"):
            release.verify_release(directory, "1.2.3", public)

    def test_signed_malformed_duplicate_unsafe_missing_extra_names_refused(self):
        directory, key, public = self.signed()
        original = (directory / "SHA256SUMS").read_bytes()
        for bad in (b"not a checksum\n", original + original, original.replace(b"axionpanel-", b"../axionpanel-", 1), original.splitlines(keepends=True)[0], original + b"0" * 64 + b"  extra.tar.gz\n"):
            (directory / "SHA256SUMS").write_bytes(bad)
            self.run_openssl("pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", directory / "SHA256SUMS", "-out", directory / "SHA256SUMS.sig")
            with self.assertRaises(release.ReleaseError):
                release.verify_release(directory, "1.2.3", public)
        (directory / "SHA256SUMS").write_bytes(original)
        self.run_openssl("pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", directory / "SHA256SUMS", "-out", directory / "SHA256SUMS.sig")
        (directory / "extra.tar.gz").write_bytes(b"extra")
        with self.assertRaises(release.ReleaseError):
            release.verify_release(directory, "1.2.3", public)
        (directory / "extra.tar.gz").unlink()
        (directory / release.archive_name("1.2.3", "amd64")).unlink()
        with self.assertRaises(release.ReleaseError):
            release.verify_release(directory, "1.2.3", public)

    def test_signing_key_rejects_lax_mode_symlink_and_wrong_algorithm(self):
        key, _ = self.keypair()
        key.chmod(0o644)
        with self.assertRaises(release.ReleaseError):
            release.validate_signing_key(key)
        key.chmod(0o600)
        link = self.root / "link"
        link.symlink_to(key)
        with self.assertRaises(release.ReleaseError):
            release.validate_signing_key(link)
        self.run_openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
        key.chmod(0o600)
        with self.assertRaises(release.ReleaseError):
            release.validate_signing_key(key)

    def test_unsigned_development_explicit_not_release_signed(self):
        directory = self.root / "unsigned"
        directory.mkdir()
        for arch in release.ARCHES:
            (directory / release.archive_name("1.2.3", arch)).write_bytes(arch.encode())
        with self.assertRaises(release.ReleaseError):
            release.write_checksums(directory, "1.2.3")
        release.write_checksums(directory, "1.2.3", unsigned_development=True)
        self.assertTrue((directory / "SHA256SUMS.unsigned-development").is_file())
        self.assertFalse((directory / "SHA256SUMS.sig").exists())
        _, public = self.keypair()
        with self.assertRaises(release.ReleaseError):
            release.verify_release(directory, "1.2.3", public)


if __name__ == "__main__":
    unittest.main()
