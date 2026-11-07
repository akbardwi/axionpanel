"""Installer foundation contract: real CLI, private scratch, no host provisioning.

Run: python3 -B -m unittest discover -s tests/install -v
Fixture ELF headers test packaging checks, not executable binaries or runtime.
All key generation, fake roots and staging stay under Hermes scratch.
"""
import importlib.util
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
INSTALL = REPO / "install.sh"
SCRATCH = Path(os.environ.get("TMPDIR", str(Path.home() / ".hermes/cache/scratch")))


def release_module():
    spec = importlib.util.spec_from_file_location("release", REPO / "scripts/release.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = release_module()
VERSION = "1.2.3"


def elf(arch):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, 62 if arch == "amd64" else 183, 1)
    return bytes(header)


class InstallContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="install-test-", dir=SCRATCH)
        cls.base = Path(cls.tmp.name)
        cls.key = cls.base / "ephemeral.key"
        cls.public = cls.base / "ephemeral.pub"
        for args in (("genpkey", "-algorithm", "ED25519", "-out", cls.key),):
            subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)
        cls.key.chmod(0o600)
        subprocess.run(["openssl", "pkey", "-in", str(cls.key), "-pubout", "-out", str(cls.public)], check=True, capture_output=True)
        cls.fixtures = cls.base / "signed"
        cls.fixtures.mkdir()
        # Create unsigned-development archives through release tooling, then sign
        # same archive bytes through write_checksums. No production key exists.
        for arch in release.ARCHES:
            with tarfile.open(cls.fixtures / release.archive_name(VERSION, arch), "w:gz", format=tarfile.USTAR_FORMAT) as archive:
                for name in (*release.BINARIES, *release.PACKAGE_FILES):
                    data = elf(arch) if name in release.BINARIES else b"fixture\n"
                    member = tarfile.TarInfo(name)
                    member.mode = 0o755 if name in release.BINARIES else 0o644
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
        release.write_checksums(cls.fixtures, VERSION, unsigned_development=True)
        (cls.fixtures / "SHA256SUMS").unlink()
        (cls.fixtures / "SHA256SUMS.unsigned-development").unlink()
        release.write_checksums(cls.fixtures, VERSION, signing_key=cls.key)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.tmpcase = tempfile.TemporaryDirectory(prefix="case-", dir=self.base)
        self.addCleanup(self.tmpcase.cleanup)
        self.work = Path(self.tmpcase.name)
        self.root = self.work / "root"
        self.root.mkdir()
        self.directory = self.work / "release"
        shutil.copytree(self.fixtures, self.directory)
        for name, content in {
            "etc/os-release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
            "usr/bin/systemctl": "fixture",
            "usr/lib/systemd/systemd": "fixture",
        }.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.stage = self.work / "stage"

    def cli(self, *args, mode: str | None = "--preflight-only", root=True, stage=True):
        self.assertTrue(INSTALL.is_file(), "install.sh missing: installer foundation unimplemented")
        command = ["bash", str(INSTALL)]
        if mode:
            command.append(mode)
        command += ["--directory", str(self.directory), "--version", VERSION,
                    "--public-key", str(self.public)]
        if stage:
            command += ["--stage-dir", str(self.stage)]
        if root:
            command += ["--root", str(self.root), "--arch", "amd64"]
        return subprocess.run([*command, *args], capture_output=True, text=True,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(SCRATCH)})

    def reject(self, result, text):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(text, result.stderr)

    def resign(self):
        (self.directory / "SHA256SUMS").unlink()
        (self.directory / "SHA256SUMS.sig").unlink()
        release.write_checksums(self.directory, VERSION, signing_key=self.key)

    def test_preflight_correct_layout_authenticates_without_extracting(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Preflight passed", result.stdout)
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")))
        self.assertFalse(self.stage.exists(), "inspection workspace must be removed")

    def test_preflight_missing_required_files(self):
        for name in ("etc/os-release", "usr/bin/systemctl", "usr/lib/systemd/systemd"):
            with self.subTest(name=name):
                path = self.root / name
                data = path.read_bytes()
                path.unlink()
                self.reject(self.cli(), "required file missing")
                path.write_bytes(data)

    def test_os_matrix(self):
        for distro, versions in (("ubuntu", ("24.04", "26.04")), ("debian", ("12", "13"))):
            for version in versions:
                with self.subTest(distro=distro, version=version):
                    (self.root / "etc/os-release").write_text(f'ID={distro}\nVERSION_ID="{version}"\n')
                    result = self.cli()
                    self.assertEqual(result.returncode, 0, result.stderr)
        (self.root / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
        self.reject(self.cli(), "unsupported OS")

    def test_standard_os_release_symlink_stays_inside_inspection_root(self):
        path = self.root / "etc/os-release"
        data = path.read_bytes()
        path.unlink()
        target = self.root / "usr/lib/os-release"
        target.write_bytes(data)
        path.symlink_to("../usr/lib/os-release")
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        path.unlink()
        path.symlink_to(self.work / "outside-os-release")
        (self.work / "outside-os-release").write_bytes(data)
        self.reject(self.cli(), "os-release symlink escapes inspection root")

    def test_wrong_arch(self):
        self.reject(self.cli("--arch", "riscv64"), "unsupported architecture")

    def test_architecture_aliases_not_supported(self):
        self.reject(self.cli("--arch", "x86_64"), "unsupported architecture")
        self.reject(self.cli("--arch", "aarch64"), "unsupported architecture")

    def test_missing_archive_refused(self):
        (self.directory / release.archive_name(VERSION, "arm64")).unlink()
        self.reject(self.cli(mode="--verify-only"), "verification failed")
        self.assertFalse(self.stage.exists())

    def test_version_is_strict(self):
        self.reject(self.cli("--version", "../1.2.3"), "refused")
        self.assertFalse(self.stage.exists())

    def test_unsigned_marker_refused(self):
        (self.directory / "SHA256SUMS.unsigned-development").touch()
        self.reject(self.cli(mode="--verify-only"), "verification failed")
        self.assertFalse(self.stage.exists())

    def test_no_stage_binaries_execute(self):
        result = self.cli(mode=None, root=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Nothing executed or installed", result.stdout)

    def test_existing_state_and_conflicting_panels(self):
        for marker in ("var/lib/axionpanel", "etc/axionpanel", "opt/axionpanel", "etc/systemd/system/axionpanel.service"):
            with self.subTest(marker=marker):
                path = self.root / marker
                path.parent.mkdir(parents=True, exist_ok=True)
                path.mkdir()
                self.reject(self.cli(), "existing AxionPanel state")
                path.rmdir()
        for marker in ("www/server/panel", "usr/local/cpanel", "usr/local/psa", "usr/local/hestia"):
            with self.subTest(marker=marker):
                path = self.root / marker
                path.parent.mkdir(parents=True, exist_ok=True)
                path.mkdir()
                self.reject(self.cli(), "conflicting panel")
                path.rmdir()

    def test_both_inspection_modes_require_signature(self):
        (self.directory / "SHA256SUMS.sig").unlink()
        for mode in ("--preflight-only", "--verify-only"):
            with self.subTest(mode=mode):
                self.reject(self.cli(mode=mode), "verification failed")
                self.assertFalse(self.stage.exists())

    def test_tampered_archive(self):
        with (self.directory / release.archive_name(VERSION, "amd64")).open("ab") as stream:
            stream.write(b"tamper")
        self.reject(self.cli(mode="--verify-only"), "verification failed")

    def test_public_key_later_replacement_does_not_alter_snapshot(self):
        """Replacing the key path after staging cannot change copied bytes."""
        key = self.work / "mutable.pub"
        key.write_bytes(self.public.read_bytes())
        key.chmod(0o644)
        stage = self.stage
        result = self.cli("--public-key", str(key), mode=None, root=False, stage=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        original = (stage / "snapshot/trusted-public-key.pem").read_bytes()
        key.write_bytes(b"DECOY")
        self.assertEqual((stage / "snapshot/trusted-public-key.pem").read_bytes(), original)
        self.assertEqual(original, self.public.read_bytes())
        shutil.rmtree(stage)

    @unittest.skipUnless(shutil.which("strace"), "strace required")
    def test_public_key_path_opened_once(self):
        """The validated key path is opened exactly once, never re-opened."""
        keyname = "unique-anchor.pem"
        key = self.work / keyname
        key.write_bytes(self.public.read_bytes())
        key.chmod(0o644)
        trace = self.work / "trace.txt"
        result = subprocess.run(
            ["strace", "-f", "-e", "openat", "-o", str(trace),
             "bash", str(INSTALL), "--verify-only",
             "--directory", str(self.directory), "--version", VERSION,
             "--public-key", str(key), "--stage-dir", str(self.stage)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.stage.exists())
        opens = [line for line in trace.read_text().splitlines()
                 if keyname in line and "openat(" in line]
        self.assertEqual(len(opens), 1, "\n".join(opens))

    def test_wrong_public_key(self):
        # Public key is valid Ed25519 but signature was not made by this key.
        key = self.work / "other.key"
        public = self.work / "other.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)], check=True, capture_output=True)
        self.reject(self.cli("--public-key", str(public), mode="--verify-only"), "verification failed")

    def test_unsigned_extra_archive_and_symlink_refused(self):
        marker = self.directory / "SHA256SUMS.unsigned-development"
        marker.touch()
        self.reject(self.cli(mode="--verify-only"), "verification failed")
        marker.unlink()
        extra = self.directory / "extra.tar.gz"
        extra.touch()
        self.reject(self.cli(mode="--verify-only"), "verification failed")
        extra.unlink()
        archive = self.directory / release.archive_name(VERSION, "amd64")
        archive.unlink()
        archive.symlink_to(self.fixtures / archive.name)
        self.reject(self.cli(mode="--verify-only"), "symlink")

    def test_stage_is_exclusive_and_private(self):
        result = self.cli(mode=None, root=False, stage=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.stage.stat().st_mode & 0o777, 0o700)
        payload = self.stage / "payload"
        files = {str(p.relative_to(payload)) for p in payload.rglob("*") if p.is_file()}
        self.assertEqual(files, set(release.PACKAGE_FILES) | set(release.BINARIES))
        self.assertEqual(len(files), 16)
        # Authentication snapshot must survive staging for independent review.
        self.assertEqual((self.stage / "snapshot/SHA256SUMS.sig").read_bytes(), (self.directory / "SHA256SUMS.sig").read_bytes())
        self.reject(self.cli(mode=None, root=False, stage=True), "stage directory already exists")

    def test_stage_root_and_arch_overrides_are_inspection_only(self):
        self.reject(self.cli(mode=None, stage=True), "--root and --arch are inspection-only")
        self.assertFalse(self.stage.exists())

    def test_no_implicit_workspace_or_parent_creation(self):
        # Even inspection needs an explicit workspace: no implicit temp writes.
        self.reject(self.cli(stage=False), "required: --stage-dir")
        self.assertFalse(self.stage.exists())
        self.assertEqual({p.name for p in self.work.iterdir()}, {"root", "release"})
        self.assertFalse((self.root / "opt").exists())
        self.assertFalse((self.root / "var").exists())
        self.assertEqual((self.root / "usr/bin/systemctl").read_text(), "fixture")
        self.assertEqual((self.root / "usr/lib/systemd/systemd").read_text(), "fixture")
        self.assertEqual((self.root / "etc/os-release").read_text(), 'ID=ubuntu\nVERSION_ID="24.04"\n')
        self.assertFalse(self.stage.exists())
        self.assertEqual(len(list(self.work.iterdir())), 2)
        result = subprocess.run(["bash", str(INSTALL), "--verify-only"], capture_output=True, text=True)
        self.reject(result, "required")
        # Staging without --stage-dir is refused, never defaulted.
        self.reject(self.cli(mode=None, root=False, stage=False), "required: --stage-dir")

        self.stage = self.work / "missing-parent/new"
        self.reject(self.cli(stage=True), "stage parent")
        self.assertFalse(self.stage.parent.exists())

    def test_stage_symlinks_and_unsafe_parent_refused(self):
        self.stage.symlink_to(self.work / "missing")
        self.reject(self.cli(mode=None, root=False), "stage directory already exists")
        self.assertTrue(self.stage.is_symlink())
        self.stage.unlink()
        alias = self.work / "alias"
        alias.symlink_to(self.work, target_is_directory=True)
        self.stage = alias / "stage"
        self.reject(self.cli(mode=None, root=False), "symlink ancestor")
        self.assertFalse((self.work / "stage").exists())
        self.stage = self.work / "stage"
        self.work.chmod(0o777)
        self.reject(self.cli(mode=None, root=False), "stage parent")
        self.work.chmod(0o700)

    def test_existing_account_in_fake_root_refused(self):
        (self.root / "etc/passwd").write_text("axionpanel:x:123:123::/var/lib/axionpanel:/usr/sbin/nologin\n")
        self.reject(self.cli(), "existing AxionPanel state: service account")
        self.assertFalse(self.stage.exists())

    def test_os_release_never_executes_shell(self):
        # Shell-looking fields are inert data.
        sentinel = self.work / "shell-executed"
        (self.root / "etc/os-release").write_text(f'ID=ubuntu\nVERSION_ID="24.04"\nEVIL=$(touch {sentinel})\n')
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())

    def test_stage_failure_leaves_no_extraction(self):
        (self.directory / "SHA256SUMS.sig").write_bytes(b"x" * 64)
        self.reject(self.cli(mode=None, root=False), "verification failed")
        self.assertFalse(self.stage.exists())

    def test_missing_stage_parent_refused(self):
        # Existing parents are never auto-created.
        self.stage = self.work / "missing-parent/new"
        self.reject(self.cli(stage=True), "stage parent")
        self.assertFalse(self.stage.parent.exists())

    def test_apply_missing_required_inputs_refused_before_host_handling(self):
        self.assertTrue(INSTALL.is_file(), "install.sh missing")
        for args in (("--apply",), (str(self.root), "--apply"), ("--apply", "--stage-dir", str(self.stage))):
            with self.subTest(args=args):
                result = subprocess.run(["bash", str(INSTALL), *args], capture_output=True, text=True)
                self.reject(result, "required")
                self.assertFalse(self.stage.exists())
        if os.geteuid() == 0:
            # Read real script using inherited FD; /root need not be traversable
            # after dropping privileges. No writable production path involved.
            with INSTALL.open("rb") as script:
                def drop():
                    os.setgroups([])
                    os.setgid(65534)
                    os.setuid(65534)
                result = subprocess.run(["bash", f"/proc/self/fd/{script.fileno()}", "--apply"], pass_fds=(script.fileno(),), preexec_fn=drop, capture_output=True, text=True)
            self.reject(result, "required")

    def test_signed_unsafe_tar_boundaries(self):
        for attack in ("duplicate", "absolute", "traversal", "symlink", "hardlink", "fifo", "mode", "oversize", "missing", "wrong-elf", "extra"):
            with self.subTest(attack=attack):
                # Rebuild signed archives; signatures do not imply safe contents.
                shutil.copyfile(self.fixtures / release.archive_name(VERSION, "amd64"), self.directory / release.archive_name(VERSION, "amd64"))
                path = self.directory / release.archive_name(VERSION, "amd64")
                with tarfile.open(path) as original:
                    entries = [(m, original.extractfile(m).read()) for m in original.getmembers()]
                if attack == "missing":
                    entries.pop()
                elif attack in ("absolute", "traversal", "extra"):
                    entries[0][0].name = {"absolute": "/escape", "traversal": "../escape", "extra": "unexpected"}[attack]
                elif attack == "duplicate":
                    entries.append(entries[0])
                elif attack in ("symlink", "hardlink", "fifo"):
                    entries[0][0].type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE}[attack]
                    entries[0][0].linkname = "outside"
                elif attack == "mode":
                    entries[0][0].mode = 0o4755
                elif attack == "oversize":
                    # Template cap 1 MiB, total cap separate from compressed size.
                    entries[-1] = (entries[-1][0], b"x" * (1024 * 1024 + 1))
                    entries[-1][0].size = len(entries[-1][1])
                elif attack == "wrong-elf":
                    entries[0] = (entries[0][0], elf("arm64"))
                with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
                    for member, data in entries:
                        archive.addfile(member, io.BytesIO(data) if member.isfile() else None)
                self.resign()
                result = self.cli(mode="--verify-only")
                self.reject(result, "unsafe archive")
                self.assertFalse(self.stage.exists())
                self.assertFalse((self.work / "escape").exists())


    def test_stage_parent_writable_ancestor_refused(self):
        # The immediate parent can be 0700/caller-owned, but if any ancestor is
        # publicly writable, the parent is not trusted (TOCTOU rename window).
        attacker = self.work / "attacker"
        attacker.mkdir()
        attacker.chmod(0o777)
        parent = attacker / "stage-parent"
        parent.mkdir()
        parent.chmod(0o700)
        self.stage = parent / "stage"
        self.reject(self.cli(mode=None, root=False), "stage parent")
        self.assertFalse(self.stage.exists())

    def test_public_key_writable_ancestor_refused(self):
        attacker = self.work / "attacker"
        attacker.mkdir()
        attacker.chmod(0o777)
        key_parent = attacker / "key-parent"
        key_parent.mkdir(mode=0o700)
        pk = key_parent / "release.pub"
        pk.write_bytes(self.public.read_bytes())
        self.reject(self.cli("--public-key", str(pk), mode="--verify-only"), "public key")
        self.assertFalse(self.stage.exists())
        attacker.chmod(0o700)

    def test_public_key_writable_file_refused(self):
        pk = self.work / "writable.pub"
        pk.write_bytes(self.public.read_bytes())
        for mode in (0o664, 0o646, 0o666):
            with self.subTest(mode=oct(mode)):
                pk.chmod(mode)
                self.reject(self.cli("--public-key", str(pk), mode="--verify-only"), "public key")
                self.assertFalse(self.stage.exists())

    @unittest.skipUnless(os.geteuid() == 0, "foreign owner fixture requires root")
    def test_public_key_foreign_owner_refused(self):
        pk = self.work / "foreign.pub"
        pk.write_bytes(self.public.read_bytes())
        pk.chmod(0o644)
        os.chown(pk, 65534, 65534)
        self.reject(self.cli("--public-key", str(pk), mode="--verify-only"), "public key")
        self.assertFalse(self.stage.exists())

    def test_trusted_inputs_symlink_and_writable_public_key_refused(self):

        link = self.work / "pk-symlink.pem"
        link.symlink_to(self.public)
        self.reject(self.cli("--public-key", str(link), mode="--verify-only"), "public key")
        self.assertFalse(self.stage.exists())
        link.unlink()
        parent = self.work / "gou-pk"
        parent.mkdir()
        parent.chmod(0o777)
        pk = parent / "release.pub"
        pk.write_bytes(self.public.read_bytes())
        self.reject(self.cli("--public-key", str(pk), mode="--verify-only"), "public key")


if __name__ == "__main__":
    unittest.main()
