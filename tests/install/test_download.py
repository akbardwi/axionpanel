"""Standalone bootstrap contract: single-file verify and bounded HTTPS download.

Run: python3 -B -m unittest tests.install.test_download -v
Fixtures are signed with an ephemeral key; nothing here is a production release.
"""
import functools
import http.server
import importlib.util
import io
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest

REPO = Path(__file__).resolve().parents[2]
INSTALL = REPO / "install.sh"
SCRATCH = Path(os.environ.get("TMPDIR", str(Path.home() / ".hermes/cache/scratch")))
VERSION = "1.2.3"


def release_module():
    spec = importlib.util.spec_from_file_location("release", REPO / "scripts/release.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = release_module()


def installer_namespace(source=None):
    """Execute the real embedded installer source in an isolated namespace."""
    text = INSTALL.read_text() if source is None else source
    embedded = text.split("<<'PY'\n", 1)[1].rsplit("\ntry:\n    main()", 1)[0]
    namespace = {}
    exec(compile(embedded, "installer-test", "exec"), namespace)
    return namespace


def elf(arch):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, 62 if arch == "amd64" else 183, 1)
    return bytes(header)


class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        routes = getattr(self.server, "routes", None) or {}
        if self.path in routes:
            self.send_response(302)
            self.send_header("Location", routes[self.path])
            self.end_headers()
            return
        redirect = getattr(self.server, "redirect", None)
        if redirect is not None:
            self.send_response(302)
            self.send_header("Location", redirect)
            self.end_headers()
            return
        if getattr(self.server, "header_drip", False):
            # Trickle headers without ever ending the header block: every
            # individual socket read is quick, so only a total deadline stops it.
            try:
                self.wfile.write(b"HTTP/1.1 200 OK\r\n")
                self.wfile.flush()
                stop = time.monotonic() + 6
                while time.monotonic() < stop:
                    self.wfile.write(b"X-Trickle: 1\r\n")
                    self.wfile.flush()
                    time.sleep(0.2)
            except OSError:
                return
            return
        if getattr(self.server, "drip", False):
            # Trickle one byte every 0.2s without finishing the body: no
            # individual read blocks long enough for the socket timeout.
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.end_headers()
            try:
                stop = time.monotonic() + 3
                while time.monotonic() < stop:
                    self.wfile.write(b"\0")
                    self.wfile.flush()
                    time.sleep(0.2)
            except OSError:
                return
        if self.path.endswith(".tar.gz"):
            limit = getattr(self.server, "archive_limit", None)
            if limit is not None:
                data = (self.server.directory / self.path.lstrip("/")).read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/gzip")
                self.send_header("Content-Length", str(limit))
                self.end_headers()
                # Oversize Content-Length is refused without downloading body.
                return
        return super().do_GET()


class _HTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    directory: Path
    redirect: str | None = None
    archive_limit: int | None = None
    routes: dict[str, str] | None = None
    drip: bool = False
    header_drip: bool = False


class _Server:
    def __init__(self, directory, cert, key, redirect=None):
        self.directory = Path(directory)
        handler = functools.partial(_Handler, directory=str(self.directory))
        self.httpd = _HTTPServer(("127.0.0.1", 0), handler)
        self.httpd.directory = self.directory
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.httpd.socket = self.context.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class DownloadContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="download-test-", dir=SCRATCH)
        cls.base = Path(cls.tmp.name)
        cls.key = cls.base / "ephemeral.key"
        cls.public = cls.base / "ephemeral.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(cls.key)],
                       check=True, capture_output=True)
        cls.key.chmod(0o600)
        subprocess.run(["openssl", "pkey", "-in", str(cls.key), "-pubout", "-out", str(cls.public)],
                       check=True, capture_output=True)
        cls.fixtures = cls.base / "signed"
        cls.fixtures.mkdir()
        for arch in release.ARCHES:
            with tarfile.open(cls.fixtures / release.archive_name(VERSION, arch), "w:gz",
                              format=tarfile.USTAR_FORMAT) as archive:
                for name in (*release.BINARIES, *release.PACKAGE_FILES):
                    data = elf(arch) if name in release.BINARIES else b"fixture\n"
                    member = tarfile.TarInfo(name)
                    member.mode = 0o755 if name in release.BINARIES else 0o644
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
        release.write_checksums(cls.fixtures, VERSION, signing_key=cls.key)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(prefix="case-", dir=self.base)
        self.addCleanup(self.case.cleanup)
        self.work = Path(self.case.name)
        self.directory = self.work / "release"
        shutil.copytree(self.fixtures, self.directory)
        self.stage = self.work / "stage"
        self.cert = self.work / "server.crt"
        self.server_key = self.work / "server.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
             "-keyout", str(self.server_key), "-out", str(self.cert)],
            check=True, capture_output=True)

    def cli(self, *args, base=None, ca=True, ca_path=None, install=None, stage=True,
            public=None):
        script = Path(install or INSTALL)
        command = ["bash", str(script), "--verify-only"]
        command += ["--version", VERSION, "--public-key", str(public or self.public)]
        if base is not None:
            command += ["--download-base-url", base]
        else:
            command += ["--directory", str(self.directory)]
        if ca:
            command += ["--ca-file", str(ca_path or self.cert)]
        if stage:
            command += ["--stage-dir", str(self.stage)]
        return subprocess.run([*command, *args], capture_output=True, text=True,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                                   "TMPDIR": str(SCRATCH)})

    def url(self, server):
        port = server.httpd.server_address[1]
        return f"https://127.0.0.1:{port}"

    def test_downloads_and_authenticates_from_https(self):
        with _Server(self.directory, self.cert, self.server_key) as server:
            result = self.cli(base=self.url(server) + "/")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified", result.stdout)
        self.assertFalse(self.stage.exists())

    def test_single_file_copy_verifies_without_checkout(self):
        isolated = self.work / "isolated"
        isolated.mkdir()
        script = isolated / "install.sh"
        shutil.copy2(INSTALL, script)
        result = self.cli(install=script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified", result.stdout)

    def test_plaintext_source_refused(self):
        result = self.cli(base="http://127.0.0.1:1/releases")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTPS", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_url_credentials_query_and_fragment_refused(self):
        for base in ("https://user:pw@127.0.0.1/releases",
                     "https://127.0.0.1/releases?token=x",
                     "https://127.0.0.1/releases#fragment"):
            with self.subTest(base=base):
                result = self.cli(base=base)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("refused", result.stderr)

    def test_missing_artifact_refused(self):
        (self.directory / release.archive_name(VERSION, "arm64")).unlink()
        with _Server(self.directory, self.cert, self.server_key) as server:
            result = self.cli(base=self.url(server))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verification failed", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_tampered_artifact_refused(self):
        with (self.directory / release.archive_name(VERSION, "amd64")).open("ab") as stream:
            stream.write(b"tamper")
        with _Server(self.directory, self.cert, self.server_key) as server:
            result = self.cli(base=self.url(server))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verification failed", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_untrusted_tls_refused_without_ca(self):
        with _Server(self.directory, self.cert, self.server_key) as server:
            result = self.cli(base=self.url(server), ca=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verification failed", result.stderr)

    def test_ambiguous_manifest_refused(self):
        manifest = self.directory / "SHA256SUMS"
        manifest.write_text(manifest.read_text() + manifest.read_text())
        (self.directory / "SHA256SUMS.sig").unlink()
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.key),
                        "-in", str(manifest), "-out", str(self.directory / "SHA256SUMS.sig")],
                       check=True, capture_output=True)
        with _Server(self.directory, self.cert, self.server_key) as server:
            result = self.cli(base=self.url(server))
        self.assertNotEqual(result.returncode, 0)
        # Signature over the duplicate manifest is valid, so the parser must
        # still refuse the ambiguous entries after authentication.
        self.assertIn("duplicate", result.stderr)

    def test_https_downgrade_redirect_refused(self):
        with _Server(self.directory, self.cert, self.server_key) as server:
            server.httpd.redirect = "http://127.0.0.1:9/"
            result = self.cli(base=self.url(server))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTPS redirect refused", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_oversized_download_refused_before_body(self):
        with _Server(self.directory, self.cert, self.server_key) as server:
            # Header rejection avoids sending a 256 MiB body.
            server.httpd.archive_limit = 256 * 1024 * 1024 + 1
            result = self.cli(base=self.url(server))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("size limit", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_relative_redirect_uses_most_recent_url(self):
        # The second Location is relative to /moved/manifest, not /start.
        (self.directory / 'moved').mkdir()
        shutil.move(self.directory / 'SHA256SUMS', self.directory / 'moved/SHA256SUMS')
        expected = (self.directory / 'moved/SHA256SUMS').read_bytes()
        with _Server(self.directory, self.cert, self.server_key) as server:
            server.httpd.routes = {"/start": "/moved/manifest", "/moved/manifest": "SHA256SUMS"}
            namespace = installer_namespace()
            context = namespace["ca_context"](self.cert.read_bytes())
            destination = self.work / "redirected"
            namespace["download_file"](self.url(server) + "/start", destination, 4096, context)
        self.assertEqual(destination.read_bytes(), expected)

    def test_trickling_body_has_total_deadline(self):
        # Shorten the internal budget in an isolated copy of the source, not via
        # an installer environment override available to production callers.
        text = INSTALL.read_text()
        self.assertTrue("DOWNLOAD_DEADLINE = 300" in text,
                        "embedded total-download-deadline constant is missing")
        namespace = installer_namespace(text.replace("DOWNLOAD_DEADLINE = 300",
                                                     "DOWNLOAD_DEADLINE = 0.6"))
        import concurrent.futures
        with _Server(self.directory, self.cert, self.server_key) as server:
            server.httpd.drip = True
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                # Executed off the main thread: no SIGALRM, only the
                # cooperative per-chunk monotonic checks may stop this.
                future = pool.submit(namespace["download_file"], self.url(server) + "/drip",
                                     self.work / "drip", 4096,
                                     namespace["ca_context"](self.cert.read_bytes()))
                try:
                    with self.assertRaisesRegex(Exception, "deadline|timed out"):
                        future.result(timeout=2)
                finally:
                    future.cancel()
            finally:
                server.httpd.drip = False
                pool.shutdown(wait=False)

    def test_header_trickle_bounded_by_total_deadline(self):
        # Headers trickle forever in small reads, so only an absolute outer
        # cancellation bounds the transfer. Run the real CLI from a copy whose
        # embedded budget is shortened at the source; there is no env override.
        text = INSTALL.read_text()
        self.assertTrue("DOWNLOAD_DEADLINE = 300" in text,
                        "embedded total-download-deadline constant is missing")
        script = self.work / "install-short-deadline.sh"
        script.write_text(text.replace("DOWNLOAD_DEADLINE = 300", "DOWNLOAD_DEADLINE = 0.6"))
        with _Server(self.directory, self.cert, self.server_key) as server:
            server.httpd.header_drip = True
            started = time.monotonic()
            result = self.cli(base=self.url(server), install=script)
            elapsed = time.monotonic() - started
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deadline", result.stderr)
        self.assertLess(elapsed, 4.0, "header trickle was not bounded by the total deadline")
        self.assertFalse(self.stage.exists())

    def test_unsigned_malformed_manifest_fails_signature_first(self):
        # Unauthenticated bytes must never reach the parser: the stale signature
        # no longer matches, so the signature gate rejects before "malformed".
        (self.directory / "SHA256SUMS").write_bytes(b"not a checksum manifest\n")
        with _Server(self.directory, self.cert, self.server_key) as server:
            result = self.cli(base=self.url(server))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature", result.stderr)
        self.assertNotIn("malformed", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_short_signature_refused(self):
        signature = self.directory / "SHA256SUMS.sig"
        valid = signature.read_bytes()
        self.assertEqual(len(valid), 64)
        signature.write_bytes(valid[:32])
        with _Server(self.directory, self.cert, self.server_key) as server:
            result = self.cli(base=self.url(server))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("64", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_ec_prime192v1_signed_release_refused(self):
        # A genuine prime192v1 key with a genuine, verifiable ECDSA signature
        # is still not an Ed25519 release and must be refused by key type.
        ec_key = self.work / "ec192.key"
        ec_public = self.work / "ec192.pub"
        subprocess.run(["openssl", "ecparam", "-name", "prime192v1", "-genkey", "-noout",
                        "-out", str(ec_key)], check=True, capture_output=True)
        subprocess.run(["openssl", "ec", "-in", str(ec_key), "-pubout", "-out", str(ec_public)],
                       check=True, capture_output=True)
        signature = self.directory / "SHA256SUMS.sig"
        signature.unlink()
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(ec_key),
                        "-out", str(signature), str(self.directory / "SHA256SUMS")],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(ec_public),
                        "-signature", str(signature), str(self.directory / "SHA256SUMS")],
                       check=True, capture_output=True)
        result = self.cli(public=ec_public)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ed25519", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_ed448_public_key_refused(self):
        key = self.work / "ed448.key"
        public = self.work / "ed448.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED448", "-out", str(key)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)],
                       check=True, capture_output=True)
        result = self.cli(public=public)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ed25519", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_rsa_public_key_refused(self):
        key = self.work / "rsa.key"
        public = self.work / "rsa.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)],
                       check=True, capture_output=True)
        result = self.cli(public=public)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ed25519", result.stderr)
        self.assertFalse(self.stage.exists())

    def test_ca_file_group_writable_refused(self):
        ca = self.work / "ca-writable.pem"
        shutil.copy2(self.cert, ca)
        ca.chmod(0o666)
        with _Server(self.directory, self.cert, self.server_key) as server:
            result = self.cli(base=self.url(server), ca_path=ca)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("writable", result.stderr)
        self.assertFalse(self.stage.exists())

    @unittest.skipUnless(os.geteuid() == 0, "needs root to hand the CA file to another owner")
    def test_ca_file_foreign_owner_refused(self):
        ca = self.work / "ca-foreign.pem"
        shutil.copy2(self.cert, ca)
        os.chown(ca, 65534, 65534)
        namespace = installer_namespace()
        with self.assertRaisesRegex(Exception, "owned"):
            namespace["read_ca_file"](ca)

    def test_ca_context_survives_replacement_of_checked_path(self):
        # The context is built once from the validated bytes; the pathname is
        # never reopened, so replacing it afterwards cannot swap the trust root.
        ca = self.work / "ca-pinned.pem"
        shutil.copy2(self.cert, ca)
        other = self.work / "other.crt"
        other_key = self.work / "other.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=other.invalid", "-keyout", str(other_key), "-out", str(other)],
            check=True, capture_output=True)
        namespace = installer_namespace()
        checked = namespace["read_ca_file"](ca)
        context = namespace["ca_context"](checked)
        shutil.copy2(other, ca)
        expected = (self.directory / "SHA256SUMS").read_bytes()
        destination = self.work / "pinned"
        with _Server(self.directory, self.cert, self.server_key) as server:
            received = namespace["download_file"](self.url(server) + "/SHA256SUMS",
                                                  destination, 4096, context)
        self.assertEqual(received, len(expected))
        self.assertEqual(destination.read_bytes(), expected)

    def test_environment_proxy_is_ignored(self):
        env = {**os.environ, "HTTPS_PROXY": "http://127.0.0.1:9",
               "https_proxy": "http://127.0.0.1:9", "TMPDIR": str(SCRATCH)}
        with _Server(self.directory, self.cert, self.server_key) as server:
            result = subprocess.run(
                ["bash", str(INSTALL), "--verify-only", "--version", VERSION,
                 "--public-key", str(self.public), "--ca-file", str(self.cert),
                 "--download-base-url", self.url(server), "--stage-dir", str(self.stage)],
                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
