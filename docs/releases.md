# Release Packaging

`scripts/release.py` builds two Linux archives (`amd64`, `arm64`) containing the
panel, the agent, and the tracked deployment templates/docs. It never installs,
deploys, mutates runtime state, or manages keys for you. `--signing-key` must
point at a key **you** already own and keep outside this repository.

Requires Go 1.26+, Node 22+ (only when building the web UI), and OpenSSL 3.x with
Ed25519 support.

## Build a development package (unsigned, explicit)

```sh
python3 -B scripts/release.py build \
  --version 0.1.0-dev \
  --output /tmp/axionpanel-0.1.0-dev \
  --unsigned-development
```

This archives `axionpanel` and `axionpanel-agent` (with validated `web/dist`
assets embedded in the panel), `README.md`, and the systemd/nginx examples and
docs listed in `PACKAGE_FILES`. The output directory also contains
`SHA256SUMS` and `SHA256SUMS.unsigned-development`. It is **not** a signed release: it carries no
signature, and `verify` rejects it. Use it only for local testing.

## Build with a real signing key

```sh
python3 -B scripts/release.py build \
  --version 1.2.3 \
  --output /tmp/axionpanel-1.2.3 \
  --signing-key /secure/offline/release-ed25519.key
```

The key must be an Ed25519 private key, a regular file (no symlink), owned by
you, with no group/other permission bits (`chmod 600`). The tool refuses
anything else and never copies, generates, or stores a key.

Omit `--signing-key` and `--unsigned-development` is required instead: there is
no implicit mode. Both flags are mutually exclusive.

### Version and UI rules

- `--version` must be SemVer without a `v` prefix (maximum 64 characters):
  `1.2.3`, `1.2.3-rc.1`, `1.2.3+build.4`. Characters that could alter paths or
  Go `-ldflags` are rejected before any build.
- A usable UI is required. Without `--prebuilt-web` the tool runs `make web`
  itself; with `--prebuilt-web` it validates `web/dist` and requires an
  `index.html` plus a JavaScript module script under `assets/`. Placeholder-only
  builds, symlinks, and files that look like runtime state or secrets are
  refused.
- Output directories and files are created exclusively. Existing output is
  never overwritten or merged.

## Archive layout

Deterministic `tar.gz`, one per architecture:

```text
axionpanel / axionpanel-agent     mode 0755
README.md                         mode 0644
deploy/...  docs/...              mode 0644
```

Entries are sorted, `mtime`/`uid`/`gid` are zeroed, owner names blanked, and
gzip is written without a timestamp, so the same inputs produce identical bytes.
Symlinks, extra files, databases, keys, logs, and runtime state are excluded by
an explicit allowlist. The build uses `CGO_ENABLED=0`, `-trimpath`, and
`-X main.version=<version>`.

## Verify a release

Verification needs a public key obtained through a channel you already trust
(out-of-band, pinned in your automation, or read from an offline media check).
Do not trust a key that arrived alongside the artifacts.

```sh
python3 -B scripts/release.py verify \
  --version 1.2.3 \
  --directory ./axionpanel-1.2.3 \
  --public-key /secure/offline/release-ed25519.pub
```

Order of checks: Ed25519 signature over `SHA256SUMS` **first**, then strict
manifest parsing (exact two archive names for the version, no duplicates,
malformed lines, or path components), then the directory must contain exactly
those archives, then SHA-256 digests. Errors are fail-closed and exit non-zero.
Verification scope is the named directory only; it does not recurse.

The signature covers the checksum file. It confirms the manifest was signed by
the holder of the private key. It is **not** provenance attestation, not a
reproducibility guarantee, and not proof that a binary was built from a given
commit.

The tool shells out to the installed OpenSSL CLI with the equivalent of:

```sh
openssl pkeyutl -sign   -rawin -inkey release-ed25519.key -in SHA256SUMS -out SHA256SUMS.sig
openssl pkeyutl -verify -pubin -rawin -inkey release-ed25519.pub -in SHA256SUMS -sigfile SHA256SUMS.sig
```

You can reproduce either direction with those commands; the tool validates the
DER key type is Ed25519 before calling them.

## Local trust bootstrap (development only)

For local testing, create a throwaway key and keep it inside a scratch
directory, never in the repository:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out /tmp/axion-test.key
openssl pkey -in /tmp/axion-test.key -pubout -out /tmp/axion-test.pub
```

Then build and verify as above. Tests in `scripts/test_release.py` do the same
with ephemeral keys under the scratch directory; they cover wrong-key,
tampered-archive, tampered-manifest, tampered-signature, malformed/duplicate/
unsafe manifest names, missing/extra archives, and lax key permissions.

## Still pending

- **Real offline release-key management**: generation on an offline machine,
  split/backed-up custody, rotation, and revocation are operational decisions
  not implemented here. The repository intentionally ships no production key
  and no key-generation step. Nothing in this document should be read as
  approval of a key-handling process.
- **Installer (`install.sh`)**: not provided yet. The archives are inputs for a
  future installer and for manual systemd deployment.
- **Reproducible builds across hosts/compilers**: deterministic *archive*
  metadata is tested; identical binaries across different Go toolchains,
  hosts, or build paths are not claimed.
- **Windows/macOS packaging and ARM64 hardware execution**: only Linux
  archives are produced. Here the ARM64 panel was smoke-tested on an aarch64
  host (`--help`, `-init-tls`, native HTTPS health route, `/`, and a hashed
  JavaScript asset); the AMD64 binary was built and inspected but not
  executed, and no installer was run.
- **Release signing infrastructure**: no CI signing service, HSM, or
  transparency log integration.

## Tests

```sh
python3 -B -m unittest discover -s scripts -p test_release.py -v
```

Unit tests use fixture binary bytes to check archive layout and determinism, and
real ephemeral Ed25519 keys for sign/verify paths. They do not build Go binaries;
exercise the full pipeline with the `build` command above on the target arch.
