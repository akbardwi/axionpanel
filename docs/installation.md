# Installing AxionPanel — foundation batch (NOT a complete installer)

Status: foundation batch only. It provides `--preflight-only`, `--verify-only`
and private safe staging. `--apply` remains explicitly disabled. No host
provisioning, account creation, unit installation, boot start, firewall or
port change exists yet. A passing fake-root test proves the fixture layout,
not readiness of a clean VPS.

## Inputs

Run from a reviewed checkout containing `install.sh` and
`scripts/release.py`. The installer loads that trusted local verifier; it does
not use a bundled copy from an archive and never downloads release material.
Use Linux, Bash, Python 3.11+ and OpenSSL 3.x with Ed25519 support. No Go,
Node, package-manager operation or hosting stack is needed for this batch.
Run inspection and staging as an unprivileged operator where possible; root
is not required. Use an existing private scratch parent owned by that operator.

```text
local release directory:
  axionpanel-VERSION-linux-amd64.tar.gz
  axionpanel-VERSION-linux-arm64.tar.gz
  SHA256SUMS
  SHA256SUMS.sig
trusted Ed25519 public key
new private stage directory
```

The release directory must contain exactly the two architecture archives and
the signed manifest. Extra archives and unsigned-development markers are
refused.

## Preflight (read-only)

```sh
bash install.sh --preflight-only \
  --directory /secure/releases/1.2.3 \
  --version 1.2.3 \
  --public-key /secure/trust/release-ed25519.pub \
  --stage-dir /root/axion-stage
```

`--root` and `--arch` are inspection overrides. They may inspect a fake chroot
layout but do not prove that the live host is ready. The tool checks the OS
matrix (Ubuntu 24.04/26.04, Debian 12/13), required `systemd` paths,
architecture, existing AxionPanel state and conflicting panels. It parses
`os-release` as data, never sources or executes it.

## Verification (read-only)

```sh
bash install.sh --verify-only \
  --directory /secure/releases/1.2.3 \
  --version 1.2.3 \
  --public-key /secure/trust/release-ed25519.pub \
  --stage-dir /root/axion-stage
```

The installer copies the bounded release inputs into a private 0700 snapshot,
authenticates the Ed25519 signature with the separately supplied public key,
verifies the SHA-256 manifest, then rejects duplicate/absolute/traversal/
symlink/hardlink/FIFO/sparse members, oversized content, wrong installer
modes, missing or extra members and wrong ELF class/architecture. Both
architecture archives are inspected; extraction happens only in the staging
command.

## Private staging

```sh
bash install.sh \
  --directory /secure/releases/1.2.3 \
  --version 1.2.3 \
  --public-key /secure/trust/release-ed25519.pub \
  --stage-dir /root/axion-stage
```

All input and output paths must be absolute. `--stage-dir` is required in every
mode and must name a new directory whose caller-owned parent already exists
and is not group/other writable. Every ancestor of the stage parent and of the
public key must be owned by the caller or root and must not be group/other
writable; the stage parent is pinned by descriptor across creation, so a
concurrent rename cannot redirect staging. Inspection uses this directory only
for its private snapshot and verifier temporary files, then removes it; it does
not write elsewhere or change host configuration. The new stage is mode 0700 and
contains `payload/` (authenticated installer-selected bytes) plus a retained
`snapshot/` for independent review. Inspection modes remove the stage directory
on completion. Staged binaries are not executed.

## Apply

`--apply` exits non-zero with "apply not implemented" before any host handling.
No systemd unit, service user, unit file, `/opt` directory, boot start,
service stop, firewall, HSTS or redirect behavior is present.

## Trust and signing-key custody

The public key is the trust anchor and must be obtained out-of-band. Every
ancestor of the key path must be owned by the caller or root and not
group/other writable; symlink inputs are refused. The key file itself must also
be caller/root-owned and not group/other writable. Its bounded bytes are read
from the same descriptor whose owner and mode were validated, so the file is
never reopened for snapshotting. Keep the full checkout, key path and all
ancestors under trusted ownership. A key delivered together with the archive,
or a key obtained only from an untrusted environment, is not trusted. The
signature proves that the holder of the matching private key signed
`SHA256SUMS`, not provenance or reproducibility. Ephemeral test keys exist only
under the test scratch directory. A production trust anchor is not yet
published; this is an explicit blocker.

## Verification limits

The test suite uses real subprocess calls against real `install.sh`, ephemeral
Ed25519 keys, a fake root, and private scratch staging. It does not create
accounts, install units, start services, or execute staged binaries. The
production release matrix on a clean VPS remains unverified.

## Explicitly unverified / not part of this batch

- PID1/systemd runtime, clean VPS matrix, reboot, upgrade/recovery.
- Hosting-stack installation or public port opening.
- Live `--apply` host mutation and service lifecycle.
