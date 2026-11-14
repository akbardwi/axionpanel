# Standalone pre-alpha installation

`install.sh` is a single-file installer with authenticated verification, private
staging and explicit fresh-host apply. Copy only the reviewed `install.sh` to
the destination: its isolated Python program includes the verifier and apply
engine. No repository checkout, Go, Node, downloaded Python code or hosting
stack is required.

This is limited pre-alpha testing distribution, **not a stable release**.
Exact artifact publication and the independently distributed signing trust
anchor must be confirmed before use; the default URL convention below is not
an assertion that any version or key has been published. Isolated systemd
namespace preparation and the real install/start/login/agent runtime gate are
still pending. Implementation does not establish clean-VPS readiness.

## Host prerequisites and scope

- Linux on amd64 or arm64; supported OS checks accept Ubuntu 24.04/26.04 and
  Debian 12/13. This is the supported target matrix, not a tested runtime matrix.
- Bash, Python 3.11+, OpenSSL 3 with Ed25519 support, and `ca-certificates` for
  normal HTTPS certificate validation.
- systemd and its standard host tools. Apply requires root and real systemd
  PID 1; a fake filesystem root is not an installation target.
- A fresh host without existing AxionPanel state, accounts or units, a detected
  conflicting control panel, or an occupied selected listener.

Missing prerequisites are diagnosed, not silently installed through APT.
Nginx, Apache, PHP, Docker, Certbot and a hosting database are not prerequisites
and are not installed. SQLite metadata is embedded in the panel.

## Trust and artifact inputs

Both `--version` and `--public-key` are mandatory. Pin an exact SemVer without
its `v` prefix; there is no `latest` discovery or source compilation. Obtain the
Ed25519 public key through an independently trusted out-of-band channel, and
review the installer itself. Downloading a key beside the archives does not
establish trust. There is no TOFU or unsigned bypass. A signature authenticates
the signed manifest, not reproducibility or the safety of signed binaries.

With no `--directory` or `--download-base-url`, the installer uses the HTTPS
GitHub convention:

```text
https://github.com/akbardwi/axionpanel/releases/download/v<VERSION>/
```

`<VERSION>` is a placeholder, not a published release. A custom
`--download-base-url` must use HTTPS without URL credentials, query or fragment.
Normal CA validation applies; `--ca-file` can supply an explicitly trusted CA
bundle. Downloads are bounded and timed, ignore ambient proxy settings, and
refuse HTTPS-to-HTTP redirects. The installer downloads **both amd64 and arm64
archives**, `SHA256SUMS` and `SHA256SUMS.sig`, even on a single-architecture host.

Alternatively, `--directory` selects a local release directory containing
exactly these four files (replace `VERSION` with the pinned version):

```text
axionpanel-VERSION-linux-amd64.tar.gz
axionpanel-VERSION-linux-arm64.tar.gz
SHA256SUMS
SHA256SUMS.sig
```

Extra files, archives and unsigned-development markers are refused. Local and
HTTPS sources are mutually exclusive and use the same verification boundary.

## Verification, preflight and private staging

All supplied filesystem paths must be absolute. `--stage-dir` is required
except for apply, which can allocate a private directory under `/var/tmp`.
An explicit stage must be new, with an existing caller-owned parent. Every
ancestor of the stage parent and public key must be caller/root-owned, not
group/other writable, and not a symlink. The key must be a bounded regular,
caller/root-owned file, not group/other writable. Its validated descriptor
supplies the snapshot bytes. Use inspection/staging without root where possible.

The following values are **placeholders**. Replace the version with the exact
available pre-alpha SemVer, and replace paths with independently trusted inputs.
Do not run the placeholder literally. Each invocation needs a new stage path.

```sh
VERSION='<PINNED_PRE_ALPHA_SEMVER>'

# Authenticate and inspect both archives; do not extract or execute binaries.
bash install.sh --verify-only \
  --version "$VERSION" --public-key /root/trust/release-ed25519.pub \
  --stage-dir /root/axion-verify

# Also inspect the host's OS/systemd paths and existing/conflicting state.
bash install.sh --preflight-only \
  --version "$VERSION" --public-key /root/trust/release-ed25519.pub \
  --stage-dir /root/axion-preflight

# Local source; retain authenticated payload and snapshot for review only.
bash install.sh --directory /root/releases/pinned-pre-alpha \
  --version "$VERSION" --public-key /root/trust/release-ed25519.pub \
  --stage-dir /root/axion-stage
```

Preflight parses `os-release` as data. `--root` and `--arch` are inspection-only
overrides, allowed with `--verify-only` or `--preflight-only`; fixtures are not
proof of a working host or PID 1. Preflight also authenticates the artifacts.
Neither inspection mode changes host configuration; both remove their private
workspace on completion. They do create temporary verification files.

The installer authenticates the Ed25519 manifest with OpenSSL and checks exact
archive names and SHA-256 digests before parsing archives. Both archives must
satisfy the fixed 16-member USTAR allowlist, bounds, modes and ELF architecture
checks. Duplicate, traversal, absolute, linked, special, sparse, missing and
extra members are refused. Without an inspection flag or `--apply`, only the
selected architecture is extracted under a new 0700 stage as `payload/`, with
`snapshot/` retained. Staged binaries are not executed or installed.

## Fresh-host apply

Apply is a separate explicit action: `--apply` is required, followed by terminal
confirmation or prior consent through `--yes`.
It requires root, an authenticated payload and a supported fresh systemd host.
`--root` and `--arch` cannot bypass the real-host boundary. For a confirmed
available testing version and independently trusted key (same placeholder rule):

```sh
VERSION='<PINNED_PRE_ALPHA_SEMVER>'
sudo bash install.sh --apply --yes \
  --version "$VERSION" --public-key /root/trust/release-ed25519.pub \
  --host 127.0.0.1
```

Apply prints the resolved plan — listener, origin, administrator, firewall action —
and then requires the operator to type `INSTALL` on the controlling terminal. Any
other answer aborts before provisioning. `--yes` records prior consent and skips
only that prompt; it never publishes a listener by itself.

`--host` accepts `auto`, a canonical IP address, or `127.0.0.1`. `auto` is the
default: the address the kernel selects for the default route is used, discovered
through a connected UDP socket on a documentation address, so nothing is sent,
resolved or looked up externally. Detection fails closed (no default route,
loopback or malformed result) and then requires an explicit `--host`. The resolved
address is frozen before validation, and the same address is bound, served and
certified. An address that is not globally routable is labelled **LOCAL**, with a
statement that external reachability depends on provider routing; the installer
never claims public reachability it did not verify.

`--port` selects an unprivileged port in 1024–65535; port **7800 is refused**. A
non-loopback bind additionally requires explicit `--allow-public-listen`. No
hosting service is adopted and the Unix-only agent is never exposed over TCP.
Public access and certificate trust remain operator decisions.

`--open-firewall` is the only firewall action and is optional. It requires
`--apply`, a non-loopback listener, and an already active UFW reporting
`Status: active` with no existing rule covering the port. The installer never
enables, resets or reconfigures a firewall, never switches to another backend,
and adds one `ufw allow <port>/tcp comment <invocation-id>` rule, only after the panel answered
readiness locally. On a later failure it attempts to delete that rule and reports
whether removal succeeded; a rule it cannot attribute leaves manual
reconciliation to the operator. Provider security groups and port ranges stay
manual.

`https://127.0.0.1:8443` is no longer the implicit default. With no `--host`,
the installer selects the default-route address but refuses a non-loopback bind
unless `--allow-public-listen` is also supplied. Pass
`--host 127.0.0.1 --port 8443` for an SSH-tunnel-only installation.

Direct HTTPS is an operator-facing choice, not a claim of public reachability:
provider routing, DNS and every firewall outside the optional UFW rule remain
outside the installer.


Apply serializes installation with a root-controlled lock and refuses unsafe
ownership, writable ancestors, symlink destinations, existing accounts/units or
state, conflicting panels and occupied listeners. It provisions:

- Root-owned binaries at `/usr/local/axionpanel/bin/`, authenticated reference
  files under `/usr/local/axionpanel/share/`, and generated hardened units at
  `/etc/systemd/system/axionpanel{,-agent}.service`. Archive templates are
  references, not arbitrary root-executed unit directives.
- A non-root `axionpanel` service account and private 0700
  `/var/lib/axionpanel/` state. The panel cannot rewrite binaries, units or policy.
- A root agent with a peer-UID-checked Unix socket at
  `/run/axionpanel/agent.sock`. Only its four built-in read-only operations are
  enabled; static-site and hosting-stack mutation are not enabled by installation.
- Native self-signed IP TLS under `/etc/axionpanel/tls/` (root:axionpanel 0750;
  certificate and key 0640). Self-signed TLS encrypts traffic but does not
  automatically establish trusted server identity. HSTS is not enabled.
- A secret entrance and `/var/lib/axionpanel/bootstrap.json`, generated as the
  service user using exclusive files. Both secret files are mode 0600;
  bootstrap contains username, generated password, entrance path and origin.

Only the two new AxionPanel units are started and enabled. Success requires
active units, certificate-pinned HTTPS, entrance and login UI checks, a real
authenticated login, agent-backed system information, and readiness-session
logout. A bare health HTTP 200 is not enough. These are implemented success
checks, **not a claim that the pending runtime acceptance gate has passed**.

## Optional reviewed local preset

To avoid typing the same flags, copy
[`deploy/install-preset.example`](../deploy/install-preset.example) alongside
`install.sh`. The preset is a Bash argument array, not an installer-supported
configuration format. It contains no credentials and does not invoke anything
when sourced. **Source only a reviewed, operator-controlled file**: Bash
configuration can execute code. Do not source an untrusted downloaded preset
as root.

For a fresh testing VPS, save your reviewed copy as
`/root/install-preset.conf`, set it to root-owned mode 0600, and edit:

- `--version`: an exact available version, without the `v` prefix.
- `--public-key`: the absolute path to an independently trusted Ed25519 public key.
- `--directory`: the absolute directory containing the four signed release inputs
  described above, including both architecture archives.

No public release or signing trust anchor is implied by the example. It will
not install until real artifacts and a trusted key have been supplied. The
preset deliberately keeps HTTPS on loopback port 8443 and does not open firewall
ports. `--ca-file` is **optional**, for custom HTTPS trust only; a local directory
source does not need it. The public signing key is still mandatory.

From a trusted SSH shell, in the directory containing your reviewed `install.sh`:

```bash
# Review and edit the preset first; do not run its placeholders literally.
source /root/install-preset.conf
printf 'Installer arguments: '; printf '%q ' "${AXION_INSTALL_ARGS[@]}"; printf '\n'
read -r -p 'Provision this fresh VPS? Type INSTALL: ' confirmation
if [[ "$confirmation" == INSTALL ]]; then
  sudo bash ./install.sh "${AXION_INSTALL_ARGS[@]}"
else
  printf 'Cancelled; installer not invoked.\n'
fi
```

The confirmation above is an operator-side convenience; the underlying
`--apply --yes`, OS/fresh-host checks, signature verification and rerun refusal
remain unchanged. Keep bootstrap passwords and private signing keys out of the
preset. This is not an upgrade or a way to install over an existing panel.

## Initial access and secret custody

Installer output contains only the origin, certificate SHA-256 fingerprint and
bootstrap file location—not passwords or the entrance. Retrieve bootstrap over
a trusted SSH session only, for example with a privileged read of
`/var/lib/axionpanel/bootstrap.json`. Never paste its contents into chat,
telemetry, support logs or a web-accessible file. Keep `secret.key` separate from
DB backups; do not regenerate it to recover access.

For an explicit tunnel-only installation (`--host 127.0.0.1`), tunnel the same
local port so the exact origin stays `https://127.0.0.1:8443`. With the default
`--host auto`, open the resolved origin directly from a trusted client; a local
address is labelled LOCAL and external reachability is not assumed.

```sh
ssh -N -L 8443:127.0.0.1:8443 OPERATOR@SERVER
```

`OPERATOR@SERVER` is a placeholder. Verify the SSH-reported certificate
fingerprint before trusting the self-signed certificate, then visit the secret
entrance path from bootstrap at that origin and log in. The entrance is defense
in depth, not a replacement for authentication. Avoid capturing the secret URL
in routine logs or screenshots.

## Reruns, partial failure and verification limits

Reruns refuse existing installations; they do not adopt, reset, overwrite or
regenerate credentials. This is not an upgrade, repair, uninstall or live
migration tool. On partial failure the installer requests stops only for units
it attempted to start, retains installation state for diagnosis, and requires
**manual reconciliation**. A stop can fail; inspect actual service state. There
is no automatic reset, recursive deletion of installed data or transactional OS
rollback. Do not delete state just to force a retry.

Runtime acceptance in an isolated PID/mount/network namespace with private
systemd PID 1 is pending, including namespace preparation. Clean-VPS execution,
reboot, every advertised OS/architecture, and upgrade/recovery remain separately
unverified. Local fixtures, unit tests and static unit validation do not establish
those results. No live development VPS migration is authorized by this guide.

The profiles in [deployment.md](deployment.md) and
[native-tls-systemd.md](native-tls-systemd.md) remain explicitly **manual**
operator procedures, distinct from installer-generated units. See the
[standalone contract](standalone-installer-plan.md) and the broader
[installation plan](installation-plan.md) for acceptance and future scope.
