# Standalone pre-alpha installer contract

Status: implementation in progress. This is limited testing distribution, not a stable release or evidence of all clean-VPS matrix gates.

## Boundary

`install.sh` is the only source file required on the destination host. Bash invokes an embedded isolated Python 3.11+ program; no checkout, Go, Node, hosting stack or downloaded Python code is needed. OpenSSL 3 authenticates Ed25519 manifests. Missing tooling is diagnosed, not silently installed through APT.

- Explicit pinned SemVer `--version`; no latest discovery or source compilation.
- Exactly one source: local `--directory` or HTTPS `--download-base-url` (default GitHub akbardwi/axionpanel release download for vVERSION).
- `--public-key` remains an independently trusted Ed25519 key. No TOFU, no downloaded verifier or key, no unsigned bypass. The key's immutable bytes must prove a 44-byte Ed25519 SubjectPublicKeyInfo (RSA, EC/ECDSA, Ed448 and malformed keys are refused) and the detached signature must be exactly 64 bytes. The signature is verified before any manifest byte is parsed.
- Existing local verify/preflight/staging modes retain their safety boundaries. The release manifest contains both amd64/arm64 archives. Initial download mode obtains both bounded archives, manifest and detached signature; later optimization is out of scope.
- HTTPS uses normal certificate verification, bounded streaming and absolute total deadlines that cover DNS, connect, TLS handshake, header parsing and body transfer. Initial base URLs may not carry credentials, query or fragment; `--ca-file` supplies an explicitly trusted bundle whose metadata is checked once and whose bytes are pinned for every download. Redirects may only target HTTPS with no credentials; a mirror's HTTPS Location may add query parameters (GitHub release-asset redirects do), but never downgrade to HTTP. Downloaded files stay in a new 0700 private stage.
- Authenticate manifest and check exact expected archive names/digests before parsing archives. Keep strict 16-member USTAR allowlist, size limits and ELF architecture validation.

## Fresh-host apply

`--apply --yes` authorizes provisioning only on a supported fresh systemd host. Root is required. `--root` and `--arch` remain inspection-only: no production fake-root apply escape hatch. Refuse existing AxionPanel state/account/unit, other panels, occupied listener and invalid options before provisioning. Serialize concurrent installation attempts using a root-controlled lock. Validate parent ownership/modes and refuse symlinked destinations.

Default native HTTPS binds 127.0.0.1:8443 with origin https://127.0.0.1:8443. Explicit `--host` selects a canonical IP address, `--port` an unprivileged non-7800 port; non-loopback binds additionally require `--allow-public-listen`. No firewall rule is changed. Port 7800 and the Unix-only agent are never exposed publicly. DNS origins and automatic public-IP guessing are excluded from this first slice.

Provision root-owned binaries, an axionpanel service user, private state, native self-signed TLS and hardened systemd units using fixed paths. The agent retains only its four read-only operations and Unix peer credential checks. Generate entrance/admin bootstrap as the service user with exclusive output files. Secrets never enter installer stdout/stderr/journal; print only origin, certificate fingerprint and bootstrap file path. Configure native TLS without Nginx or other hosting services.

Start/enable only the two new AxionPanel units. Verify service states, pinned self-signed HTTPS health, entrance/UI availability and authenticated agent-backed system information before success. On failure stop only newly started units, retain diagnostics/state and require manual reconciliation; do not silently retry/reset, delete data or claim transactional OS rollback.

## Acceptance

1. A copied single installer verifies/stages signed fixtures with no repo.
2. Real local HTTPS download with a trusted fixture CA; tamper, wrong key, missing/extra manifest, downgrade and oversized downloads fail closed.
3. CLI consent, options, existing installation, symlink and occupied-port checks deny before mutation.
4. Real signed binaries install/start/login and retrieve agent-backed data in a separate PID/mount/network namespace with a clean Ubuntu userspace and private systemd PID1. No host service commands or host network listeners occur. Rerun preserves existing secrets/state. Reboot and other OS/architecture combinations remain separately unverified unless exercised.
5. Independent review and scoped regression gates before verified commit/push. Pre-alpha publication still requires explicit user authorization and has not been granted; local signed artifacts for isolated testing are not a publication. Never deploy over the live development VPS.
