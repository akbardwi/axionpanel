# Standalone installation and host provisioning plan

Status: standalone pre-alpha installer implemented; acceptance PARTIAL.
The single-file `install.sh` implements signed artifact verification, private
staging and root-only `--apply --yes` with generated units, initial onboarding
and authenticated readiness checks. Isolated systemd namespace preparation and
runtime acceptance remain pending. No stable release, exact published testing
artifact/key, clean-VPS matrix result, reboot result or upgrade/recovery
capability is claimed. Native TLS, explicit certificate initialization, entrance
and protected bootstrap files are implemented in the binary (see
[native-tls-plan.md](native-tls-plan.md)); optional package provisioning and
software-management screens remain unimplemented. Manual loopback systemd templates remain in
[deployment.md](deployment.md); the separately validated
[native-HTTPS profile](native-tls-systemd.md) is a manual alternative, not a live
migration.

## 1. Alignment with the original MVP

Keep Go + embedded Vue 3, a non-root panel, a root agent with a closed operation
API, SQLite metadata, Ubuntu/Debian first, amd64/arm64, and a single administrator
with local and later enrolled remote hosts. Keep all expanded-MVP workloads:
Nginx/Apache websites and PHP-FPM, certificates, MariaDB-first database management,
files, cron, firewall/SSH, terminal/logs, Docker/Compose, Git deployment, curated
templates, managed-host grouping, and encrypted local/S3 backup/restore.

This changes dependency order. Subsequent approved scope additions include
Nginx/Apache adapters, explicit coexistence profiles and managed-node HTTP load
balancing; see [the extended plan](web-stack-and-catalog-plan.md). OpenLiteSpeed
remains outside the MVP. Multi-user
hosting, DNS/mail/FTP, distributed scheduling/HA and the license remain subject
to the existing scope boundaries; the license is still deferred.

## 2. Independent control plane

The Go panel serves embedded UI, API and HTTPS directly. Neither installation,
login nor panel availability requires Nginx, Apache, PHP, Docker, Certbot or a
hosting database server. SQLite is embedded metadata storage, not a managed
hosting database service. Installer tooling requires Bash, Python 3.11+,
OpenSSL 3 with Ed25519 support, `ca-certificates` and standard systemd tools.
No repository checkout, Go or Node is needed on the destination host.

- Apply defaults to native `https://127.0.0.1:8443`; explicit canonical
  IP/port flags can change the bind. Non-loopback binds require
  `--allow-public-listen`, and port 7800 is refused. No public IP is guessed and
  no firewall or provider-network rule is changed.
- The panel runs as non-root `axionpanel`; the local root agent exposes only a
  permission-controlled Unix socket.
- Ports 80/443 remain available for later managed websites. No panel vhost is
  created. A reverse proxy is optional, not a dependency.
- Stopping or removing a hosting service must not stop panel HTTPS or login.
- The public pre-alpha deployment using Nginx and loopback HTTP is unchanged.
  The installer does not migrate a live host.

## 3. Shipped standalone installer contract

`install.sh` is the only file copied to the destination. Its embedded Python
program verifies/stages signed artifacts and may perform the explicit apply
mutation. The versionless "run this URL" command must not be published unless
the exact artifact and independently distributed trust key are confirmed.

1. `--version` accepts an exact pinned SemVer; `--public-key` is mandatory.
   Obtain that key out-of-band and review the installer. No latest discovery,
   source compilation, TOFU, downloaded verifier or unsigned bypass.
2. Local `--directory` must contain exactly two architecture archives plus
   `SHA256SUMS` and `SHA256SUMS.sig`; HTTPS download defaults to
   `https://github.com/akbardwi/axionpanel/releases/download/v<VERSION>/`,
   with `<VERSION>` an explicit placeholder rather than a claimed published
   release. A custom HTTPS `--download-base-url` is allowed. Downloads obtain
   both amd64/arm64 archives, the manifest and detached signature, then
   authenticate the manifest and check exact names/digests before parsing.
3. Preflight/verification modes may run without root and use a new explicit
   `--stage-dir`. Apply may allocate its own private `/var/tmp` workspace.
   `--root`/`--arch` remain inspection-only. Existing AxionPanel state,
   conflicting panels, occupied listeners and unsafe paths are refused.
4. `--apply --yes` authorizes root provisioning on a supported fresh systemd
   host. It writes root-owned binaries, creates the non-root service account,
   private state, self-signed TLS and generated units, and stores a 0600
   entrance and `bootstrap.json` created as the service user. The agent remains
   read-only over Unix peer credentials.
5. Secret material never goes to installer stdout, stderr or the journal. Only
   the origin, certificate fingerprint and bootstrap path are printed. The
   operator retrieves bootstrap securely through SSH.
6. Apply starts and enables only the two AxionPanel units, checking unit
   state, certificate-pinned HTTPS, entrance/UI, authenticated health,
   agent-backed system information and session cleanup. These checks are
   implemented as part of the engine but do not yet constitute a passed runtime
   acceptance gate.

Existing behavior, repair, upgrade and uninstall are distinct. Reruns refuse
adoption and must not regenerate credentials or reset state. Partial failure
preserves state and requires manual reconciliation; no automatic reset,
deletion or transactional OS rollback is promised.

## 4. Initial TLS and certificate custody

The shipped fresh-host installer generates a self-signed certificate for the
selected IP in the certificate's Subject Alternative Name and prints its
fingerprint for out-of-band verification. Browsers warn until the certificate
is trusted; self-signed TLS does not establish authenticated server identity.
Public plaintext HTTP login is not an installation mode. SSH tunneling remains
an alternative.

Panel HTTPS keys remain separate from site TLS and agent enrollment keys. The
installed `/etc/axionpanel/tls/` layout is `root:axionpanel` mode `0750`, with
the key mode `0640`; the panel reads the key, and neither key is exposed through
API/UI. Site keys remain under agent custody per spec §4/§5. Do not grant the
panel site-key access or relax agent sandboxing to share them.

A later trusted hostname/certificate can replace the initial certificate
without making a hosting web server mandatory. HSTS remains omitted until a
separate trusted-TLS policy. Automated panel-certificate renewal/reload and
origin transitions are still pending. Site SSL remains a separate feature under
spec §9.

## 5. Empty-host UX and later provisioning

A clean install shows real state: panel/agent ready; web server, PHP and hosting
database absent; no websites. Never invent versions, healthy services or sample
websites. Preserve existing design language and real-path navigation, with new
software/setup screens designed to the same conventions.

**DESIGN / NOT IMPLEMENTED:** optional package provisioning and Software/Services
management remain separate from the installer. Use a
closed reviewed component/version catalog, OS-specific compatibility checks,
explicit install confirmation and target host selection. Initial managed stack:
Nginx, Apache, supported PHP-FPM versions and MariaDB; version/package-source choices must
be verified rather than assumed from the test host. Not all websites require
PHP or a database: static/reverse-proxy sites must not force unrelated installs.
Container/template dependencies are checked when those features are implemented.
Existing software is detected as unmanaged; detection never implies permission
to take ownership or rewrite its configuration.

Package mutation requires typed agent operations, local policy, fresh sudo,
durable mutation audit and durable jobs with progress, serialization for package
manager locks, timeout/interruption/restart reconciliation and clear partial
failure states. No arbitrary package names, shell commands, repository URLs or
service arguments from the browser. APT/package maintainer scripts run with
privilege; fixed argv is not a sandbox. Only reviewed package sources and
privileged installation boundaries may be supported. Current best-effort agent
JSON logs are not sufficient for these mutation operations.

## 6. Dependency order and acceptance gates

1. The standalone installer contract, port/origin, native TLS, bootstrap/entrance
   and partial-failure boundaries are implemented in `install.sh`.
2. Standalone HTTPS and secure initial setup are implemented; the loopback/SSH
   manual profile remains available.
3. Finish namespace preparation and verify clean-host
   install, authenticated login, agent-backed readiness, rerun refusal, reboot,
   failure handling and supported OS/architecture combinations.
4. Add durable jobs/audit and typed optional component provisioning.
5. Implement real Websites against deliberately installed/managed Nginx/Apache,
   with validate/apply/rollback, then complete remaining MVP work.

The standalone installer is deliberately ahead of Websites. Each advertised
OS/architecture needs its own verified matrix result; development-host success
does not certify all targets. Primary acceptance: on a clean supported VPS
without Nginx/Apache/PHP/MariaDB, install, reboot and access the panel securely
by IP; verify control-plane health, no unintended port/service/firewall/config
changes, and authenticated agent-backed behavior. Those gates remain planned,
not passed.

See [the operating guide](installation.md) for prerequisite checks, exact
placeholder examples, trust custody, SSH retrieval, partial-failure behavior
and verification limits.
