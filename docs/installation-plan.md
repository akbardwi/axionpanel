# Standalone installation and host provisioning plan

Status: approved installer design, NOT IMPLEMENTED. This supplements
[spec.md](spec.md). Native TLS and explicit certificate initialization are now
implemented in the binary (see [native-tls-plan.md](native-tls-plan.md));
`install.sh`, automated onboarding, package jobs and software-management screens
remain unimplemented. Manual loopback systemd templates remain in
[deployment.md](deployment.md); a separate statically validated
[native-HTTPS profile](native-tls-systemd.md) documents fresh-host preparation,
not an installer or live migration.

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
hosting database service. Optional dependencies of installer tooling are not
hosting-stack prerequisites.

- Planned initial address: `https://<server-ip>:8443`; port is configurable.
  Format IPv6 literals with brackets. Installer checks the actual selected port,
  reports available addresses, and does not assume it can infer a public IP
  correctly behind NAT. Operator chooses/overrides the advertised address.
- The panel runs as `axionpanel`; its unprivileged port does not require root.
  The local root agent exposes only a permission-controlled Unix socket.
- Ports 80/443 remain available for managed websites. No mandatory panel vhost
  is created. An operator-configured reverse proxy is optional, not a dependency.
- Stopping or removing a hosting service must not stop panel HTTPS or login.
- The existing public pre-alpha deployment uses Nginx and loopback HTTP. Leave
  it unchanged until native TLS is implemented, verified and explicitly migrated.
  The binary supports manual direct-IP HTTPS; automated installation and live
  migration remain pending.

## 3. Installer contract

The intended entry point is a downloaded, reviewed `install.sh` run with root
privileges. Do not publish a runnable install command or download URL until the
installer and release artifacts exist. The installer owns privileged host setup;
admin bootstrap runs as the non-root panel service user.

1. Validate the supported OS/version/architecture matrix in spec §2, systemd,
   resources, selected port, existing installation and conflicting panels. Keep
   the original refusal to install over another detected control panel. Never
   stop, replace or silently adopt an existing service to free a port.
2. Retrieve matching versioned binaries and verify release signatures using an
   independently trusted verification key. Checksums alone do not authenticate
   downloads. Avoid compiling Go/Vue on the target VPS.
3. Create service users, root-owned binaries, restricted configuration/data paths
   and systemd units. The non-root service must have execute access to its
   binary but no write access to binaries, units or agent policy.
4. Configure native HTTPS and an exact advertised origin, then generate initial
   admin access as the panel user. Preserve original auth requirements: secure
   cookies, CSRF/Origin checks, MFA, sudo, and the optional secret entrance path.
   The entrance path is defense in depth, never a substitute for authentication.
5. Store one-time bootstrap access in an owner-only local file, not systemd
   logs, telemetry, remote callbacks or chat. Display the URL, certificate
   fingerprint and file location to the SSH operator, not secrets in routine logs.
6. Start services and verify HTTPS, panel health, agent peer credentials and login
   readiness before reporting installation success. Do not install hosting-stack
   packages as a side effect.

Preflight lists the required inbound panel port. Do not disable a firewall or
silently open ports; firewall and provider-network changes require explicit
operator consent. Do not expose a local agent listener publicly. Remote agent
mTLS remains a separate authenticated-enrollment design, not an installer shortcut.

Idempotency means re-running detects and preserves an existing installation;
it must not regenerate keys/admin credentials, overwrite configuration or reset
metadata. Distinguish install, repair and upgrade. Verify signatures and
compatibility before upgrade, back up metadata and configuration with restrictive
permissions, and document recovery across schema changes; binary rollback alone
is not database rollback. Uninstall preserves workloads, data and keys by default;
destructive removal is a separate explicitly confirmed operation. Do not promise
transactional OS-package rollback.

## 4. Initial TLS and certificate custody

For initial IP access, generate a self-signed certificate with the selected IP
in its Subject Alternative Name. Print its fingerprint over SSH for independent
verification. Browsers warn until the certificate is trusted; self-signed TLS does
not establish authenticated server identity automatically. Public plaintext HTTP
login is not an installation mode. SSH tunneling remains an alternative.

Panel HTTPS keys are separate from site TLS keys and agent enrollment keys. Plan
`/etc/axionpanel/tls/` as `root:axionpanel` mode `0750`, with private key mode
`0640`, readable by the non-root TLS server but never exposed through API/UI.
Site keys remain under agent custody per spec §4/§5. Do not grant the panel read
access to the site-key tree or relax systemd sandboxing to share those keys.

A later panel hostname/trusted certificate can replace the initial certificate
without making a hosting web server mandatory. Preserve spec §5.2's trusted-only
HSTS rule; certificate trust is not inferred from merely loading a TLS file.
Exact renewal/reload and origin-transition behavior must be designed and tested
before claiming automated panel-certificate management. Site SSL remains a
separate feature under spec §9.

## 5. Empty-host UX and later provisioning

A clean install shows real state: panel/agent ready; web server, PHP and hosting
database absent; no websites. Never invent versions, healthy services or sample
websites. Preserve existing design language and real-path navigation, with new
software/setup screens designed to the same conventions.

Provide Software/Services management before enabling website creation. Use a
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

1. Specify installation, port/origin, native TLS, bootstrap/entrance and recovery.
2. Implement standalone HTTPS and secure initial setup; retain loopback/SSH mode.
3. Build signed release packaging and an installer; verify clean-machine install
   without any hosting stack, rerun safety, failure handling, upgrade and recovery.
4. Add durable jobs/audit and typed optional component provisioning.
5. Implement real Websites against deliberately installed/managed Nginx/Apache, with
   validate/apply/rollback; continue all remaining original MVP features.

Installer work moves ahead of Websites; final integrated release acceptance stays
at M13. Each advertised OS/architecture needs its own verified matrix result;
Ubuntu development-host success is not evidence for Debian or all architectures.
Primary acceptance: on a clean supported VPS without Nginx/Apache/PHP/MariaDB,
install, reboot and access the panel securely by IP. Verify control-plane health
also when hosting services are absent/stopped, and verify no unintended port,
service, firewall or configuration changes. These gates are planned, not passed.
