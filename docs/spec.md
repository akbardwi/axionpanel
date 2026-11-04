# AxionPanel technical specification

Status: draft v0.2, expanded MVP (Phase 1). Last updated 2026-11-02.

**Implementation boundary:** this is a design contract, not a feature inventory.
The repository currently has Go entrypoints (panel health endpoint, agent stub),
a SQLite store, the initial migration and store tests. Authentication,
provisioning and the management features below are not wired into a working
backend. All newly added contracts are **DESIGN / NOT IMPLEMENTED**, including
remote enrollment/mTLS, containers/Compose, Git deploy, curated templates,
backup/restore, Fail2ban monitoring and SSH public-key management. The initial
migration is unchanged; proposed schema additions are listed separately in §8.
Static UI references and prototypes do not demonstrate working infrastructure.

This document is the contract between the panel, the agent, and the web UI.
Change it in the same pull request as the code that changes the behavior.

## 1. Scope

The MVP lets one administrator manage a local VPS and multiple enrolled hosts
from one central web UI and one SQLite metadata database:

- websites: Nginx with PHP-FPM, static sites, or reverse proxy
- Let's Encrypt and custom SSL certificates
- MariaDB/MySQL databases and database users
- file manager with upload, download, edit, archive and extract
- cron jobs, nftables firewall rules, SSH settings, system services
- web terminal, log viewer, live resource stats
- Docker container lifecycle, logs, stats, managed volumes/networks and Compose
  stacks (**DESIGN / NOT IMPLEMENTED**, §9.9)
- Git deployment with manual and authenticated webhook triggers, builds, release
  history, health checks and rollback (**DESIGN / NOT IMPLEMENTED**, §9.10)
- curated, versioned one-click application templates, not a public marketplace
  (**DESIGN / NOT IMPLEMENTED**, §9.11)
- multi-node inventory, grouping, host selection, capabilities, enrollment and
  revocation over mTLS (**DESIGN / NOT IMPLEMENTED**, §6.4)
- encrypted local and S3-compatible scheduled/manual backup and scoped restore
  (**DESIGN / NOT IMPLEMENTED**, §9.12)
- Fail2ban monitoring and SSH public-key management
  (**DESIGN / NOT IMPLEMENTED**, §9.13)

Not in the MVP: multiple panel users/resellers, mail, DNS server, FTP, a public
app marketplace, Apache/OpenLiteSpeed, RHEL-family distros, distributed workload
scheduling, Kubernetes/Swarm orchestration, live workload migration, distributed
storage, Raft consensus, quorum-based leadership or control-plane HA.
“Cluster” means managed-host grouping, not a distributed scheduler: deployments
explicitly target one host and Compose runs on that host only. No automatic
cross-host failover or replication is promised.

Foundations required by this MVP:

- host-owned resources carry `server_id`; user-owned resources also carry
  `owner_user_id` (shared metadata/join tables derive scope from their parent)
- every authorization decision goes through one policy layer, even while the
  only role is `admin`
- the agent client uses the same closed operation API over a local Unix socket
  or remote mutually authenticated TLS; remote hosts have no metadata DB replica
- capabilities are detected per host; unavailable features show a reason, not
  fabricated healthy telemetry

UI provenance and screen mapping belong in `docs/design/README.md`. Supplied
references under `docs/design/reference/` guide layout, not implementation
claims. Their Raft/leader/mesh, full-host snapshots, UFW, wildcard DNS-01 and
sample service/version labels do not override this specification. Missing
screens can be designed directly; all mock data/actions must be marked as such.

## 2. Supported platforms (MVP)

- Ubuntu 24.04 LTS and 26.04 LTS, Debian 12 and 13
- amd64 and arm64
- systemd is required; Linux 5.6+ is required for `openat2` (all targets ship
  newer kernels)
- a fresh server is recommended; the installer refuses to run when another
  control panel is detected (`/www/server/panel`, `/usr/local/cpanel`,
  `/usr/local/CyberCP`, `/usr/local/hestia`)
- minimum 1 vCPU and 512 MB RAM. Design target: panel and agent together stay
  under 60 MB RSS at idle. This is a target to measure, not a measured number.
  Docker workloads, Git builds and backup staging need additional capacity;
  preflight checks must report host-specific RAM, disk and runtime constraints.

## 3. Architecture

```
browser --HTTPS--> axionpanel (user: axionpanel)
                     |-- SQLite: /var/lib/axionpanel/panel.db
                     |-- HTTP over Unix socket --> local agent (root)
                     '-- HTTPS/mTLS --> enrolled remote agents (root)
                                         |-- nginx, php-fpm, mariadb
                                         |-- nftables, cron, sshd, Fail2ban
                                         |-- local Docker/Compose, build worker
                                         '-- ACME, PTYs, backup/restore worker
```

The panel handles authentication, sessions, authorization, first-pass
validation, persistence, job tracking, the SPA, WebSocket fan-out and the
audit log.

The agent executes a closed set of operations, validates every request again
(it never trusts the panel), renders and applies configuration with rollback,
reports metrics, and owns site TLS private keys. Each host's agent accesses
only its local Docker socket; neither the panel nor the browser receives that
socket or an unrestricted Docker API proxy. Agents perform local data-plane
work; the central panel stores metadata and coordinates explicitly host-targeted
jobs. Host grouping is metadata only, without election or consensus.

**DESIGN / NOT IMPLEMENTED:** isolated unprivileged build workers and scoped
backup workers run on the target host under agent supervision, not as commands
inside the root agent. Local and remote agents share capability checks and
policy enforcement. SQLite remains central for this single-admin, multi-host
MVP; PostgreSQL is an optional future metadata backend, not a prerequisite for
remote hosts and not a claim of HA.

The panel never runs privileged commands, never holds the database root
credentials, and never reads site TLS private keys. Everything privileged goes
through the agent.

### systemd units

- `axionpanel.service`: `User=axionpanel`, `NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `ReadWritePaths=/var/lib/axionpanel /var/log/axionpanel`
- `axionpanel-agent.service`: runs as root, `RuntimeDirectory=axionpanel`,
  `RuntimeDirectoryMode=0750`, `Group=axionpanel`, with
  `--allow-uid axionpanel --socket-gid axionpanel`. The agent accepts this
  root:axionpanel directory as-is and never chmods an existing directory.

## 4. Filesystem layout

| Path | Owner, mode | Purpose |
|---|---|---|
| `/usr/local/axionpanel/bin/` | root 0755 | `axionpanel`, `axionpanel-agent` |
| `/etc/axionpanel/panel.toml` | root:axionpanel 0640 | listen address, TLS, paths |
| `/etc/axionpanel/agent.toml` | root 0600 | agent policy the panel cannot change |
| `/etc/axionpanel/secret.key` | axionpanel 0600 | AES-256-GCM key for `*_enc` columns |
| `/etc/axionpanel/ssl/<cert_id>/` | root 0700 | certificates and private keys |
| `/etc/axionpanel/acme/` | root 0700 | ACME account keys |
| `/var/lib/axionpanel/panel.db` | axionpanel 0600 | panel database (+ `-wal`, `-shm`) |
| `/var/lib/axionpanel/backups/` | axionpanel 0700 | encrypted panel metadata backups; raw DB staging restricted and temporary |
| `/var/lib/axionpanel/acme-challenge/` | root 0755 | HTTP-01 challenge files |
| `/var/log/axionpanel/` | root 0750 | panel, agent, agent audit, cron, site logs |
| `/run/axionpanel/agent.sock` | root:axionpanel 0660 | agent socket (dir 0750) |
| `/etc/nginx/axionpanel/` | root 0755 | generated vhosts and snippets |
| `/etc/php/<ver>/fpm/pool.d/axion-<user>.conf` | root 0644 | per-site PHP-FPM pool |
| `/etc/cron.d/axionpanel` | root 0644 | generated cron table |
| `/var/www/<domain>/` | see 9.3 | site home: `public/`, `tmp/` |
| `/etc/axionpanel/pki/` | root 0700 on agent; panel service identity in restricted panel-owned store | DESIGN / NOT IMPLEMENTED: mTLS keys, CA trust, identities; no browser access |
| `/etc/axionpanel/backup-keys/` | root 0700, key files 0600 | DESIGN / NOT IMPLEMENTED: host backup wrapping keys, independent of `secret.key` |
| `/var/lib/axionpanel-agent/jobs/` | root 0700 | DESIGN / NOT IMPLEMENTED: durable operation journal and checkpoints |
| `/var/lib/axionpanel-agent/backups/` | root 0700 | DESIGN / NOT IMPLEMENTED: encrypted local archives and restricted transient staging |
| `/var/lib/axionpanel-agent/apps/` | root metadata; isolated worker-owned workspaces | DESIGN / NOT IMPLEMENTED: managed Compose specs, releases, builds; no arbitrary path access |

## 5. Security model

### 5.1 Authentication

- Passwords are hashed with argon2id. Parameters follow the current OWASP
  recommendation and are stored in the hash string so they can be raised later.
- TOTP 2FA (RFC 6238) with 10 single-use recovery codes, stored hashed.
  Enrolled accounts never receive a password-only session: login starts a
  short-lived challenge that must be completed with a code or recovery code.
- Secret entrance path: the installer generates a random 12-character path.
  Visiting it sets an entrance cookie. Unauthenticated requests without that
  cookie get `404`, so scanners cannot fingerprint the panel.
- Login rate limits: 5 failures per username per 15 minutes locks the account
  with backoff; 20 failures per IP per 15 minutes blocks the IP. The IP bucket
  keys on the TCP peer address; behind a reverse proxy or NAT every client
  shares one address, so a single noisy client can exhaust the shared budget.
  A trusted-proxy configuration that honours `X-Forwarded-For` is a later
  prerequisite — do not place the panel behind a proxy until it exists.
- Sessions: 32 random bytes in cookie `axp_session` (`HttpOnly`, `Secure`,
  `SameSite=Strict`). The database stores only the SHA-256 hash. Idle timeout
  2 hours, absolute 24 hours, both configurable.
- CSRF: state-changing requests must send `X-CSRF-Token` matching the session
  token, and the `Origin` header must match the panel origin. The token is
  mirrored to the UI in a readable `axp_csrf` cookie (double-submit); session
  and challenge cookies remain `HttpOnly`.
- Sudo mode: the terminal, root-scope file access, firewall, SSH settings and
  security settings require re-authentication (password + TOTP) within the
  last 10 minutes. **DESIGN / NOT IMPLEMENTED:** enrollment/revocation,
  SSH-key mutation, container/Compose mutation, deploy/template launch, backup
  target/key changes, archive deletion and restore also require sudo mode;
  explicit destructive confirmations are additional, not replaced by sudo.
- Optional IP allowlist for the whole panel.

### 5.2 Transport

HTTPS only. The installer creates a self-signed certificate and prints its
fingerprint; the admin can switch to a Let's Encrypt certificate for the panel
hostname. HSTS is sent only with a trusted certificate. Every response carries
`Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin`.
WebSocket upgrades require a valid session and a matching `Origin`.

### 5.3 Agent hardening

- Local Unix transport reads the peer UID with `SO_PEERCRED` and rejects
  anything that is not the `axionpanel` user. Remote transport instead requires
  verified mTLS and a non-revoked enrollment identity (§6.4); actor headers are
  audit context, never transport credentials.
- Operations come from a fixed registry. There is no generic "exec" operation.
- Parameters are decoded with unknown fields rejected, validated, and passed to
  programs as argv. Control-plane wrappers never interpolate shell strings,
  clear the environment for child processes, and apply operation timeouts.
  Explicit admin cron commands, PTYs and Git build scripts can execute arbitrary
  code by their nature; these are separate execution boundaries, not generic
  root RPCs. Build code must never execute with agent/root privileges (§9.10).
- File operations run in a child process with the site user's UID/GID and open
  paths with `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)`, so the kernel
  blocks `..` and symlink escapes. The agent derives the scope root from the
  system user's home directory; it never accepts a root path from the panel.
- `agent.toml` holds policy the panel cannot change: `allow_root_terminal`,
  `allow_root_files`, `allowed_services`. **DESIGN / NOT IMPLEMENTED:** add
  permitted managed users, container mount roots/security restrictions, build
  limits and explicit network target allowlists for Git, registries and S3.
  Panel requests cannot relax these host-local policies.
- The agent writes its own append-only audit log, separate from the panel DB.
- Each subsystem (nginx, each PHP-FPM version, cron file, firewall) has its own
  lock, so concurrent operations cannot interleave config writes.
- **DESIGN / NOT IMPLEMENTED:** locks also cover each managed stack/release,
  backup source and restore target, with deterministic lock ordering. Restores
  cannot race deployments or backup reads of the same resource.

The separation has limits. If the panel is compromised, the attacker gets
every operation the agent allows. With `allow_root_terminal = true`, that
includes root, which is why the terminal sits behind sudo mode and the flag
lives in a file the panel cannot write.

### 5.4 Secrets at rest

Columns ending in `_enc` hold AES-256-GCM ciphertext encoded as
`v1:` + base64(nonce || ciphertext), using `secret.key`. The agent reaches
MariaDB as root through `unix_socket` authentication, so no database root
password is stored anywhere.

**DESIGN / NOT IMPLEMENTED:** deployment secrets and Git/S3 credentials are
write-only API inputs encrypted at rest; UI/API responses expose only references,
names and redacted metadata. Jobs and logs must not persist raw tokens, private
keys, URLs containing credentials, secret environment values or plaintext backup
keys. Deliver needed credentials only to the authorized host for the operation;
remove transient files afterward. mTLS identity keys and backup wrapping keys
have separate custody and rotation rules (§6.4, §9.12).

### 5.5 Input validation

One package, `internal/validate`, is used by both binaries.

- Domain: lowercased, IDN converted to punycode, labels of 1-63 characters
  from `[a-z0-9-]` that do not start or end with `-`, total length up to 253,
  at least two labels. No wildcards in the MVP (they need DNS-01). The panel
  hostname and `localhost` are rejected.
- System user: `^[a-z][a-z0-9_]{0,31}$`.
- Database name and database user: `^[a-z0-9_]{1,32}$`.
- PHP version: must be in the agent's detected list.
- Paths: relative to the scope root, cleaned. Absolute paths only in root scope.
- Ports: 1-65535. Addresses and CIDRs are parsed with `net/netip`.
- Cron: 5-field schedules parsed with the standard parser. Commands must not
  contain newlines, which would inject extra cron lines. The agent escapes `%`,
  which cron treats as a newline.
- Custom Nginx directives: allowed for admins only. They are checked by
  `nginx -t` but can still change behavior, so they must stay admin-only when
  multi-user arrives.

### 5.6 Outbound targets and SSRF (DESIGN / NOT IMPLEMENTED)

Git repositories, submodules/LFS, registries, template downloads, build egress
and S3-compatible endpoints are not arbitrary server-side fetch URLs. Validate
scheme, hostname, port, resolved IPs and destination against explicit agent-local
allowlists at configuration time and every connection/retry. Deny loopback,
link-local/cloud metadata, multicast and private networks by default; a private
Git/S3 service needs a narrow operator-configured host/port/CIDR exception, never
a blanket bypass. Block redirects unless the new destination passes the same
policy; pin/verify the checked destination on connect to prevent DNS rebinding.
Disallow Git `file://`, local paths, `ext::` and arbitrary remote helpers. Support
HTTPS and explicitly allowed SSH (pinned host key, no accept-new in automation);
S3 uses HTTPS with certificate verification and bucket/prefix-scoped credentials.
Do not leak credentials on redirects, error messages or cross-origin requests.
Application egress is separate; build isolation must enforce its own egress
policy rather than assuming URL validation contains untrusted build scripts.

## 6. Panel-agent protocol

HTTP/1.1 over `/run/axionpanel/agent.sock`, JSON bodies. Every request sends
`Axion-Protocol: 1`, `Axion-Request-ID`, and `Axion-Actor` (the panel user ID,
for the agent audit log). A protocol mismatch returns `protocol_mismatch`.
**DESIGN / NOT IMPLEMENTED:** remote agents serve this same API over TCP with
mTLS in the MVP, bound to an operator-approved interface and restricted to panel
network addresses. Never publish an unauthenticated agent listener.

### 6.1 Endpoints

Implemented so far: `GET /v1/info` and `POST /v1/ops/{name}`, with the
read-only operations `system.info`, `system.stats`, `system.metrics` and `capabilities.refresh`
(see `docs/agent.md`). Every other row below is design, not a running endpoint;
the agent catalog reports the actual registrations.

| Method and path | Purpose |
|---|---|
| `GET /v1/info` | version, protocol, OS, arch, kernel, per-host capabilities and reasons: PHP/DB, firewall, Docker/Compose, build sandbox, backup/dump tools, Fail2ban, SSH; capability revision and observation time |
| `POST /v1/ops/{name}` | run an operation; body `{"params": {...}}` |
| `GET /v1/jobs/{id}` | job status, progress, result, error |
| `GET /v1/jobs/{id}/events` | NDJSON stream of `log`, `progress`, `done` events |
| `GET /v1/stats/stream` | NDJSON metrics every 2 seconds |
| `GET /v1/terminal?user=` | WebSocket; binary frames carry PTY data, text frames carry `{"type":"resize","cols":N,"rows":N}` |

Synchronous operations return `200 {"result": {...}}`. Asynchronous
operations return `202 {"job_id": "<ULID>"}`.

Errors use `{"error": {"code": "...", "message": "...", "details": {}}}`:

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_params` | 400 | validation failed; `details` names the fields |
| `protocol_mismatch` | 400 | panel and agent protocol versions differ |
| `forbidden_by_policy` | 403 | blocked by `agent.toml` |
| `not_found` | 404 | resource does not exist on the host |
| `conflict` | 409 | exists with different properties, or subsystem busy |
| `preexisting_config_error` | 422 | `nginx -t` failed before this change; nothing was written |
| `config_test_failed` | 422 | the change failed its test and was rolled back; `details.output` has tool output |
| `unsupported` | 501 | not available on this OS or configuration |
| `internal` | 500 | unexpected failure |

### 6.2 Operation design

Configuration mutations are desired-state: the panel sends the full intended
state and the agent converges to it. `site.apply` covers create, update and
suspend. Not every mutation is safe to replay: builds, database dumps, restore,
key rotation and destructive actions require explicit idempotency and durable
result lookup, not blind retry (§9.8).

**DESIGN / NOT IMPLEMENTED:** requests include a stable operation/job ID and
idempotency key bound to host, actor, operation and parameter digest. Duplicate
keys return the existing job/result; a different digest is a conflict. Agents
check current capabilities and local policy when executing, even if the panel's
capability cache previously allowed the operation.

### 6.3 Operation catalog (MVP)

| Operation | Mode | Notes |
|---|---|---|
| `system.info`, `system.stats`, `system.metrics` | sync | |
| `service.list`, `service.action` | sync | `start|stop|restart|reload`, names limited to `allowed_services` |
| `site.apply` | async | system user, dirs, PHP-FPM pool, vhost, SSL binding, suspension |
| `site.remove` | async | optional file removal |
| `php.versions` | sync | installed and installable versions |
| `php.install` | async | from the configured package source |
| `ssl.issue`, `ssl.renew` | async | ACME HTTP-01 |
| `ssl.import` | sync | checks that the key matches the certificate |
| `ssl.remove` | sync | |
| `db.list`, `db.size` | sync | used for import and reconciliation |
| `db.create`, `db.drop` | sync | |
| `db.user_create`, `db.user_password`, `db.user_drop` | sync | |
| `db.grant`, `db.revoke` | sync | |
| `fs.list`, `fs.stat`, `fs.read`, `fs.write` | sync | `fs.read` and `fs.write` are capped at 5 MB |
| `fs.mkdir`, `fs.rename`, `fs.copy`, `fs.delete`, `fs.chmod` | sync | |
| `fs.chown` | sync | root scope only |
| `fs.archive`, `fs.extract` | async | |
| `fs.upload`, `fs.download` | stream | chunked |
| `cron.apply` | sync | full desired list rendered to `/etc/cron.d/axionpanel` |
| `firewall.apply`, `firewall.confirm` | sync | see 9.6 |
| `ssh.get`, `ssh.apply`, `ssh.confirm` | sync | see 9.7 |
| `log.tail` | sync | at most 1000 lines |
| `log.follow` | stream | |

Added catalog entries below are **DESIGN / NOT IMPLEMENTED**. Names define
bounded operations, not a pass-through Docker API or arbitrary shell executor.

| Operation | Mode | Notes |
|---|---|---|
| `capabilities.refresh` | sync | re-detect tools, versions, policy and unsupported reasons on this host |
| `container.list`, `container.inspect`, `container.stats` | sync | redacted managed resource inventory |
| `container.apply`, `container.action`, `container.remove` | async | validated spec; start/stop/restart only; deletion confirmation |
| `container.logs` | stream | bounded, redacted; no unrestricted container exec RPC |
| `volume.list`, `network.list` | sync | local managed resources only |
| `volume.apply`, `volume.remove`, `network.apply`, `network.remove` | async | deletion checks references and explicit data-loss confirmation |
| `compose.plan` | sync | validate/render normalized spec and affected resources without mutation |
| `compose.apply`, `compose.remove` | async | per-stack lock; preserve volumes by default |
| `deploy.validate` | sync | repository/ref/build mode and host preflight; no code execution |
| `deploy.run`, `deploy.rollback` | async | pinned commit/release, isolated build, health gate; §9.10 |
| `template.validate` | sync | catalog version, input schema and host capability check |
| `template.install` | async | expand approved manifest into managed resources; §9.11 |
| `backup.target_test` | async | allowlisted local/S3 target access; minimal safe test object |
| `backup.create`, `backup.verify`, `backup.remove` | async | immutable archive ID, manifest, retention safety; central panel metadata uses restricted local store capture/handoff (§9.12) |
| `restore.plan` | async | inspect archive, keys, compatibility, space and target conflicts; no writes |
| `restore.run` | async | execute expiring confirmed plan, scoped targets only |
| `fail2ban.status`, `fail2ban.jails`, `fail2ban.bans` | sync | read-only monitoring, no generic jail configuration/unban RPC |
| `ssh.keys_list`, `ssh.keys_apply` | sync | validated public keys for policy-allowed managed users; sudo mutation |
| `identity.rotate`, `identity.revoke` | sync | authenticated rotation or host-side revocation acknowledgement; §6.4 |

Every `fs.*` operation takes a scope: `{"system_user": "..."}` or
`{"root": true}`. Root scope requires `allow_root_files`.

### 6.4 Remote host lifecycle (DESIGN / NOT IMPLEMENTED)

1. An admin in sudo mode creates a host enrollment with approved endpoint/network
   and a short expiry (default 15 minutes, maximum 1 hour). Generate at least
   32 random bytes; show the token once and store only its SHA-256 hash, expiry,
   intended host identity and consumption/revocation timestamps. Do not put it
   in URLs, process arguments, command history or logs.
2. The operator installs the agent on the host and securely supplies the token
   plus the panel CA fingerprint out of band. Agent generates its private key
   locally and sends a CSR to the dedicated HTTPS bootstrap endpoint after
   verifying the pinned panel identity. This endpoint is the sole token-auth
   exception; it cannot run agent operations or act as a public token API.
3. The panel atomically consumes the unused, unexpired token and binds the CSR
   to the intended host. Failed validation must not issue an identity. Issue a
   short-lived host certificate with a server ID identity and required EKUs;
   the panel uses its own client identity. Private keys never cross the network.
   Pin host identity as well as the CA; a valid certificate for another host or
   panel is insufficient. Renewal uses authenticated mTLS and checks revocation.
4. Panel connects only to the approved endpoint, verifies certificate identity,
   protocol and capabilities, then marks the host online. Heartbeats record
   `last_seen_at`; stale telemetry is offline/stale, not zero usage. Refresh
   capabilities after upgrades, reconnect and before dependent jobs.
5. Offboarding first disables dispatch and new renewals, revokes enrollment
   tokens and host certificate identity/serial, disconnects active streams,
   cancels queued jobs and records running work for reconciliation. Revoke the
   panel's host-specific access at the agent when reachable; for an offline
   host, central revocation is immediate but remote cleanup is explicitly
   pending until an operator removes local trust/agent access or reconnects.
   Agents enforce a local revocation/trust policy and short certificate expiry;
   an offline host must not be reported as remotely wiped. Disconnect alone
   does not destroy workloads, volumes or backups. Destructive cleanup is a
   separate confirmed action; retain host tombstone, jobs and audit history.
6. Rotate certificates/CA with bounded overlap, explicit trusted identities and
   audited revocation. Bootstrap CA private material is encrypted/restricted on
   the central host, not in the ordinary metadata DB; a lost panel requires
   documented trust recovery or re-enrollment, not trust-on-first-use.

An agent accepts operations only from its enrolled panel identity; a host
certificate cannot impersonate a panel. Group labels and topology views show
panel-to-host connectivity only: there are no leader/worker elections, quorum,
Raft terms, cross-host overlay or scheduler implied by this protocol.

## 7. REST API

Base path `/api/v1`, JSON. Browsers authenticate with the session cookie.
Public bearer API tokens remain outside the MVP; the
initial table is reserved for a later phase. Enrollment/bootstrap tokens are a
separate, narrow mechanism (§6.4), not reusable public API credentials.

**DESIGN / NOT IMPLEMENTED:** all added endpoints below are design contracts.
For existing host-local collection/system endpoints, `server_id` is required
in multi-host context (query for reads/streams, body for mutations); omission
may select local row 1 only in an explicitly single-host UI context. Resource-ID
endpoints derive host/owner from stored metadata and reject a conflicting
`server_id`. Never accept raw agent URLs from ordinary operation requests.
Host selection is checked against enrolled/non-revoked state, capabilities and
policy; no silent fallback to another host. Group views are aggregate reads,
not implicit fan-out mutations. Async responses identify the target host.

Conventions:

- lists: `{"data": [...], "meta": {"page": 1, "per_page": 50, "total": 123}}`
- errors: `{"error": {"code": "...", "message": "...", "fields": {"name": "..."}}}`
- async: `202 {"job": {"id": "<ULID>", "status": "queued"}}`
- timestamps: RFC 3339 UTC. IDs are integers, except jobs (ULID).
- `[sudo]` marks endpoints that require sudo mode.

### Auth

| Endpoint | Notes |
|---|---|
| `POST /auth/login` | `{username, password}` → `{mfa_required}` |
| `POST /auth/login/mfa` | `{code}` or `{recovery_code}` |
| `POST /auth/logout` | |
| `GET /auth/me` | |
| `POST /auth/reauth` | `{password, code}` → sudo mode for 10 minutes |
| `POST /auth/password` | `{current, new}` |
| `POST /auth/mfa/setup` | → `{secret, otpauth_url}` |
| `POST /auth/mfa/enable` | `{code}` → `{recovery_codes}` |
| `POST /auth/mfa/disable` | [sudo] |
| `GET /auth/sessions`, `DELETE /auth/sessions/{id}` | |

Implemented in this revision: `POST /auth/login`, `POST /auth/login/mfa`,
`POST /auth/logout`, `GET /auth/me`, `POST /auth/reauth`,
`POST /auth/mfa/setup`, `POST /auth/mfa/enable` and `POST /auth/mfa/disable`,
with argon2id password hashing, failed-login lockout, per-IP and per-username
throttles, idle/absolute session expiry, hashed session and challenge storage,
CSRF/Origin enforcement, TOTP replay blocking and hashed single-use recovery
codes. Auth also stores encrypted pending TOTP secrets (§5.4). The remaining
Auth rows (password change, session listing/revocation) stay
**DESIGN / NOT IMPLEMENTED**, as does the secret entrance path.

### System

| Endpoint | Notes |
|---|---|
| `GET /system/info`, `GET /system/stats` | |
| `GET /system/agent` | agent connection probe: `{connected, reason}` |
| `WS /ws/stats` | live metrics |
| `GET /services` | |
| `POST /services/{name}/{action}` | |

Implemented in this revision: `GET /system/info`, `GET /system/stats`,
`GET /system/metrics` and `GET /system/agent`, local host only. They require a
valid session (safe GETs, no CSRF token), proxy the agent's read-only
`GET /v1/info`, `POST /v1/ops/system.stats` and `POST /v1/ops/system.metrics`
over the Unix socket named by the panel flag
`-agent-socket` (default `/run/axionpanel/agent.sock`), and send
`Axion-Actor` from the validated session's user ID, never from the browser.
Responses are `Cache-Control: no-store`. An unreachable agent or a protocol,
oversize (1 MiB) or malformed response yields `503 agent_unavailable`; agent
4xx/501 codes pass through, agent 5xx collapse to `502 agent_error` with no
internal detail; `GET /system/agent` answers `200 {connected:false}` instead.
The Overview screen renders these values in its header and four resource cards
(refresh every 5 s; no history is fabricated). `WS /ws/stats`, services and
multi-host selection stay **DESIGN / NOT IMPLEMENTED**.

### Sites and PHP

| Endpoint | Notes |
|---|---|
| `GET /sites`, `POST /sites` | create is async |
| `GET /sites/{id}`, `PATCH /sites/{id}` | update is async |
| `DELETE /sites/{id}?delete_files=true` | async |
| `POST /sites/{id}/suspend`, `POST /sites/{id}/unsuspend` | async |
| `POST /sites/{id}/domains`, `DELETE /sites/{id}/domains/{domain_id}` | async |
| `GET /sites/{id}/logs/{access|error}?lines=200` | |
| `GET /php/versions`, `POST /php/versions` | install is async |

### SSL

| Endpoint | Notes |
|---|---|
| `GET /ssl` | all certificates with expiry |
| `POST /sites/{id}/ssl/letsencrypt` | async |
| `PUT /sites/{id}/ssl/custom` | `{cert_pem, key_pem}` |
| `DELETE /sites/{id}/ssl` | |

### Databases

| Endpoint | Notes |
|---|---|
| `GET /databases`, `POST /databases` | create may include a new user |
| `DELETE /databases/{id}` | |
| `GET /database-users`, `POST /database-users` | |
| `POST /database-users/{id}/password`, `DELETE /database-users/{id}` | |
| `PUT /databases/{id}/grants/{user_id}`, `DELETE /databases/{id}/grants/{user_id}` | |

### Files

Scope is `?site_id=` or `?scope=root` [sudo].

| Endpoint | Notes |
|---|---|
| `GET /files?path=` | directory listing |
| `GET /files/content?path=`, `PUT /files/content` | text editor |
| `POST /files/upload` | chunked multipart with `upload_id` |
| `GET /files/download?path=` | |
| `POST /files/{mkdir|rename|copy|delete|chmod|chown|compress|extract}` | `chown` is root scope only; compress and extract are async |

### Cron, firewall, SSH, terminal

| Endpoint | Notes |
|---|---|
| `GET /cron`, `POST /cron`, `PATCH /cron/{id}`, `DELETE /cron/{id}` | |
| `POST /cron/{id}/run`, `GET /cron/{id}/log` | run is async |
| `GET /firewall`, `POST /firewall/rules`, `DELETE /firewall/rules/{id}` | [sudo] |
| `POST /firewall/confirm` | [sudo] |
| `GET /ssh`, `PUT /ssh`, `POST /ssh/confirm` | [sudo] |
| `WS /ws/terminal` | [sudo] |

### Multi-node inventory (DESIGN / NOT IMPLEMENTED)

| Endpoint | Notes |
|---|---|
| `GET /servers`, `GET /servers/{id}` | inventory, heartbeat freshness, grouping and connectivity |
| `PATCH /servers/{id}` | [sudo] name/group labels; endpoint change requires identity verification |
| `GET /servers/{id}/capabilities`, `POST /servers/{id}/capabilities/refresh` | detected versions, support reasons; refresh [sudo] |
| `POST /server-enrollments`, `DELETE /server-enrollments/{id}` | [sudo] expiring single-use token issuance/revocation |
| `POST /bootstrap/enroll` | pinned HTTPS token + CSR only; rate limited, no session/CSRF; §6.4 |
| `POST /servers/{id}/identity/rotate` | [sudo] authenticated certificate rotation |
| `POST /servers/{id}/revoke` | [sudo] offboard/revoke with confirmation; retain metadata tombstone |

### Containers, Compose, deploy and templates (DESIGN / NOT IMPLEMENTED)

| Endpoint | Notes |
|---|---|
| `GET /containers`, `GET /containers/{id}`, `GET /containers/{id}/stats` | host-scoped, redacted inspection |
| `POST /containers`, `PATCH /containers/{id}` | [sudo] validated managed spec, async |
| `POST /containers/{id}/{start|stop|restart}`, `DELETE /containers/{id}` | [sudo] async; remove needs confirmation, volumes retained |
| `GET /containers/{id}/logs`, `WS /ws/containers/{id}/logs` | bounded streams; not a Docker socket proxy |
| `GET /volumes`, `GET /networks` | managed host-local inventory |
| `POST /volumes`, `POST /networks`, `DELETE /volumes/{id}`, `DELETE /networks/{id}` | [sudo] async; references checked; data loss separately confirmed |
| `GET /stacks`, `GET /stacks/{id}`, `POST /stacks/plan` | Compose manifest validation and diff |
| `POST /stacks`, `PUT /stacks/{id}`, `DELETE /stacks/{id}` | [sudo] async; delete preserves volumes unless separately confirmed |
| `GET /deployments`, `POST /deployments`, `PATCH /deployments/{id}` | Git source/ref and approved build mode; writes [sudo] |
| `POST /deployments/{id}/run`, `POST /deployments/{id}/rollback` | [sudo] async, pinned commit or release ID |
| `GET /deployments/{id}/releases`, `GET /deployments/{id}/builds` | immutable commit/image metadata; logs via jobs |
| `PUT /deployments/{id}/secrets/{name}`, `DELETE /deployments/{id}/secrets/{name}` | [sudo] write-only secret, no readback |
| `POST /deployments/{id}/webhook` | provider-authenticated signed event, not browser CSRF; rate/replay limits; §9.10 |
| `GET /templates`, `GET /templates/{id}/versions/{version}` | curated catalog, requirements, inputs and persistence/backup notes |
| `POST /applications`, `GET /applications`, `GET /applications/{id}` | [sudo] install versioned template on explicit host; install async |

### Backup and restore (DESIGN / NOT IMPLEMENTED)

| Endpoint | Notes |
|---|---|
| `GET /backup-targets`, `POST /backup-targets`, `PATCH /backup-targets/{id}` | writes [sudo]; local/S3 config, encrypted write-only credentials |
| `POST /backup-targets/{id}/test` | [sudo] async, network policy enforced |
| `GET /backup-plans`, `POST /backup-plans`, `PATCH /backup-plans/{id}`, `DELETE /backup-plans/{id}` | writes [sudo]; source IDs, target, schedule, retention and consistency mode |
| `POST /backup-plans/{id}/run`, `GET /backups`, `GET /backups/{id}` | manual run [sudo], async; show consistency/verification/remote status separately |
| `POST /backups/{id}/verify`, `DELETE /backups/{id}` | [sudo] async; retention/key safety; delete confirmation |
| `POST /backups/{id}/restore-plan` | [sudo] async; workload targets/conflict policy only, no mutation; panel metadata recovery is offline (§9.12) |
| `POST /restore-plans/{id}/confirm` | [sudo] issue short-lived single-use confirmation bound to plan digest |
| `POST /restore-plans/{id}/run` | [sudo] async; consume confirmation, recheck target state |

### SSH keys and Fail2ban (DESIGN / NOT IMPLEMENTED)

| Endpoint | Notes |
|---|---|
| `GET /ssh/keys?system_user_id=` | public-key fingerprint, type, label and managed state; explicit host scope |
| `POST /ssh/keys`, `DELETE /ssh/keys/{id}` | [sudo] managed public keys only; lockout warning/confirmation |
| `GET /fail2ban/status`, `GET /fail2ban/jails`, `GET /fail2ban/bans` | read-only detected state; unavailable/stale reason if missing/offline |

### Jobs, audit, settings

| Endpoint | Notes |
|---|---|
| `GET /jobs`, `GET /jobs/{id}`, `WS /ws/jobs/{id}` | |
| `GET /audit?user_id=&action=&from=&to=` | |
| `GET /settings`, `PATCH /settings` | `security.*` keys need [sudo] |

## 8. Data model

The source of truth for the implemented schema is
`internal/store/migrations/*.sql`, applied with goose.
`internal/store/store_test.go` applies the migrations with the production
driver and checks their implemented constraints, not the entire feature contract.
The following table describes the **existing initial schema only**. Existing
schema support is not evidence that a backend feature is wired or functional.

| Table | Purpose |
|---|---|
| `packages` | quotas for future plans (Phase 3); NULL means unlimited |
| `users` | panel accounts; role, parent (reseller), package, 2FA, lockout |
| `user_recovery_codes` | hashed single-use 2FA recovery codes |
| `sessions` | hashed session and CSRF tokens, MFA and sudo state |
| `api_tokens` | reserved hashed public API tokens with scopes/IP allowlist (future, not enrollment tokens) |
| `servers` | managed hosts; row 1 is local; current fields do not yet cover enrollment/revocation/grouping |
| `system_users` | Linux users created for sites |
| `ssl_certificates` | certificate metadata; files live under `/etc/axionpanel/ssl` |
| `sites` | websites: kind, root, PHP version or proxy target, status |
| `site_domains` | domains per site, globally unique, one primary per site |
| `databases`, `database_users`, `database_grants` | database metadata |
| `cron_jobs` | scheduled commands; NULL system user means root (admin only) |
| `firewall_rules` | desired firewall rules; `is_system` rules cannot be deleted |
| `jobs` | async job tracking (ULID ids) |
| `audit_log` | append-only record of who did what |
| `settings` | runtime settings as JSON values |

Conventions:

- `STRICT` tables
- timestamps are TEXT in UTC ISO-8601 (`2026-11-02T13:00:00Z`)
- booleans are INTEGER 0/1 with CHECK constraints
- JSON columns are TEXT checked with `json_valid()`
- `*_hash` columns never hold the raw secret; `*_enc` columns hold ciphertext
- `audit_log` rows cannot be updated, except that deleting a user sets
  `user_id` to NULL (the `username` snapshot keeps the history readable)

Every connection sets `foreign_keys=ON`, `journal_mode=WAL`,
`busy_timeout=5000` and `synchronous=NORMAL` through the DSN, so new pool
connections get the same settings.

**DESIGN / NOT IMPLEMENTED:** proposed schema extension (migration work deferred;
`00001_init.sql` is unchanged):

| Proposed table/extension | Contract |
|---|---|
| `servers` extension, `server_groups`, `server_group_memberships` | enrollment state/tombstone, approved endpoint, group labels; no consensus roles |
| `server_enrollments` | token hash only, intended host, expiry, consumed/revoked timestamps; atomic one-use |
| `agent_identities`, `server_capabilities` | certificate fingerprint/serial, validity, revocation, capability revision/observed time; no private keys |
| `containers`, `compose_stacks`, `managed_volumes`, `managed_networks` | owner + host scope, normalized desired spec/digest, external runtime IDs and observed state; secrets referenced, not embedded |
| `deployments`, `deployment_releases`, `deployment_secrets`, `applications` | host/owner, source/ref, pinned commit/image, template version, write-only `_enc` values, release/build/job links |
| `webhook_deliveries` | provider delivery/event digest, replay state and job reference, no credential payload |
| `backup_targets`, `backup_plans`, `backup_runs`, `backup_artifacts` | host/owner, credential references, source IDs, schedule/retention, manifest/digests, encryption key ID, consistency and local/remote verification states |
| `restore_plans` | source archive, target IDs/state digest, expiry, confirmation hash and consumption, job result |
| `ssh_public_keys` | host/managed user, public key, fingerprint, label and audit metadata; no SSH private keys |
| `jobs` extension / operation journal | idempotency digest, agent job ID, durable checkpoints, locks, cancellation/reconciliation and retry metadata |

Host-scoped foreign keys and application validation must prevent cross-host
joins (e.g. a deployment mounting another host's volume). Do not retrofit new
fields into JSON `settings` to pretend the required schema exists. Existing
cascading `servers` foreign keys must be reviewed before lifecycle migrations;
MVP offboarding uses tombstones, not hard deletes that erase jobs/audit context.
Keep existing global domain uniqueness unless explicitly revised in a future
migration; host grouping does not imply duplicate-domain routing.

Daily panel metadata backups use a consistent SQLite `VACUUM INTO` (or SQLite
backup API) capture, encrypted before retention under
`/var/lib/axionpanel/backups/`, default 7 successful daily copies. This automatic
MVP behavior is **DESIGN / NOT IMPLEMENTED**, not a current store feature.
Copying `panel.db` alone while WAL writes continue is not a valid backup. Recovery
requires the independently secured `secret.key` plus agent/trust recovery
material where applicable, not just the DB; §9.12 defines custody and restore.

SQLite remains the central metadata store for one admin managing multiple hosts
in the MVP. Optional future PostgreSQL support would use a separate migration
set, not a “multi-server mode” requirement. Application queries should stay
portable; SQLite-specific capture operations remain in the store adapter.

## 9. Provisioning behavior

### 9.1 Applying configuration

Every generated file is written the same way:

1. run the subsystem test first (`nginx -t`). If it already fails, abort with
   `preexisting_config_error` and write nothing, because the failure is not
   caused by this change.
2. write to a temp file in the target directory, fsync
3. rename the current file to `*.axionbak`, rename the temp file into place
4. run the test again (`nginx -t`, `php-fpm<ver> -t`)
5. on success, reload the service and delete the backup
6. on failure, restore the backup, reload, return `config_test_failed` with
   the tool output

### 9.2 Site apply sequence

1. The panel validates input, inserts the site with `status=provisioning`,
   creates a job, and calls `site.apply`.
2. The agent creates the group and system user if missing: shell
   `/usr/sbin/nologin`, home `/var/www/<domain>`, no password.
3. It creates directories and permissions (9.3).
4. For PHP sites it writes the PHP-FPM pool and reloads that PHP version.
5. It writes the Nginx vhost and reloads Nginx.
6. The panel sets `status=active`, or `status=error` with `last_error`.

System user names are `ap_` plus the domain with `.` and `-` replaced by `_`,
cut to 28 characters. Collisions get a numeric suffix. The result never
exceeds 32 characters.

### 9.3 Permissions

Each site has its own user and group with the same name. `www-data` is added
to every site group so Nginx can read static files.

- `/var/www/<domain>`: `root:<site group>`, 0750. Root-owned so chrooted SFTP
  can be added later.
- `public/` and `tmp/`: `<site user>:<site group>`, 0750
- PHP-FPM runs with umask 0027, so new files stay inside the site group

Site users cannot read other sites because they are not members of other
site groups.

### 9.4 Nginx vhost

The template includes:

- `listen 80`, plus `listen 443 ssl` with HTTP/2 when a certificate is bound
- `server_name` and `root`
- a shared ACME challenge location
- `fastcgi_pass unix:/run/php/axion-<user>.sock` for PHP sites, or
  `proxy_pass` for proxy sites
- deny rules for dotfiles, except `/.well-known/`
- per-site access and error logs under `/var/log/axionpanel/sites/<domain>/`,
  with logrotate
- the custom directives snippet, if set

Suspended sites return a 503 page.

PHP-FPM pools use `pm = ondemand`, a per-site `open_basedir`,
`upload_tmp_dir`, and `session.save_path` under the site's `tmp/`.

### 9.5 SSL

ACME runs inside the agent (lego as a library), so private keys never leave
root-owned storage. HTTP-01 challenges are served from
`/var/lib/axionpanel/acme-challenge/` through a location included in every
vhost, which also works for proxy sites.

Renewal: a daily panel job renews certificates when one third of their
lifetime remains, rather than at a fixed number of days, so shorter CA
certificate lifetimes need no code change.

### 9.6 Firewall

The agent manages only its own nftables table, `inet axionpanel`, and applies
rule files with `nft -f`, which applies the whole file as one transaction.

Applying a change starts a 60-second timer. If the panel does not call
`firewall.confirm` before it expires, the agent restores the previous rule
set, so a bad rule cannot lock the admin out. The SSH port and panel port are
`is_system` rules that cannot be deleted.

If ufw or firewalld is active, firewall management is read-only and the UI
explains why. In nftables, an accept in one table does not override a drop in
another table on the same hook, so two managers produce rules that silently
do nothing.

### 9.7 SSH settings

The agent writes `/etc/ssh/sshd_config.d/10-axionpanel.conf`, validates with
`sshd -t`, and uses the same confirm-or-revert timer as the firewall. Recent
Ubuntu releases start SSH through socket activation (`ssh.socket`), where a
port change needs `systemctl daemon-reload` and a restart of `ssh.socket`
instead of reloading `sshd`. The agent detects which mode is active.

### 9.8 Jobs

**DESIGN / NOT IMPLEMENTED:** panel-side workers (initial global concurrency 2,
configurable after measurement) process host-targeted jobs and persist progress.
Apply per-host/per-subsystem concurrency and resource limits; one offline host
must not consume the entire pool. Every build, deploy, template install, backup,
verify and restore is a job with redacted events, actor, host, target IDs,
idempotency digest, checkpoints and result references.

The agent persists accepted operation IDs, parameter digests, checkpoints and
terminal results to its restricted local journal before acknowledging work.
In-memory event replay may expire after 1 hour; it is not the authority for
whether destructive work ran. On reconnect/restart, reconcile panel job IDs with
`GET /v1/jobs/{id}` and observed resources. Unknown or ambiguous outcomes are
marked failed with `interrupted`/manual-reconciliation detail; do not automatically
repeat a restore/build or create duplicate releases/archives. Certificate expiry,
revocation and offboarding block new dispatch and record cleanup still pending.

Jobs use `queued → running → succeeded|failed|canceled`; proposed phase,
checkpoint and reconciliation metadata need §8 migrations. Cancellation is
cooperative only at documented safe boundaries, with cleanup; a restore in its
commit phase cannot claim to be canceled halfway through. Retries reuse the
original operation identity when reconciling; an explicit new attempt follows
preflight and links its predecessor. Multi-resource templates use tracked child
steps and compensations, not an asserted distributed transaction. Retention and
scheduling are panel-coordinated, explicitly timezone-aware, skip overlapping
runs by default and record missed/offline runs rather than silently backfilling
an unbounded backlog.

### 9.9 Docker and Compose (DESIGN / NOT IMPLEMENTED)

Detect Docker Engine/API version, Compose v2 plugin, storage driver, cgroup
limits and daemon availability per host; installing/enabling a runtime is an
explicit approved operation, not an implicit side effect of a read. MVP manages
local Docker and single-host Compose only; no Swarm/Kubernetes or cross-host
service discovery. External/unmanaged resources are read-only until explicitly
adopted with a validated plan; inventory never implies permission to delete them.

The root agent is the only component allowed to use the local Docker socket.
Never expose/mount it into the panel, browser, workloads or build sandboxes; do
not offer raw Docker JSON passthrough. Managed specs validate image/digest,
commands, env references, resource limits, health checks, ports, volumes and
networks. Reject privileged mode, host PID/IPC/network, dangerous capabilities,
devices, unrestricted bind mounts and socket mounts. Restrict bind sources to
agent-derived managed roots and enforce path resolution; prefer named volumes.
Compose parsing is size/depth bounded, normalized and rejects remote includes,
arbitrary env-file paths, unsupported extensions and policy bypasses. `build:`
can only use the isolated build path in §9.10, never an implicit root build.

Default application ports bind loopback behind the managed Nginx/SSL route;
public port publication needs explicit approval and conflict checks. Docker's
own netfilter chains can bypass expected host ingress policy: validate effective
Docker forwarding/isolation behavior and enforce the supported integration before
allowing public exposure; do not assume `inet axionpanel` alone filters every
published port. If coexistence cannot be enforced, disable publication with an
unsupported reason. Retain nftables as §9.6 specifies, not UFW from mock labels.

Apply stack changes under a per-stack lock, capture previous normalized spec and
image digests, run health checks, then switch routes. Failed deployments restore
the prior route/release where possible. Do not promise transactional rollback of
all container side effects or data migrations. Removal retains data volumes by
default; pruning/deleting referenced data needs a separate scoped confirmation.

### 9.10 Git deploy (DESIGN / NOT IMPLEMENTED)

A deployment selects one enrolled host, repository, tracked branch/tag, build
mode (Dockerfile or explicit supported recipe), runtime limits, secret references,
health check and route. Manual runs and authenticated push events resolve the
ref to an immutable commit and record it before execution. No floating-ref-only
release history. MVP does not require Nixpacks merely because a reference labels
it; builder choice/version remains an implementation decision with these limits.

Webhook delivery requires provider signature verification over the raw body,
a per-deployment secret, bounded payload/time window where the provider supports
it, unique delivery-ID replay protection and a configured repository/ref match.
An event queues only a preconfigured deployment; it cannot supply arbitrary
commands, credentials, host targets or build settings. Separate rate limits and
bounded queues apply. Unsigned/duplicate/mismatched events do not start builds.
Checkout also enforces §5.6 for submodules/LFS; secrets are not embedded in URLs.

**Security boundary:** repository code, Dockerfiles, dependency installers and
build scripts are arbitrary untrusted code. Run them in disposable unprivileged
isolated workers with CPU/RAM/disk/time/process limits, restricted egress, no host
credentials, no root agent privileges, no host filesystem or Docker socket, and
no production secrets by default. Build-only secrets are explicitly granted,
ephemeral and redacted; masking logs alone cannot prevent malicious exfiltration.
A rootless/container build is not a promise of hostile-tenant isolation: the
single admin must trust the source, or use a stronger isolated builder adapter.
If the required sandbox is unavailable on a host, builds there are unsupported;
never fall back to root shell or privileged Docker-in-Docker. Existing explicit
admin terminal access is not a justification to weaken automated builds.

Stages: validate/preflight → fetch pinned commit → isolated build → immutable
artifact/image digest → candidate start → health check → route switch → retain
previous release. Build/cache failures do not alter the active route. Rollback
selects a retained release and rechecks compatibility/health. Database migrations
are explicit, opt-in, scoped steps with backup guidance; reverting an image does
not reverse a schema/data change. Zero downtime is conditional on the workload
and available capacity, not guaranteed. Logs/artifacts use bounded retention;
container terminal/exec is not implicitly enabled by deploy support.

### 9.11 Curated one-click applications (DESIGN / NOT IMPLEMENTED)

Ship an application catalog owned/reviewed by the project, with immutable
versions, provenance/digests, supported architectures, host capabilities,
resource minimums, input schemas, port/network rules, health checks, secret
requirements, data volumes, update/rollback and backup/restore notes. Candidate
initial entries: WordPress + MariaDB, PostgreSQL, Redis, Strapi, Next.js,
Meilisearch and Ollama. The final version matrix and GPU/resource support require
validation; reference logos/version counts are not support guarantees. A
PostgreSQL application container is distinct from PostgreSQL panel metadata or
native database-manager support.

“One-click” means a guided validated launch, not silent installation: select host
and template version, fill validated inputs, preview resources/ports/persistence
and confirm the plan. Templates expand into the same restricted Compose/deploy
contracts, with generated unique secrets. No downloaded root install scripts,
unrestricted template shell hooks or unreviewed third-party catalog imports.
Track installed version, resource ownership and child jobs. Failure preserves
pre-existing data and records partial cleanup; uninstall preserves volumes by
default. Updating an app is a new planned release with migration/backup warnings,
not an unbounded auto-update or a public app-store contract.

### 9.12 Encrypted backups and scoped restore (DESIGN / NOT IMPLEMENTED)

**Scope and consistency.** Support local encrypted archives on the source host
and encrypted uploads to an explicitly approved S3-compatible bucket/prefix,
manual or scheduled, with retention by successful artifact count/age. Sources
are panel metadata, managed site files/config metadata, supported logical database
dumps and named managed container volumes. A “snapshot” UI label means a backup
artifact, not a block-level/full-OS/hypervisor snapshot. No root filesystem or
bare-metal restore is included. Provider/hypervisor snapshots require a separate
explicit provider adapter and are not promised by this MVP.

- Capture SQLite via a consistent backup API/`VACUUM INTO`, not raw live file copy.
- Dump MariaDB/MySQL using supported logical tools: transactional-consistent
  dumps where possible; nontransactional tables need locking/quiesce or an
  explicitly labeled crash-consistent/unsupported outcome. Never archive a live
  database data directory and call it application-consistent. Container DBs
  require a catalog-approved dump adapter (e.g. `pg_dump` for PostgreSQL),
  otherwise stop/quiesce the application or mark it unsupported.
- Site files/volumes require a documented consistency mode. Application-consistent
  capture uses allowlisted typed hooks or controlled service/container pause/stop
  plus dump ordering, bounded downtime and mandatory resume attempts in cleanup
  (failed resume is an explicit critical job error, never a hidden guarantee). No
  arbitrary root pre/post scripts. Live file archives are only crash-consistent
  and show that limitation. A multi-resource set records capture times/order;
  it is not a cross-host atomic snapshot. Verify free space and source scope,
  and exclude sockets, device files, secrets not explicitly in scope and symlink
  escapes. Credentials/TLS key backup needs a separate protected recovery scope;
  routine site archives must not accidentally include host identity material.

**Encryption and custody.** Use an established authenticated-encryption archive
format/library (format/tool selection still open), with fresh random data key per
artifact, authenticated manifest, checksums, format/schema version, source host
and resource IDs, consistency mode, tool versions and capture times. Encrypt
before writing retained local archives or uploading objects. Restrict unavoidable
plaintext dump/staging to worker-only temporary paths, limit lifetime and clean
on completion/failure/restart; do not claim secure erasure on SSDs. Verification
must check ciphertext authentication plus the manifest/content checksums, not
just an S3 ETag. List “captured”, “uploaded” and “verified” as distinct states;
a failed upload does not count as a successful remote backup.

For panel metadata, the panel captures SQLite through its store adapter on the
central host; a restricted local handoff to the backup worker encrypts that
capture. Do not grant the panel direct access to root backup keys or give remote
agents unrestricted SQLite access. A dedicated typed metadata-capture path must
validate the fixed source and temporary handoff, not accept arbitrary root paths.

Wrap data keys using host backup keys in `/etc/axionpanel/backup-keys/`, separate
from the panel's `secret.key`; archive headers store key IDs, never plaintext
keys. Panel metadata holds key references only. Document an out-of-band encrypted
key/recovery export and require the admin to acknowledge separate custody before
enabling schedules; losing keys makes archives unrecoverable. Keys/credentials
are never in UI logs or ordinary download responses; recovery import is a
restricted agent-side administrative procedure, not chat/browser plaintext key
collection. Rotation preserves decryptability for retained archives; deleting a
key must be blocked while referenced or require explicit irreversible-loss
acknowledgement. A same-disk local archive alone is not disaster recovery.

The panel DB's encrypted secrets require `secret.key` for recovery; mTLS/CA and
site key recovery also need separately protected material or re-enrollment/reissue.
Recovery material must not be backed up in plaintext alongside ciphertext. Test
recovery on a clean target with documented key import and trust reset, without
quietly restoring old active sessions or revoked enrollment identities.

**Targets and retention.** Local destinations are approved host-local directories
outside the source tree, not caller-chosen root paths. S3 endpoint, bucket, prefix
and TLS settings pass §5.6; credentials are scoped to necessary object actions
and configured location. Bounded multipart upload/retry cleans incomplete objects.
Verify the uploaded object before pruning older successful copies; do not prune
last good copies because a new job merely started. Retention cannot delete an
artifact used by an active restore. Record provider immutability/versioning if
available; do not claim it is guaranteed by every S3-compatible provider.

**Restore is separate from capture.** Build a read-only restore plan, authenticate
and verify the archive, check key availability, format/tool/engine compatibility,
capabilities, disk space, scoped target mappings and overwrite conflicts. Default
to new/staged resources. Cross-host restore is explicit and allowed only when
capabilities/mappings match; never use the source `server_id` to bypass target
validation. Bind a short-lived single-use confirmation to archive digest, target
host/resources, observed target-state digest and overwrite/data-loss plan; sudo
mode, typed destructive acknowledgement and confirmation consumption precede
writes. A stale plan must be rebuilt, not silently adapted.

Restore only managed files, logical DBs and approved volumes as their scoped
users/workers. Reject absolute/traversal archive paths, escaping links, special
files, setuid bits and unsafe ownership; never restore arbitrary `/etc`, `/root`,
sshd, agent trust or executable host hooks from an archive. Quiesce affected
services, take a pre-restore backup where possible (otherwise explicit risk
acknowledgement), restore to staging, validate and switch at a recorded commit
boundary, then health-check/resume. Record partial failures and rollback limits;
no root restore or universal transactional rollback is implied. Panel metadata
recovery is an offline operator recovery procedure while the panel is stopped,
not a browser API overwriting the active SQLite store. UI restore endpoints
handle workload resources only; provider-level restoration is out of scope.

### 9.13 SSH keys and Fail2ban monitoring (DESIGN / NOT IMPLEMENTED)

Detect Fail2ban presence, version, service state, jails, current bans and available
counters through a typed, bounded adapter; missing permissions/tools show
unsupported/unknown, not “0 attacks”. MVP monitoring is read-only, without
arbitrary jail editing, unban or session-revocation actions merely because mock
buttons exist. Do not merge Fail2ban rules into the panel nftables table or claim
UFW is the managed backend; detect/report coexistence separately.

SSH key management accepts only validated single-line public keys for explicitly
policy-allowed managed system users, with supported key type/strength,
fingerprint and label, bounded payloads and no newlines/authorized_keys options
that inject commands or policy. Never generate, upload or store users' SSH private
keys. Agent derives `.ssh/authorized_keys` from the allowed user's system home,
resolves paths safely, applies proper owner/modes and atomic writes, and manages
only its marked entries, preserving unmanaged keys. Root key management is
disabled by default under host-local policy, not implied by the reference's root
shell or the file manager root flag. Audit additions/removals by fingerprint,
require sudo for mutations and warn/confirm potential last-key lockout. Do not
automatically disable password login or alter `PermitRootLogin` when adding keys;
SSH daemon settings remain a distinct tested confirm-or-revert change (§9.7).

## 10. Testing and CI

- Unit tests: table-driven and fuzz tests for validators (domains, paths,
  cron), golden-file tests for templates, migration tests for the store.
- Agent integration tests run in Incus/LXD system containers (they run
  systemd) for each supported OS, nightly.
- CI on every push: `go vet`, `go test -race`, `staticcheck`, `govulncheck`.
- Releases: goreleaser builds amd64 and arm64 and signs artifacts. The
  installer and any future updater verify signatures before installing.
- DESIGN / NOT IMPLEMENTED test gates: mTLS identity confusion/rotation/revocation,
  atomic one-use/expired enrollment, offline offboarding and capability mismatch;
  no Docker socket exposure, Compose path/privilege bypass, Docker/nftables port
  isolation; SSRF redirects/rebinding/private-target exceptions and Git helpers;
  sandbox escape/secret leakage/resource limits, webhook replay and immutable
  release rollback; template partial failure and volume retention; backup
  consistency/dump/quiesce/resume failures, encryption/key-loss/rotation, S3
  upload/retention failures and verified restore drills; malicious archives,
  stale confirmation and interrupted restore; SSH-key injection/last-key
  warnings and Fail2ban absence. Exercise central SQLite with multiple real
  enrolled agents; no HA or consensus test claim follows from host grouping.

These are required acceptance gates, not claims that CI, integration adapters or
the associated feature tests already exist. Current executable coverage is the
store migration/constraint test suite.

## 11. Milestones

| Milestone | Scope |
|---|---|
| M0 | workspace scaffold, initial SQLite store/migration and constraint tests (present); panel health endpoint; agent stub |
| M1 | DESIGN / NOT IMPLEMENTED: auth (login, 2FA, sessions, CSRF, entrance path), settings, audit; expanded-schema migrations reviewed separately |
| M2 | PARTIAL: local agent socket/peer credentials, closed registry and read-only info/stats/capability detection implemented (`docs/agent.md`); panel client and authenticated `GET /system/{info,stats,agent}` wired for the local host. DESIGN / NOT IMPLEMENTED: managed capabilities, services, durable jobs and reconciliation |
| M3 | DESIGN / NOT IMPLEMENTED: sites, users, PHP-FPM, Nginx apply/test/rollback |
| M4 | DESIGN / NOT IMPLEMENTED: SSL with lego |
| M5 | DESIGN / NOT IMPLEMENTED: native MariaDB database management |
| M6 | DESIGN / NOT IMPLEMENTED: file manager and uploads |
| M7 | DESIGN / NOT IMPLEMENTED: cron, nftables, SSH settings/public keys, Fail2ban monitoring, terminal and logs |
| M8 | DESIGN / NOT IMPLEMENTED: remote mTLS enrollment/rotation/revocation, host inventory/grouping, central SQLite multi-host routing, offline lifecycle |
| M9 | DESIGN / NOT IMPLEMENTED: Docker/Compose lifecycle, volumes/networks, restrictions and verified firewall integration |
| M10 | DESIGN / NOT IMPLEMENTED: isolated Git build/deploy, signed webhooks, immutable releases, health gates and rollback |
| M11 | DESIGN / NOT IMPLEMENTED: reviewed one-click application catalog, versioned manifests, input/host preflight and partial-failure handling |
| M12 | DESIGN / NOT IMPLEMENTED: encrypted local/S3 backups, consistency adapters, key custody/recovery, retention, confirmed scoped restore and drills |
| M13 | DESIGN / NOT IMPLEMENTED: integrated UI pass, installer, packaging, signed releases, full expanded-MVP acceptance gates, v0.1.0 |

No delivery estimates are assigned. Ordering expresses dependencies, not completed
backend work; static screen work can proceed in parallel without changing status.
Expanded MVP acceptance includes M8–M12, not a preview deferred past v0.1.0.

## 12. Open decisions

- License: deferred.
- PHP package source: ondrej PPA (Ubuntu) and packages.sury.org (Debian).
  Coverage for Ubuntu 26.04 and Debian 13 must be verified before M3, along
  with which PHP versions to offer by default.
- Default database engine: MariaDB, which is in the distro repositories for
  every target and uses `unix_socket` auth for root by default. MySQL support
  depends on demand.
- Firewall when ufw or firewalld is active: read-only in the MVP (9.6). An
  adapter for ufw is a candidate for Phase 2.
- UI component library for Vue 3; screen/layout provenance in
  `docs/design/README.md`, without treating static controls as live features.
- Remote certificate authority/library, exact short certificate lifetime and
  rotation overlap, network topology prerequisites and agent installation UX;
  mTLS, pinned identities, one-use expiring hashed enrollment and revocation are
  required, not open scope choices.
- Supported Docker/Compose version matrix, rootless builder implementation,
  build recipe/catalog versions and effective nftables/Docker forwarding
  enforcement on each supported OS. No privileged fallback is acceptable.
- Initial curated application list/version/architecture matrix and supported
  database dump/quiesce adapters. Broader native PostgreSQL database management
  is distinct from launching a PostgreSQL template and remains future work.
- Backup encryption tool/format, key export/recovery procedure, staging/downtime
  limits and tested S3 compatibility matrix. Authenticated encryption, scoped
  confirmation and consistency disclosure are required; full-root snapshots are
  not silently added while choosing tools.
- Docker/Compose, Git deploy, curated templates, managed multi-node grouping,
  encrypted local/S3 backup/restore and SSH-key/Fail2ban views are decided MVP
  scope. PostgreSQL metadata, distributed scheduling/Raft/HA and a public
  marketplace are not required by this decision.
