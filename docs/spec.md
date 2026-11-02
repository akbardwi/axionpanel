# AxionPanel technical specification

Status: draft v0.1, covers the MVP (Phase 1). Last updated 2026-11-02.

This document is the contract between the panel, the agent, and the web UI.
Change it in the same pull request as the code that changes the behavior.

## 1. Scope

The MVP lets one administrator manage one VPS from a web UI:

- websites: Nginx with PHP-FPM, static sites, or reverse proxy
- Let's Encrypt and custom SSL certificates
- MariaDB/MySQL databases and database users
- file manager with upload, download, edit, archive and extract
- cron jobs, firewall rules, SSH settings, system services
- web terminal, log viewer, live resource stats

Not in the MVP: multiple panel users, mail, DNS server, FTP, backups,
Docker, app store, multi-node, Apache/OpenLiteSpeed, RHEL-family distros.

Three foundations must exist from the first release even though the features
that need them come later:

- every resource row carries `owner_user_id` and `server_id`
- every authorization decision goes through one policy layer, even while the
  only role is `admin`
- the panel reaches the agent through a client interface whose transport can
  change from a Unix socket to mutual-TLS TCP without touching callers

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

## 3. Architecture

```
browser --HTTPS--> axionpanel (user: axionpanel)
                     |-- SQLite: /var/lib/axionpanel/panel.db
                     '-- HTTP over Unix socket --> axionpanel-agent (root)
                                                     |-- nginx, php-fpm, mariadb
                                                     |-- nftables, cron, sshd
                                                     '-- ACME client, PTYs
```

The panel handles authentication, sessions, authorization, first-pass
validation, persistence, job tracking, the SPA, WebSocket fan-out and the
audit log.

The agent executes a closed set of operations, validates every request again
(it never trusts the panel), renders and applies configuration with rollback,
reports metrics, and owns TLS private keys.

The panel never runs privileged commands, never holds the database root
credentials, and never reads site TLS private keys. Everything privileged goes
through the agent.

### systemd units

- `axionpanel.service`: `User=axionpanel`, `NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `ReadWritePaths=/var/lib/axionpanel /var/log/axionpanel`
- `axionpanel-agent.service`: runs as root, `RuntimeDirectory=axionpanel`

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
| `/var/lib/axionpanel/backups/` | axionpanel 0700 | daily panel.db snapshots |
| `/var/lib/axionpanel/acme-challenge/` | root 0755 | HTTP-01 challenge files |
| `/var/log/axionpanel/` | root 0750 | panel, agent, agent audit, cron, site logs |
| `/run/axionpanel/agent.sock` | root:axionpanel 0660 | agent socket (dir 0750) |
| `/etc/nginx/axionpanel/` | root 0755 | generated vhosts and snippets |
| `/etc/php/<ver>/fpm/pool.d/axion-<user>.conf` | root 0644 | per-site PHP-FPM pool |
| `/etc/cron.d/axionpanel` | root 0644 | generated cron table |
| `/var/www/<domain>/` | see 9.3 | site home: `public/`, `tmp/` |

## 5. Security model

### 5.1 Authentication

- Passwords are hashed with argon2id. Parameters follow the current OWASP
  recommendation and are stored in the hash string so they can be raised later.
- TOTP 2FA (RFC 6238) with 10 single-use recovery codes, stored hashed.
- Secret entrance path: the installer generates a random 12-character path.
  Visiting it sets an entrance cookie. Unauthenticated requests without that
  cookie get `404`, so scanners cannot fingerprint the panel.
- Login rate limits: 5 failures per username per 15 minutes locks the account
  with backoff; 20 failures per IP per 15 minutes blocks the IP.
- Sessions: 32 random bytes in cookie `axp_session` (`HttpOnly`, `Secure`,
  `SameSite=Strict`). The database stores only the SHA-256 hash. Idle timeout
  2 hours, absolute 24 hours, both configurable.
- CSRF: state-changing requests must send `X-CSRF-Token` matching the session
  token, and the `Origin` header must match the panel origin.
- Sudo mode: the terminal, root-scope file access, firewall, SSH settings and
  security settings require re-authentication (password + TOTP) within the
  last 10 minutes.
- Optional IP allowlist for the whole panel.

### 5.2 Transport

HTTPS only. The installer creates a self-signed certificate and prints its
fingerprint; the admin can switch to a Let's Encrypt certificate for the panel
hostname. HSTS is sent only with a trusted certificate. Every response carries
`Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin`.
WebSocket upgrades require a valid session and a matching `Origin`.

### 5.3 Agent hardening

- The agent reads the peer UID with `SO_PEERCRED` and rejects anything that is
  not the `axionpanel` user.
- Operations come from a fixed registry. There is no generic "exec" operation.
- Parameters are decoded with unknown fields rejected, validated, and passed to
  programs as argv. The agent never builds shell strings, clears the
  environment for child processes, and applies a timeout to every operation.
- File operations run in a child process with the site user's UID/GID and open
  paths with `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)`, so the kernel
  blocks `..` and symlink escapes. The agent derives the scope root from the
  system user's home directory; it never accepts a root path from the panel.
- `agent.toml` holds policy the panel cannot change: `allow_root_terminal`,
  `allow_root_files`, `allowed_services`.
- The agent writes its own append-only audit log, separate from the panel DB.
- Each subsystem (nginx, each PHP-FPM version, cron file, firewall) has its own
  lock, so concurrent operations cannot interleave config writes.

The separation has limits. If the panel is compromised, the attacker gets
every operation the agent allows. With `allow_root_terminal = true`, that
includes root, which is why the terminal sits behind sudo mode and the flag
lives in a file the panel cannot write.

### 5.4 Secrets at rest

Columns ending in `_enc` hold AES-256-GCM ciphertext encoded as
`v1:` + base64(nonce || ciphertext), using `secret.key`. The agent reaches
MariaDB as root through `unix_socket` authentication, so no database root
password is stored anywhere.

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

## 6. Panel-agent protocol

HTTP/1.1 over `/run/axionpanel/agent.sock`, JSON bodies. Every request sends
`Axion-Protocol: 1`, `Axion-Request-ID`, and `Axion-Actor` (the panel user ID,
for the agent audit log). A protocol mismatch returns `protocol_mismatch`.
Multi-node will serve the same API over TCP with mutual TLS.

### 6.1 Endpoints

| Method and path | Purpose |
|---|---|
| `GET /v1/info` | version, protocol, OS, arch, kernel, capabilities (PHP versions, DB engines, firewall backend) |
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

Mutating operations are desired-state: the panel sends the full intended
state and the agent converges to it. Retrying after a timeout is therefore
safe. `site.apply` covers create, update and suspend; one operation is a
smaller surface than three.

### 6.3 Operation catalog (MVP)

| Operation | Mode | Notes |
|---|---|---|
| `system.info`, `system.stats` | sync | |
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

Every `fs.*` operation takes a scope: `{"system_user": "..."}` or
`{"root": true}`. Root scope requires `allow_root_files`.

## 7. REST API

Base path `/api/v1`, JSON. Browsers authenticate with the session cookie.
API tokens (`Authorization: Bearer axp_...`) arrive in Phase 2; the table
already exists.

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

### System

| Endpoint | Notes |
|---|---|
| `GET /system/info`, `GET /system/stats` | |
| `WS /ws/stats` | live metrics |
| `GET /services` | |
| `POST /services/{name}/{action}` | |

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

### Jobs, audit, settings

| Endpoint | Notes |
|---|---|
| `GET /jobs`, `GET /jobs/{id}`, `WS /ws/jobs/{id}` | |
| `GET /audit?user_id=&action=&from=&to=` | |
| `GET /settings`, `PATCH /settings` | `security.*` keys need [sudo] |

## 8. Data model

The source of truth is `internal/store/migrations/*.sql`, applied with goose.
`internal/store/store_test.go` applies the migrations with the production
driver and checks the constraints described here.

| Table | Purpose |
|---|---|
| `packages` | quotas for future plans (Phase 3); NULL means unlimited |
| `users` | panel accounts; role, parent (reseller), package, 2FA, lockout |
| `user_recovery_codes` | hashed single-use 2FA recovery codes |
| `sessions` | hashed session and CSRF tokens, MFA and sudo state |
| `api_tokens` | hashed API tokens with scopes and IP allowlist (Phase 2) |
| `servers` | managed hosts; row 1 is the local server |
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

The panel takes a daily `VACUUM INTO` snapshot to `/var/lib/axionpanel/backups/`
and keeps 7. aaPanel's FAQ documents recovering a corrupted panel database
from backups; AxionPanel makes those backups automatic from day one.

PostgreSQL support (multi-server mode) will use a separate migration set.
Application queries must stay portable: no SQLite-only functions in queries.

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

Panel-side workers (pool size 2) process queued jobs and record progress in
`jobs`. On panel start, jobs left in `running` are checked against
`GET /v1/jobs/{id}`; jobs the agent no longer knows are marked failed with
`interrupted`. The agent keeps finished job results in memory for 1 hour.

## 10. Testing and CI

- Unit tests: table-driven and fuzz tests for validators (domains, paths,
  cron), golden-file tests for templates, migration tests for the store.
- Agent integration tests run in Incus/LXD system containers (they run
  systemd) for each supported OS, nightly.
- CI on every push: `go vet`, `go test -race`, `staticcheck`, `govulncheck`.
- Releases: goreleaser builds amd64 and arm64 and signs artifacts. The
  installer and the updater verify the signature before installing.

## 11. Milestones

| Milestone | Scope |
|---|---|
| M0 | workspace scaffold (done) |
| M1 | store and migrations, auth (login, 2FA, sessions, CSRF, entrance path), settings, audit |
| M2 | agent: socket server, peer credentials, operation registry, info, stats, services, jobs |
| M3 | sites: system users, PHP-FPM pools, Nginx vhosts, apply and rollback |
| M4 | SSL with lego |
| M5 | databases (MariaDB) |
| M6 | file manager and uploads |
| M7 | cron, firewall, SSH settings, terminal, logs |
| M8 | web UI pass, installer, packaging, signed releases, v0.1.0 |

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
- UI component library for Vue 3.
