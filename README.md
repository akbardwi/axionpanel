# AxionPanel

VPS control panel inspired by aaPanel and cPanel. Planned for one administrator
managing a local server and multiple enrolled hosts from one dashboard, with a
path to multi-user hosting later. The license is still undecided; the project
is not yet open source by definition.

**Status: pre-alpha — working authentication + embedded UI, design-only management features.**

The panel binary now serves the embedded Vue UI and a real authentication
backend: password login, TOTP 2FA with single-use recovery codes, hashed
sessions, sudo re-authentication, and CSRF/Origin enforcement (see
`docs/spec.md` §5.1). Everything else — websites, databases, SSL, files, cron,
containers, deploy, backups, multi-node — remains **DESIGN / NOT IMPLEMENTED**.
The MVP features below are design contracts, not evidence that their actions
work. Static UI references/prototypes are design artifacts with mock data.

## MVP scope

Implemented:
- Authentication: argon2id password hashing, TOTP 2FA + recovery codes, hashed
  sessions with idle/absolute expiry, sudo mode, CSRF + Origin enforcement,
  failed-login lockout and per-IP/per-username throttling.

Design only (not implemented):
- Installer, settings and audit
- Host dashboard, live resource metrics, services, terminal and logs
- Nginx websites (PHP-FPM, static, reverse proxy), Let's Encrypt/custom SSL
- MariaDB-first native database/user management, file manager and cron
- nftables firewall with confirm-or-revert, SSH settings/public-key management,
  and read-only Fail2ban monitoring
- Docker container lifecycle, logs/stats, managed volumes/networks and
  single-host Compose stacks
- Git deploy: manual and authenticated webhook triggers, isolated builds,
  immutable releases, health checks and rollback limits
- Curated, versioned one-click application templates with capability/input
  preflight and explicit host selection; not a public app marketplace
- Multi-node inventory, grouping/cluster UI, per-host capability detection,
  expiring one-use enrollment, remote mTLS, rotation and revocation/offboarding
- Encrypted local and S3-compatible manual/scheduled backups, consistent DB
  dumps/quiesce where required, retention, integrity checks and confirmed scoped
  restore with separately secured recovery keys

All of these are included in the MVP, not previews deferred to a later phase.
“Cluster” means centrally managed host grouping: each deployment targets one
host. It does **not** promise a distributed scheduler, Raft/leader elections,
quorum, cross-host replication, automatic failover or control-plane HA.

Backups cover managed workload resources and panel metadata, not arbitrary
root/full-OS restore or hypervisor snapshots. Provider snapshots need a separate
provider adapter and are not an MVP promise. Panel metadata recovery is an
offline operator procedure; browser restore actions target managed workloads.
The reference screens' UFW, Raft and full-host snapshot labels do not override
these boundaries.

## Architecture — design contract

Two processes with separated privileges:

- `panel` — unprivileged API/UI, authentication, central metadata and job tracking
- `agent` — privileged host daemon with a closed operation registry; local
  requests over a peer-credential-checked Unix socket, remote requests over mTLS

SQLite remains the **central metadata database for the single-admin, multi-host
MVP**. PostgreSQL is an optional future metadata backend, not required for remote
hosts. Managed application databases are separate from panel metadata; launching
a PostgreSQL application template does not imply native PostgreSQL management
or a PostgreSQL-backed panel.

Security contracts include host-local policy/capability checks, hashed single-use
expiring enrollment tokens, identity revocation and explicit offboarding state.
The Docker socket is never exposed to the panel, browser, apps or build workers.
Git builds execute arbitrary untrusted code and require an isolated unprivileged
worker; there is no root/privileged-build fallback. Git/S3 and related outbound
targets require allowlists and SSRF protections. Backup encryption/key custody,
consistency disclosure, restore preflight and destructive confirmation are
required, not inferred from mock UI controls.

See [the technical specification](docs/spec.md) for APIs, operation catalog,
proposed schema extensions, lifecycle/security details, test gates and milestones.
The initial migration remains unchanged; proposed additions are explicitly
separated from existing tables. No delivery estimates are assigned.

## Later scope

Multi-user admin/reseller/user roles, packages/quotas, DNS/mail/FTP, a public app
marketplace, public API tokens, notifications and signed automatic updates remain
future work. Signed installer/release verification belongs to the MVP release
gates. Distributed scheduling/consensus/HA is not promised by the multi-node UI.

## Stack

- Go: panel and agent binaries; initial store uses `modernc.org/sqlite`
- Vue 3 + Vite + Tailwind: production UI embedded in the panel binary via
  `go:embed`; hash routing, no SPA server-side fallback needed
- SQLite: central MVP metadata; optional future PostgreSQL adapter

## Layout

```
cmd/panel/     Panel entrypoint (API server + embedded UI + auth)
cmd/agent/     Agent entrypoint (currently stub)
internal/      Store/migrations, auth, secret, totp, webui
internal/secret/  AES-256-GCM envelope for encrypted fields
internal/totp/    RFC 6238 TOTP with replay-step tracking
internal/webui/   Static UI handler + security headers/CSP
web/           Frontend workspace (Vue 3, embedded into the panel binary)
docs/          Technical specification and design artifacts
scripts/       Installer and packaging workspace
```

Design provenance, screen mapping and prototype guidance belong in
[docs/design/README.md](docs/design/README.md); supplied references are under
`docs/design/reference/`. New screens may be designed directly, with mock actions
and unsupported capabilities clearly distinguished from implemented behavior.

## Build and local smoke test

Requires Go matching `go.mod`, Node.js 20.19+ or 22.12+, npm and make.
This is a development setup, not an installer or production deployment.

1. Build the frontend and binaries from the repository root:

   ```sh
   make web
   make build
   ```

2. Create a private data directory and bootstrap the first administrator:

   ```sh
   install -d -m 700 ./data
   ./bin/axionpanel -db ./data/panel.db -bootstrap-admin admin
   ```

   Save the generated password securely; it is printed once. Bootstrap refuses
   to run when any user exists. Keep `data/secret.key` (0600) separate from DB
   backups; losing it makes encrypted TOTP secrets unreadable. Existing keys
   readable by group/others are rejected rather than silently replaced.

3. Start a loopback-only development instance:

   ```sh
   ./bin/axionpanel -db ./data/panel.db \
     -addr 127.0.0.1:7800 -origin http://127.0.0.1:7800 -insecure-loopback
   ```

   Open `http://127.0.0.1:7800/`, or use an SSH tunnel forwarding local port
   7800 to server port 7800. `-insecure-loopback` disables Secure cookies only
   for an explicit HTTP loopback origin. Do not use it for public access.
   Native TLS, installer and trusted-proxy support are not implemented; peer-IP
   rate limits are shared by clients behind a proxy/NAT. Setting `-origin` does
   not enable TLS. Only auth is functional; host controls remain sample UI.

MFA enrollment/disable and sudo have API endpoints but no wired settings UI yet.
Password changes, session listing/revocation and audit writes remain pending.
A clean checkout builds with a placeholder UI; without `make web`, `/` returns
503 explaining how to build the frontend. Preview mode is explicit:
`VITE_DESIGN_PREVIEW=true npm --prefix web run dev` (sign-in disabled).

## Verification

```sh
go vet ./...
go test -race -count=1 ./...
npm --prefix web test
cd web
npx playwright test --config tests/auth.playwright.config.js
npx playwright test
```

Auth browser contract tests mock API responses in tests only. Design tests start
an isolated preview server and write screenshots to `docs/design/screens/`.
Actual-binary browser smoke tests have also exercised password login, reload,
TOTP/recovery login and logout; mocked tests alone do not prove integration.

## License

Not decided yet. No license file is included on purpose; until one is added,
the code is not open source by definition.
