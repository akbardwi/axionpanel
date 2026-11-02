# AxionPanel

VPS control panel inspired by aaPanel and cPanel. Planned for one administrator
managing a local server and multiple enrolled hosts from one dashboard, with a
path to multi-user hosting later. The license is still undecided; the project
is not yet open source by definition.

**Status: pre-alpha — scaffold and design, not a working management backend.**
The repository has Go entrypoints (a panel health endpoint and an agent stub),
a SQLite store, the initial migration and store constraint tests. The MVP
features below are **DESIGN / NOT IMPLEMENTED**. Static UI references/prototypes
are design artifacts with mock data, not evidence that their actions work.
No new schema migrations or backend features are supplied by the scope update.

## MVP scope — DESIGN / NOT IMPLEMENTED

- Installer, authentication with TOTP 2FA, sessions, settings and audit
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
- Vue 3 + Vite + Tailwind: planned production UI embedded in the panel binary
- SQLite: central MVP metadata; optional future PostgreSQL adapter

## Layout

```
cmd/panel/     Panel entrypoint (currently health endpoint)
cmd/agent/     Agent entrypoint (currently stub)
internal/      Store/migrations; planned API, services, validation and templates
web/           Frontend workspace; static designs are not a wired SPA backend
docs/          Technical specification and design artifacts
scripts/       Installer and packaging workspace
```

Design provenance, screen mapping and prototype guidance belong in
[docs/design/README.md](docs/design/README.md); supplied references are under
`docs/design/reference/`. New screens may be designed directly, with mock actions
and unsupported capabilities clearly distinguished from implemented behavior.

## License

Not decided yet. No license file is included on purpose; until one is added,
the code is not open source by definition.
