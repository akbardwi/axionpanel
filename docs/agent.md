# Agent

The AxionPanel **agent** is the privileged host daemon. The **panel** is the
unprivileged web/API process. The agent runs only the operations in a closed
registry and accepts requests only over a Unix socket whose peer UID the kernel
reports. This document describes the current default foundation and opt-in
static-site configuration; the full protocol is specified in `docs/spec.md` §6.

## Status

The default startup catalog contains four read-only operations, with socket
transport, a peer-UID gate, strict request validation, host policy enforcement
and fixed-shape request audit records. A separate opt-in static HTTP Nginx
adapter registers `site.plan`, `site.apply`, `site.remove` and `site.status`.
Integration and review of that slice are in progress; this document is not a
release, deployment or final readiness claim. See
[static-sites-plan.md](static-sites-plan.md) for scope and acceptance gates.

Remote mTLS transport, agent jobs/stats-stream/terminal endpoints and general
host mutation remain unimplemented. Installer preflight/verification/staging
exist, but host apply does not. Manual systemd templates and deployment checks
are documented in [deployment.md](deployment.md); those templates retain the
read-only default and are not a static-site deployment profile.

## Threat model

- The agent runs as `root` (or a privileged account). The panel runs as its own
  unprivileged user.
- The agent never binds TCP or any generic HTTP listener.
- The only entry point is a Unix socket. The kernel supplies the peer UID via
  `SO_PEERCRED`; a request from any other UID is closed with zero bytes before
  HTTP parsing, so forged headers cannot matter.
- A peer with uid 0 is always refused, even if the server is misconfigured with
  a zero allowed UID; the panel must never run as root. (The Go `Server` has an
  `AllowRootPeer` field used only by tests; the CLI never sets it.)
- Rejected peers are closed immediately with no artificial per-connection
  delay. This avoids amplification from a queued foreign-peer flood; it does
  not guarantee availability under sustained local resource exhaustion. Socket
  group permissions restrict ordinary access; keep group membership narrow.
- Peer UID is transport authentication, not per-request authorization. The
  panel is trusted to be the panel; the registry and policy still bound what it
  may ask for.

## Socket and permissions

- Default socket: `/run/axionpanel/agent.sock`, mode `0660`, owner
  `root:<panel-group>`. Parent directory is created `0750` with that same group.
- An existing parent directory is accepted when it is owned by root or the agent
  euid, is not group/world writable, and has the socket group — so the systemd
  `RuntimeDirectory` shape (`root:<panel-group> 0755`) works without chmodding
  it. A directory that the agent cannot vouch for is refused, never adjusted.
- A missing parent is created if all ancestors are safe; it is never chmodded
  or chowned if it already exists. Any existing endpoint — including a stale
  socket — is refused; an operator must remove it by hand. The agent never
  dials-and-unlinks a socket (that would be a race).
- Ancestor directories must not be symlinks and must not be group- or
  world-writable (sticky roots such as `/tmp` are allowed as ancestors, never as
  the direct parent). Existing directories are never modified.
- Because the Linux abstract namespace is not used, the path must be an absolute
  clean path no longer than 107 bytes.

## CLI

```
axionpanel-agent \
  -socket /run/axionpanel/agent.sock \
  -policy /etc/axionpanel/agent.toml \
  -allow-uid axionpanel \
  -socket-gid axionpanel
```

- `-allow-uid` — required. Panel user, by name or numeric UID. `0` is refused;
  the panel must run as its own user.
- `-socket-gid` — required. Group for the socket and its directory, by name or
  numeric GID. `0` is refused; use a dedicated panel group.
- `-policy` — optional path. A missing file means deny-by-default and is logged,
  not fatal. An invalid, foreign-owned, group/world-readable, symlinked, or
  oversized policy file is fatal (fail closed).
- `-version` — print the stamped version and exit.

### Static-site opt-in

Without `-static-sites`, only the four built-in read-only operations are
registered. Setting any static-site option without that opt-in is a startup
error. Enabling it requires **all seven** options below plus
`allow_static_sites = true` in the host policy; missing configuration or policy
fails startup, rather than falling back to an unmanaged host Nginx instance.

| Flag | Trusted startup value |
|---|---|
| `-site-state-dir` | private root-only journal and lock directory |
| `-site-content-dir` | managed static content root |
| `-site-config-dir` | managed vhost configuration directory |
| `-nginx-binary` | absolute path to the trusted Nginx executable |
| `-nginx-config` | absolute path to the prepared isolated main configuration |
| `-nginx-prefix` | dedicated Nginx `-p` prefix directory |
| `-site-listen` | fixed literal `ip:port` listener |

These are operator-selected values, never request parameters. Prepare and
review the isolated Nginx instance and safe root-owned directories separately;
this opt-in does not install, start or adopt an existing hosting stack, open
ports, or enable workload TLS. The supplied read-only systemd sandbox is not a
static-site profile: it needs a separate privilege/writable-path review, not
blanket hardening removal. No generic root-file or service grant substitutes
for this dedicated permission.

Exit codes: clean `SIGTERM`/`SIGINT` shutdown exits `0`.

## Protocol (implemented subset)

- `GET /v1/info` — flat JSON document: version, protocol, OS, arch, kernel,
  hostname, `detected_tools`, `capabilities`, `capability_revision`,
  `observed_at`, `operations`.
- `POST /v1/ops/{name}` — operation call. Body is one JSON object with a single
  `params` object: `{"params":{...}}`. Response is `{"result":{...}}`.

Required headers on every request, validated before routing:

| Header | Rule |
|---|---|
| `Axion-Protocol` | must equal `1`; mismatch → `400 protocol_mismatch` |
| `Axion-Request-ID` | required, `[A-Za-z0-9._:-]{1,128}`, echoed only when valid |
| `Axion-Actor` | required, positive integer (the panel user ID, for audit) |

Unknown or duplicate `Axion-*` headers are rejected. Body is capped at 1 MiB and
must be a single JSON object with no duplicate keys at any depth and no trailing
data. Errors use `{"error":{"code","message","details"}}`. Codes come from
`docs/spec.md` §6.1 plus local extensions (`payload_too_large`,
`method_not_allowed`, `capability_unavailable` → 501). Internal failures are
returned only as `internal` with a generic message.

On `SIGTERM`/`SIGINT` the agent stops accepting connections and lets in-flight
requests finish for up to 5 seconds, then force-closes what remains.

## Operations (default, read-only)

| Operation | Result |
|---|---|
| `system.info` | host identity and the capability catalogue |
| `system.stats` | load average, memory, uptime read from `/proc` |
| `system.metrics` | live CPU percent, root disk usage and default-interface network throughput |
| `capabilities.refresh` | re-detect tools and capabilities |

`system.info` reads `/proc/sys/kernel/osrelease`, `/etc/os-release` and the
hostname; `system.stats` reads `/proc/loadavg`, `/proc/meminfo` and
`/proc/uptime`; `system.metrics` samples `/proc/stat` and `/proc/net/dev` twice
250 ms apart and stats the root filesystem, returning a null resource plus a
sanitized reason (`read_failed`, `invalid_data`, `no_default_route`) on any
partial failure; `capabilities.refresh` only performs PATH lookups. None of them
writes, spawns processes, or accepts a panel-supplied path. `detected_tools` reports only
`exec.LookPath` results — a present binary is *not* a managed capability. Every
managed feature (`php`, `database`, `firewall`, `docker`, `compose`,
`build_sandbox`, `backup`, `fail2ban`, `ssh`, `systemd`) currently reports
`available: false, reason: "unimplemented"`.

### Static-site operations (opt-in)

All four use the dedicated `static_sites` classification and require
`allow_static_sites = true`, including the non-mutating plan/status calls.
The actual `/v1/info` operation catalog is authoritative for the running agent.

| Operation | Parameters | Scope |
|---|---|---|
| `site.plan` | `domain` | preview derived paths and the fixed listener, without mutation |
| `site.status` | `domain` | managed-file state, not a runtime health probe |
| `site.apply` | `domain`, `operation_id` | initial root-owned static content and managed vhost |
| `site.remove` | `domain`, `operation_id` | remove only the managed vhost; retain content |

Parameter keys are validated against an exact, case-sensitive allowlist before
struct decoding: `DOMAIN`, `Domain`, paths, ports, snippets, extra fields and
duplicate keys are rejected. The domain must already be a lowercase ASCII DNS
hostname (at least two labels, no wildcard, IP literal or trailing dot).
Mutation IDs must be exactly 32 lowercase hexadecimal characters. Plan/status
do not accept `operation_id`; status/apply/remove require a live context deadline.
The adapter revalidates input independently. Retained content cannot be silently
adopted by a later create. No user accounts, writable uploads, PHP, Apache,
reverse proxy, workload TLS or general file-management API are included.

For synchronous create/remove, the panel dispatch budget is **90 s**, the
panel's site agent-client ceiling **95 s**, and the opt-in agent's HTTP operation
deadline **100 s** for `site.apply`/`site.remove`. Both panel and agent HTTP write
timeouts are **120 s**, leaving response/persistence headroom. Other agent
operations keep the **60 s** default; the longer mutation budget does not widen
read-only calls. Shutdown still has the shorter drain window described above;
a timeout, restart or lost response is not proof of rollback and requires
reconciliation rather than blind replay.

## Policy

`agent.toml` is a restricted flat key-value subset (no tables, no escapes, no
dotted keys). Recognised keys are `allow_root_terminal`, `allow_root_files`,
`allow_static_sites` (booleans), and `allowed_services` (string array), matching
`docs/spec.md` §5.3. Loader rules: regular file, owner equals the agent euid,
no group or world permission bits (`0600` recommended; `0400` also accepted), opened `O_NOFOLLOW` and read bounded to 64 KiB after an `fstat` on
the held descriptor.

### Enforcement

Policy is enforced in one place: `Server.dispatch`, the canonical path shared by
`/v1/info`, `/v1/ops/{name}` and the embedding `Registry.Run`. A handler cannot
run without passing it.

- Every registration carries exactly one permission at startup: `read_only`,
  `root_terminal`, `root_files`, `static_sites`, or `service:<target>`. Registering an unknown
  permission, more than one permission, or an invalid service target panics at
  startup. A registration with no permission is accepted but is denied at
  execution (`forbidden_by_policy`), so an unclassified operation can never run.
- `root_terminal` and `root_files` require the corresponding boolean in
  `agent.toml`. Services require an exact, case-sensitive match against
  `allowed_services`; no wildcard, suffix, prefix, path, shell or leading-dash
  target is accepted, and the target is fixed at registration — request
  parameters cannot select or widen it.
- Policy and the operation catalog (handlers and permission metadata) are
  copied once on first use and never reread. Later registrations cannot widen
  a running server, and dispatch and audit use the same snapshot. There is no
  remote reload.
- Unknown operations stay `not_found` (404). A known but unclassified operation
  is `forbidden_by_policy` (403).

### Narrow static-site exception; generic privileged operations unsupported

Policy permission alone does not enable a handler. The startup-selected
`static_sites` adapter is the only non-`read_only` exception: it uses a separate
private durable operation journal for identity, digest and recovery state before
mutation. That journal is distinct from the best-effort request logger. Pending
or ambiguous outcomes require manual reconciliation, not automatic replay; an
operation ID reused with different input conflicts.

`root_terminal`, `root_files` and `service:<target>` remain unsupported even
when their policy keys allow them: dispatch returns `unsupported` (501) without
calling those handlers. Policy denial still returns `forbidden_by_policy` (403).
No generic shell, file or service execution is auto-authorized, and those grants
do not authorize `site.*`. A broken request logger is not treated as durable
mutation evidence.

### Audit

Each request that reaches the HTTP layer emits one JSON record through `Logger`:
`event`, `outcome` (`success`/`failed`/`denied`), `operation`, `classification`,
optional `target`, `request_id`, `actor`, kernel `peer_uid`, `duration_ms`, and a
closed-set `error_code`. Operation and classification come from the startup
registry, never from the request. Unknown names are logged as `unknown`.

`peer_uid` is the `SO_PEERCRED` value on the accepted connection, not
`-allow-uid`. `request_id` and `actor` are recorded only after header validation.
Actor is panel-supplied audit context, never transport authentication or an
authorization grant.
Parameters, results, headers, bodies, paths and raw error text are never logged;
handlers that panic or return invented error codes are logged as `internal`.
Audit is a fixed-shape record, so a compromised panel cannot inject log fields.
Because `Logger` has no error return, failed writes (for example a panicking
sink) are recovered and cannot leak data, but they are not retried.

## Running for development

```sh
# as root, with a dedicated panel user/group (here: axionpanel)
make build
install -o root -g axionpanel -m 0750 -d /run/axionpanel
./bin/axionpanel-agent -socket /run/axionpanel/agent.sock \
  -policy /etc/axionpanel/agent.toml \
  -allow-uid axionpanel -socket-gid axionpanel
```

Test the socket from the panel user:

```sh
curl -sS --unix-socket /run/axionpanel/agent.sock \
  -H 'Axion-Protocol: 1' -H 'Axion-Request-ID: dev-1' -H 'Axion-Actor: 1' \
  http://unix/v1/info
```

Manual systemd templates exist in `deploy/systemd/`; they keep static sites
disabled. Installer host apply remains unavailable. This development example
does not prepare or enable the separate static-site adapter.
