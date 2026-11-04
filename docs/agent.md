# Agent

The AxionPanel **agent** is the privileged host daemon. The **panel** is the
unprivileged web/API process. The agent runs only the operations in a closed
registry and accepts requests only over a Unix socket whose peer UID the kernel
reports. This document is the operational reference for the foundation
implemented so far; the full protocol is specified in `docs/spec.md` §6.

## Status

Implemented and tested: socket transport, peer-UID gate, strict request
envelope, four read-only operations, and a host policy loader. Not yet
implemented: any mutating operation, remote mTLS transport, jobs/stats/terminal
endpoints, installer, and systemd unit.

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

## Operations (implemented, read-only)

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

## Policy

`agent.toml` is a restricted flat key-value subset (no tables, no escapes, no
dotted keys). The only recognised keys today are `allow_root_terminal`,
`allow_root_files` (booleans), and `allowed_services` (string array), matching
`docs/spec.md` §5.3. Loader rules: regular file, owner equals the agent euid,
no group or world permission bits (`0600` recommended; `0400` also accepted), opened `O_NOFOLLOW` and read bounded to 64 KiB after an `fstat` on
the held descriptor.

Known gap for future parameterized operations: Go's `encoding/json` matches
struct fields case-insensitively, so `name` and `NAME` decode into the same
field. The duplicate-key check catches exact repeats only. Before adding an
operation with parameters, decode case-sensitively or validate against a schema.

The policy is parsed and stored on the server, but no registered operation
consults it yet because the catalogue is read-only. Deny-by-default currently
comes from that read-only catalogue, not from policy evaluation. Before the
first privileged operation is added, enforcement must live in one place so a
new operation cannot forget to check it.

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

No installer or systemd unit exists yet; this is manual groundwork.
