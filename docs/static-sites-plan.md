# Static Nginx websites — first vertical slice

Status: integration and review in progress; no live service adoption or deployment.

This deliberately narrow slice adds local static HTTP websites only. PHP, Apache,
reverse proxy, TLS, DNS changes, package installation, file editing/uploads,
suspension and remote nodes remain unavailable. The control plane stays independent
of Nginx. Existing Nginx configuration is never adopted automatically.

## Trust and ownership

Website operations are absent from the default agent catalog. An operator must
explicitly select a dedicated, prepared Nginx configuration/prefix, trusted binary,
managed configuration/content/private-state directories and listener at startup.
Host policy must separately enable the dedicated `allow_static_sites` permission. Requests
may select only a validated domain and an operation identity, never paths, ports,
service names, commands, snippets or an executable. No installer or package-start
side effects are part of this slice.

Static initial content is root-owned and is not executable. There are no site OS
users or writable application runtimes yet. The site model must describe this
limited ownership truthfully; it must not insert fictitious users to satisfy the
old speculative schema. A migration may make the site system-user relationship
optional for static-only sites while retaining existing records and references.
Multi-tenant isolation and writable uploads are not claimed.

## Workflow

1. Signed-in admin opens `/websites`; inventory comes from SQLite, never samples.
2. A safe read plan previews the normalized domain, fixed listener and derived
   document root. An unavailable/unconfigured agent explains why; no fallback to
   a different host or unmanaged Nginx occurs.
3. Create/remove require the existing exact-Origin, session CSRF and fresh sudo
   checks. The server derives actor and local host identity, validates the request
   again and commits site/domain reservation, job and audit intent together before
   dispatch. Each job gets a random operation ID. Duplicate domains conflict.
4. Agent validates independently, locks its Nginx subsystem across requests and
   processes, journals operation identity/digest before mutation, and checks the
   baseline Nginx configuration before writing. It publishes only managed files,
   validates the new configuration, reloads and records a terminal result.
5. Failure restores the managed configuration and attempts recovery. Ambiguous
   outcomes are errors requiring reconciliation, never automatic replay. Repeated
   IDs with different input conflict; an interrupted journal is not rerun.
6. Panel records terminal job/site state. Process restarts mark unfinished work
   interrupted/manual-reconciliation rather than pretending success or replaying.
   A lost response must not be advertised as a successful rollback.
7. Remove requires the domain as explicit confirmation. Only the managed vhost is
   removed. Content is retained, disclosed to the user and cannot be silently
   adopted by a later create. No recursive data deletion endpoint is provided.

## Acceptance gates

- Test-first changes with observed RED then GREEN; full Go tests/race/vet and web
  tests/build. A clean tracked checkout still builds without ignored assets.
- Strict validation, policy denial before mutation, duplicate-domain serialization,
  cross-process locking, symlink/hardlink/path escape rejection, journal replay and
  crash ambiguity, baseline failure, config/reload rollback and retained content.
- Real Nginx in a private prefix and a high loopback port: create → HTTP content,
  dotfile/dynamic-source denial → status → remove with retained files.
- Bounded readiness probes verify that applied and roll-backed configurations
  actually serve before success; reload signals alone are never sufficient.
  Cross-process and context-aware in-process serialization preserve operation
  deadlines; pinned directory ownership/modes are revalidated at operation
  boundaries.
- End-to-end test proves real session → panel API → Unix agent → isolated
  Nginx → durable metadata/content-retained removal, without touching host
  services.
- Auth integration covers missing session, bad Origin/CSRF, stale sudo, non-admin,
  audit failure before dispatch and durable job retrieval. Browser smoke uses the
  production bundle, real paths and no CSP violations or fabricated live data.
- No restart/reload or configuration changes to existing host services; test
  listeners are isolated, high-port and loopback-only. No deployment.
