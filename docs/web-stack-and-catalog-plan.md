# Multi-web-server, multi-node load balancing and software catalog

Status: DESIGN / NOT IMPLEMENTED. Nginx + Apache support and managed-node HTTP
load balancing are approved additions to the MVP plan. The catalog architecture
below is a recommendation, not an already deployed external service. This
supplements [spec.md](spec.md) and [installation-plan.md](installation-plan.md).

## 1. Multi-web-server without a control-plane dependency

The panel serves its own HTTPS; installing or stopping either web server must
not affect panel access. Support these explicit hosting profiles:

- Nginx only: static, PHP-FPM and reverse-proxy sites.
- Apache only: static, PHP-FPM and reverse-proxy sites with a separate tested
  adapter, configuration validator and certificate/challenge integration.
- Nginx frontend + Apache backend: one owner of public HTTP/HTTPS listeners;
  Apache uses a dedicated loopback listener. Managed site metadata explicitly
  selects Nginx-native or Apache-backed routing. No implicit universal proxy
  configuration, public Apache backend or automatic port takeover.

Profiles may coexist only with non-overlapping listeners. Default recommendation
for a single-IP mixed host is Nginx frontend and Apache backend; Apache-only
remains available when Nginx is not installed. Explicit address-separated setups
need their own tested configuration contract. IPv4/IPv6 wildcard listeners,
HTTP/HTTPS and the independent panel port all participate in conflict checks.
Do not let package default starts briefly seize an existing listener during
installation: prepare safe first-start policy/configuration before starting.

Never equate adapter selection with taking ownership of an unmanaged service.
Changing a host profile needs dependency inventory, affected-site preview,
confirmed maintenance impact, configuration test, health checks and recovery.
Do not promise lossless Nginx-to-Apache configuration conversion. User snippets
and Apache per-directory overrides require separate validation/security rules;
`.htaccess` compatibility is not promised merely by installing Apache.
PHP execution uses reviewed FPM integration, not an implicit root or mod_php
fallback. Apache module/version/OS matrices must be verified before implementation.

One authoritative site model holds host ID, site ID, domains, hosting profile,
runtime, listener bindings, proxy target and TLS references. Existing API/schema
contracts that assume Nginx require reviewed extensions/migrations; do not ship a
second unrelated website database. Adapters render engine-specific configuration
and implement validate, apply, reload, health check and recovery semantics.

## 2. Managed-node HTTP load balancing

Multi-node enrollment/grouping was already in the MVP. Extend it with an explicit
HTTP/HTTPS load-balancer resource rather than treating grouping as scheduling.
Initial implementation recommendation: Nginx upstream groups on a selected
managed gateway host. This uses an optional hosting service, not the panel itself
as a traffic proxy. HAProxy and TCP/UDP balancing are not implied additions.

- Enrolled backend hosts have distinct mTLS identities and capability checks.
  Management mTLS does not establish application-network connectivity or backend
  TLS trust; verify private routing, ports, firewall and backend certificates
  separately. Never expose Docker sockets or local agent sockets as upstreams.
- Gateway, upstream members and ports are explicit, owner/scoped resources.
  Resolve members from enrolled/authorized host resources, enforce destination
  allowlists, prevent SSRF/control-plane/metadata targets, and revalidate changes.
- Initial options: round-robin or least-connections, weights, timeouts, passive
  failure thresholds, member disable/drain and explicit HTTP health-test results.
  Active probing is a separate future implementation contract, not a claim that
  every Nginx package has a bundled active-health feature. Drain changes need
  connection-lifetime limits and verification, not an instant zero-loss promise.
- Configure TLS termination and optional upstream TLS explicitly. Site keys remain
  on the hosts that terminate TLS; never share the panel HTTPS key. Certificate
  issuance/challenge routing and renewal must work through the chosen gateway.
- Handle Host headers, WebSockets, forwarding headers and client-IP trust as
  deliberate per-hop contracts. Validate/test/reload gateway changes with durable
  jobs, policy, sudo, audit, health gates and recovery of failed changes.

A load balancer does not synchronize application code, uploads, session storage
or databases. Deployment and runtime topology must disclose these prerequisites;
session affinity is not replicated session storage. Start with operator-prepared
backends; integrate existing Git/template deployment later, without claiming an
automatic distributed scheduler or database/storage replication.

A single gateway remains a single point of failure. Backend failure avoidance is
not gateway failover, control-plane HA, Raft or cross-host workload migration.
Redundant gateways/VIP/provider integration require a separate proposal and test
matrix, and are not included merely by adding an upstream group.

## 3. Software/services versus applications

Keep separate models and UI:

- Components: Nginx, Apache, PHP-FPM, MariaDB, Docker and other reviewed host
  runtimes. Installation uses typed OS-aware package adapters and trusted sources.
- Services: installed units, running/enabled state, versions, dependencies,
  managed/unmanaged ownership and safe operations.
- Applications: versioned curated manifests that consume those components or
  container runtimes, with configuration, permissions and data lifecycle.

All mutating actions need the existing policy, fresh sudo, durable agent mutation
audit and jobs prerequisites. No browser-supplied shell/package/repository command
is accepted. Package maintainer scripts and application build/install hooks are
execution boundaries, not harmless metadata.

## 4. Central catalog recommendation

Do not make every panel depend on a second live website/database service. Start
with a version-controlled catalog shipped in the signed release; later publish
immutable signed catalog snapshots and installer artifacts through static HTTPS
hosting. A separate public catalog/API website can be added for browsing and
maintainer workflows, but is not required to boot or operate an installed panel.
A catalog database, if introduced for authoring, is publication infrastructure,
not the panel metadata DB or a user hosting database.

Manifests declare stable ID/version, OS/architecture constraints, dependencies,
artifact source/digest/signature, reviewed recipe/adapter version, typed inputs,
secret fields, ports, privileges and upgrade/uninstall/data-retention behavior.
Avoid user-selectable arbitrary root installation scripts. App code/hooks/builds
need the existing isolated unprivileged worker and network/resource policies.

A remote signature does not authorize an automatic install: both publisher trust
and local policy/admin consent are required. Use an independently trusted root,
versioned immutable metadata, expiry/rollback checks and a documented trust-key
rotation/recovery procedure. Do not permit redirects/mirrors to bypass source
allowlists or integrity verification. Cache verified compatible catalog metadata;
show age/expiry and refuse unsafe stale/new installs rather than silently treating
old metadata as current. Exact metadata protocol remains an implementation choice.

A catalog outage must not prevent login, existing workloads or local service
management. New installs requiring uncached artifacts can fail clearly; do not
promise offline package installation without the packages and dependencies cached.

Suggested later separation: public documentation/catalog site, static signed
artifact distribution, and an optional private authoring/publishing backend.
Installed instances retain their own SQLite metadata and managed workload DBs.
There is no required central database of users' secrets, installed applications
or VPS state; remote reporting/telemetry would require a separate explicit design.

## 5. Order and acceptance

1. Standalone HTTPS/IP installer and secure setup remain first.
2. Durable jobs/mutation audit and optional component/service provisioning.
3. Nginx and Apache adapters plus coexistence/listener-conflict tests before
   declaring multi-web-server support complete.
4. Multi-node identity/routing foundation, then gateway/upstream lifecycle and
   two real backend hosts, TLS, failure/drain and network-policy acceptance tests.
5. Curated versioned catalog in signed releases; optional remote distribution
   before expanding automatic application installation.

All previously agreed MVP features remain in scope. Implementation may be staged,
but neither Apache nor HTTP load balancing should be called delivered from a UI
mock, package detection or standalone Nginx test. Update API/schema design before
implementing these new resource models; no new capability is live yet.
