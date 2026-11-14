# Direct listener discovery (M3a) — installer contract

Status: implemented; automated regression gates and independent review passed.
Clean-host systemd, reboot and real-firewall acceptance remain pending.
Scope is the standalone installer's choice of
browser-facing listener. The panel binary already serves native HTTPS for one
canonical origin; this milestone adds no DNS origins, ACME, multi-origin support
or address translation.

## Why

Operators may run the panel directly on a VPS without Nginx. The previous
loopback-only default required manual listener selection for direct access.
Route-source detection selects an address present on the machine; it does not
discover a public NAT identity or prove external access.

## Listener identity rules

- `--host auto` (new default) resolves the address the kernel selects for the
  default route. Detection uses a connected UDP socket to a documentation
  address and reads the local address; no packet is sent, no external service is
  contacted and no name is resolved. The resolved address is written back to
  `args.host`, so repeated validation under the lock cannot drift.
- Detection fails closed. Refused: no default route, loopback, unspecified,
  multicast, reserved or link-local results, and any address that is not
  canonical. The error names `--host` as the explicit alternative.
- An explicit `--host <IP>` keeps the existing canonical-unicast rules and stays
  the way to select `127.0.0.1` for an SSH tunnel or a reverse proxy.
- The panel binds, serves and certifies exactly one address: the resolved
  `--host`. There is no separate bind/origin identity and no wildcard listener.
- A non-loopback address still requires `--allow-public-listen`. `--yes` is
  consent to provision, never consent to publish a listener.
- The installer prints the resolved plan — listen address, origin, administrator
  and firewall action — and, without `--yes`, requires the operator to type
  `INSTALL` on the terminal. Anything else aborts before provisioning.
- When the resolved address is private or otherwise not globally routable, the
  summary calls it a **local address** and states that public reachability
  depends on the provider's routing. The installer never claims public access
  it did not verify.
- No new port is opened by default and port 7800/agent remain untouched.

## Firewall

`--open-firewall` is optional and explicit. Preconditions, checked read-only
before acquisition and repeated under the lock: the flag is combined with
`--apply`, the listener is not loopback, `/usr/sbin/ufw` is a root-owned
executable, and `ufw status` reports exactly `Status: active`. A missing,
inactive or ambiguous firewall is a refusal — never an implicit `ufw enable`,
`reset` or default-policy change, and never a switch to nftables/firewalld.

The installer adds `ufw allow <port>/tcp comment <invocation-id>` after local
readiness. A later failure triggers `ufw delete allow <port>/tcp comment
<invocation-id>`; unexpected command output or failed removal requires manual
reconciliation. Existing rules covering the port, including ranges or multiport
rules, and ambiguous status output are refused. Preconditions are rechecked
immediately before adding the rule. This does not lock out concurrent external
firewall administration. A same-tuple rule added concurrently can be retagged
by UFW before unexpected output causes failure, and rollback may remove it.
Avoid concurrent firewall changes during installation; comments do not provide
transactional ownership across this check/add race.
Other backends and cloud security lists stay manual operator actions.

## Acceptance

1. Detection unit tests cover selection, canonicalisation, absence of a default
   route, and refusal of loopback/unspecified/malformed results.
2. `--host` tests prove bind, origin, certificate host and readiness target are
   the same address, and that loopback needs no public consent.
3. Confirmation tests prove the plan is shown after discovery, that anything
   except `INSTALL` aborts before host checks, and that `--yes` bypasses only the
   prompt.
4. Firewall tests prove refusals before mutation, the exact single command, the
   after-readiness ordering and the delete-on-failure path; no test touches the
   host firewall.
5. Full installer suite, Go suite, web build/tests and a clean archive build pass,
   and an independent reviewer returns an explicit pass.
6. Isolated end-to-end apply with a real listener stays loopback; a real clean
   VPS and a real `ufw allow` remain unverified and must be reported as such.

## Deliberately excluded

Public-IP/NAT address translation (`--public-ip`, wildcard binds, split
bind/origin identity), DNS/domain origins, ACME and renewal, certificate
replacement for a changed address, multi-origin serving, IPv6-only default
routes, cloud provider security lists, firewalld/nftables support, and any
automatic public-IP lookup over the network.
