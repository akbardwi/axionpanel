# Native panel HTTPS implementation plan (M2a)

Status: implemented in source, not deployed. Scope is the control-plane listener
only. Hosting web servers, installer automation and provisioning remain later.
This step does not complete the standalone-installation milestone.

## Manual local HTTPS example

After `make web && make build`, run as the intended non-root panel user in a
private working directory. This example uses loopback and does not open a public
port or configure a service/firewall. Do not replace an existing data directory.

```sh
install -d -m 700 ./data ./panel-tls
./bin/axionpanel -init-tls -tls-host 127.0.0.1 \
  -tls-cert ./panel-tls/cert.pem -tls-key ./panel-tls/key.pem
./bin/axionpanel -init-entrance -entrance-file ./data/entrance
./bin/axionpanel -db ./data/panel.db -bootstrap-admin admin \
  -origin https://127.0.0.1:8443 \
  -entrance-file ./data/entrance -bootstrap-out ./data/bootstrap.json
./bin/axionpanel -db ./data/panel.db \
  -addr 127.0.0.1:8443 -origin https://127.0.0.1:8443 \
  -tls-cert ./panel-tls/cert.pem -tls-key ./panel-tls/key.pem \
  -entrance-file ./data/entrance
```

Open the exact entrance path from `bootstrap.json`, then `https://127.0.0.1:8443`.
Bootstrap writes credentials to an exclusive 0600 file without printing them;
keep that file private. Verify the certificate fingerprint over SSH before
accepting any browser exception. See [secure onboarding](secure-onboarding.md)
for file permissions, failure behavior and gate limits. For a manually
approved direct-IP listener, generate the certificate for the chosen server IP
and change both `-addr` and `-origin` consistently. Do not expose port 7800 or the
agent socket; public service and firewall setup remain separate operator actions.
A health request with `curl --cacert ./panel-tls/cert.pem` verifies certificate
identity against the explicitly selected certificate, but the entrance gate
returns 404 until a valid discovery cookie is supplied. Keep any probe cookie
jar private. Ordinary startup never creates a missing certificate and never
falls back to HTTP.

## Goal

The panel binary serves embedded UI/API directly over HTTPS by IP or DNS without
Nginx/Apache/PHP/MariaDB. The existing loopback HTTP transport remains available
for SSH-tunnel development and explicitly configured reverse proxies.

## Configuration contract

- `-tls-cert` and `-tls-key`: both required together; validate readable regular
  files and matching PEM material before database/key initialization or listening.
  Symlinks to regular certificate/key files are allowed for managed certificate
  layouts. Reject unsafe private-key permissions and nonregular input files.
- `-addr`: safe default stays `127.0.0.1:7800`. Plain HTTP must bind a literal
  loopback IP or `localhost`, not a wildcard/public address. Trusted-proxy headers
  do not authorize public plaintext transport. The installer later selects an
  explicit native-HTTPS bind and port, typically `:8443`.
- `-origin`: existing exact-origin validation remains. Native TLS requires HTTPS,
  no `-insecure-loopback`, a certificate valid for the origin hostname and time,
  and the origin's effective port matching the listening port. The configured
  origin must already be in the browser's canonical serialization: no explicit
  `:443`, no leading-zero port, no expanded/uppercase IPv6, no legacy numeric IPv4
  spelling and no Unicode host. Startup fails with a canonical suggestion rather
  than accepting a URL that browsers would rewrite. Different concrete bind/origin
  IPs fail; a DNS origin is not compared literally with the bind IP because DNS and
  NAT can legitimately differ. Wildcard binding is compatible with a
  certificate-valid origin. No automatic DNS lookup establishes trust.
- Legacy loopback HTTP behind a reverse proxy still accepts the browser-facing
  HTTPS origin, whose port may differ from the local socket. Development HTTP
  origins still require explicit `-insecure-loopback` and loopback transport.
- Normal serving validates configuration, then acquires its listener before
  creating the encryption key or opening SQLite. Invalid listen-port syntax or
  bind failure must leave no new panel state and must not modify existing state.
  Certificate initialization and first-admin bootstrap do not acquire a listener.
- No plaintext fallback, implicit redirect listener, or extra opened port.
- TLS minimum 1.2 with Go's safe defaults. Keep existing server timeouts,
  header-size bound and graceful shutdown.
- HSTS remains omitted in this step, including for externally trusted certificates.
  Certificate trust at server startup alone does not establish every browser's
  trust or justify an irreversible long-lived HSTS policy.

## Explicit certificate initialization

`axionpanel -init-tls -tls-cert PATH -tls-key PATH -tls-host IP_OR_DNS`

- Generate an ECDSA P-256 self-signed server certificate with requested IP/DNS SAN,
  server-auth usage and bounded validity. Generated key mode is 0600; certificate
  mode is 0644 or stricter. Validate the single host input. Initialization and
  startup must agree on browser numeric-host identity: reject legacy numeric IPv4
  spellings and invalid numeric-final DNS names before creating either file;
  suggest a canonical IP when available rather than silently normalizing a SAN.
  IPv4-mapped IPv6 identities (for example `::ffff:7f00:1`) are unsupported:
  reject them during initialization, certificate loading and native-origin
  validation. Use IPv4 or native IPv6 instead; Go and other TLS clients differ
  on mapped-address SAN matching.
- Exit without creating/opening the panel database or encryption key.
- Refuse existing destinations, including symlinks; no force/overwrite option.
  Certificate/key paths must differ. Exclusive creation and failure cleanup must
  preserve pre-existing material. Use a private, operator-controlled directory;
  do not silently change its ownership or permissions.
- Print SHA-256 certificate fingerprint and validity for verification via SSH.
  Never print private-key material or put TLS files in the web root. Installer
  layout and service ownership are a later step.
- Self-signed certificates cause a browser warning. Fingerprint verification over
  SSH is required before accepting an exception; an SSH tunnel remains safer for
  initial access. No public HTTP login fallback.
- Existing first-admin bootstrap remains separate. Password output stays local
  and protected; never send credentials through chat or logs.

## Request behavior

- Use the prevalidated keypair in the server TLS configuration. No late switch
  to plaintext if loading or serving TLS fails.
- Native TLS validates request Host against configured origin authority. Existing
  mutation Origin/CSRF enforcement remains, including missing/wrong values.
- HTTPS session/challenge cookies remain Secure, HttpOnly and SameSite=Strict;
  the readable CSRF cookie remains Secure and SameSite=Strict, not HttpOnly.
  Explicit loopback HTTP development retains its documented Secure exception.
- Forwarded client-address headers remain trusted-proxy scoped, never trusted
  solely because TLS is enabled. Direct connections use socket peer address.
- Health uses the same listener and discloses no TLS paths/material. Existing
  HTML5 deep routes, strict CSP and JSON API 404 behavior remain unchanged.

## Verification gates

Use strict RED/GREEN cycles for new behavior, recording actual missing-feature
failures separately from supplemental regression coverage.

1. Test certificate generation, IP/DNS SANs, usage, validity, fingerprint, modes,
   overwrite/symlink refusal and partial-failure cleanup.
2. Test paired flags, malformed/missing/nonregular files, mismatched keypair,
   expired/not-yet-valid certificates, hostname mismatch and unsafe key modes.
3. Test native-origin scheme/port/IP validation, wildcard binding, DNS origins,
   and compatible legacy loopback proxy/development modes.
4. Exercise actual compiled binary on an isolated loopback port and scratch DB:
   trusted HTTPS health, password login, authenticated API, deep-path reload,
   logout, Secure cookies, wrong/missing Origin and CSRF, wrong Host, plaintext
   and TLS<1.2 rejection. Invalid startup must leave no listener or new DB/key.
5. Exercise browser against compiled embedded UI over HTTPS. Distinguish trust
   established through a test CA/fingerprint/SPKI from a browser runner that
   bypasses certificate errors; do not claim trust verification from bypass.
6. Keep HTTP lifecycle/auth/browser regression suites passing, run full Go race
   tests and vet, build a clean placeholder-only copy and production bundle,
   and obtain independent review before commit.

## Verification recorded for this change

- Parent-run full Go race suite and vet passed; clean placeholder-only archive
  overlay tests/build passed with 16 source files. Production frontend/binary
  build and 205 Node tests passed. Browser contract suites: auth 35 passed,
  lifecycle 5 passed, live data 2 passed/1 skipped.
- Invalid listen-port syntax and bind failures leave no new panel database or
  encryption key; normal serving reserves the listener before state creation.
- Real compiled HTTPS binary passed `curl --cacert` health, wrong-Host 421,
  plaintext rejection, OpenSSL TLS 1.1 protocol-version rejection and SIGTERM
  exit 0. Chromium exercised login, Secure cookies, reload, deep route and logout
  without runtime/CSP errors. Browser used an explicit generated SPKI exception,
  not operating-system trust-store installation. Host-data 503 is expected because
  this isolated browser test deliberately has no agent.
- Static systemd template verification: 120 assertions, zero failures. This does
  not exercise PID1 or establish a clean-VPS installer result.

## Deferred

ACME, automatic renewal/reload, HSTS, installer/signed release packaging, public
service migration, Update Manager and Software Version Manager.

Current live deployment stays `127.0.0.1:7800` behind Nginx. Tests open loopback
ports only. No live service, firewall or public listener changes in this step.
A clean-VPS installer matrix belongs to the installer milestone; loopback tests
on the development host are not proof of a clean-VPS installation.
