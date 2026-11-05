# Secure onboarding primitives

Implemented: native HTTPS, explicit self-signed certificate initialization,
optional secret entrance and exclusive first-admin bootstrap file. These are
manual primitives, not a standalone installer or clean-VPS installation proof.
No hosting stack is required. These commands do not change firewall rules.

## Manual isolated example

Run as the intended panel user, on an empty data directory. Choose an unused
loopback port; do not replace an existing installation's files or credentials.
Build first with `make web && make build`.

```sh
install -d -m 700 ./data
./bin/axionpanel -init-tls -tls-host 127.0.0.1 \
  -tls-cert ./data/panel.crt -tls-key ./data/panel.key
./bin/axionpanel -init-entrance -entrance-file ./data/entrance
./bin/axionpanel -db ./data/panel.db -bootstrap-admin admin \
  -origin https://127.0.0.1:17800 \
  -entrance-file ./data/entrance -bootstrap-out ./data/bootstrap.json
./bin/axionpanel -db ./data/panel.db -addr 127.0.0.1:17800 \
  -origin https://127.0.0.1:17800 \
  -tls-cert ./data/panel.crt -tls-key ./data/panel.key \
  -entrance-file ./data/entrance
```

Bootstrap does not bind a listener. Native serving requires both certificate
and key. A self-signed certificate causes browser warnings; verify the printed
SHA-256 fingerprint through a trusted SSH connection before trusting it.
Do not expose port 7800 or the agent socket publicly. Remote access can use an
SSH tunnel preserving the configured browser origin and port.

Read `bootstrap.json` only through trusted local/SSH access. It contains
`username`, `password`, `entrance_path`, and `origin`. Visit that origin plus the
exact entrance path, then sign in. Do not send this file, passwords or entrance
paths through chat. Remove the bootstrap artifact once credentials are stored
securely; keep the entrance file available to the server. Keep encryption keys
separate from database backups.

## Guarantees and limits

- `-init-entrance` generates `/` plus 12 base64url characters from 9 random bytes.
  It cannot be combined with TLS initialization or administrator bootstrap.
- Entrance and bootstrap destinations are created exclusively, mode 0600, in a
  private directory owned by the effective user. Existing files are not replaced.
- `-bootstrap-out` requires `-bootstrap-admin` and `-entrance-file`. It writes no
  password or entrance value to stdout/stderr. Bootstrap refuses if any user
  exists. Concurrent file-bootstrap attempts serialize their database check.
- File creation/write failure rolls back the administrator transaction. A commit
  error retains the artifact because commit outcome may be ambiguous. Inspect
  local database state before retrying; do not assume rollback or delete the only
  recovery copy.
- Without `-entrance-file`, discovery gating is disabled for compatibility.
  Legacy bootstrap without `-bootstrap-out` still prints a generated password;
  do not run that mode through routine service logs.
- Exact GET to the entrance, without query or encoded aliases, returns 303 to
  `/login`. HEAD and other methods do not mint cookies.
- `axp_entrance` is HttpOnly, SameSite=Strict, Path=/, Secure except explicit
  insecure loopback development. Its signed timestamp enforces a 24-hour TTL
  server-side; the key is a domain-separated SHA-256 derivative of the path.
- Missing, malformed, duplicate, tampered or expired entrance cookies grant
  nothing. A genuine session verified against the database can bypass discovery.
  Entrance alone never grants a session, CSRF token, MFA completion or sudo.
- Denials return 404 with `Cache-Control: no-store` and
  `Referrer-Policy: no-referrer`. This reduces application discovery; it does not
  hide network/TLS fingerprints. Reverse proxies must avoid logging secret
  request paths. Do not publish the entrance in monitoring URLs.
- The health endpoint is gated too. Health probes need discovery credentials or
  a separately designed local mechanism; do not weaken this gate for monitoring.

Signed releases, systemd installer wiring, rerun/upgrade/recovery workflows and
clean-host validation remain separate work under [installation plan](installation-plan.md).
