# Manual native-HTTPS systemd profile

Status: templates and static verification only; not an installer, not tested
under PID1. No clean-VPS, reboot or cross-distribution result is claimed.
Following the preparation steps does not open a public port; starting an edited
unit can expose its chosen address. There are no firewall changes here.
The existing loopback and Nginx deployment is not migrated by this guide.

## Scope and prerequisites

Use only on a deliberately prepared **fresh installation**, with no existing
panel state, units or credentials. Existing installations require a separate
backup and migration plan. Never run two panel units against the same database.
The sample uses `192.0.2.10`, a TEST-NET documentation address, not a usable server
address. Do not start the unedited sample.

Before continuing:

- Complete the account, trusted binary-directory and deny-by-default agent-policy
  preparation in [deployment.md](deployment.md), steps 1–4 only. Build embedded
  UI with `make web` before `make build`. Do not run its plaintext bootstrap or
  install its loopback panel unit for this profile.
- Verify `axionpanel` is the dedicated non-root account; `/var/lib/axionpanel` is
  `axionpanel:axionpanel 0700`, and binaries are root-owned, executable by the
  account and not writable by it. No Nginx, Apache, PHP or MariaDB is required.
- Choose an unprivileged port (example `8443`), advertised origin and certificate
  identity explicitly. Check selected bind address exists locally and port is
  unused. Never stop another service to free it.
- For NAT, the advertised IP can differ from the local interface. Use a deliberate
  wildcard bind such as `:8443` with the advertised IP in the origin/SAN; do not
  pretend the public NAT address is a local interface. A wildcard can expose all
  local interfaces when started. IPv6 bind/origin literals need brackets; the
  `-tls-host` value is unbracketed. DNS origins must use canonical ASCII spelling.
- Do not expose port `7800` or the agent. Public exposure, provider-network rules
  and firewall changes need explicit operator approval. SSH tunneling remains
  available; this guide does not authorize opening any port.

## 1. Create panel-only TLS material

Run as root in a private SSH session after inspecting all preexisting paths.
Refuse existing TLS destinations, symlinks or unexpected directory ownership;
these commands are not a repair procedure. The optional
`deploy/systemd/axionpanel-tls.tmpfiles.conf.example` describes the same directory,
not the files. Do not apply tmpfiles to silently change preexisting ownership.

```sh
install -d -o root -g axionpanel -m 0750 /etc/axionpanel/tls
umask 077
/usr/local/axionpanel/bin/axionpanel -init-tls -tls-host 192.0.2.10 \
  -tls-cert /etc/axionpanel/tls/panel.crt \
  -tls-key /etc/axionpanel/tls/panel.key
chown root:axionpanel /etc/axionpanel/tls/panel.crt /etc/axionpanel/tls/panel.key
chmod 0640 /etc/axionpanel/tls/panel.crt /etc/axionpanel/tls/panel.key
openssl x509 -noout -fingerprint -sha256 -in /etc/axionpanel/tls/panel.crt
```

Replace the example IP **before** generation. Certificate/key creation uses
exclusive destinations; it does not replace existing material. Root retains
write custody. `chgrp axionpanel` alone would also grant the intended group,
but never grant other users key access. The panel can read, not replace, its
TLS files. Site TLS keys remain separate and inaccessible to the panel.

The initial certificate is self-signed. Record its SHA-256 fingerprint over
SSH and independently compare it before accepting a browser exception. Browser
warnings are expected. Do not use `--insecure` as identity verification. Neither
loading TLS files nor an encrypted connection proves browser trust. Renewal,
reload, trusted-certificate acquisition and HSTS remain separate work.

## 2. Initialize private entrance and first administrator

Run before starting either panel profile. This creates state as the non-root
service account, not root, and writes credentials only to a local 0600 file.
Do not run bootstrap through a unit, journald, a recorded shell or chat. Review
[secure-onboarding.md](secure-onboarding.md) for failure and recovery behavior.

```sh
runuser -u axionpanel -- /bin/sh -c '
  cd /var/lib/axionpanel && umask 077 &&
  /usr/local/axionpanel/bin/axionpanel -init-entrance \
    -entrance-file /var/lib/axionpanel/entrance &&
  exec /usr/local/axionpanel/bin/axionpanel \
    -addr 192.0.2.10:8443 -origin https://192.0.2.10:8443 \
    -tls-cert /etc/axionpanel/tls/panel.crt \
    -tls-key /etc/axionpanel/tls/panel.key \
    -db /var/lib/axionpanel/panel.db \
    -secret-key /var/lib/axionpanel/secret.key \
    -entrance-file /var/lib/axionpanel/entrance \
    -bootstrap-admin admin -bootstrap-out /var/lib/axionpanel/bootstrap.json
'
```

Substitute the same chosen bind/origin/identity as the serving unit. Init and
bootstrap never acquire a listener. Successful bootstrap does not prove that
the configured address can bind or that the agent is reachable. Do not rerun
these commands to reset credentials: existing users/artifacts are refused.
Inspect partial failures and preserve recovery artifacts; never blindly delete
keys/database or regenerate credentials. Password and entrance path must not be
copied into unit files, command arguments or logs. Open the bootstrap file only
in a private local SSH session; it contains `origin`, `entrance_path`, `username`
and `password`. Its directory is 0700; entrance and bootstrap files are 0600.
Remove or securely archive the credential artifact after access is confirmed,
according to local backup policy. Keep the entrance file; the service needs it.

## 3. Review and install one panel profile

Copy and edit `deploy/systemd/axionpanel-native.service.example` in a private
staging directory. Replace TEST-NET `-addr` and `-origin` values, consistent with
certificate and bootstrap settings. The source example is not enabled by default.
Install it **as `axionpanel.service`**, not as a second concurrent service named
`axionpanel-native.service`. Use the existing read-only agent unit unchanged.

On the fresh target only, after explicit operator approval:

```sh
# Supply your reviewed, edited native profile; refuse existing destinations.
test ! -e /etc/systemd/system/axionpanel.service && \
  test ! -L /etc/systemd/system/axionpanel.service && \
  install -o root -g root -m 0644 ./axionpanel-native.service \
    /etc/systemd/system/axionpanel.service
test ! -e /etc/systemd/system/axionpanel-agent.service && \
  test ! -L /etc/systemd/system/axionpanel-agent.service && \
  install -o root -g root -m 0644 deploy/systemd/axionpanel-agent.service \
    /etc/systemd/system/axionpanel-agent.service
systemd-analyze verify /etc/systemd/system/axionpanel.service \
  /etc/systemd/system/axionpanel-agent.service
```

Stop on any failure. The checks above are fresh-host guardrails, not atomic
installation or protection against another privileged process changing paths.
Inspect vendor units/drop-ins and existing services too; absence of files at
these two paths alone does not prove the host is fresh.

Only after separate consent for the configured listener, reload systemd and
start the agent, verify its socket/allowed-UID probe per deployment.md, then
start the panel. Check actual active state and logs; `Type=simple` startup is not
readiness. Do not enable boot startup until readiness and recovery are verified.
No `ExecStartPre` generates keys, bootstraps users or deletes stale sockets.

## 4. Verify readiness without logging secrets

Probe from an allowed client with the selected certificate as an explicit trust
anchor (`curl --cacert /etc/axionpanel/tls/panel.crt`), never by ignoring errors.
Before entrance discovery, `/api/health` must return 404. After privately opening
the URL formed from bootstrap `origin` plus `entrance_path`, the browser receives
a Secure/HttpOnly/Strict discovery cookie; health then returns `status: ok`.
A bare health check returning 404 is not itself proof of readiness.

Do not paste the secret URL into a command argument, public monitor or shell
history. Automated probes must load it from the private artifact and keep cookie
jars private, with response/body/path logging disabled. Confirm administrator
login, authenticated API, expected certificate fingerprint, agent peer-UID
access, and refusal without valid credentials. The secret entrance is defense
in depth, not authentication and not concealment of TLS/network fingerprints.

## Verification limits

`python3 scripts/verify-systemd.py` validates both alternative panel profiles
against actual CLI flags and runs `systemd-analyze` in a disposable filesystem
root. It never starts a service or changes host accounts, units or firewall.
Executable placeholders in that static check do not test sandbox runtime.

PID1 sandbox execution, clean supported OS/architecture installations, reboot,
upgrade/recovery and externally reachable native HTTPS remain unverified for
this profile. The existing live Nginx-backed service remains unchanged.
