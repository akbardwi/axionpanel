# Deployment: read-only systemd foundation

These are manual templates, not an installer. Review before running commands.
They do not configure nginx, databases, firewall rules, TLS, or public access.
The examples target Ubuntu 26.04 with systemd 259; other versions require their
own verification. See [agent.md](agent.md) for transport and policy details.

**This sample has no TLS and no public exposure.** The panel listens only on
`127.0.0.1:7800`, using `-origin http://127.0.0.1:7800 -insecure-loopback`.
Access it through an SSH tunnel. The flag removes `Secure` from cookies; do not
use this configuration on a public listener or behind a public proxy. Neither
binary currently implements HTTPS listener flags. Public deployment is outside
this guide; do not change nginx or an existing host database to follow it.

## Files and privileges

| Path | Owner:group | Mode | Purpose |
|---|---|---|---|
| `/usr/local/axionpanel/bin/{axionpanel,axionpanel-agent}` | root:root | 0755 | trusted executables |
| `/etc/axionpanel` | root:axionpanel | 0750 | configuration directory |
| `/etc/axionpanel/agent.toml` | root:root | 0400 | owner-only policy |
| `/var/lib/axionpanel` | axionpanel:axionpanel | 0700 | panel state and working directory |
| `/var/lib/axionpanel/panel.db` and WAL/SHM | axionpanel:axionpanel | 0600 | SQLite state, created under umask 077 |
| `/var/lib/axionpanel/secret.key` | axionpanel:axionpanel | 0600 | generated encryption key |
| `/run/axionpanel` | root:axionpanel | 0750 | agent runtime directory |
| `/run/axionpanel/agent.sock` | root:axionpanel | 0660 | peer-UID authenticated Unix socket |

The root agent uses `Group=axionpanel`, `-allow-uid axionpanel`, and
`-socket-gid axionpanel`. Create this group and the non-root system user before
starting either service. Keep group membership narrow. The panel's stable UID,
not a request header or group membership alone, authenticates the transport.
Do not run the panel or bootstrap command as root.

The policy file may be empty; comments are also valid. It must be a regular,
non-symlink file owned by the agent's effective UID (root here), with no group
or world permission bits. **Policy is parsed only, not enforced yet.** Current
deny-by-default behavior comes from the closed read-only operation registry,
not policy evaluation. Empty policy does not itself disable future operations.
Enforcement must accompany any future mutating operations. Today there is no
generic exec, terminal, or host mutation operation: only `system.info`,
`system.stats`, and `capabilities.refresh` are registered. Tool detection is
PATH lookup only, never tool execution or permission to manage that tool.

## Manual preparation (not performed by this guide)

Run commands below only after operator approval, as root except where stated.
Use a trusted, root-owned release checkout. Stop any existing panel and agent
before replacing binaries or changing state, and back up existing state first.
Do not apply these fresh-install commands blindly to existing installations.

1. Build as an ordinary build user in the repository, then return to root for
   installation. Use Go and Node versions specified by the project:

   ```sh
   make web
   make build
   ```

   `make web` embeds the frontend; building without it may serve a 503 at `/`.
   The resulting files are `bin/axionpanel` and `bin/axionpanel-agent`.

2. Create the dedicated primary group first, then the system user. These
   commands assume both names are unused; if either exists, inspect its UID,
   GID, primary group, memberships, home and login shell instead of reusing it
   blindly. Do not use an account belonging to another application.

   ```sh
   groupadd --system axionpanel
   useradd --system --gid axionpanel --home-dir /var/lib/axionpanel \
     --no-create-home --shell /usr/sbin/nologin axionpanel
   getent group axionpanel
   getent passwd axionpanel
   id axionpanel
   ```

   Alternatively install `deploy/systemd/axionpanel.sysusers.conf` as
   `/etc/sysusers.d/axionpanel.conf` (root:root 0644) and run
   `systemd-sysusers /etc/sysusers.d/axionpanel.conf` instead of `groupadd` and
   `useradd`. Do not use both methods. Missing user/group can fail with
   systemd `217/USER` or `216/GROUP`, before the executable runs.

3. Create trusted directories **before** installing binaries. All executable
   ancestors must be root-owned, not group/world writable, and not symlinks;
   the panel must never be able to replace its own executable or agent binary.
   Inspect any preexisting paths and do not silently change their ownership.

   ```sh
   install -d -o root -g root -m 0755 /usr/local/axionpanel /usr/local/axionpanel/bin
   install -d -o root -g axionpanel -m 0750 /etc/axionpanel
   install -d -o axionpanel -g axionpanel -m 0700 /var/lib/axionpanel
   install -o root -g root -m 0755 bin/axionpanel bin/axionpanel-agent /usr/local/axionpanel/bin/
   ```

   Alternatively use the supplied tmpfiles template for directory creation:
   install it as `/etc/tmpfiles.d/axionpanel.conf` (root:root 0644), then run
   `systemd-tmpfiles --create /etc/tmpfiles.d/axionpanel.conf`. It never creates
   or truncates policy and does not own `/run/axionpanel`. The unit's
   `StateDirectory=axionpanel` also creates the state directory on service
   startup, but bootstrap occurs before that, so create it explicitly here.

4. On a **fresh install only**, create the policy without overwriting an
   existing one. The supplied comment-only example is equivalent to an empty
   file. Inspect and edit an existing policy separately; do not truncate it.

   ```sh
   test ! -e /etc/axionpanel/agent.toml && test ! -L /etc/axionpanel/agent.toml && \
     install -o root -g root -m 0400 deploy/systemd/agent.toml.example /etc/axionpanel/agent.toml
   ```

5. With the panel stopped, bootstrap as its non-root user, using absolute paths
   and a safe working directory. `runuser` is available on the target Ubuntu
   host; the outer root shell is not the owner of the generated state.

   ```sh
   runuser -u axionpanel -- /bin/sh -c '
     cd /var/lib/axionpanel && umask 077 &&
     exec /usr/local/axionpanel/bin/axionpanel \
       -addr 127.0.0.1:7800 -origin http://127.0.0.1:7800 -insecure-loopback \
       -db /var/lib/axionpanel/panel.db \
       -secret-key /var/lib/axionpanel/secret.key \
       -agent-socket /run/axionpanel/agent.sock -bootstrap-admin admin
   '
   ```

   Bootstrap exits without serving HTTP or needing the agent. It refuses any
   database already containing a user. The generated password appears once on
   stdout: use a private terminal, avoid recordings/logging, store it securely,
   and complete the documented login/MFA setup. Do not put passwords in CLI
   arguments. Restrictive umask matters: SQLite otherwise creates files using
   the calling process's umask. Keep DB, WAL/SHM and encryption key private.

6. Install units but do not start them implicitly. Review actual installed
   flags first (`axionpanel -h`; agent flags are listed in `docs/agent.md`).
   An older panel binary without `-agent-socket` is incompatible.

   ```sh
   install -o root -g root -m 0644 deploy/systemd/axionpanel.service \
     deploy/systemd/axionpanel-agent.service /etc/systemd/system/
   systemd-analyze verify /etc/systemd/system/axionpanel.service /etc/systemd/system/axionpanel-agent.service
   systemctl daemon-reload
   systemctl start axionpanel-agent.service
   systemctl status --no-pager axionpanel-agent.service
   systemctl start axionpanel.service
   systemctl status --no-pager axionpanel.service
   curl --fail --silent --show-error http://127.0.0.1:7800/api/health
   ```

   Start only after verifying socket ownership and logs. An agent probe must
   run as the allowed UID, not root:

   ```sh
   runuser -u axionpanel -- curl --fail --silent --show-error \
     --unix-socket /run/axionpanel/agent.sock \
     -H 'Axion-Protocol: 1' -H 'Axion-Request-ID: deploy-check-1' \
     -H 'Axion-Actor: 1' http://unix/v1/info
   ```

   This is a local transport probe with synthetic audit actor 1, not a panel
   login test. For automatic boot startup, separately approve and run
   `systemctl enable axionpanel-agent.service axionpanel.service`. There is no
   socket activation and no `.socket` unit.

## SSH tunnel access

From your own workstation, use a loopback-bound SSH tunnel:

```sh
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:7800:127.0.0.1:7800 user@server
```

Browse exactly `http://127.0.0.1:7800/`. Do not use `localhost` or a different
local port: the browser origin must match `-origin` exactly. SSH encrypts the
remote leg; HTTP remains local on both ends. The listening service itself has
no TLS. Host-local processes and users still require trust; do not advertise
this as a production public-access configuration.

## Lifecycle, ordering and hardening

Both units use `Type=simple`; neither binary sends `sd_notify`. `After=` only
orders process startup, not socket readiness. `Wants=` pulls the agent up while
leaving login/UI available if the agent fails; host-data calls then fail closed.
The panel does not require a ready agent to bootstrap or serve its login page.

Agent SIGTERM/SIGINT handling drains requests for up to 5 seconds. The current
panel code also handles SIGTERM/SIGINT with a 10-second `http.Server.Shutdown`
deadline, then closes remaining connections. Both units use `TimeoutStopSec=15s`
for headroom. An idle signal-stop smoke exited 0 for both; this is not proof
that long-running requests drain correctly under systemd. `Restart=on-failure`
does not override an explicit systemctl stop. Failed startups are rate-limited
to 3 attempts/60 seconds; inspect failures before using `systemctl reset-failed`.

Hardening fits the read-only foundation, **not future host mutations**:

- `ProtectSystem=strict`, `ProtectHome=yes`, private devices/tmp, no new
  privileges, no namespace creation, no realtime scheduling or SUID/SGID file
  creation. Kernel tunables, modules, logs, clock and control groups protected.
- Panel capability set empty. Agent retains only `CAP_CHOWN` for socket metadata;
  it runs as root but has no generic command execution API. Future operations
  need a new privilege/sandbox review, not blanket removal of these limits.
- Agent accepts only `AF_UNIX`; panel permits Unix sockets and IPv4/IPv6 for
  loopback TCP. Address-family limits do not themselves constrain TCP addresses;
  the explicit `-addr 127.0.0.1:7800` does that.
- `SystemCallFilter=@system-service`, native syscall architecture and
  `MemoryDenyWriteExecute=yes`. These still require runtime sandbox testing on
  each target systemd/kernel/architecture; static validation is not that test.
- `/proc` deliberately remains visible: binding uses `/proc/self/fd`, while
  info/stats read kernel identity, load, memory and uptime there. No
  `ProtectProc=` or `ProcSubset=pid`, and no mask over `/proc`.
- Writable persistent paths are limited to systemd's `StateDirectory=` and
  `RuntimeDirectory=` exceptions. Private temporary storage is also writable.
  No host nginx/database configuration is writable through these units.

### Stale socket: inspect, stop, then remove manually

The agent refuses **every preexisting endpoint**, including a stale socket.
There is deliberately no `ExecStartPre=rm`. `RuntimeDirectoryPreserve=yes`
prevents systemd from erasing a preexisting/stale endpoint after failed startup;
ordinary agent shutdown removes its own socket. The directory remains until
reboot/manual removal. `/run` is ephemeral across boots.

1. Stop both services, confirm neither is active, and check for independently
   launched agents before touching the path:

   ```sh
   systemctl stop axionpanel.service axionpanel-agent.service
   systemctl is-active axionpanel.service axionpanel-agent.service
   pgrep -af axionpanel-agent
   ss -xlpn
   stat -c '%F %U:%G %a %n' /run/axionpanel /run/axionpanel/agent.sock
   ```

2. Only after confirming no listener/process owns that exact endpoint, verify
   the directory is not a symlink, is root:axionpanel 0750, and the stale object
   is the expected socket. Then remove **only that socket**, never recursively:

   ```sh
   test ! -L /run/axionpanel && test ! -L /run/axionpanel/agent.sock && \
     test -S /run/axionpanel/agent.sock && rm -- /run/axionpanel/agent.sock
   ```

   If the endpoint is a symlink, ordinary file, or otherwise unexpected, stop
   and investigate; do not automate its removal. Ancestors must be real safe
   directories, not symlinks or group/world writable. Never chmod/chown system
   ancestors to bypass an agent refusal.

3. Start agent, inspect logs/socket ownership, then start panel. If the start
   rate limit was reached, reset failure only after resolving its cause.

## Verification and limitations

From the repository root, without root privileges:

```sh
python3 scripts/verify-systemd.py
```

The script checks unit configuration against CLI flags in the actual Go
sources, directory/UID/socket contract, sandbox settings and documentation.
It runs this command with a disposable root under `$TMPDIR`:

```text
systemd-analyze --root=<scratch> verify axionpanel.service axionpanel-agent.service
```

That root contains synthetic passwd/group entries, minimal dependency targets
and executable placeholders at the production paths. No executable is launched;
no live account, unit or configuration is changed. Static verification returned
exit 0 with no diagnostics on systemd 259. Assertions first failed for missing
templates/docs, then passed after those files were added.

A separate direct-process smoke used freshly built binaries, root agent and an
existing non-root UID in temporary directories: `/v1/info` worked for the
allowed UID, root was refused, socket mode was 0660, an empty root-owned 0400
policy loaded, stale endpoints and wrong parent GID were refused, and graceful
agent stop removed its socket. Loopback panel health returned HTTP 200; idle
SIGTERM exited 0. This did **not** execute the systemd sandbox.

**Units not tested under PID1.** No actual install, enable, systemctl start,
account creation, nginx/database change or public listener was performed.
Runtime namespaces, syscall filtering, capability bounding, startup ordering,
full request draining, upgrades/reboot, bootstrap using the production paths,
and cross-platform compatibility remain unverified. Parent integration tests
cover the panel client separately; the direct smoke is not proof of every API.

## Operations notes

- Inspect with `journalctl -u axionpanel-agent.service -u axionpanel.service`.
  Do not bootstrap through journald; the generated password is stdout output.
- Back up SQLite consistently (SQLite online backup or stopped panel, preserving
  WAL/SHM as needed), together with `secret.key`; losing the key loses access to
  encrypted fields. Secure backups with the same privacy as live credentials.
- On upgrade, stop panel and agent, back up state/key, replace only trusted
  binaries/units, verify, reload and start in the documented order. Schema
  rollback is not promised; retain restorable backups.
- No `panel.toml`, TLS flags, mTLS remote transport, socket activation, generic
  exec or host mutation is supplied by this deployment. Design-spec paths for
  future features are not supported configuration for these binaries.
