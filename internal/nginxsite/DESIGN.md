# Secure Nginx static-site adapter — implementation spec

Package: `internal/nginxsite`. New package; no other files touched.

## Public API

```go
type Config struct {
    StateDir    string // absolute, root-owned: journal, locks, pid
    ContentDir  string // absolute, root-owned: <domain>/public content
    ConfigDir   string // absolute, root-owned: conf.d vhosts + bak
    NginxBinary string // absolute executable; no shell
    NginxConfig string // absolute main config (isolated prefix's nginx.conf)
    Prefix      string // nginx -p prefix
    Listen      string // startup-trusted literal "address:port"
}

type Plan struct {
    Domain  string
    Vhost   string
    Root    string
    Listen  string
    Applied bool
    WouldDo string // "create" | "update" | "noop"
}

type Result struct {
    Domain      string
    OperationID string
    Status      string // "applied","removed","absent"
    Changed     bool
}

type Manager struct{ ... }

func New(cfg Config) (*Manager, error)
func (m *Manager) Close() error
func (m *Manager) Plan(domain string) (Plan, error)
func (m *Manager) Apply(ctx context.Context, operationID, domain string) (Result, error)
func (m *Manager) Remove(ctx context.Context, operationID, domain string) (Result, error)
func (m *Manager) Status(ctx context.Context, domain string) (Result, error)

type Runner interface { // optional trusted startup override
    Run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error)
}
// Config.Reloader func(context.Context) error opts into an isolated-harness
// reload; default sends `nginx -s reload` to the pinned prefix/config.
```

## Validation at the implemented boundary

The declarations above reflect the final package contract. Optional trusted
`Config.Runner Runner` and `Config.Reloader func(context.Context) error` are
startup-only overrides. They must honor context deadlines; production defaults
use fixed argv with `exec.CommandContext`, not a shell.

## Validation notes after implementation

The initial design below was written before the first suite. Where it differs,
`README.md` and the Go declarations are authoritative: only StateDir requires
0700; other roots/ancestors require root ownership and no group/other write.
Traversal uses Linux openat with O_NOFOLLOW on every component, not openat2.
Create publishes a new file; Remove uses .axionbak. No update operation exists.
Retained directories are always refused, regardless of marker presence.
Reload uses `nginx -s reload`, not `-s HUP`. Prefix/nginx main config remain
trusted startup inputs; operators must isolate their pid/log/temp paths.

## Original validation requirements (before first suite)

- domain: `[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+`, no wildcards, no IP, no trailing dot.
- operationID: 32 lowercase hex chars.
- ctx deadline required (bounded execution).

## Security invariants

- New() validates every dir is absolute, exists, root-owned 0700; parent dirs root-owned 0755.
- All managed-file opens: pinned fd (O_NOFOLLOW, O_DIRECTORY, O_CLOEXEC, OpenAt2 open_how if Go 1.23+) with owner/mode re-check on the open fd; symlink/hardlink into managed refs refused.
- Pre-created opt-in dirs: ConfigDir/conf.d, StateDir/journal, StateDir/logs, ContentDir/<domain>/public — only these, trusted at startup.
- Vhost template: closed — literal safe root, deny `.` files, deny `*.*` dynamic extensions (php, phtml, cgi, pl, py, asp, aspx, jsp, shtml), no includes.
- Apply/Remove: preexisting `nginx -t` gate first (fail → preexisting error, no writes).
- Atomic publish: write tmp → rename live to .axionbak → rename tmp to live → re-test → reload → delete bak; on failure restore bak + reload.
- Journal: append durable private record BEFORE mutation (operationID, request digest); completed records keep result. Same operationID + same digest → replay stored result. Same ID + different digest → conflict error. ID present with no completion record → interrupted → fail-closed `interrupted_operation` error (manual reconcile only; no replay).
- Locks: in-process mutex + flock on StateDir/nginxsite.lock (advisory, across processes).
- Remove: deletes vhost config (+bak), reloads; content data RETAINED, journal marked removed; re-Apply after Remove refuses adoption unless content dir empty of the marker — marker file `ContentDir/<domain>/.axion-managed` written at apply; if `.axion-managed` survives Remove, Apply must not silently adopt (Remove only deletes the vhost file, never the marker or content; so a re-Apply after Remove errors `retained_content`).
- No new listeners, no package installs; runner argv fixed at startup: `nginx -t -p <prefix> -c <cfg>`, `nginx -s HUP ...` (or kill HUP to pid).

## Test matrix (required)

1. Happy path: real nginx, isolated prefix, loopback high port; vhost live, content served.
2. Preexisting `nginx -t` fail → no writes, `preexisting_config_error`.
3. Reload/config failure after publish → rollback restores previous vhost, reload ok.
4. Domain validation: uppercase, wildcard, IP, empty, trailing dot, hyphen-edge → rejected.
5. Symlink injection: `ContentDir/<d>/public` symlinked to outside → refused; managed vhost symlinked → refused; hardlink swap refused.
6. operationID: 31/33 chars, non-hex, uppercase hex → rejected.
7. Duplicate Apply same opID+digest → result replay; changed request same opID → conflict; interrupted (crash sim) → fail-closed.
8. Remove: vhost gone, data retained, re-Apply → retained_content error.
9. Status reflects applied/removed/absent.
10. Non-root ownership of a managed dir → New() error.
11. Concurrency: two managers (flock) serialize.

Test gate: tests requiring nginx skip with clear message if binary missing; run with real /usr/bin/nginx.
