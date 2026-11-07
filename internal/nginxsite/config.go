package nginxsite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrInvalidConfig      = errors.New("nginxsite: invalid config")
	ErrInvalidDomain      = errors.New("nginxsite: invalid domain")
	ErrInvalidOperationID = errors.New("nginxsite: invalid operation id")
	ErrDeadlineRequired   = errors.New("nginxsite: context deadline required")
	ErrUnsafePath         = errors.New("nginxsite: unsafe path")
	ErrPreexistingConfig  = errors.New("nginxsite: preexisting nginx config error")
	ErrConfigTestFailed   = errors.New("nginxsite: nginx config test failed")
	ErrReloadFailed       = errors.New("nginxsite: nginx reload failed")
	ErrOperationConflict  = errors.New("nginxsite: operation id reused with a different request")
	ErrInterruptedOp      = errors.New("nginxsite: interrupted operation requires manual reconcile")
	ErrRetainedContent    = errors.New("nginxsite: retained content cannot be adopted")
	ErrLocked             = errors.New("nginxsite: another operation holds the lock")
	ErrNotApplied         = errors.New("nginxsite: site is not applied")
	ErrNotServing         = errors.New("nginxsite: site is not serving")
	ErrStillServing       = errors.New("nginxsite: removed site is still being served")
	ErrReadinessUnknown   = errors.New("nginxsite: serving state could not be established")
)

// Config is the trusted, startup-supplied configuration. Every path is
// absolute and must already exist, root-owned (uid 0) with mode 0700, except
// the nginx binary/config which are read-only operator inputs. No field is
// ever derived from a request.
type Config struct {
	StateDir    string                      // journal, flock, pid — private root-only
	ContentDir  string                      // <domain>/public static content
	ConfigDir   string                      // vhost files, published atomically
	NginxBinary string                      // absolute path to nginx
	NginxConfig string                      // absolute path to the isolated main config
	Prefix      string                      // nginx -p
	Listen      string                      // literal "ip:port", trusted at startup
	Runner      Runner                      // optional trusted startup executor; nil uses os/exec
	Reloader    func(context.Context) error // optional trusted startup reloader (must be bounded by ctx)

	// Readiness is a focused test seam only. Nil — the production default — means
	// every mutation is verified by a bounded HTTP probe of the configured
	// literal listener. A non-nil value replaces that probe and is called with
	// the state that must hold (applied or not). It must itself respect ctx.
	Readiness func(ctx context.Context, domain string, applied bool) error
}

// Plan is a non-mutating description of what Apply would do.
type Plan struct {
	Domain  string `json:"domain"`
	Vhost   string `json:"vhost"`
	Root    string `json:"root"`
	Listen  string `json:"listen"`
	Applied bool   `json:"applied"`
	WouldDo string `json:"would_do"` // "create" | "update" | "noop"
}

// Result is returned by Apply, Remove and Status.
type Result struct {
	Domain      string `json:"domain"`
	OperationID string `json:"operation_id,omitempty"`
	Status      string `json:"status"` // applied|removed|absent|replayed
	Changed     bool   `json:"changed"`
}

var domainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validateDomain accepts only lowercase ASCII DNS hostnames with at least two
// labels. Wildcards, IP literals, trailing dots and IDN/punycode-adjacent
// shapes are rejected because the domain is used as a path component and as a
// server_name.
func validateDomain(d string) error {
	if d == "" || len(d) > 253 {
		return fmt.Errorf("%w: empty or too long", ErrInvalidDomain)
	}
	if strings.HasSuffix(d, ".") {
		return fmt.Errorf("%w: trailing dot", ErrInvalidDomain)
	}
	if net.ParseIP(d) != nil {
		return fmt.Errorf("%w: IP literal", ErrInvalidDomain)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: needs at least two labels", ErrInvalidDomain)
	}
	for _, l := range labels {
		if !domainLabel.MatchString(l) {
			return fmt.Errorf("%w: bad label %q", ErrInvalidDomain, l)
		}
	}
	// Reject numeric TLDs (IP-ish) and the reserved test/localhost shapes are
	// allowed only as ordinary names; nothing else to do.
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return fmt.Errorf("%w: numeric TLD", ErrInvalidDomain)
	}
	return nil
}

var opIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// validateOperationID requires exactly 32 lowercase hex characters.
func validateOperationID(id string) error {
	if !opIDPattern.MatchString(id) {
		return fmt.Errorf("%w: want 32 lowercase hex chars", ErrInvalidOperationID)
	}
	return nil
}

// requireDeadline refuses unbounded execution: every mutating call must carry
// a context deadline.
func requireDeadline(ctx interface{ Deadline() (time.Time, bool) }) error {
	if ctx == nil {
		return ErrDeadlineRequired
	}
	dl, ok := ctx.Deadline()
	if !ok || time.Until(dl) <= 0 {
		return ErrDeadlineRequired
	}
	return nil
}

// Validate checks shape and literal-address invariants without touching disk.
func (c Config) Validate() error {
	for name, p := range map[string]string{
		"StateDir":    c.StateDir,
		"ContentDir":  c.ContentDir,
		"ConfigDir":   c.ConfigDir,
		"NginxBinary": c.NginxBinary,
		"NginxConfig": c.NginxConfig,
		"Prefix":      c.Prefix,
	} {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p || !regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`).MatchString(p) {
			return fmt.Errorf("%w: %s must be a clean absolute path", ErrInvalidConfig, name)
		}
	}
	if err := literalListen(c.Listen); err != nil {
		return err
	}
	return nil
}

// literalListen accepts only a numeric IP literal plus port. Hostnames would
// reintroduce request-independent DNS resolution at bind time and are refused.
func literalListen(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("%w: Listen %q: %v", ErrInvalidConfig, listen, err)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("%w: Listen %q is not an IP literal", ErrInvalidConfig, listen)
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return fmt.Errorf("%w: Listen port invalid", ErrInvalidConfig)
	}
	if strings.HasPrefix(port, "0") && port != "0" {
		return fmt.Errorf("%w: Listen %q has a non-canonical port", ErrInvalidConfig, listen)
	}
	return nil
}

// openPinnedDir opens an existing directory without following a final
// symlink, returning a pinned handle usable for *at operations.
func openPinnedDir(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open dir %s: %v", ErrUnsafePath, path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("%w: wrap dir %s", ErrUnsafePath, path)
	}
	fi, err := f.Stat()
	if err != nil || !fi.IsDir() {
		f.Close()
		return nil, fmt.Errorf("%w: not a directory: %s", ErrUnsafePath, path)
	}
	return f, nil
}
