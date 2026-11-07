// Package nginxsite provisions root-owned initial static sites, not user
// accounts, uploads, PHP, TLS, or a general file manager.
package nginxsite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const managedMarker = "# axionpanel static v1\n"
const contentMarkerName = ".axion-managed"
const phasePending = "pending"
const phaseDone = "done"
const fileLimit = 64 << 10

// Runner is a trusted startup boundary. No request supplies executable or args.
type Runner interface {
	Run(context.Context, string, ...string) (string, string, error)
}
type execRunner struct{}
type boundedOutput struct{ data []byte }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	left := fileLimit - len(b.data)
	if left > len(p) {
		left = len(p)
	}
	b.data = append(b.data, p[:left]...)
	return n, nil
}
func (execRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	c.WaitDelay = time.Second
	var out, errout boundedOutput
	c.Stdout = &out
	c.Stderr = &errout
	e := c.Run()
	return string(out.data), string(errout.data), e
}

type journal struct {
	OperationID string  `json:"operation_id"`
	Action      string  `json:"action"`
	Domain      string  `json:"domain"`
	Digest      string  `json:"digest"`
	Phase       string  `json:"phase"`
	Result      *Result `json:"result,omitempty"`
	Error       string  `json:"error,omitempty"`
	Code        string  `json:"code,omitempty"`
}

func requestDigest(action, domain, listen string) string {
	b, _ := json.Marshal([]string{"static-v1", action, domain, listen})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Manager struct {
	cfg                            Config
	state, content, conf, lockFile *os.File
	gate                           chan struct{}
	closed                         bool
	runner                         Runner
	planTimeout                    time.Duration
	roots                          map[string]rootIdentity
}

// New pins preexisting root-owned roots with non-writable ancestors. StateDir
// must be 0700. It creates only the private lock file, never a listener.
func New(c Config) (m *Manager, err error) {
	if err = c.Validate(); err != nil {
		return nil, err
	}
	paths := []string{c.StateDir, c.ContentDir, c.ConfigDir}
	for i, p := range paths {
		for j, q := range paths {
			if i != j && (p == q || strings.HasPrefix(p, q+"/")) {
				return nil, fmt.Errorf("%w: overlapping roots", ErrInvalidConfig)
			}
		}
	}
	m = &Manager{cfg: c, runner: execRunner{}, gate: make(chan struct{}, 1), planTimeout: 5 * time.Second}
	if c.Runner != nil {
		m.runner = c.Runner
	}
	created := m
	defer func() {
		if err != nil {
			created.Close()
		}
	}()
	if m.state, err = trustedDir(c.StateDir, true); err != nil {
		return nil, err
	}
	if m.content, err = trustedDir(c.ContentDir, false); err != nil {
		return nil, err
	}
	if m.conf, err = trustedDir(c.ConfigDir, false); err != nil {
		return nil, err
	}
	// Packaging symlinks are permitted only for the startup-trusted executable;
	// canonical target and its ancestors must still meet ownership/mode checks.
	var resolved string
	resolved, err = filepath.EvalSymlinks(c.NginxBinary)
	if err != nil {
		return nil, err
	}
	c.NginxBinary = resolved
	m.cfg.NginxBinary = resolved
	if err = trustedInput(c.NginxBinary, true); err != nil {
		return nil, err
	}
	if err = trustedInput(c.NginxConfig, false); err != nil {
		return nil, err
	}
	var p *os.File
	p, err = trustedDir(c.Prefix, false)
	if err != nil {
		return nil, err
	}
	p.Close()
	m.lockFile, err = openAt(m.state, "nginxsite.lock", unix.O_CREAT|unix.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = m.pinRoots(); err != nil {
		return nil, err
	}
	return m, nil
}
func trustedDir(path string, private bool) (*os.File, error) {
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "/")
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(int(f.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		f.Close()
		if e != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrUnsafePath, path, e)
		}
		f = os.NewFile(uintptr(next), part)
		var st unix.Stat_t
		if e = unix.Fstat(next, &st); e != nil || st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
			f.Close()
			return nil, fmt.Errorf("%w: untrusted directory %s", ErrUnsafePath, path)
		}
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if private && st.Mode().Perm() != 0700 {
		f.Close()
		return nil, fmt.Errorf("%w: StateDir must be 0700", ErrUnsafePath)
	}
	return f, nil
}
func trustedInput(path string, executable bool) error {
	p, e := trustedDir(filepath.Dir(path), false)
	if e != nil {
		return e
	}
	defer p.Close()
	f, e := openAt(p, filepath.Base(path), unix.O_RDONLY, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	if executable && st.Mode().Perm()&0111 == 0 {
		return ErrUnsafePath
	}
	return nil
}
func openAt(root *os.File, name string, flags int, mode uint32) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return nil, ErrUnsafePath
	}
	fd, e := unix.Openat(int(root.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
	if e != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrUnsafePath, name, e)
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != 0 || st.Mode&0022 != 0 {
		f.Close()
		return nil, fmt.Errorf("%w: unsafe managed file %s", ErrUnsafePath, name)
	}
	return f, nil
}
func readAt(root *os.File, name string) ([]byte, error) {
	f, e := openAt(root, name, unix.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, fileLimit+1))
	if len(b) > fileLimit {
		return nil, ErrUnsafePath
	}
	return b, e
}
func renameAt(root *os.File, old, new string) error {
	if e := unix.Renameat(int(root.Fd()), old, int(root.Fd()), new); e != nil {
		return e
	}
	return root.Sync()
}
func unlinkAt(root *os.File, name string) error {
	if e := unix.Unlinkat(int(root.Fd()), name, 0); e != nil {
		return e
	}
	return root.Sync()
}
func writeExclusive(root *os.File, name string, data []byte, mode uint32) error {
	f, e := openAt(root, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = root.Sync()
	}
	return e
}
func (m *Manager) Close() error {
	m.gate <- struct{}{}
	defer func() { <-m.gate }()
	if m.closed {
		return nil
	}
	m.closed = true
	var errs []error
	for _, f := range []*os.File{m.lockFile, m.state, m.content, m.conf} {
		if f != nil {
			errs = append(errs, f.Close())
		}
	}
	return errors.Join(errs...)
}
func (m *Manager) acquire(ctx context.Context) (err error) {
	select {
	case m.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() {
		if err != nil {
			<-m.gate
		}
	}()
	if m.closed {
		return os.ErrClosed
	}
	if e := m.validateRoots(); e != nil {
		return e
	}
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		e := unix.Flock(int(m.lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			if e = m.validateRoots(); e != nil {
				unix.Flock(int(m.lockFile.Fd()), unix.LOCK_UN)
				return e
			}
			return nil
		}
		if !errors.Is(e, unix.EWOULDBLOCK) {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func (m *Manager) release() {
	unix.Flock(int(m.lockFile.Fd()), unix.LOCK_UN)
	<-m.gate
}
func (m *Manager) writeJournal(j journal) error {
	if e := m.validateRoots(); e != nil {
		return e
	}
	b, e := json.Marshal(j)
	if e != nil {
		return e
	}
	name := j.OperationID + ".json"
	tmp := name + ".tmp"
	// The record must be readable only by root before the mutation it
	// precedes. Reject an existing non-0600/non-root journal or tmp file
	// rather than silently accepting tampering.
	if err := m.assertJournalDir(); err != nil {
		return err
	}
	if e = writeExclusive(m.state, tmp, b, 0600); e != nil {
		return e
	}
	return renameAt(m.state, tmp, name)
}

func (m *Manager) assertJournalDir() error {
	var st unix.Stat_t
	if e := unix.Fstat(int(m.state.Fd()), &st); e != nil {
		return e
	}
	if st.Uid != 0 || st.Mode&0077 != 0 {
		return fmt.Errorf("%w: StateDir is not private", ErrUnsafePath)
	}
	return nil
}
func validJournal(j journal, id string) bool {
	if j.OperationID != id || validateOperationID(id) != nil || validateDomain(j.Domain) != nil || (j.Action != "apply" && j.Action != "remove") || len(j.Digest) != 64 || (j.Phase != phasePending && j.Phase != phaseDone) {
		return false
	}
	if j.Result != nil && (j.Result.OperationID != id || j.Result.Domain != j.Domain || (j.Result.Status != "applied" && j.Result.Status != "removed" && j.Result.Status != "absent")) {
		return false
	}
	return j.Phase != phaseDone || ((j.Result != nil) != (j.Error != ""))
}
func (m *Manager) readJournal(id string) (journal, bool, error) {
	var j journal
	if err := m.assertJournalDir(); err != nil {
		return j, true, err
	}
	b, e := readAt(m.state, id+".json")
	if errors.Is(e, os.ErrNotExist) {
		return j, false, nil
	}
	if e != nil {
		return j, false, e
	}
	if e = m.journalPathStat(id + ".json"); e != nil {
		return j, true, fmt.Errorf("%w: %v", ErrInterruptedOp, e)
	}
	if e = json.Unmarshal(b, &j); e != nil || !validJournal(j, id) {
		return j, true, fmt.Errorf("%w: corrupt journal", ErrInterruptedOp)
	}
	return j, true, nil
}

// journalPathStat checks a specific journal record's ownership/mode without
// following a symlink.
func (m *Manager) journalPathStat(name string) error {
	var st unix.Stat_t
	if e := unix.Fstatat(int(m.state.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0077 != 0 {
		return fmt.Errorf("%w: journal record %s is not a private root file", ErrUnsafePath, name)
	}
	return nil
}
func namesAt(root *os.File) ([]string, error) {
	fd, e := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "root")
	defer f.Close()
	names, e := f.Readdirnames(4097)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(names) > 4096 {
		return nil, fmt.Errorf("%w: directory capacity exceeded", ErrInterruptedOp)
	}
	return names, nil
}
func (m *Manager) checkJournals() error {
	names, e := namesAt(m.state)
	if e != nil {
		return e
	}
	for _, n := range names {
		if strings.HasSuffix(n, ".tmp") {
			return ErrInterruptedOp
		}
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		j, _, e := m.readJournal(strings.TrimSuffix(n, ".json"))
		if e != nil || j.Phase != phaseDone {
			return fmt.Errorf("%w: %s", ErrInterruptedOp, n)
		}
	}
	return nil
}
func (m *Manager) nginxT(ctx context.Context) error {
	if e := m.validateRoots(); e != nil {
		return e
	}
	_, out, e := m.runner.Run(ctx, m.cfg.NginxBinary, "-t", "-p", m.cfg.Prefix, "-c", m.cfg.NginxConfig, "-e", "stderr")
	if e != nil {
		return fmt.Errorf("nginx -t: %w: %.65536s", e, out)
	}
	return nil
}
func (m *Manager) reload(ctx context.Context) error {
	if e := m.validateRoots(); e != nil {
		return e
	}
	if m.cfg.Reloader != nil {
		return m.cfg.Reloader(ctx)
	}
	_, out, e := m.runner.Run(ctx, m.cfg.NginxBinary, "-p", m.cfg.Prefix, "-c", m.cfg.NginxConfig, "-s", "reload", "-e", "stderr")
	if e != nil {
		return fmt.Errorf("reload: %w: %.65536s", e, out)
	}
	return nil
}
func (m *Manager) render(domain string) string {
	return fmt.Sprintf(`%sserver {
    listen %s;
    server_name %s;
    root "%s";
    index index.html;
    autoindex off;
    disable_symlinks on;
    location ~ /\. { deny all; }
    location ~* \.(php[0-9]*|phtml|pht|phar|cgi|pl|py|jsp|shtml|sh|asp|aspx)([./]|$) { deny all; }
    location / { try_files $uri $uri/ =404; }
}
`, managedMarker, m.cfg.Listen, domain, filepath.Join(m.cfg.ContentDir, domain, "public"))
}
func (m *Manager) inspect(domain string) (Result, error) {
	b, e := readAt(m.conf, domain+".conf")
	if e == nil {
		if string(b) != m.render(domain) {
			return Result{}, fmt.Errorf("%w: unmanaged or modified config", ErrUnsafePath)
		}
		if err := m.verifyContent(domain); err != nil {
			return Result{}, err
		}
		return Result{Domain: domain, Status: "applied"}, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return Result{}, e
	}
	var st unix.Stat_t
	e = unix.Fstatat(int(m.content.Fd()), domain, &st, unix.AT_SYMLINK_NOFOLLOW)
	if e == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return Result{}, ErrUnsafePath
		}
		return Result{Domain: domain, Status: "removed"}, nil
	}
	if !errors.Is(e, unix.ENOENT) {
		return Result{}, e
	}
	return Result{Domain: domain, Status: "absent"}, nil
}

// verifyContent enforces the invariants on the applied site's content
// directory: it must exist with root ownership and correct modes, the
// public/ subdir must be a real directory (not a symlink/hardlink), the
// marker file must be present, and index.html must be a root-owned regular
// file. Any tampering fails the operation before any write.
func (m *Manager) verifyContent(domain string) error {
	sitePath := domain

	// site dir
	var st unix.Stat_t
	if e := unix.Fstatat(int(m.content.Fd()), sitePath, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return fmt.Errorf("%w: site dir %s: %v", ErrUnsafePath, domain, e)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
		return fmt.Errorf("%w: site dir %s is not a root-owned private dir", ErrUnsafePath, domain)
	}

	// open site dir by descriptor
	siteFd, e := unix.Openat(int(m.content.Fd()), sitePath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(siteFd)

	// public/ — must not be a symlink
	var pubSt unix.Stat_t
	if e = unix.Fstatat(siteFd, "public", &pubSt, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return fmt.Errorf("%w: public dir: %v", ErrUnsafePath, e)
	}
	if pubSt.Mode&unix.S_IFMT != unix.S_IFDIR || pubSt.Uid != 0 || pubSt.Mode&0022 != 0 {
		return fmt.Errorf("%w: public dir is unsafe", ErrUnsafePath)
	}
	pubFd, e := unix.Openat(siteFd, "public",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(pubFd)

	// marker — private, unlinked, root-owned regular file
	if e = unix.Fstatat(siteFd, contentMarkerName, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return fmt.Errorf("%w: missing content marker", ErrUnsafePath)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0077 != 0 {
		return fmt.Errorf("%w: content marker is not a private unlinked root file", ErrUnsafePath)
	}

	// index.html — regular root-owned file
	if e = unix.Fstatat(pubFd, "index.html", &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return fmt.Errorf("%w: index.html: %v", ErrUnsafePath, e)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0022 != 0 {
		return fmt.Errorf("%w: index.html is not a safe root-owned regular file", ErrUnsafePath)
	}
	return nil
}
func (m *Manager) Plan(domain string) (Plan, error) {
	if e := validateDomain(domain); e != nil {
		return Plan{}, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.planTimeout)
	defer cancel()
	if e := m.acquire(ctx); e != nil {
		return Plan{}, e
	}
	defer m.release()
	if e := m.checkJournals(); e != nil {
		return Plan{}, e
	}
	r, e := m.inspect(domain)
	if e != nil {
		return Plan{}, e
	}
	if r.Status == "removed" {
		return Plan{}, ErrRetainedContent
	}
	would := "create"
	if r.Status == "applied" {
		would = "noop"
	}
	return Plan{Domain: domain, Vhost: filepath.Join(m.cfg.ConfigDir, domain+".conf"), Root: filepath.Join(m.cfg.ContentDir, domain, "public"), Listen: m.cfg.Listen, Applied: r.Status == "applied", WouldDo: would}, nil
}
func (m *Manager) Status(ctx context.Context, domain string) (Result, error) {
	if e := requireDeadline(ctx); e != nil {
		return Result{}, e
	}
	if e := validateDomain(domain); e != nil {
		return Result{}, e
	}
	if e := m.acquire(ctx); e != nil {
		return Result{}, e
	}
	defer m.release()
	if e := m.checkJournals(); e != nil {
		return Result{}, e
	}
	return m.inspect(domain)
}
func (m *Manager) Apply(ctx context.Context, id, domain string) (Result, error) {
	return m.operate(ctx, id, domain, "apply")
}
func (m *Manager) Remove(ctx context.Context, id, domain string) (Result, error) {
	return m.operate(ctx, id, domain, "remove")
}
func savedError(j journal) error {
	if j.Error == "" {
		return nil
	}
	base := ErrInterruptedOp
	switch j.Code {
	case "config":
		base = ErrConfigTestFailed
	case "readiness":
		base = ErrNotServing
	default:
		base = ErrReloadFailed
	}
	return fmt.Errorf("%w: %s", base, j.Error)
}
func (m *Manager) operate(ctx context.Context, id, domain, action string) (Result, error) {
	if e := requireDeadline(ctx); e != nil {
		return Result{}, e
	}
	if e := validateDomain(domain); e != nil {
		return Result{}, e
	}
	if e := validateOperationID(id); e != nil {
		return Result{}, e
	}
	if e := m.acquire(ctx); e != nil {
		return Result{}, e
	}
	defer m.release()
	digest := requestDigest(action, domain, m.cfg.Listen)
	if j, found, e := m.readJournal(id); e != nil {
		return Result{}, e
	} else if found {
		if j.Digest != digest {
			return Result{}, ErrOperationConflict
		}
		if j.Phase != phaseDone {
			return Result{}, ErrInterruptedOp
		}
		if j.Result != nil {
			return *j.Result, savedError(j)
		}
		return Result{}, savedError(j)
	}
	if e := m.checkJournals(); e != nil {
		return Result{}, e
	}
	r, e := m.inspect(domain)
	if e != nil {
		return Result{}, e
	}
	if action == "apply" && r.Status == "removed" {
		return Result{}, ErrRetainedContent
	}
	if e = m.auditConfigs(); e != nil {
		return Result{}, e
	}
	if e = m.nginxT(ctx); e != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrPreexistingConfig, e)
	}
	j := journal{OperationID: id, Domain: domain, Action: action, Digest: digest, Phase: phasePending}
	if e = m.writeJournal(j); e != nil {
		return Result{}, e
	}
	r.OperationID = id
	r.Changed = false
	if action == "apply" && r.Status == "absent" {
		if e = m.createContent(domain); e == nil {
			e = m.publish(ctx, domain, false)
		}
		r.Status = "applied"
		r.Changed = e == nil
	} else if action == "remove" && r.Status == "applied" {
		e = m.publish(ctx, domain, true)
		r.Status = "removed"
		r.Changed = e == nil
	}
	if e == nil && !r.Changed && action == "apply" {
		// A no-op still answers "is the site operational?"; a config that exists
		// but is not served must not be reported applied. Nothing was mutated,
		// so the outcome is settled rather than pending.
		if ready := m.ready(ctx, domain, true); ready != nil {
			e = &settledError{fmt.Errorf("%w: %v", ErrNotServing, ready)}
		}
	}
	if e == nil && !r.Changed && action == "remove" {
		// Any unchanged "removed" outcome must still prove the listener is not
		// returning this site's content, whether or not managed content is
		// retained; other managed sites may keep listening.
		if ready := m.ready(ctx, domain, false); ready != nil {
			e = &settledError{ready}
		}
	}
	if e != nil {
		var restored *restoredError
		var settled *settledError
		if !errors.As(e, &restored) && !errors.As(e, &settled) {
			return Result{}, e
		}
		j.Phase = phaseDone
		j.Error = e.Error()
		switch {
		case errors.Is(e, ErrConfigTestFailed):
			j.Code = "config"
		case errors.Is(e, ErrNotServing), errors.Is(e, ErrStillServing), errors.Is(e, ErrReadinessUnknown):
			j.Code = "readiness"
		default:
			j.Code = "reload"
		}
		if we := m.writeJournal(j); we != nil {
			return Result{}, errors.Join(e, we)
		}
		return Result{}, e
	}
	j.Phase = phaseDone
	j.Result = &r
	if e = m.writeJournal(j); e != nil {
		return Result{}, fmt.Errorf("%w: completion journal: %v", ErrInterruptedOp, e)
	}
	return r, nil
}
func (m *Manager) auditConfigs() error {
	names, e := namesAt(m.conf)
	if e != nil {
		return e
	}
	for _, n := range names {
		if strings.HasSuffix(n, ".tmp") || strings.HasSuffix(n, ".axionbak") {
			return ErrInterruptedOp
		}
		if !strings.HasSuffix(n, ".conf") {
			continue
		}
		d := strings.TrimSuffix(n, ".conf")
		if validateDomain(d) != nil {
			return ErrUnsafePath
		}
		b, e := readAt(m.conf, n)
		if e != nil {
			return e
		}
		if string(b) != m.render(d) {
			return fmt.Errorf("%w: unmanaged config %s", ErrUnsafePath, n)
		}
	}
	return nil
}
func (m *Manager) createContent(domain string) error {
	if e := m.validateRoots(); e != nil {
		return e
	}
	if e := unix.Mkdirat(int(m.content.Fd()), domain, 0755); e != nil {
		return fmt.Errorf("%w: content exists: %v", ErrRetainedContent, e)
	}
	if e := m.content.Sync(); e != nil {
		return e
	}
	fd, e := unix.Openat(int(m.content.Fd()), domain, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	site := os.NewFile(uintptr(fd), domain)
	defer site.Close()
	if e = unix.Mkdirat(fd, "public", 0755); e != nil {
		return e
	}
	if e = site.Sync(); e != nil {
		return e
	}
	pubfd, e := unix.Openat(fd, "public", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	pub := os.NewFile(uintptr(pubfd), "public")
	defer pub.Close()
	if e = writeExclusive(pub, "index.html", []byte("<!doctype html><title>"+domain+"</title><h1>"+domain+"</h1>\n"), 0644); e != nil {
		return e
	}
	return writeExclusive(site, contentMarkerName, []byte("static-v1\n"), 0600)
}

type restoredError struct{ error }

func (e *restoredError) Unwrap() error { return e.error }

// settledError marks a no-mutation outcome that is nevertheless terminal for
// the operation: the managed state was not changed, but the requested serving
// claim could not be verified.
type settledError struct{ error }

func (e *settledError) Unwrap() error { return e.error }
func (m *Manager) publish(ctx context.Context, domain string, remove bool) error {
	if e := m.validateRoots(); e != nil {
		return e
	}
	live := domain + ".conf"
	bak := live + ".axionbak"
	tmp := live + ".tmp"
	rollback := func(cause error) error {
		if e := m.validateRoots(); e != nil {
			return errors.Join(cause, ErrInterruptedOp, e)
		}
		var restore error
		if remove {
			restore = renameAt(m.conf, bak, live)
		} else {
			restore = unlinkAt(m.conf, live)
		}
		if restore != nil {
			return errors.Join(cause, fmt.Errorf("%w: rollback restore: %v", ErrInterruptedOp, restore))
		}
		recovery, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := m.nginxT(recovery); e != nil {
			return errors.Join(cause, fmt.Errorf("%w: rollback config test: %v", ErrInterruptedOp, e))
		}
		if e := m.reload(recovery); e != nil {
			return errors.Join(cause, fmt.Errorf("%w: rollback reload: %v", ErrInterruptedOp, e))
		}
		if e := m.ready(recovery, domain, remove); e != nil {
			return errors.Join(cause, fmt.Errorf("%w: rollback readiness: %v", ErrInterruptedOp, e))
		}
		return &restoredError{cause}
	}
	if remove {
		if e := renameAt(m.conf, live, bak); e != nil {
			return e
		}
	} else {
		if e := writeExclusive(m.conf, tmp, []byte(m.render(domain)), 0644); e != nil {
			return e
		}
		if e := renameAt(m.conf, tmp, live); e != nil {
			return e
		}
	}
	if e := m.nginxT(ctx); e != nil {
		return rollback(fmt.Errorf("%w: %v", ErrConfigTestFailed, e))
	}
	if e := m.reload(ctx); e != nil {
		return rollback(fmt.Errorf("%w: %v", ErrReloadFailed, e))
	}
	if e := m.validateRoots(); e != nil {
		return errors.Join(ErrInterruptedOp, e)
	}
	if remove {
		if e := m.ready(ctx, domain, false); e != nil {
			return rollback(fmt.Errorf("%w: %v", ErrStillServing, e))
		}
		if e := m.validateRoots(); e != nil {
			return errors.Join(ErrInterruptedOp, e)
		}
		return unlinkAt(m.conf, bak)
	}
	if e := m.ready(ctx, domain, true); e != nil {
		return rollback(fmt.Errorf("%w: %v", ErrNotServing, e))
	}
	return nil
}
