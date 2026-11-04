package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The zero value of Server must never accept root: uid 0 is only ever allowed
// through the explicit test/E2E escape hatch below.
func TestZeroValueAllowedUIDRejectsRootPeer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to dial as uid 0")
	}
	sock := makeSocket(t)
	s := &Server{Registry: builtins(t), Socket: sock}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	assertPeerDenied(t, sock)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// AllowRootPeer is the only way to admit uid 0, and only together with an
// explicit AllowedUID of 0.
func TestAllowRootPeerAcceptsRootWhenExplicit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to dial as uid 0")
	}
	sock := makeSocket(t)
	s := &Server{Registry: builtins(t), Socket: sock, AllowedUID: 0, AllowRootPeer: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = s.Serve(ctx, ln) }()
	if code := infoStatus(t, sock); code != 200 {
		t.Fatalf("status = %d", code)
	}
}

func infoStatus(t *testing.T, sock string) int {
	t.Helper()
	cli := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	req, _ := http.NewRequest("GET", "http://unix/v1/info", nil)
	req.Header.Set("Axion-Protocol", "1")
	req.Header.Set("Axion-Request-ID", "r")
	req.Header.Set("Axion-Actor", "1")
	res, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

func assertPeerDenied(t *testing.T, sock string) {
	t.Helper()
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := "GET /v1/info HTTP/1.1\r\nHost: x\r\nAxion-Protocol: 1\r\nAxion-Request-ID: forged-1\r\nAxion-Actor: 1\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		if !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatal(err)
		}
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if n > 0 {
		t.Fatalf("denied peer got %d response bytes: %q", n, buf[:n])
	}
	if err == nil {
		t.Fatal("denied peer connection not closed")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("denied peer connection hung (not closed)")
	}
}

// sliceListener replays pre-built conns, then reports closure.
type sliceListener struct {
	conns []net.Conn
}

func (l *sliceListener) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, net.ErrClosed
	}
	c := l.conns[0]
	l.conns = l.conns[1:]
	return c, nil
}
func (l *sliceListener) Close() error   { return nil }
func (l *sliceListener) Addr() net.Addr { return &net.UnixAddr{Name: "test", Net: "unix"} }

// Rejecting a queue must not add an attacker-controlled sleep to admission.
// Socketpair peers have real kernel credentials; all rejected connections close.
func TestPeerCheckedListenerRejectQueueDoesNotStall(t *testing.T) {
	const n = 300
	var peers []net.Conn
	inner := &sliceListener{}
	for i := 0; i < n; i++ {
		a, b, err := unixSocketPair()
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		defer b.Close()
		peers = append(peers, b)
		inner.conns = append(inner.conns, a)
	}
	l := &peerCheckedListener{Listener: inner, allowed: uint32(os.Geteuid()) + 1, allowRoot: true, logf: func(string, ...any) {}}
	start := time.Now()
	conn, err := l.Accept()
	elapsed := time.Since(start)
	if conn != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept=%v,%v", conn, err)
	}
	if elapsed > time.Second {
		t.Fatalf("reject queue stalled admission: %v (300 rejects must not impose 3s sleep)", elapsed)
	}
	for i, p := range peers {
		p.SetReadDeadline(time.Now().Add(time.Second))
		if k, err := p.Read(make([]byte, 1)); k != 0 || err == nil {
			t.Fatalf("rejected conn %d still open: n=%d err=%v", i, k, err)
		}
	}
}

func unixSocketPair() (net.Conn, net.Conn, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	mk := func(fd int) (net.Conn, error) {
		f := os.NewFile(uintptr(fd), "pair")
		defer f.Close()
		return net.FileConn(f)
	}
	a, err := mk(fds[0])
	if err != nil {
		syscall.Close(fds[1])
		return nil, nil, err
	}
	b, err := mk(fds[1])
	if err != nil {
		a.Close()
		return nil, nil, err
	}
	return a, b, nil
}

func TestServerForeignUIDClosedNotHung(t *testing.T) {
	sock := makeSocket(t)
	s := &Server{Registry: builtins(t), Socket: sock, AllowedUID: uint32(os.Geteuid()) + 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Forged valid headers must not bypass peer UID. The agent may close the
	// connection before the write completes; EPIPE/ECONNRESET also prove denial.
	req := "POST /v1/ops/system.info HTTP/1.1\r\nHost: x\r\nAxion-Protocol: 1\r\nAxion-Request-ID: forged-1\r\nAxion-Actor: 1\r\nContent-Length: 15\r\n\r\n{\"params\":{}}"
	if _, err := c.Write([]byte(req)); err != nil {
		if !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatal(err)
		}
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if n > 0 {
		t.Fatalf("foreign UID got %d response bytes: %q", n, buf[:n])
	}
	if err == nil {
		t.Fatal("foreign UID connection not closed")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("foreign UID connection hung (not closed)")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestServerGracefulShutdownClosesActiveConn(t *testing.T) {
	sock := makeSocket(t)
	s := &Server{Registry: builtins(t), Socket: sock, AllowedUID: uint32(os.Geteuid()), AllowRootPeer: true, ShutdownTimeout: 200 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Open a request and leave it hanging (no body end) so the conn is active.
	if _, err := c.Write([]byte("POST /v1/ops/system.info HTTP/1.1\r\nHost: x\r\nAxion-Protocol: 1\r\nAxion-Request-ID: g\r\nAxion-Actor: 1\r\nContent-Length: 5\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve error: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("shutdown took %v", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not await shutdown")
	}
	// Active conn must be force-closed by Shutdown timeout -> Close.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || err == nil {
		t.Fatalf("active conn still open after shutdown: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket not unlinked on close: %v", err)
	}
}

func TestServeShutdownNoGoroutineLeak(t *testing.T) {
	sock := makeSocket(t)
	s := &Server{Registry: builtins(t), Socket: sock, AllowedUID: uint32(os.Geteuid()), AllowRootPeer: true, ShutdownTimeout: 100 * time.Millisecond}
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	for i := 0; i < 3; i++ {
		c, err := net.DialTimeout("unix", sock, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("GET /v1/info HTTP/1.1\r\nHost: x\r\nAxion-Protocol: 1\r\nAxion-Request-ID: x\r\nAxion-Actor: 1\r\n\r\n"))
		c.SetReadDeadline(time.Now().Add(time.Second))
		io.Copy(io.Discard, c)
		c.Close()
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	time.Sleep(200 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("goroutines leaked: before=%d after=%d", before, after)
	}
}

func TestServeAwaitsActiveHandlerBeforeReturning(t *testing.T) {
	sock := makeSocket(t)
	started := make(chan struct{})
	exited := make(chan struct{})
	inspect := make(chan struct{})
	contextErr := make(chan error, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseHandler()
	r := NewRegistry()
	r.Register("test.slow", func(ctx context.Context, _ Params, _ RequestMeta) (any, error) {
		close(started)
		// Deliberately ignore cancellation: Shutdown must drain this work.
		<-inspect
		contextErr <- ctx.Err()
		<-release
		close(exited)
		return "finished", nil
	}, ReadOnly)
	s := &Server{Socket: sock, Registry: r, AllowedUID: uint32(os.Geteuid()), AllowRootPeer: true, ShutdownTimeout: 2 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("POST /v1/ops/test.slow HTTP/1.1\r\nHost: x\r\nAxion-Protocol: 1\r\nAxion-Actor: 1\r\nAxion-Request-ID: wait\r\nContent-Length: 13\r\n\r\n{\"params\":{}}")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler not started")
	}
	start := time.Now()
	cancel()
	close(inspect)
	select {
	case err := <-contextErr:
		// Signal cancellation must not reach handlers: it would abort in-flight
		// work instead of letting ShutdownTimeout drain it.
		if err != nil {
			t.Fatalf("handler context cancelled by signal: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not observe its context")
	}
	select {
	case <-done:
		t.Fatal("Serve returned while a handler still ran")
	case <-time.After(150 * time.Millisecond):
	}
	releaseHandler()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
			t.Fatalf("Serve returned before handler completed: %v", elapsed)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Serve did not return")
	}
	select {
	case <-exited:
	default:
		t.Fatal("Serve returned while handler still active")
	}
}

func TestSocketListenerCloseIdempotentAndUnlink(t *testing.T) {
	sock := makeSocket(t)
	s := &Server{Registry: builtins(t), Socket: sock, AllowedUID: uint32(os.Geteuid())}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket not unlinked: %v", err)
	}
}

func builtins(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	RegisterBuiltins(r)
	return r
}

func makeSocket(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "agent.sock")
}

func TestListenRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"writable-parent", "symlink-parent", "symlink-ancestor", "writable-ancestor", "foreign-parent", "file", "symlink", "stale-socket"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "run")
			if err := os.Mkdir(dir, 0750); err != nil {
				t.Fatal(err)
			}
			sock := filepath.Join(dir, "agent.sock")
			switch kind {
			case "writable-parent":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			case "writable-ancestor":
				if err := os.Chmod(base, 0777); err != nil {
					t.Fatal(err)
				}
			case "foreign-parent":
				if os.Geteuid() != 0 {
					t.Skip("requires chown privilege")
				}
				if err := os.Chown(dir, 12345, os.Getegid()); err != nil {
					t.Fatal(err)
				}
			case "symlink-parent", "symlink-ancestor":
				alias := filepath.Join(base, "alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink-ancestor" {
					if err := os.Mkdir(filepath.Join(dir, "nested"), 0750); err != nil {
						t.Fatal(err)
					}
					sock = filepath.Join(alias, "nested", "agent.sock")
				} else {
					sock = filepath.Join(alias, "agent.sock")
				}
			case "file":
				if err := os.WriteFile(sock, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(base, "missing"), sock); err != nil {
					t.Fatal(err)
				}
			case "stale-socket":
				l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				l.SetUnlinkOnClose(false)
				l.Close()
			}
			before, _ := os.Lstat(dir)
			s := &Server{Socket: sock, AllowedUID: uint32(os.Geteuid())}
			ln, err := s.Listen(context.Background())
			if err == nil {
				ln.Close()
				t.Fatal("unsafe socket path accepted")
			}
			after, _ := os.Lstat(dir)
			if before.Mode() != after.Mode() {
				t.Fatal("existing directory mode changed")
			}
			if kind == "stale-socket" && !strings.Contains(err.Error(), "manual") {
				t.Fatalf("operator cleanup absent: %v", err)
			}
			if kind == "file" {
				data, _ := os.ReadFile(sock)
				if string(data) != "keep" {
					t.Fatal("existing file changed")
				}
			}
		})
	}
}

func TestServerAcceptsAllowedPeerUID(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "agent.sock")

	r := NewRegistry()
	RegisterBuiltins(r)
	// Dials as the test process; AllowRootPeer lets this run when tests are root.
	s := &Server{Registry: r, Socket: sock, AllowedUID: uint32(os.Getuid()), AllowRootPeer: true}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = s.Serve(ctx, ln) }()

	c, err := net.DialTimeout("unix", sock, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest("GET", "http://unix/v1/info", nil)
	req.Header.Set("Axion-Protocol", "1")
	req.Header.Set("Axion-Request-ID", "r")
	req.Header.Set("Axion-Actor", "1")
	cli := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return c, nil
	}}}
	res, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

// systemd RuntimeDirectory= with Group=<panel> yields a root-owned direct
// parent with the socket group, typically 0755. That shape is safe: only
// root/euid can create entries, and the socket itself is 0660.
func TestListenAcceptsRootOwnedRuntimeDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires chown to root")
	}
	const gid = 4242
	for _, tc := range []struct {
		mode os.FileMode
		ok   bool
	}{{0755, true}, {0750, true}, {0775, false}, {0757, false}} {
		t.Run(fmt.Sprintf("%o", tc.mode), func(t *testing.T) {
			dir := filepath.Join(shortTempDir(t), "run")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(dir, 0, gid); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatal(err)
			}
			s := &Server{Socket: filepath.Join(dir, "agent.sock"), SocketGID: gid}
			ln, err := s.Listen(context.Background())
			if err == nil {
				ln.Close()
			}
			if tc.ok && err != nil {
				t.Fatalf("root:%d %o parent rejected: %v", gid, tc.mode, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("root:%d %o parent accepted", gid, tc.mode)
			}
			fi, _ := os.Stat(dir)
			if fi.Mode().Perm() != tc.mode {
				t.Fatalf("existing directory mode changed to %o", fi.Mode().Perm())
			}
		})
	}
}

// shortTempDir keeps socket paths under the 107-byte sun_path limit even for
// long test names (t.TempDir embeds the test name).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// The direct parent group must still match the socket group.
func TestListenRejectsRuntimeDirectoryWithWrongGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires chown")
	}
	dir := filepath.Join(shortTempDir(t), "run")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 0, 4243); err != nil {
		t.Fatal(err)
	}
	s := &Server{Socket: filepath.Join(dir, "agent.sock"), SocketGID: 4242}
	if ln, err := s.Listen(context.Background()); err == nil {
		ln.Close()
		t.Fatal("parent with foreign gid accepted")
	}
}

func TestListenRejectsMalformedPaths(t *testing.T) {
	for _, sock := range []string{"", "agent.sock", "./agent.sock", "/tmp/../tmp/agent.sock", "/tmp/agent.sock/", "/" + strings.Repeat("a", 120)} {
		if ln, err := (&Server{Socket: sock}).Listen(context.Background()); err == nil {
			ln.Close()
			t.Errorf("accepted %q", sock)
		}
	}
}

func TestListenCreatesPrivateParent(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "run", "agent.sock")
	s := &Server{Socket: sock, AllowedUID: uint32(os.Geteuid())}
	ln, err := s.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	di, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o750 {
		t.Fatalf("created dir mode=%o", di.Mode().Perm())
	}
	st := di.Sys().(*syscall.Stat_t)
	if st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) {
		t.Fatalf("created dir owner=%d:%d", st.Uid, st.Gid)
	}
}

func TestListenSetsSocketPermissions(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "agent.sock")
	r := NewRegistry()
	RegisterBuiltins(r)
	s := &Server{Registry: r, Socket: sock, AllowedUID: uint32(os.Getuid())}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %o, want 660", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o750 {
		t.Fatalf("socket dir mode = %o, want 750", di.Mode().Perm())
	}
	for name, info := range map[string]os.FileInfo{"socket": fi, "parent": di} {
		st := info.Sys().(*syscall.Stat_t)
		if st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) {
			t.Errorf("%s ownership=%d:%d want=%d:%d", name, st.Uid, st.Gid, os.Geteuid(), os.Getegid())
		}
	}
}

func TestListenRefusesLiveSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "agent.sock")
	r := NewRegistry()
	RegisterBuiltins(r)
	s := &Server{Registry: r, Socket: sock, AllowedUID: uint32(os.Getuid())}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := s.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := s.Listen(ctx); err == nil {
		t.Fatal("expected refusal for a live socket")
	}
}
