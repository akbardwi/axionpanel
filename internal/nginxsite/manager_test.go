package nginxsite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) Config {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root ownership contract")
	}
	// /root is trusted (unlike /tmp). Nginx workers run root ONLY in this isolated harness.
	base, err := os.MkdirTemp("/root/.hermes/cache/scratch", "nginxsite-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	c := testConfig(t, base)
	for _, p := range []string{c.StateDir, c.ConfigDir, c.ContentDir, c.Prefix, filepath.Join(c.Prefix, "logs")} {
		if err := os.Mkdir(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	os.Chmod(c.StateDir, 0700)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.Listen = ln.Addr().String()
	ln.Close()
	c.NginxBinary, err = exec.LookPath("nginx")
	if err != nil {
		t.Skip("real nginx unavailable")
	}
	main := fmt.Sprintf("user root;\nworker_processes 1;\npid %s/nginx.pid;\nerror_log %s/error.log;\nevents { worker_connections 32; }\nhttp { access_log off; client_body_temp_path %s/body; proxy_temp_path %s/proxy; fastcgi_temp_path %s/fastcgi; uwsgi_temp_path %s/uwsgi; scgi_temp_path %s/scgi; include %s/*.conf; }\n", c.Prefix, c.Prefix, c.Prefix, c.Prefix, c.Prefix, c.Prefix, c.Prefix, c.ConfigDir)
	if err := os.WriteFile(c.NginxConfig, []byte(main), 0600); err != nil {
		t.Fatal(err)
	}
	return c
}
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

const op1 = "00000000000000000000000000000001"
const op2 = "00000000000000000000000000000002"
const op3 = "00000000000000000000000000000003"
const op4 = "00000000000000000000000000000004"

func manager(t *testing.T, c Config) *Manager {
	t.Helper()
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func TestRealNginxLifecycle(t *testing.T) {
	c := fixture(t)
	// Start only the test prefix, never the system instance.
	cmd := exec.Command(c.NginxBinary, "-p", c.Prefix, "-c", c.NginxConfig, "-e", "stderr")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("start nginx: %v: %s", e, out)
	}
	t.Cleanup(func() {
		exec.Command(c.NginxBinary, "-p", c.Prefix, "-c", c.NginxConfig, "-s", "quit", "-e", "stderr").Run()
	})
	m := manager(t, c)
	ctx := testCtx(t)
	before, _ := os.ReadDir(c.ContentDir)
	p, e := m.Plan("example.com")
	if e != nil || p.Domain != "example.com" {
		t.Fatalf("plan %v %v", p, e)
	}
	after, _ := os.ReadDir(c.ContentDir)
	if len(before) != len(after) {
		t.Fatal("plan mutated")
	}
	r, e := m.Apply(ctx, op1, "example.com")
	if e != nil || r.Status != "applied" {
		t.Fatalf("apply %v %v", r, e)
	}
	replay, e := m.Apply(ctx, op1, "example.com")
	if e != nil || replay != r {
		t.Fatalf("replay %v %v", replay, e)
	}
	if _, e = m.Apply(ctx, op1, "other.com"); !errors.Is(e, ErrOperationConflict) {
		t.Fatalf("conflict: %v", e)
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	request := func(path string) (int, string) {
		req, _ := http.NewRequest("GET", "http://"+c.Listen+path, nil)
		req.Host = "example.com"
		resp, e := client.Do(req)
		if e != nil {
			return 0, e.Error()
		}
		defer resp.Body.Close()
		b := make([]byte, 2048)
		n, _ := resp.Body.Read(b)
		return resp.StatusCode, string(b[:n])
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		code, body := request("/")
		if code == 200 && strings.Contains(body, "example.com") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve: %d %s", code, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, name := range []string{".secret", "x.php", "x.PHP", "x.php.bak", "x.phtml", "x.cgi"} {
		os.WriteFile(filepath.Join(c.ContentDir, "example.com", "public", name), []byte("SECRET"), 0644)
		code, body := request("/" + name)
		if code != 403 || strings.Contains(body, "SECRET") {
			t.Errorf("source disclosure %s: %d %s", name, code, body)
		}
	}
	status, e := m.Status(ctx, "example.com")
	if e != nil || status.Status != "applied" {
		t.Fatalf("status %v %v", status, e)
	}
	if _, e = m.Remove(ctx, op2, "example.com"); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(c.ContentDir, "example.com", "public", "index.html")); e != nil {
		t.Fatal("content was not retained", e)
	}
	if _, e = m.Apply(ctx, op3, "example.com"); !errors.Is(e, ErrRetainedContent) {
		t.Fatalf("retained adoption: %v", e)
	}
	status, e = m.Status(ctx, "example.com")
	if e != nil || status.Status != "removed" {
		t.Fatalf("removed status %v %v", status, e)
	}
}

// TestBoundaryAndRecovery uses real nginx -t; only reload is injected so the
// failure is deterministic and cannot signal any non-test process.
func unitFixture(t *testing.T) Config {
	t.Helper()
	c := fixture(t)
	// No nginx process serves this fixture: reload and readiness are the only
	// injected boundaries, so lifecycle mechanics stay deterministic. The
	// real-binary probe is exercised unmocked by TestRealNginxLifecycle and the
	// readiness tests.
	c.Reloader = func(context.Context) error { return nil }
	c.Readiness = func(context.Context, string, bool) error { return nil }
	return c
}

func TestBoundaryAndRecovery(t *testing.T) {
	t.Run("preexisting", func(t *testing.T) {
		c := unitFixture(t)
		c.Reloader = func(context.Context) error { return nil }
		m := manager(t, c)
		os.WriteFile(c.NginxConfig, []byte("invalid;"), 0600)
		if _, e := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(e, ErrPreexistingConfig) {
			t.Fatal(e)
		}
		for _, d := range []string{c.ConfigDir, c.ContentDir} {
			ls, _ := os.ReadDir(d)
			if len(ls) != 0 {
				t.Fatal("preexisting failure wrote", d)
			}
		}
		if _, e := os.Stat(filepath.Join(c.StateDir, op1+".json")); !os.IsNotExist(e) {
			t.Fatal("preexisting failure journaled")
		}
	})
	t.Run("reload rollback", func(t *testing.T) {
		c := unitFixture(t)
		calls := 0
		c.Reloader = func(context.Context) error {
			calls++
			if calls == 1 {
				return errors.New("injected reload failure")
			}
			return nil
		}
		m := manager(t, c)
		if _, e := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(e, ErrReloadFailed) {
			t.Fatal(e)
		}
		if calls != 2 {
			t.Fatalf("rollback reload calls=%d", calls)
		}
		if _, e := os.Stat(filepath.Join(c.ConfigDir, "example.com.conf")); !os.IsNotExist(e) {
			t.Fatal("config not rolled back")
		}
	})
	t.Run("symlink config", func(t *testing.T) {
		c := unitFixture(t)
		c.Reloader = func(context.Context) error { return nil }
		m := manager(t, c)
		os.Symlink(c.NginxConfig, filepath.Join(c.ConfigDir, "example.com.conf"))
		if _, e := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(e, ErrUnsafePath) {
			t.Fatalf("symlink %v", e)
		}
	})
	t.Run("retained symlink content", func(t *testing.T) {
		c := unitFixture(t)
		c.Reloader = func(context.Context) error { return nil }
		m := manager(t, c)
		os.Symlink(c.Prefix, filepath.Join(c.ContentDir, "example.com"))
		if _, e := m.Apply(testCtx(t), op1, "example.com"); e == nil {
			t.Fatal("adopted symlink")
		}
	})
	t.Run("hardlink config", func(t *testing.T) {
		c := unitFixture(t)
		c.Reloader = func(context.Context) error { return nil }
		m := manager(t, c)
		os.Link(c.NginxConfig, filepath.Join(c.ConfigDir, "example.com.conf"))
		if _, e := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(e, ErrUnsafePath) {
			t.Fatalf("hardlink %v", e)
		}
	})
	t.Run("unmanaged config", func(t *testing.T) {
		c := unitFixture(t)
		c.Reloader = func(context.Context) error { return nil }
		m := manager(t, c)
		path := filepath.Join(c.ConfigDir, "example.com.conf")
		os.WriteFile(path, []byte("# unmanaged"), 0644)
		if _, e := m.Apply(testCtx(t), op1, "example.com"); e == nil {
			t.Fatal("adopted unmanaged config")
		}
		b, _ := os.ReadFile(path)
		if string(b) != "# unmanaged" {
			t.Fatal("modified unmanaged config")
		}
	})
}

func TestInterruptedJournalFailsClosed(t *testing.T) {
	c := unitFixture(t)
	c.Reloader = func(context.Context) error { return nil }
	m := manager(t, c)
	j := journal{OperationID: op1, Action: "apply", Domain: "example.com", Digest: requestDigest("apply", "example.com", c.Listen), Phase: phasePending}
	if err := m.writeJournal(j); err != nil {
		t.Fatal(err)
	}
	m.Close()
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(err, ErrInterruptedOp) {
		t.Fatal(err)
	}
	if _, err := m.Apply(testCtx(t), op2, "other.com"); !errors.Is(err, ErrInterruptedOp) {
		t.Fatalf("global fail closed %v", err)
	}
}

func TestNewRejectsUnsafeAncestors(t *testing.T) {
	c := fixture(t)
	os.Chmod(c.ContentDir, 0777)
	if m, e := New(c); e == nil {
		m.Close()
		t.Fatal("writable root accepted")
	}
	os.Chmod(c.ContentDir, 0755)
	parent := filepath.Dir(c.ContentDir)
	os.Chmod(parent, 0777)
	defer os.Chmod(parent, 0700)
	if m, e := New(c); e == nil {
		m.Close()
		t.Fatal("writable ancestor accepted")
	}
}
