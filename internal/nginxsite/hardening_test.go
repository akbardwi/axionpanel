package nginxsite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRejectTemplateInjection(t *testing.T) {
	for _, suffix := range []string{"/bad\"root", "/bad$root", "/bad\nroot", "/bad;root", "/bad\\root"} {
		c := testConfig(t, "/root/safe")
		c.ContentDir += suffix
		if e := c.Validate(); e == nil {
			t.Errorf("accepted unsafe root %q", c.ContentDir)
		}
	}
	for _, listen := range []string{"127.0.0.1:http", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:80;"} {
		c := testConfig(t, "/root/safe")
		c.Listen = listen
		if e := c.Validate(); e == nil {
			t.Errorf("accepted listener %q", listen)
		}
	}
}

type failTestRunner struct {
	inner Runner
	mu    sync.Mutex
	calls int
}

func (r *failTestRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls == 4 {
		return "", "injected configuration error", errors.New("nginx -t injected")
	}
	if r.inner == nil {
		r.inner = execRunner{}
	}
	return r.inner.Run(ctx, name, args...)
}
func TestRemoveConfigFailureRestoresExactVhost(t *testing.T) {
	c := unitFixture(t)
	c.Reloader = func(context.Context) error { return nil }
	run := &failTestRunner{}
	c.Runner = run
	m := manager(t, c)
	ctx := testCtx(t)
	if _, e := m.Apply(ctx, op1, "example.com"); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(c.ConfigDir, "example.com.conf")
	before, _ := os.ReadFile(path)
	if _, e := m.Remove(ctx, op2, "example.com"); !errors.Is(e, ErrConfigTestFailed) {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("rollback did not restore exact old config")
	}
	// Same failure is durable and must not execute any more commands.
	calls := run.calls
	if _, e := m.Remove(ctx, op2, "example.com"); !errors.Is(e, ErrConfigTestFailed) {
		t.Fatal(e)
	}
	if run.calls != calls {
		t.Fatal("failed operation replayed")
	}
}
func TestRollbackFailureBlocksAllFurtherMutation(t *testing.T) {
	c := unitFixture(t)
	c.Reloader = func(context.Context) error { return errors.New("reload broken") }
	m := manager(t, c)
	if _, e := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(e, ErrInterruptedOp) {
		t.Fatalf("missing recovery error: %v", e)
	}
	if _, e := m.Apply(testCtx(t), op2, "other.com"); !errors.Is(e, ErrInterruptedOp) {
		t.Fatalf("not fail closed: %v", e)
	}
}
func TestTwoManagersSerialize(t *testing.T) {
	c := unitFixture(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	c.Reloader = func(context.Context) error { entered <- struct{}{}; <-release; return nil }
	m1 := manager(t, c)
	m2 := manager(t, c)
	done := make(chan error, 1)
	go func() { _, e := m1.Apply(testCtx(t), op1, "example.com"); done <- e }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("operation did not enter reload")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, e := m2.Apply(ctx, op2, "other.com")
	close(release)
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("flock did not serialize: %v", e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestCorruptJournalFailsClosed(t *testing.T) {
	c := unitFixture(t)
	c.Reloader = func(context.Context) error { return nil }
	m := manager(t, c)
	os.WriteFile(filepath.Join(c.StateDir, op1+".json"), []byte(`{"phase":"done"}`), 0600)
	if _, e := m.Apply(testCtx(t), op2, "example.com"); !errors.Is(e, ErrInterruptedOp) {
		t.Fatalf("corrupt done journal accepted: %v", e)
	}
}
func TestRunnerOutputIsBounded(t *testing.T) {
	b := &boundedOutput{}
	large := []byte(strings.Repeat("x", fileLimit*2))
	n, e := b.Write(large)
	if e != nil || n != len(large) || len(b.data) != fileLimit {
		t.Fatalf("bounded writer %d %d %v", n, len(b.data), e)
	}
}
