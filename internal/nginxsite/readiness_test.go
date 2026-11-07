package nginxsite

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func readJournalFile(t *testing.T, path string) journal {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var j journal
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatalf("journal %s: %v", b, err)
	}
	return j
}

func TestZeroReloadWithoutServingFailsClosed(t *testing.T) {
	c := fixture(t)
	c.Reloader = func(context.Context) error { return nil }
	m := manager(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if r, e := m.Apply(ctx, op1, "example.com"); e == nil {
		t.Fatalf("signal without server accepted: %+v", r)
	}
}

func TestOccupiedListenerCannotBecomeApplied(t *testing.T) {
	c := fixture(t)
	cmd := exec.Command(c.NginxBinary, "-p", c.Prefix, "-c", c.NginxConfig, "-e", "stderr")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("start: %v %s", e, b)
	}
	t.Cleanup(func() {
		exec.Command(c.NginxBinary, "-p", c.Prefix, "-c", c.NginxConfig, "-s", "quit", "-e", "stderr").Run()
	})
	blocker, e := net.Listen("tcp", c.Listen)
	if e != nil {
		t.Fatal(e)
	}
	defer blocker.Close()
	m := manager(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if r, e := m.Apply(ctx, op1, "example.com"); e == nil {
		t.Fatalf("occupied listener accepted: %+v", r)
	}
	j := readJournalFile(t, filepath.Join(c.StateDir, op1+".json"))
	if j.Phase != phasePending {
		t.Fatalf("ambiguous rollback must stay pending: %+v", j)
	}
	if _, e := m.Status(testCtx(t), "example.com"); !errors.Is(e, ErrInterruptedOp) {
		t.Fatalf("ambiguity hidden: %v", e)
	}
}
