package nginxsite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAppliedContentTamperingFailsClosed(t *testing.T) {
	for _, kind := range []string{"symlink-public", "hardlink-index", "world-writable-public", "missing-marker"} {
		t.Run(kind, func(t *testing.T) {
			c := unitFixture(t)
			c.Reloader = func(context.Context) error { return nil }
			m := manager(t, c)
			ctx := testCtx(t)
			if _, e := m.Apply(ctx, op1, "example.com"); e != nil {
				t.Fatal(e)
			}
			site := filepath.Join(c.ContentDir, "example.com")
			pub := filepath.Join(site, "public")
			switch kind {
			case "symlink-public":
				os.Rename(pub, pub+"-old")
				os.Symlink(pub+"-old", pub)
			case "hardlink-index":
				os.Link(filepath.Join(pub, "index.html"), filepath.Join(c.Prefix, "linked"))
			case "world-writable-public":
				os.Chmod(pub, 0777)
			case "missing-marker":
				os.Remove(filepath.Join(site, ".axion-managed"))
			}
			if _, e := m.Apply(ctx, op2, "example.com"); !errors.Is(e, ErrUnsafePath) {
				t.Fatalf("tamper accepted: %v", e)
			}
		})
	}
}
func TestJournalIsPrivateBeforeContentMutation(t *testing.T) {
	c := unitFixture(t)
	c.Reloader = func(context.Context) error {
		b, e := os.ReadFile(filepath.Join(c.StateDir, op1+".json"))
		if e != nil || len(b) == 0 {
			t.Error("journal absent before reload", e)
		}
		return nil
	}
	m := manager(t, c)
	if _, e := m.Apply(testCtx(t), op1, "example.com"); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(c.StateDir, op1+".json")
	os.Chmod(p, 0644)
	if _, e := m.Apply(testCtx(t), op2, "other.com"); !errors.Is(e, ErrInterruptedOp) {
		t.Fatalf("nonprivate journal accepted: %v", e)
	}
}
