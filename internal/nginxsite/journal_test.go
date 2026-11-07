package nginxsite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCompletedJournalSurvivesRestart(t *testing.T) {
	c := unitFixture(t)
	c.Reloader = func(context.Context) error { return nil }
	m := manager(t, c)
	r, e := m.Apply(testCtx(t), op1, "example.com")
	if e != nil {
		t.Fatal(e)
	}
	m.Close()
	m = manager(t, c)
	again, e := m.Apply(testCtx(t), op1, "example.com")
	if e != nil || again != r {
		t.Fatalf("restart replay: %v %v", again, e)
	}
	removed, e := m.Remove(testCtx(t), op2, "example.com")
	if e != nil {
		t.Fatal(e)
	}
	again, e = m.Remove(testCtx(t), op2, "example.com")
	if e != nil || again != removed {
		t.Fatalf("remove replay: %v %v", again, e)
	}
}
func TestMismatchedCompletedJournalFailsClosed(t *testing.T) {
	c := unitFixture(t)
	c.Reloader = func(context.Context) error { return nil }
	m := manager(t, c)
	j := journal{OperationID: op1, Action: "apply", Domain: "example.com", Digest: requestDigest("apply", "example.com", c.Listen), Phase: phaseDone, Result: &Result{Domain: "other.com", OperationID: op1, Status: "applied"}}
	if e := m.writeJournal(j); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(e, ErrInterruptedOp) {
		t.Fatalf("mismatched result accepted: %v", e)
	}
}
func TestNewRejectsOwnershipAndSymlinkAncestor(t *testing.T) {
	t.Run("ownership", func(t *testing.T) {
		c := unitFixture(t)
		os.Chown(c.ContentDir, 65534, 65534)
		defer os.Chown(c.ContentDir, 0, 0)
		if m, e := New(c); e == nil {
			m.Close()
			t.Fatal("nonroot root accepted")
		}
	})
	t.Run("ancestor symlink", func(t *testing.T) {
		c := unitFixture(t)
		base := filepath.Dir(c.ContentDir)
		alias := base + "-alias"
		if e := os.Symlink(base, alias); e != nil {
			t.Fatal(e)
		}
		defer os.Remove(alias)
		c.ContentDir = filepath.Join(alias, "content")
		if m, e := New(c); e == nil {
			m.Close()
			t.Fatal("symlink ancestor accepted")
		}
	})
}
func TestMarkerMustBePrivateUnlinkedRootFile(t *testing.T) {
	for _, kind := range []string{"mode", "link"} {
		t.Run(kind, func(t *testing.T) {
			c := unitFixture(t)
			c.Reloader = func(context.Context) error { return nil }
			m := manager(t, c)
			if _, e := m.Apply(testCtx(t), op1, "example.com"); e != nil {
				t.Fatal(e)
			}
			marker := filepath.Join(c.ContentDir, "example.com", ".axion-managed")
			if kind == "mode" {
				os.Chmod(marker, 0666)
			} else {
				os.Link(marker, filepath.Join(c.Prefix, "link"))
			}
			if _, e := m.Status(testCtx(t), "example.com"); !errors.Is(e, ErrUnsafePath) {
				t.Fatalf("unsafe marker accepted: %v", e)
			}
		})
	}
}
