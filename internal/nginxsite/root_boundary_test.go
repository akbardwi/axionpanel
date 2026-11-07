package nginxsite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRootChangesAfterNewFailEveryOperation(t *testing.T) {
	for _, root := range []string{"conf", "content", "state", "ancestor"} {
		for _, change := range []string{"mode", "owner", "rename", "symlink"} {
			for _, operation := range []string{"plan", "status", "apply", "remove"} {
				t.Run(root+"/"+change+"/"+operation, func(t *testing.T) {
					c := unitFixture(t)
					m := manager(t, c)
					p := map[string]string{"conf": c.ConfigDir, "content": c.ContentDir, "state": c.StateDir, "ancestor": filepath.Dir(c.StateDir)}[root]
					switch change {
					case "mode":
						info, _ := os.Stat(p)
						if e := os.Chmod(p, 0777); e != nil {
							t.Fatal(e)
						}
						defer os.Chmod(p, info.Mode().Perm())
					case "owner":
						if e := os.Chown(p, 65534, 65534); e != nil {
							t.Fatal(e)
						}
						defer os.Chown(p, 0, 0)
					case "rename", "symlink":
						if e := os.Rename(p, p+"-old"); e != nil {
							t.Fatal(e)
						}
						defer func() { os.RemoveAll(p); os.Rename(p+"-old", p) }()
						if change == "symlink" {
							if e := os.Symlink(p+"-old", p); e != nil {
								t.Fatal(e)
							}
						} else if e := os.Mkdir(p, 0700); e != nil {
							t.Fatal(e)
						}
					}
					var e error
					switch operation {
					case "plan":
						_, e = m.Plan("example.com")
					case "status":
						_, e = m.Status(testCtx(t), "example.com")
					case "apply":
						_, e = m.Apply(testCtx(t), op1, "example.com")
					case "remove":
						_, e = m.Remove(testCtx(t), op1, "example.com")
					}
					if !errors.Is(e, ErrUnsafePath) {
						t.Errorf("changed root accepted: %v", e)
					}
					// FDs remain valid; rejected boundaries must not write through old pins.
					for _, dir := range []*os.File{m.conf, m.content, m.state} {
						names, err := namesAt(dir)
						if err != nil {
							t.Fatal(err)
						}
						for _, n := range names {
							if n != "nginxsite.lock" {
								t.Errorf("rejected operation wrote %s", n)
							}
						}
					}
				})
			}
		}
	}
}

type rootChangingRunner struct {
	inner  Runner
	change func()
	calls  int
}

func (r *rootChangingRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	out, errout, e := r.inner.Run(ctx, name, args...)
	r.calls++
	if r.calls == 1 {
		r.change()
	}
	return out, errout, e
}
func TestRootsRecheckedAfterBaselineBeforeMutation(t *testing.T) {
	c := unitFixture(t)
	c.Runner = &rootChangingRunner{inner: execRunner{}, change: func() {
		if e := os.Chmod(c.ContentDir, 0777); e != nil {
			t.Error(e)
		}
	}}
	m := manager(t, c)
	if _, e := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(e, ErrUnsafePath) {
		t.Fatalf("root changed during baseline accepted: %v", e)
	}
	for _, dir := range []string{c.ContentDir, c.ConfigDir, c.StateDir} {
		entries, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if entry.Name() != "nginxsite.lock" {
				t.Errorf("unsafe boundary wrote %s", entry.Name())
			}
		}
	}
}
