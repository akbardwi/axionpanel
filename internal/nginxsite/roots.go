package nginxsite

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Remember every pathname component, not just the final descriptor: nginx
// consumes absolute paths whereas managed writes use pinned descriptors.
// Both views must still name the startup-owned tree at every boundary.
type rootIdentity struct {
	dev      uint64
	ino      uint64
	mode     uint32
	uid, gid uint32
}

func identity(f *os.File) (rootIdentity, error) {
	var st unix.Stat_t
	if e := unix.Fstat(int(f.Fd()), &st); e != nil {
		return rootIdentity{}, e
	}
	return rootIdentity{uint64(st.Dev), st.Ino, st.Mode, st.Uid, st.Gid}, nil
}
func (m *Manager) pinRoots() error {
	m.roots = map[string]rootIdentity{}
	for _, path := range []string{m.cfg.StateDir, m.cfg.ContentDir, m.cfg.ConfigDir} {
		for p := path; ; p = filepath.Dir(p) {
			f, e := trustedDir(p, p == m.cfg.StateDir)
			if e != nil {
				return e
			}
			id, e := identity(f)
			f.Close()
			if e != nil {
				return e
			}
			if id.uid != 0 || id.mode&0022 != 0 {
				return ErrUnsafePath
			}
			m.roots[p] = id
			if p == "/" {
				break
			}
		}
	}
	return nil
}
func (m *Manager) validateRoots() error {
	for path, want := range m.roots {
		f, e := trustedDir(path, path == m.cfg.StateDir)
		if e != nil {
			return e
		}
		got, e := identity(f)
		f.Close()
		if e != nil || got != want {
			return fmt.Errorf("%w: changed root or ancestor", ErrUnsafePath)
		}
	}
	for _, root := range []struct {
		f    *os.File
		path string
	}{{m.state, m.cfg.StateDir}, {m.content, m.cfg.ContentDir}, {m.conf, m.cfg.ConfigDir}} {
		got, e := identity(root.f)
		if e != nil || got != m.roots[root.path] {
			return fmt.Errorf("%w: changed pinned root", ErrUnsafePath)
		}
	}
	if m.lockFile != nil {
		current, e := openAt(m.state, "nginxsite.lock", unix.O_RDONLY, 0)
		if e != nil {
			return e
		}
		defer current.Close()
		a, e := identity(current)
		if e != nil {
			return e
		}
		b, e := identity(m.lockFile)
		if e != nil || a != b {
			return fmt.Errorf("%w: changed lock file", ErrUnsafePath)
		}
	}
	return nil
}
