package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// entranceMaxFileBytes permits the 13-byte path plus one trailing newline.
// The decoder reads one extra byte to detect oversized or concurrently grown files.
const entranceMaxFileBytes = 14

// entranceInputFile is the subset of *os.File the loader needs. Descriptor IO
// goes through this seam so a regression test can observe how many bytes the
// loader actually reads.
type entranceInputFile interface {
	io.Reader
	io.Closer
	Stat() (os.FileInfo, error)
}

// entranceOpenInput opens the entrance file without following a final symlink
// and without blocking on a FIFO. O_NONBLOCK makes open(2) on a pipe return
// immediately; the opened descriptor is rejected by checkEntranceFileInfo
// because it is not a regular file.
func entranceOpenInput(path string) (entranceInputFile, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// initEntranceFile writes a fresh 13-byte secret-entrance path to an
// owner-only file. The raw path is never echoed, and an existing destination
// is not replaced. Parent directory must exist, be a real directory, be
// owned by the effective user and have mode 0700 (no group/world bits).
func initEntranceFile(path string) error {
	return initEntranceFileWithOpen(path, entranceOpenRoot)
}

func entranceOpenRoot(path string) (*os.Root, error) {
	return os.OpenRoot(path)
}

func initEntranceFileWithOpen(path string, openRoot func(string) (*os.Root, error)) error {
	parent, name, err := resolveEntranceDestination(path)
	if err != nil {
		return err
	}
	root, err := openRoot(parent)
	if err != nil {
		return errors.New("panel: entrance destination is unavailable")
	}
	defer root.Close()
	// Validate the exact directory handle used for creation, not just the
	// pathname inspected above: a swap between check and open must not
	// redirect the secret into an unvalidated directory.
	info, err := root.Stat(".")
	if err != nil {
		return errors.New("panel: entrance destination is unavailable")
	}
	if err := checkEntranceParentInfo(info); err != nil {
		return err
	}
	buf := make([]byte, 9)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("panel: generate entrance path: %w", err)
	}
	payload := []byte("/" + base64.RawURLEncoding.EncodeToString(buf))
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errors.New("panel: entrance file already exists")
		}
		return errors.New("panel: entrance destination cannot be created")
	}
	created, err := f.Stat()
	if err != nil {
		f.Close()
		return errors.New("panel: entrance file cannot be verified")
	}
	if err := checkEntranceCreatedInfo(created); err != nil {
		f.Close()
		removeOwnedBootstrapArtifact(root, name, created)
		return err
	}
	if n, writeErr := f.Write(payload); writeErr != nil || n != len(payload) {
		f.Close()
		removeOwnedBootstrapArtifact(root, name, created)
		return errors.New("panel: write entrance file")
	}
	if err := f.Sync(); err != nil {
		f.Close()
		removeOwnedBootstrapArtifact(root, name, created)
		return errors.New("panel: sync entrance file")
	}
	if err := f.Close(); err != nil {
		removeOwnedBootstrapArtifact(root, name, created)
		return errors.New("panel: close entrance file")
	}
	return nil
}

// resolveEntranceDestination converts the destination into the parent
// directory to open plus the single file name to create. Error text never
// includes the path.
func resolveEntranceDestination(path string) (string, string, error) {
	if path == "" {
		return "", "", errors.New("panel: entrance file path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", errors.New("panel: entrance destination is unavailable")
	}
	parent := filepath.Dir(abs)
	name := filepath.Base(abs)
	if name == "" || name == string(os.PathSeparator) || name == "." || name == ".." {
		return "", "", errors.New("panel: entrance destination must be a file")
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return "", "", errors.New("panel: entrance parent is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", "", errors.New("panel: entrance parent must be a real directory")
	}
	if err := checkEntranceParentInfo(info); err != nil {
		return "", "", err
	}
	return parent, name, nil
}

// checkEntranceParentInfo ensures the directory that will receive the secret
// is a real, owner-only, owner-writable directory owned by the effective user.
func checkEntranceParentInfo(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("panel: entrance parent must be a real directory")
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 || perm&0o300 != 0o300 {
		return errors.New("panel: entrance parent must be owner-only and writable")
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("panel: entrance parent owner cannot be verified")
	}
	if int(sys.Uid) != os.Geteuid() {
		return errors.New("panel: entrance parent must be owned by the panel user")
	}
	return nil
}

// checkEntranceCreatedInfo verifies the newly created destination descriptor
// before the secret is written into it.
func checkEntranceCreatedInfo(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("panel: entrance file must be a regular file")
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 || perm&0o400 == 0 {
		return errors.New("panel: entrance file must be owner-only and readable")
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(sys.Uid) != os.Geteuid() {
		return errors.New("panel: entrance file must be owned by the panel user")
	}
	return nil
}

// loadEntrancePath reads a 13-character entrance path (slash + 12 base64url
// characters) from an owner-only regular file. A single trailing newline is
// tolerated; any other character is rejected. The returned path is the
// literal secret; callers must not log it.
func loadEntrancePath(path string) (string, error) {
	return loadEntrancePathWithOpen(path, entranceOpenInput)
}

// loadEntrancePathWithOpen opens the destination once and both verifies and
// reads that same descriptor, so a swapped pathname can never redirect the
// read after the permission and type checks.
func loadEntrancePathWithOpen(path string, open func(string) (entranceInputFile, error)) (string, error) {
	if path == "" {
		return "", errors.New("panel: entrance file is required")
	}
	f, err := open(path)
	if err != nil {
		return "", errors.New("panel: entrance file is unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", errors.New("panel: entrance file is unavailable")
	}
	if err := checkEntranceFileInfo(info); err != nil {
		return "", err
	}
	if info.Size() > entranceMaxFileBytes {
		return "", errors.New("panel: entrance file is too large")
	}
	return decodeEntranceFile(f)
}

// checkEntranceFileInfo validates the opened descriptor, not a pathname: type,
// owner-only permissions and ownership all come from the inode being read.
func checkEntranceFileInfo(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("panel: entrance file must be a regular owner-only file")
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 || perm&0o400 == 0 {
		return errors.New("panel: entrance file must be owner-only and readable")
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(sys.Uid) != os.Geteuid() {
		return errors.New("panel: entrance file must be owned by the panel user")
	}
	return nil
}

// decodeEntranceFile accepts at most one line of 13 bytes plus a trailing
// newline. Bounding the read keeps a corrupted or replaced file from making
// startup consume arbitrary memory. The path is copied to the return value and
// never included in an error.
func decodeEntranceFile(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, entranceMaxFileBytes+1))
	if err != nil || len(data) > entranceMaxFileBytes {
		return "", errors.New("panel: entrance file is too large")
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	if len(data) != 13 || data[0] != '/' || containsForbiddenEntranceChars(data) {
		return "", errors.New("panel: entrance file must contain the 13-character secret path")
	}
	if validateBootstrapEntrance(string(data)) != nil {
		return "", errors.New("panel: entrance file must contain the 13-character secret path")
	}
	return string(data), nil
}

// containsForbiddenEntranceChars reports whether the buffer contains any
// character that is not a slash, ASCII alphanumeric, underscore, or dash.
func containsForbiddenEntranceChars(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for i, c := range b {
		if i == 0 {
			if c != '/' {
				return true
			}
			continue
		}
		if c >= 'A' && c <= 'Z' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '_', '-':
			continue
		}
		return true
	}
	return false
}
