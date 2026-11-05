package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// mustNewOwnerDir returns a fresh 0700 directory owned by the panel user.
func mustNewOwnerDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "dir")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEntranceInitRejectsUnsafeParent(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "unsafe")
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := initEntranceFile(filepath.Join(parent, "entrance")); err == nil {
		t.Fatal("unsafe parent accepted")
	}
}

func TestEntranceInitUsesItsValidatedCreationRoot(t *testing.T) {
	safe := mustNewOwnerDir(t)
	unsafe := mustNewOwnerDir(t)
	if err := os.Chmod(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	err := initEntranceFileWithOpen(filepath.Join(safe, "entrance"), func(path string) (*os.Root, error) {
		return os.OpenRoot(unsafe)
	})
	if err == nil {
		t.Fatal("unsafe creation root accepted")
	}
	if _, statErr := os.Lstat(filepath.Join(unsafe, "entrance")); !os.IsNotExist(statErr) {
		t.Fatal("entrance created in unvalidated directory")
	}
	if _, statErr := os.Lstat(filepath.Join(safe, "entrance")); !os.IsNotExist(statErr) {
		t.Fatal("entrance created in validated directory")
	}
}

func TestEntranceInitErrorsOmitDestinationDetails(t *testing.T) {
	dir := mustNewOwnerDir(t)
	path := filepath.Join(dir, "destination-private-marker")
	if err := initEntranceFile(path); err != nil {
		t.Fatal(err)
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	err := initEntranceFile(path)
	if err == nil {
		t.Fatal("existing file replaced")
	}
	for _, leaked := range []string{path, filepath.Base(path), string(raw)} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("error details expose destination details")
		}
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || string(after) != string(raw) {
		t.Fatal("existing content changed")
	}
}

func TestEntranceLoaderRejectsLargeFileBeforeReading(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(16 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := loadEntrancePath(path); err == nil {
		t.Fatal("large file accepted")
	}
}

func TestEntranceLoaderRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEntrancePath(path); err == nil {
		t.Fatal("FIFO accepted")
	}
}
