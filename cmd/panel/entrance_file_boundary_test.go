package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEntranceReadBounded(t *testing.T) {
	if _, err := decodeEntranceFile(strings.NewReader(strings.Repeat("x", 1<<20))); err == nil {
		t.Fatal("oversized input accepted")
	}
	for _, raw := range []string{bootstrapTestEntrance, bootstrapTestEntrance + "\n"} {
		if got, err := decodeEntranceFile(strings.NewReader(raw)); err != nil || got != bootstrapTestEntrance {
			t.Fatal("valid input rejected")
		}
	}
}

// entranceCountingFile keeps real descriptor IO visible to the regression test.
type entranceCountingFile struct {
	*os.File
	readBytes int
	closed    bool
	afterStat func()
}

func (f *entranceCountingFile) Stat() (os.FileInfo, error) {
	info, err := f.File.Stat()
	if f.afterStat != nil {
		f.afterStat()
	}
	return info, err
}

func (f *entranceCountingFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	f.readBytes += n
	return n, err
}

func (f *entranceCountingFile) Close() error {
	f.closed = true
	return f.File.Close()
}

func TestEntranceLoaderBoundsActualFileRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entrance")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 1<<20)), 0600); err != nil {
		t.Fatal(err)
	}
	var opened *entranceCountingFile
	_, err := loadEntrancePathWithOpen(path, func(name string) (entranceInputFile, error) {
		f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		opened = &entranceCountingFile{File: f}
		return opened, nil
	})
	if err == nil {
		t.Fatal("oversized input accepted")
	}
	if opened == nil || !opened.closed {
		t.Fatal("input descriptor was not closed")
	}
	if opened.readBytes != 0 {
		t.Fatalf("loader read %d bytes from already oversized file; expected zero", opened.readBytes)
	}
}

func TestEntranceLoaderBoundsGrowthAfterStat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entrance")
	if err := os.WriteFile(path, []byte(bootstrapTestEntrance), 0600); err != nil {
		t.Fatal(err)
	}
	var opened *entranceCountingFile
	_, err := loadEntrancePathWithOpen(path, func(name string) (entranceInputFile, error) {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		opened = &entranceCountingFile{File: f, afterStat: func() {
			if err := os.WriteFile(name, []byte(strings.Repeat("x", 1<<20)), 0600); err != nil {
				t.Fatal(err)
			}
		}}
		return opened, nil
	})
	if err == nil {
		t.Fatal("grown oversized input accepted")
	}
	if opened == nil || !opened.closed {
		t.Fatal("input descriptor was not closed")
	}
	if opened.readBytes > 15 {
		t.Fatalf("loader read %d bytes after stat; maximum is 15", opened.readBytes)
	}
}

func TestEntranceReadOwnerOnlyReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entrance")
	if err := os.WriteFile(path, []byte(bootstrapTestEntrance), 0400); err != nil {
		t.Fatal(err)
	}
	if got, err := loadEntrancePath(path); err != nil || got != bootstrapTestEntrance {
		t.Fatal("read-only file rejected")
	}
}
