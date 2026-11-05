package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEntranceFilePrivateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "entrance")
	if err := initEntranceFile(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 13 {
		t.Fatal("invalid generated size")
	}
	got, err := loadEntrancePath(path)
	if err != nil || got != string(raw) {
		t.Fatalf("private entrance roundtrip failed: %v", err)
	}
	if err := initEntranceFile(path); err == nil {
		t.Fatal("existing file replaced")
	}
	if after, _ := os.ReadFile(path); string(after) != string(raw) {
		t.Fatal("existing content changed")
	}
}

func TestEntranceFileRejectsUnsafeFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		data string
	}{
		{"public", 0644, "/AbCdEf0123_-\n"},
		{"invalid", 0600, "/bad"},
		{"large", 0600, strings.Repeat("A", 1024)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "entrance")
			if err := os.WriteFile(path, []byte(tc.data), tc.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := loadEntrancePath(path); err == nil {
				t.Fatal("unsafe entrance accepted")
			}
		})
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	os.WriteFile(target, []byte("/AbCdEf0123_-"), 0600)
	os.Symlink(target, link)
	if _, err := loadEntrancePath(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := loadEntrancePath(dir); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestEntranceLoaderChecksOpenedFilePermissions(t *testing.T) {
	dir := mustNewOwnerDir(t)
	path := filepath.Join(dir, "entrance")
	if err := os.WriteFile(path, []byte(bootstrapTestEntrance), 0600); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "public")
	if err := os.WriteFile(replacement, []byte(bootstrapTestEntrance), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(replacement, 0644); err != nil {
		t.Fatal(err)
	}
	var opened *entranceCountingFile
	_, err := loadEntrancePathWithOpen(path, func(name string) (entranceInputFile, error) {
		f, err := os.OpenFile(replacement, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		opened = &entranceCountingFile{File: f}
		return opened, nil
	})
	if err == nil {
		t.Fatal("opened public inode accepted after private pathname check")
	}
	if opened == nil || !opened.closed || opened.readBytes != 0 {
		t.Fatal("unsafe opened inode read or not closed")
	}
}

const otherEntrance = "/Attacker123_"

func TestEntranceLoaderHonorsVerifiedOpen(t *testing.T) {
	dir := mustNewOwnerDir(t)
	path := filepath.Join(dir, "entrance")
	if err := os.WriteFile(path, []byte(bootstrapTestEntrance), 0600); err != nil {
		t.Fatal(err)
	}
	attacker := filepath.Join(dir, "attacker")
	if err := os.WriteFile(attacker, []byte(otherEntrance), 0600); err != nil {
		t.Fatal(err)
	}
	var opened *entranceCountingFile
	got, err := loadEntrancePathWithOpen(path, func(name string) (entranceInputFile, error) {
		f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		opened = &entranceCountingFile{File: f}
		if err := os.Rename(attacker, path); err != nil {
			f.Close()
			t.Fatal(err)
		}
		return opened, nil
	})
	if err != nil || got != bootstrapTestEntrance {
		t.Fatalf("opened descriptor was not used for the read: %v", err)
	}
	if opened == nil {
		t.Fatal("input descriptor was not opened")
	}
	if opened.readBytes > 15 {
		t.Fatalf("loader read %d bytes through the opened descriptor", opened.readBytes)
	}
	if !opened.closed {
		t.Fatal("opened descriptor was not closed")
	}
}
