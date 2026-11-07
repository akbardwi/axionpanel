package nginxsite

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// testConfig builds a minimal Config inside root; tests fill dirs under tmp.
func testConfig(t *testing.T, tmp string) Config {
	t.Helper()
	join := func(p string) string { return filepath.Join(tmp, p) }
	return Config{
		StateDir:    join("state"),
		ContentDir:  join("content"),
		ConfigDir:   join("conf"),
		NginxBinary: "/usr/bin/nginx",
		NginxConfig: join("nginx.conf"),
		Prefix:      join("prefix"),
		Listen:      "127.0.0.1:18080",
	}
}

// TestValidateDomain rejects hostile domain shapes.
func TestValidateDomain(t *testing.T) {
	ok := []string{"example.com", "a-b.example.org", "sub.domain.co.uk", "9.com"}
	for _, d := range ok {
		if err := validateDomain(d); err != nil {
			t.Errorf("validateDomain(%q) unexpected error: %v", d, err)
		}
	}
	bad := []string{
		"",              // empty
		"example.com.",  // trailing dot
		"Example.com",   // uppercase
		"*.example.com", // wildcard
		"1.2.3.4",       // IP literal
		"example",       // no dot
		"-example.com",  // leading hyphen
		"exa_mple.com",  // underscore
		"a b.com",       // space
		"ex../com.com",  // '..' not a DNS label
	}
	for _, d := range bad {
		if err := validateDomain(d); err == nil {
			t.Errorf("validateDomain(%q) expected error, got nil", d)
		}
	}
}

// TestValidateOperationID accepts exactly 32 lowercase hex chars.
func TestValidateOperationID(t *testing.T) {
	good := "0123456789abcdef0123456789abcdef"
	if err := validateOperationID(good); err != nil {
		t.Fatalf("validateOperationID(good) = %v, want nil", err)
	}
	for _, id := range []string{
		"",
		good[:31],                          // too short
		good + "f",                         // too long
		"0123456789ABCDEF0123456789ABCDEF", // uppercase hex
		strings.Repeat("g", 32),            // non-hex
		"0123456789abcdef-123456789abcdef", // dash
	} {
		if err := validateOperationID(id); err == nil {
			t.Errorf("validateOperationID(%q) expected error, got nil", id)
		}
	}
}

// TestRequireDeadline rejects undecadlined contexts.
func TestRequireDeadline(t *testing.T) {
	if err := requireDeadline(context.Background()); err == nil {
		t.Error("requireDeadline(context.Background()) expected error")
	}
	if err := requireDeadline(context.TODO()); err == nil {
		t.Error("requireDeadline(context.TODO()) expected error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	if err := requireDeadline(ctx); err == nil {
		t.Error("requireDeadline(expired) expected error")
	}
}

// TestConfigValidation enforces absolute paths and non-empty trust fields.
func TestConfigValidation(t *testing.T) {
	base := testConfig(t, "/tmp/axion")
	if err := base.Validate(); err != nil {
		t.Fatalf("absolutely-qualified config: %v", err)
	}
	c := base
	c.StateDir = "state"
	if err := c.Validate(); err == nil {
		t.Error("relative StateDir accepted")
	}
	c = base
	c.NginxBinary = ""
	if err := c.Validate(); err == nil {
		t.Error("empty NginxBinary accepted")
	}
	c = base
	c.Listen = "example.com:80" // not a literal address
	if err := c.Validate(); err == nil {
		t.Error("non-literal Listen accepted")
	}
	c = base
	c.Listen = ""
	if err := c.Validate(); err == nil {
		t.Error("empty Listen accepted")
	}
	c = base
	c.NginxConfig = filepath.Join(base.NginxConfig, "..", "..", "..", "..") // traversal-ish but still absolute; must be flagged only if outside... allow for now
	// We do NOT reject absolute paths pointing elsewhere; Config is operator-trusted.
	_ = c
}

// TestOpenPinnedDir refuses a symlinked state directory via Lstat.
func TestOpenPinnedDir_RefusesSymlink(t *testing.T) {
	tmp := t.TempDir()
	sym := filepath.Join(tmp, "symdir")
	real := t.TempDir()
	if err := symlink(real, sym); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if f, err := openPinnedDir(sym); err == nil {
		f.Close()
		t.Error("openPinnedDir(symlink dir) expected error")
	}
	if f, err := openPinnedDir(real); err != nil {
		t.Errorf("openPinnedDir(real dir) = %v, want nil", err)
	} else {
		f.Close()
	}
}

func symlink(target, link string) error {
	return unix.Symlink(target, link)
}

func removeFile(path string) error { return os.Remove(path) }
