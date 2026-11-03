package agent

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLoadPolicyDefaults(t *testing.T) {
	p, err := LoadPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	if p.AllowRootTerminal || p.AllowRootFiles || len(p.AllowedServices) != 0 {
		t.Fatalf("defaults not zero: %+v", p)
	}
}

func TestLoadPolicyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "agent.toml")
	body := "allow_root_terminal = true\nallowed_services = [\"nginx\", \"mysql\"]\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(f)
	if err != nil {
		t.Fatal(err)
	}
	if !p.AllowRootTerminal {
		t.Fatal("allow_root_terminal not set")
	}
	if len(p.AllowedServices) != 2 || p.AllowedServices[1] != "mysql" {
		t.Fatalf("services = %v", p.AllowedServices)
	}
}

func TestLoadPolicyMissingFile(t *testing.T) {
	if _, err := LoadPolicy(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPolicyRejectsUnknownKeys(t *testing.T) {
	f := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.WriteFile(f, []byte("allow_everything = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(f); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestLoadPolicyRejectsWrongTypes(t *testing.T) {
	cases := map[string]string{
		"string for bool":  "allow_root_terminal = \"yes\"\n",
		"bool for array":   "allowed_services = true\n",
		"array of bools":   "allowed_services = [true, false]\n",
		"unquoted string":  "allow_root_files = maybe\n",
		"uppercase bool":   "allow_root_files = True\n",
		"integer for bool": "allow_root_files = 1\n",
	}
	for name, body := range cases {
		f := filepath.Join(t.TempDir(), "agent.toml")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(f); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestLoadPolicyRejectsDuplicateKeys(t *testing.T) {
	f := filepath.Join(t.TempDir(), "agent.toml")
	body := "allow_root_terminal = true\nallow_root_terminal = false\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(f); err == nil {
		t.Fatal("expected error for duplicate key")
	}
}

func TestLoadPolicyRejectsInvalidKeyNames(t *testing.T) {
	cases := []string{
		"allow root = true\n",
		"allow-root = true\n",
		"Allow_Root = true\n",
		"\"allow_root\" = true\n",
		"[owner]\n",
		"allow_root.extra = true\n",
		" = true\n",
		"1allow = true\n",
	}
	for _, body := range cases {
		f := filepath.Join(t.TempDir(), "agent.toml")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(f); err == nil {
			t.Fatalf("expected error for invalid key name: %q", body)
		}
	}
}

func TestLoadPolicyRejectsEscapedQuotes(t *testing.T) {
	cases := []string{
		`allow_root_terminal = "tr\"escaped"` + "\n",
		`allowed_services = ["a\"b", "c"]` + "\n",
		`allowed_services = ["line\nbreak"]` + "\n",
		`allow_root_files = "back\slash"` + "\n",
	}
	for _, body := range cases {
		f := filepath.Join(t.TempDir(), "agent.toml")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(f); err == nil {
			t.Fatalf("expected error for escaped quote: %q", body)
		}
	}
}

func TestLoadPolicyRejectsArrayMalformed(t *testing.T) {
	cases := map[string]string{
		"unterminated":     "allowed_services = [\"nginx\"\n",
		"trailing comma":   "allowed_services = [\"nginx\",]\n",
		"unquoted element": "allowed_services = [nginx]\n",
		"nested array":     "allowed_services = [[\"nginx\"]]\n",
		"missing close":    "allowed_services = [\"nginx\", \"mysql\"\n",
		"comma only":       "allowed_services = [,]\n",
		"empty element":    "allowed_services = [\"nginx\", , \"mysql\"]\n",
	}
	for name, body := range cases {
		f := filepath.Join(t.TempDir(), "agent.toml")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(f); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestLoadPolicyAcceptsQuotedHashAndEmptyArray(t *testing.T) {
	f := filepath.Join(t.TempDir(), "agent.toml")
	body := "allow_root_terminal = false # comment\n" +
		"allowed_services = [\"a#b\"]\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.AllowedServices) != 1 || p.AllowedServices[0] != "a#b" {
		t.Fatalf("services = %v", p.AllowedServices)
	}

	g := filepath.Join(t.TempDir(), "empty.toml")
	if err := os.WriteFile(g, []byte("allowed_services = []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err = LoadPolicy(g)
	if err != nil {
		t.Fatalf("empty array rejected: %v", err)
	}
	if len(p.AllowedServices) != 0 {
		t.Fatalf("services = %v", p.AllowedServices)
	}
}

func TestLoadPolicyRejectsGroupOrWorldPerms(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o644, 0o640, 0o604, 0o666} {
		f := filepath.Join(t.TempDir(), "agent.toml")
		if err := os.WriteFile(f, []byte("allow_root_terminal = true\n"), mode); err != nil {
			t.Fatal(err)
		}
		// os.WriteFile honors umask; force the exact mode under test.
		if err := os.Chmod(f, mode); err != nil {
			t.Fatal(err)
		}
		_, err := LoadPolicy(f)
		if mode&0o077 == 0 {
			if err != nil {
				t.Fatalf("mode %o rejected but should be accepted: %v", mode, err)
			}
		} else if err == nil {
			t.Fatalf("mode %o accepted but should be rejected", mode)
		}
	}
}

func TestLoadPolicyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.toml")
	if err := os.WriteFile(target, []byte("allow_root_terminal = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(link); err == nil {
		t.Fatal("expected error for symlink path")
	}
}

func TestLoadPolicyRejectsNonRegular(t *testing.T) {
	if _, err := LoadPolicy(t.TempDir()); err == nil {
		t.Fatal("expected error for directory path")
	}
}

func TestLoadPolicyRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadPolicy(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(200 * time.Millisecond):
		// Unblock the old blocking opener before failing; no goroutine leak.
		fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			syscall.Close(fd)
		}
		<-done
		t.Fatal("policy FIFO open blocked")
	}
}

func TestLoadPolicyRejectsOversized(t *testing.T) {
	f := filepath.Join(t.TempDir(), "agent.toml")
	var b strings.Builder
	b.WriteString("allow_root_terminal = true\n# ")
	for i := 0; i < maxPolicyBytes+4096; i++ {
		b.WriteByte('x')
	}
	if err := os.WriteFile(f, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(f); err == nil {
		t.Fatal("expected error for oversized file")
	}
}

func TestLoadPolicyOwnerRootOrSelf(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("owner-rejection test requires root to chown")
	}
	body := []byte("allow_root_terminal = true\n")

	f := filepath.Join(t.TempDir(), "root.toml")
	if err := os.WriteFile(f, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(f, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(f); err != nil {
		t.Fatalf("root-owned file rejected: %v", err)
	}

	g := filepath.Join(t.TempDir(), "stranger.toml")
	if err := os.WriteFile(g, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(g, 12345, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(g); err == nil {
		t.Fatal("expected error for file owned by unrelated uid")
	}
}

func TestPolicyOwnerOKLogic(t *testing.T) {
	cases := []struct {
		owner, euid uint32
		want        bool
	}{
		{0, 0, true},
		{0, 1000, false},
		{1000, 1000, true},
		{1001, 1000, false},
		{12345, 1000, false},
	}
	for _, c := range cases {
		if got := policyOwnerOK(c.owner, c.euid); got != c.want {
			t.Fatalf("policyOwnerOK(%d,%d) = %v, want %v", c.owner, c.euid, got, c.want)
		}
	}
}

func TestLoadPolicyEmptyFileKeepsDefaults(t *testing.T) {
	f := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.WriteFile(f, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.AllowRootTerminal || p.AllowRootFiles || len(p.AllowedServices) != 0 {
		t.Fatalf("defaults not zero: %+v", p)
	}
}
