package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustBox(t *testing.T) *Box {
	t.Helper()
	box, err := LoadOrCreate(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return box
}

func TestSealOpenRoundTrip(t *testing.T) {
	box := mustBox(t)
	plaintext := "JBSWY3DPEHPK3PXP"

	ct, err := box.Seal(plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !strings.HasPrefix(ct, "v1:") {
		t.Errorf("ciphertext = %.10q, want v1: prefix (spec §5.4)", ct)
	}
	got, err := box.Open(ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != plaintext {
		t.Errorf("open = %q, want %q", got, plaintext)
	}

	// Random nonce: sealing twice must not produce the same ciphertext.
	ct2, _ := box.Seal(plaintext)
	if ct == ct2 {
		t.Error("two seals of the same plaintext must differ (random nonce)")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	box := mustBox(t)
	ct, _ := box.Seal("hello-world")

	// Mutate a body character: must change decoded bytes (flipping only the
	// last base64 char can leave them identical because of padding bits).
	body := strings.TrimPrefix(ct, "v1:")
	flip := byte('A')
	if body[0] == 'A' {
		flip = 'B'
	}
	tampered := "v1:" + string(flip) + body[1:]
	if _, err := box.Open(tampered); err == nil {
		t.Error("tampered ciphertext must fail authentication")
	}
	if _, err := box.Open("v1:AAAA"); err == nil {
		t.Error("garbage ciphertext must fail")
	}
	if _, err := box.Open("v2:AAAA"); err == nil {
		t.Error("unknown version must fail")
	}
	if _, err := box.Open("not-encrypted"); err == nil {
		t.Error("malformed input must fail")
	}

	// A different key must not open the ciphertext.
	other := mustBox(t)
	if _, err := other.Open(ct); err == nil {
		t.Error("ciphertext must not open under a different key")
	}
}

func TestLoadOrCreatePersistsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	box1, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	ct, err := box1.Seal("persisted")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	box2, err := LoadOrCreate(path) // same file: same key
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	got, err := box2.Open(ct)
	if err != nil || got != "persisted" {
		t.Errorf("reloaded key must open old ciphertext, got %q err %v", got, err)
	}

	info, err := stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("secret.key mode = %o, want 600", info.Mode().Perm())
	}
}

// A key readable by group or others is a leaked key: refuse it instead of
// silently encrypting new secrets with it.
func TestLoadOrCreateRejectsLaxPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if _, err := LoadOrCreate(path); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(path); err == nil {
			t.Errorf("mode %o accepted, want error", mode)
		}
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err != nil {
		t.Errorf("owner-only read-only key rejected: %v", err)
	}
}
