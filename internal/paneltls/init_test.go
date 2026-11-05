package paneltls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestInitCreatesServerCertificate(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "2001:db8::1", "panel.example.com"} {
		t.Run(host, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			before := time.Now()
			cert, err := Init(certPath, keyPath, host)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if err = leaf.VerifyHostname(host); err != nil {
				t.Fatal(err)
			}
			if err = leaf.CheckSignatureFrom(leaf); err == nil {
				t.Fatal("self-signed server leaf must not be CA")
			}
			if err = leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
				t.Fatal(err)
			}
			key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
			if !ok || key.Curve != elliptic.P256() {
				t.Fatalf("key = %T", pair.PrivateKey)
			}
			if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
				t.Fatal("missing server auth EKU")
			}
			if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
				t.Fatal("invalid server constraints")
			}
			if leaf.NotBefore.After(before) || leaf.NotAfter.Before(before.Add(24*time.Hour)) || leaf.NotAfter.After(before.Add(366*24*time.Hour)) {
				t.Fatalf("invalid validity %v - %v", leaf.NotBefore, leaf.NotAfter)
			}
			if sha256.Sum256(cert.Raw) != sha256.Sum256(leaf.Raw) {
				t.Fatal("returned cert differs from disk")
			}
			for path, max := range map[string]os.FileMode{certPath: 0644, keyPath: 0600} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() & ^max != 0 {
					t.Fatalf("%s mode %o", path, info.Mode().Perm())
				}
			}
			data, _ := os.ReadFile(keyPath)
			block, _ := pem.Decode(data)
			if block == nil || block.Type != "PRIVATE KEY" {
				t.Fatal("expected PKCS8 key")
			}
		})
	}
}

func TestInitRefusesExistingDestinations(t *testing.T) {
	for _, which := range []string{"cert", "key", "symlink", "dangling-symlink", "same"} {
		t.Run(which, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
			existing := certPath
			if which == "key" {
				existing = keyPath
			}
			if which == "same" {
				keyPath = certPath
			}
			sentinel := []byte("do not replace")
			if which == "symlink" || which == "dangling-symlink" {
				target := filepath.Join(dir, "target")
				if which == "symlink" {
					if err := os.WriteFile(target, sentinel, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, existing); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(existing, sentinel, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Init(certPath, keyPath, "127.0.0.1"); err == nil {
				t.Fatal("existing destination accepted")
			}
			if _, err := os.Lstat(existing); err != nil {
				t.Fatalf("existing destination removed: %v", err)
			}
			if which != "symlink" && which != "dangling-symlink" {
				data, _ := os.ReadFile(existing)
				if string(data) != string(sentinel) {
					t.Fatal("existing material replaced")
				}
			}
			if which == "key" {
				if _, err := os.Lstat(certPath); !os.IsNotExist(err) {
					t.Fatalf("partial cert left behind: %v", err)
				}
			}
		})
	}
}

func TestInitRejectsMappedIPv6BeforeWrites(t *testing.T) {
	for _, host := range []string{"::ffff:127.0.0.1", "::ffff:7f00:1", "0:0:0:0:0:ffff:7f00:1", "0000:0000:0000:0000:0000:FFFF:7F00:0001"} {
		t.Run(host, func(t *testing.T) {
			dir := t.TempDir()
			cert, err := Init(filepath.Join(dir, "cert"), filepath.Join(dir, "key"), host)
			if err == nil || !strings.Contains(err.Error(), "IPv4-mapped IPv6") || !strings.Contains(err.Error(), "use IPv4 or native IPv6") {
				t.Errorf("mapped identity needs actionable refusal: cert=%v err=%v", cert != nil, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Errorf("rejected init wrote material: %v, %v", entries, err)
			}
		})
	}
}

func TestInitRejectsBrowserNumericHosts(t *testing.T) {
	for _, host := range []string{
		"127.1", "0177.0.0.1", "0x7f000001", "0X7F000001", "0x7F.1", "2130706433", "127.0.0.1.",
		"example.123", "example.0XFF", "1.2.3.4.5", "0x100000000", "0X10000000000000000", "example.0XFFFFFFFFFFFFFFFFF", "4294967296", "09",
	} {
		t.Run(host, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := Init(filepath.Join(dir, "cert"), filepath.Join(dir, "key"), host); err == nil {
				t.Fatal("browser-numeric host accepted as DNS")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatal("invalid init wrote material")
			}
		})
	}
}

func TestInitNumericHostErrorSuggestsCanonicalIP(t *testing.T) {
	for host, want := range map[string]string{"127.1": "127.0.0.1", "0177.0.0.1": "127.0.0.1", "0X7F000001": "127.0.0.1", "2130706433": "127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			dir := t.TempDir()
			_, err := Init(filepath.Join(dir, "cert"), filepath.Join(dir, "key"), host)
			if err == nil {
				t.Fatal("numeric host accepted")
			}
			if !strings.Contains(err.Error(), strconv.Quote(want)) {
				t.Fatalf("error lacks canonical hint %q: %v", want, err)
			}
		})
	}
}

func TestInitRejectsInvalidArguments(t *testing.T) {
	for _, host := range []string{"", "https://panel.example", "host:443", "*.example.com", "foo/bar", "bad name", "-bad.example", "bad..example", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := Init(filepath.Join(dir, "cert"), filepath.Join(dir, "key"), host); err == nil {
				t.Fatal("invalid host accepted")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatal("invalid init wrote material")
			}
		})
	}
	dir := t.TempDir()
	for _, paths := range [][2]string{{"", filepath.Join(dir, "key")}, {filepath.Join(dir, "cert"), ""}, {filepath.Join(dir, "same"), filepath.Join(dir, "same")}} {
		if _, err := Init(paths[0], paths[1], "localhost"); err == nil {
			t.Fatal("invalid paths accepted")
		}
	}
}

func TestInitRollsBackOwnedFileOnSecondCreateFailure(t *testing.T) {
	dir := t.TempDir()
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, "cert")
	key := filepath.Join(dir, "absent", "key")
	if _, err := Init(cert, key, "localhost"); err == nil {
		t.Fatal("missing parent accepted")
	}
	if _, err := os.Lstat(cert); !os.IsNotExist(err) {
		t.Fatalf("partial cert left behind: %v", err)
	}
	after, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("parent permissions changed: %o to %o", before.Mode().Perm(), after.Mode().Perm())
	}
}
