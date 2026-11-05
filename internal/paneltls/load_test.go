package paneltls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLoadValidatesMaterial(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := Init(certPath, keyPath, "panel.example.com"); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(certPath, keyPath, "panel.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || len(cfg.Certificates) != 1 || cfg.Certificates[0].Leaf == nil {
		t.Fatalf("TLS config incomplete: %+v", cfg)
	}
	if _, err := Load(certPath, keyPath, "other.example.com", time.Now()); err == nil {
		t.Fatal("wrong SAN accepted")
	}
	leaf := cfg.Certificates[0].Leaf
	for _, now := range []time.Time{leaf.NotBefore.Add(-time.Second), leaf.NotAfter.Add(time.Second)} {
		if _, err := Load(certPath, keyPath, "panel.example.com", now); err == nil {
			t.Fatal("invalid certificate time accepted")
		}
	}
	for _, mode := range []os.FileMode{0600, 0640} {
		if err := os.Chmod(keyPath, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(certPath, keyPath, "panel.example.com", time.Now()); err != nil {
			t.Fatalf("safe mode %o: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0644, 0660, 0601, 0610, 0700} {
		if err := os.Chmod(keyPath, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(certPath, keyPath, "panel.example.com", time.Now()); err == nil {
			t.Fatalf("unsafe mode %o accepted", mode)
		}
	}
}

func TestLoadSupportsRegularSymlinkTargets(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := Init(certPath, keyPath, "localhost"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{certPath, keyPath} {
		if err := os.Symlink(path, path+".link"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Load(certPath+".link", keyPath+".link", "localhost", time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsMappedIPv6EvenWhenGoVerifies(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	// Init encodes 127.0.0.1 as a four-byte IPv4 SAN, which Go's verifier
	// matches for a mapped literal while curl and OpenSSL compare 16 bytes.
	if _, err := Init(certPath, keyPath, "127.0.0.1"); err != nil {
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
	for _, host := range []string{"::ffff:127.0.0.1", "::ffff:7f00:1", "0:0:0:0:0:ffff:7f00:1", "0000:0000:0000:0000:0000:FFFF:7F00:0001"} {
		t.Run(host, func(t *testing.T) {
			if err := leaf.VerifyHostname(host); err != nil {
				t.Fatalf("precondition: Go must accept mapped identity: %v", err)
			}
			if _, err := Load(certPath, keyPath, host, time.Now()); err == nil || !strings.Contains(err.Error(), "IPv4-mapped IPv6") || !strings.Contains(err.Error(), "use IPv4 or native IPv6") {
				t.Fatalf("mapped origin needs actionable refusal: %v", err)
			}
		})
	}
	// The same material stays usable for its real identities.
	if _, err := Load(certPath, keyPath, "127.0.0.1", time.Now()); err != nil {
		t.Fatalf("canonical IPv4 origin rejected: %v", err)
	}
}

func TestLoadRejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := Init(certPath, keyPath, "localhost"); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("SECRET MUST NOT LEAK"), 0600); err != nil {
		t.Fatal(err)
	}
	otherCert, otherKey := filepath.Join(dir, "othercert"), filepath.Join(dir, "otherkey")
	if _, err := Init(otherCert, otherKey, "localhost"); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][2]string{{"", keyPath}, {certPath, ""}, {certPath, certPath}, {"absent", keyPath}, {dir, keyPath}, {fifo, keyPath}, {certPath, fifo}, {"/dev/null", keyPath}, {bad, keyPath}, {certPath, bad}, {certPath, otherKey}} {
		if _, err := Load(paths[0], paths[1], "localhost", time.Now()); err == nil {
			t.Fatalf("invalid pair accepted %v", paths)
		} else if strings.Contains(err.Error(), "SECRET MUST NOT LEAK") {
			t.Fatal("material leaked")
		}
	}
}

func TestLoadRejectsClientOnlyCertificate(t *testing.T) {
	writeTestCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, true)
}

func TestLoadRejectsUnknownOnlyEKU(t *testing.T) {
	writeTestCert(t, nil, []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}}, true)
}

func TestLoadAllowsNoEKUAndServerAuthWithUnknown(t *testing.T) {
	writeTestCert(t, nil, nil, false)
	writeTestCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}}, false)
	writeTestCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}}, false)
}

func writeTestCert(t *testing.T, usage []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier, wantErr bool) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: usage, UnknownExtKeyUsage: unknown}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = Load(certPath, keyPath, "localhost", now)
	if wantErr && err == nil {
		t.Fatalf("certificate accepted: usage=%v unknown=%v", usage, unknown)
	}
	if !wantErr && err != nil {
		t.Fatalf("certificate rejected: %v", err)
	}
}
