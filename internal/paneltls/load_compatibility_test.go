package paneltls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRejectsImportedKeyUsageWithoutDigitalSignature(t *testing.T) {
	for _, tc := range []struct {
		name          string
		usage         x509.KeyUsage
		zeroExtension bool
	}{
		{name: "cert_sign_only", usage: x509.KeyUsageCertSign},
		{name: "key_encipherment_only", usage: x509.KeyUsageKeyEncipherment},
		{name: "present_zero_bits", zeroExtension: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := importedECDSAKey(t, elliptic.P256())
			fixture := newImportedTLSFixture(t, key, tc.usage, tc.zeroExtension)
			hasKU := false
			for _, extension := range fixture.leaf.Extensions {
				if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
					hasKU = true
				}
			}
			if !hasKU || fixture.leaf.KeyUsage != tc.usage {
				t.Fatal("fixture must contain expected key usage extension")
			}
			cfg, err := Load(fixture.certPath, fixture.keyPath, "localhost", fixture.now)
			if err == nil || !strings.Contains(err.Error(), "digital signature") {
				t.Fatalf("expected digital signature refusal, got error: %v", err)
			}
			if cfg != nil {
				t.Fatal("invalid key usage returned TLS configuration")
			}
		})
	}
}

func TestLoadRejectsImportedP224(t *testing.T) {
	fixture := newImportedTLSFixture(t, importedECDSAKey(t, elliptic.P224()), x509.KeyUsageDigitalSignature, false)
	cfg, err := Load(fixture.certPath, fixture.keyPath, "localhost", fixture.now)
	if err == nil || !strings.Contains(err.Error(), "TLS 1.3") {
		t.Fatalf("expected TLS 1.3 curve refusal, got error: %v", err)
	}
	if cfg != nil {
		t.Fatal("unsupported curve returned TLS configuration")
	}
}

func TestLoadRejectsImportedWeakRSA(t *testing.T) {
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newImportedTLSFixture(t, weakRSA, x509.KeyUsageDigitalSignature, false)
	cfg, err := Load(fixture.certPath, fixture.keyPath, "localhost", fixture.now)
	if err == nil || !strings.Contains(err.Error(), "2048") {
		t.Fatalf("expected weak RSA refusal, got error: %v", err)
	}
	if cfg != nil {
		t.Fatal("weak RSA returned TLS configuration")
	}
}

func TestImportedTLSHandshakeSucceedsForAcceptedMaterials(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		key   crypto.Signer
		usage x509.KeyUsage
	}{
		{name: "p256", key: importedECDSAKey(t, elliptic.P256()), usage: x509.KeyUsageDigitalSignature},
		{name: "p384", key: importedECDSAKey(t, elliptic.P384()), usage: x509.KeyUsageDigitalSignature},
		{name: "p521", key: importedECDSAKey(t, elliptic.P521()), usage: x509.KeyUsageDigitalSignature},
		{name: "rsa2048", key: rsaKey, usage: x509.KeyUsageDigitalSignature},
		{name: "ed25519", key: edKey, usage: x509.KeyUsageDigitalSignature},
		{name: "absent_key_usage", key: importedECDSAKey(t, elliptic.P256())},
		{name: "digital_signature_and_cert_sign", key: importedECDSAKey(t, elliptic.P256()), usage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newImportedTLSFixture(t, tc.key, tc.usage, false)
			cfg, err := Load(fixture.certPath, fixture.keyPath, "localhost", fixture.now)
			if err != nil {
				t.Fatalf("accepted material rejected: %v", err)
			}
			if tc.usage == 0 {
				for _, extension := range fixture.leaf.Extensions {
					if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
						t.Fatal("fixture must omit key usage extension")
					}
				}
			}
			roots := x509.NewCertPool()
			roots.AddCert(fixture.leaf)
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				t.Run(tls.VersionName(version), func(t *testing.T) {
					serverCfg := cfg.Clone()
					serverCfg.MinVersion, serverCfg.MaxVersion = version, version
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { listener.Close() })
					serverErr := make(chan error, 1)
					go func() {
						conn, err := listener.Accept()
						if err != nil {
							serverErr <- err
							return
						}
						defer conn.Close()
						if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
							serverErr <- err
							return
						}
						server := tls.Server(conn, serverCfg)
						_, err = server.Write([]byte("ok"))
						serverErr <- err
					}()
					client, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", listener.Addr().String(), &tls.Config{
						RootCAs: roots, ServerName: "localhost", MinVersion: version, MaxVersion: version,
					})
					if err != nil {
						t.Fatalf("handshake failed for accepted material: %v", err)
					}
					defer client.Close()
					if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 2)
					if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "ok" {
						t.Fatalf("data exchange: %q %v", buf, err)
					}
					if state := client.ConnectionState(); state.Version != version || len(state.VerifiedChains) == 0 {
						t.Fatal("expected negotiated version and verified certificate chain")
					}
					if err := <-serverErr; err != nil {
						t.Fatalf("server side: %v", err)
					}
				})
			}
		})
	}
}

func TestLoadRejectsObsoleteTLSVersions(t *testing.T) {
	fixture := newImportedTLSFixture(t, importedECDSAKey(t, elliptic.P256()), x509.KeyUsageDigitalSignature, false)
	cfg, err := Load(fixture.certPath, fixture.keyPath, "localhost", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("returned configuration minimum version = %s, want TLS 1.2", tls.VersionName(cfg.MinVersion))
	}
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			serverErr := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer conn.Close()
				server := tls.Server(conn, cfg)
				if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					serverErr <- err
					return
				}
				serverErr <- server.Handshake()
			}()
			client, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", listener.Addr().String(), &tls.Config{
				InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: version,
			})
			if err == nil {
				client.Close()
				t.Fatalf("%s handshake unexpectedly succeeded", tls.VersionName(version))
			}
			select {
			case err := <-serverErr:
				if err == nil {
					t.Fatal("server accepted obsolete protocol version")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server handshake did not terminate")
			}
		})
	}
}

func importedECDSAKey(t *testing.T, curve elliptic.Curve) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type importedTLSFixture struct {
	certPath, keyPath string
	leaf              *x509.Certificate
	now               time.Time
}

// Import fixtures deliberately bypass Init: startup must validate third-party material.
func newImportedTLSFixture(t *testing.T, key crypto.Signer, usage x509.KeyUsage, zeroExtension bool) importedTLSFixture {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: usage, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if zeroExtension {
		// x509.CreateCertificate omits KU when KeyUsage == 0; encode its presence explicitly.
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x01, 0x00}}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fixture := importedTLSFixture{certPath: filepath.Join(dir, "cert.pem"), keyPath: filepath.Join(dir, "key.pem"), leaf: leaf, now: now}
	if err := os.WriteFile(fixture.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return fixture
}
