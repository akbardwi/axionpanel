package paneltls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// keyUsageOID identifies the X.509 KeyUsage extension. Its presence matters even
// when every bit is clear: TLS 1.3 requires permission for digital signatures.
var keyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 15}

// Load validates certificate/key inputs and origin hostname before any listener
// starts. Regular symlink targets are allowed for package-managed certificates.
func Load(certPath, keyPath, host string, now time.Time) (*tls.Config, error) {
	if err := distinctPaths(certPath, keyPath); err != nil {
		return nil, err
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4In6() {
		return nil, fmt.Errorf("origin hostname %q: IPv4-mapped IPv6 TLS identities are not supported; use IPv4 or native IPv6", host)
	}
	certPEM, certInfo, err := readRegular(certPath, false)
	if err != nil {
		return nil, fmt.Errorf("TLS certificate: %w", err)
	}
	keyPEM, keyInfo, err := readRegular(keyPath, true)
	if err != nil {
		return nil, fmt.Errorf("TLS private key: %w", err)
	}
	if os.SameFile(certInfo, keyInfo) {
		return nil, errors.New("TLS certificate and private key must be distinct files")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate/key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse TLS certificate: %w", err)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("TLS certificate outside validity %s to %s", leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if err = leaf.VerifyHostname(host); err != nil {
		return nil, fmt.Errorf("TLS certificate does not cover origin hostname: %w", err)
	}
	if len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				serverAuth = true
			}
		}
		if !serverAuth {
			return nil, errors.New("TLS certificate does not permit server authentication")
		}
	}
	if hasKeyUsageExtension(leaf) && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("TLS certificate key usage lacks digital signature permission required for TLS")
	}
	if err = checkPublicKey(leaf.PublicKey); err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
}

func hasKeyUsageExtension(cert *x509.Certificate) bool {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(keyUsageOID) {
			return true
		}
	}
	return false
}

// checkPublicKey mirrors Go crypto/tls's TLS 1.3 support (auth.go
// signatureSchemesForPublicKey): P-256/P-384/P-521, RSA and Ed25519. It
// also enforces the panel's 2048-bit RSA floor so weak imported material is
// rejected before a configuration is returned.
func checkPublicKey(pub crypto.PublicKey) error {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		return fmt.Errorf("TLS certificate elliptic curve %s is unsupported for TLS 1.3; use P-256, P-384 or P-521", key.Curve.Params().Name)
	case *rsa.PublicKey:
		// 2048 bits is the panel's minimum RSA strength, not a Go TLS limit.
		if key.N.BitLen() < 2048 {
			return fmt.Errorf("TLS certificate RSA key is %d bits; at least 2048 bits are required", key.N.BitLen())
		}
		return nil
	case ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("TLS certificate uses unsupported public key type %T; use ECDSA, RSA or Ed25519", pub)
	}
}

// Nonblocking open plus fstat prevents FIFO hangs even if a path is swapped
// between inspection and open. No key bytes appear in errors.
func readRegular(path string, private bool) ([]byte, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%q: not a regular file", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%q: not a regular file", path)
	}
	if private && info.Mode().Perm() & ^os.FileMode(0640) != 0 {
		return nil, nil, fmt.Errorf("%q: unsafe private-key permissions %04o; use 0600 or 0640", path, info.Mode().Perm())
	}
	const maxPEM = 4 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxPEM+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxPEM {
		return nil, nil, errors.New("TLS PEM file exceeds 4 MiB limit")
	}
	return data, info, nil
}
