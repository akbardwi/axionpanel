package paneltls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"syscall"
	"time"
)

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
	pair.Leaf = leaf
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
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
