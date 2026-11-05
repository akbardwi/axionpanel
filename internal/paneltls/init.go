// Package paneltls handles explicit panel TLS material initialization and validation.
package paneltls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"axionpanel/internal/browserhost"
)

// Init creates new self-signed ECDSA P-256 server material. Existing paths,
// including dangling symlinks, are never replaced. Parent directories are untouched.
func Init(certPath, keyPath, host string) (*x509.Certificate, error) {
	if err := distinctPaths(certPath, keyPath); err != nil {
		return nil, err
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4In6() {
		return nil, fmt.Errorf("-tls-host %q: IPv4-mapped IPv6 TLS identities are not supported; use IPv4 or native IPv6", host)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if canonical, numeric, err := browserhost.IPv4(host); numeric {
			if err != nil {
				return nil, fmt.Errorf("-tls-host %q: invalid browser IPv4 host: %w", host, err)
			}
			return nil, fmt.Errorf("-tls-host %q: noncanonical browser IPv4 host; use -tls-host %q", host, canonical)
		}
	}
	if ip == nil && !validDNS(host) {
		return nil, errors.New("-tls-host must be one IP address or DNS hostname, without scheme, port or wildcard")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate TLS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	serial.Add(serial, big.NewInt(1))
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create TLS certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, fmt.Errorf("create TLS certificate: %w", err)
	}
	certInfo, err := certFile.Stat()
	if err != nil {
		certFile.Close()
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			removeOwned(certPath, certInfo)
		}
	}()
	if _, err = certFile.Write(certPEM); err != nil {
		certFile.Close()
		return nil, fmt.Errorf("write TLS certificate: %w", err)
	}
	if err = certFile.Close(); err != nil {
		return nil, err
	}
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create TLS private key: %w", err)
	}
	keyInfo, err := keyFile.Stat()
	if err != nil {
		keyFile.Close()
		return nil, err
	}
	defer func() {
		if !success {
			removeOwned(keyPath, keyInfo)
		}
	}()
	if _, err = keyFile.Write(keyPEM); err != nil {
		keyFile.Close()
		return nil, fmt.Errorf("write TLS private key: %w", err)
	}
	if err = keyFile.Close(); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	success = true
	return cert, nil
}

func removeOwned(path string, info os.FileInfo) {
	if current, err := os.Lstat(path); err == nil && os.SameFile(current, info) {
		_ = os.Remove(path)
	}
}

func distinctPaths(certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return errors.New("-tls-cert and -tls-key are both required")
	}
	cert, err := filepath.Abs(certPath)
	if err != nil {
		return err
	}
	key, err := filepath.Abs(keyPath)
	if err != nil {
		return err
	}
	if cert == key {
		return errors.New("-tls-cert and -tls-key must be distinct files")
	}
	return nil
}

func validDNS(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
