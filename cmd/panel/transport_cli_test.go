//go:build unix

package main

import (
	"axionpanel/internal/auth"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"axionpanel/internal/paneltls"
)

func buildTransportPanel(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "panel")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build panel: %v\n%s", err, out)
	}
	return binary
}

func runTransportPanel(t *testing.T, binary, dir string, args ...string) (string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("panel command hung: %v", args)
	}
	return stdout.String(), stderr.String(), err
}

func assertNoPanelState(t *testing.T, dir string) {
	t.Helper()
	for _, path := range []string{"panel.db", "panel.db-wal", "panel.db-shm", "secret.key"} {
		if _, err := os.Lstat(filepath.Join(dir, path)); !os.IsNotExist(err) {
			t.Fatalf("unexpected state %s: %v", path, err)
		}
	}
}

// occupyLoopback reserves an ephemeral loopback port with a live listener,
// so bind-failure tests are deterministic instead of assuming an address is
// unused. The listener is held until test end.
func occupyLoopback(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy loopback: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestCLIInvalidLoopbackPortLeavesNoState(t *testing.T) {
	binary := buildTransportPanel(t)
	for _, port := range []string{"not-a-port", "", "-1", "65536"} {
		for _, bootstrap := range []bool{false, true} {
			name := port + "/serve"
			if bootstrap {
				name = port + "/bootstrap"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				args := []string{"-addr", "127.0.0.1:" + port}
				if bootstrap {
					args = append(args, "-bootstrap-admin", "admin")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, args...)
				cmd.Dir = dir
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				err := cmd.Run()
				if ctx.Err() != nil || err == nil || !strings.Contains(stderr.String(), "invalid -addr") {
					t.Errorf("invalid listen port must fail configuration validation: err=%v timeout=%v stderr=%s", err, ctx.Err(), &stderr)
				}
				assertNoPanelState(t, dir)
			})
		}
	}
}

func TestFailedListenerCreatesNoNewState(t *testing.T) {
	binary := buildTransportPanel(t)
	occupied := occupyLoopback(t)
	dir := t.TempDir()
	_, stderr, err := runTransportPanel(t, binary, dir, "-addr", occupied, "-insecure-loopback",
		"-db", filepath.Join(dir, "panel.db"), "-secret-key", filepath.Join(dir, "secret.key"))
	if err == nil || !strings.Contains(stderr, "address already in use") {
		t.Fatalf("occupied loopback bind must fail: err=%v stderr=%s", err, stderr)
	}
	assertNoPanelState(t, dir)
}

func TestTLSOccupiedAddressCreatesNoState(t *testing.T) {
	binary := buildTransportPanel(t)
	occupied := occupyLoopback(t)
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := runTransportPanel(t, binary, dir,
		"-addr", occupied, "-origin", "https://"+occupied, "-tls-cert", cert, "-tls-key", key)
	if err == nil || !strings.Contains(stderr, "address already in use") {
		t.Fatalf("occupied TLS bind must fail: out=%s stderr=%s", out, stderr)
	}
	assertNoPanelState(t, dir)
}

func TestFailedListenerPreservesPreExistingState(t *testing.T) {
	binary := buildTransportPanel(t)
	dir := t.TempDir()
	out, _, err := runTransportPanel(t, binary, dir,
		"-addr", "127.0.0.1:0", "-insecure-loopback",
		"-db", filepath.Join(dir, "panel.db"), "-secret-key", filepath.Join(dir, "secret.key"),
		"-bootstrap-admin", "admin")
	if err != nil || !strings.Contains(out, "Password (shown once") {
		t.Fatalf("setup bootstrap failed: %v", err)
	}
	entries, derr := os.ReadDir(dir)
	if derr != nil {
		t.Fatal(derr)
	}
	snapshot := map[string][]byte{}
	for _, entry := range entries {
		name := entry.Name()
		data, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			t.Fatal(rerr)
		}
		snapshot[name] = data
	}
	occupied := occupyLoopback(t)
	certDir := t.TempDir()
	cert, key := filepath.Join(certDir, "cert"), filepath.Join(certDir, "key")
	if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-addr", occupied},
		{"-addr", occupied, "-origin", "https://" + occupied, "-tls-cert", cert, "-tls-key", key},
		{"-addr", "127.0.0.1:not-a-port"},
		{"-addr", "127.0.0.1:"},
		{"-addr", "127.0.0.1:-1"},
		{"-addr", "127.0.0.1:65536"},
	} {
		_, stderr, err := runTransportPanel(t, binary, dir, args...)
		if err == nil || (!strings.Contains(stderr, "address already in use") && !strings.Contains(stderr, "invalid -addr")) {
			t.Errorf("startup with pre-existing state must fail before state access: err=%v stderr=%s", err, stderr)
		}
	}
	entries, derr = os.ReadDir(dir)
	if derr != nil {
		t.Fatal(derr)
	}
	if len(entries) != len(snapshot) {
		t.Errorf("state file count changed: got %d want %d", len(entries), len(snapshot))
	}
	for _, entry := range entries {
		name := entry.Name()
		want, ok := snapshot[name]
		if !ok {
			t.Errorf("new state file %q created by failed startup", name)
			continue
		}
		got, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil || !bytes.Equal(got, want) {
			t.Errorf("%s changed by failed startup: %v", name, rerr)
		}
	}
}

func TestCLIPortZeroLoopbackDevelopmentStillServes(t *testing.T) {
	// -addr 127.0.0.1:0 keeps the existing loopback development behavior:
	// an ephemeral port selected by the OS. Port syntax validation must keep
	// "0" valid; the listener's real address is what the panel reports.
	binary := buildTransportPanel(t)
	dir := t.TempDir()
	db, key := filepath.Join(dir, "panel.db"), filepath.Join(dir, "secret.key")
	out, stderr, err := runTransportPanel(t, binary, dir,
		"-addr", "127.0.0.1:0", "-insecure-loopback",
		"-db", db, "-secret-key", key, "-bootstrap-admin", "admin")
	if err != nil || !strings.Contains(out, "Password (shown once") {
		t.Fatalf("port-0 bootstrap setup: err=%v stderr=%s", err, stderr)
	}
	logPath := filepath.Join(dir, "panel.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command(binary, "-addr", "127.0.0.1:0", "-insecure-loopback", "-db", db, "-secret-key", key)
	cmd.Dir = dir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	data, _ := os.ReadFile(logPath)
	deadline := time.Now().Add(10 * time.Second)
	var listening string
	for time.Now().Before(deadline) {
		data, _ = os.ReadFile(logPath)
		if m := regexPortZero.FindStringSubmatch(string(data)); m != nil {
			listening = m[1]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if listening == "" {
		t.Fatalf("port-0 startup did not log a real listen address: %s", data)
	}
	// Confirm the reported address is actually serving on loopback.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + listening + "/api/health")
	if err != nil {
		t.Fatalf("health on reported address %q: %v", listening, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
}

var regexPortZero = regexp.MustCompile(`listening on (\S+)`)

func TestBootstrapAndInitDoNotBind(t *testing.T) {
	binary := buildTransportPanel(t)
	occupied := occupyLoopback(t)
	cert, key := filepath.Join(t.TempDir(), "cert"), filepath.Join(t.TempDir(), "key")
	if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, nativeTLS := range []bool{false, true} {
		dir := t.TempDir()
		args := []string{"-addr", occupied, "-bootstrap-admin", "admin"}
		if nativeTLS {
			args = append(args, "-origin", "https://"+occupied, "-tls-cert", cert, "-tls-key", key)
		}
		out, stderr, err := runTransportPanel(t, binary, dir, args...)
		if err != nil || !strings.Contains(out, "Password (shown once") {
			t.Fatalf("bootstrap must succeed on occupied address (TLS=%t): err=%v stderr=%s", nativeTLS, err, stderr)
		}
		for _, path := range []string{"panel.db", "secret.key"} {
			if _, err := os.Stat(filepath.Join(dir, path)); err != nil {
				t.Fatalf("bootstrap state %s missing: %v", path, err)
			}
		}
	}
	dir := t.TempDir()
	_, stderr, err := runTransportPanel(t, binary, dir,
		"-init-tls", "-tls-host", "127.0.0.1", "-tls-cert", "cert", "-tls-key", "key",
		"-addr", occupied)
	if err != nil {
		t.Fatalf("init-tls must succeed on occupied address: err=%v stderr=%s", err, stderr)
	}
	assertNoPanelState(t, dir)
	if _, err := os.Stat(filepath.Join(dir, "cert")); err != nil {
		t.Fatalf("init-tls did not create certificate: %v", err)
	}
}

func TestStartupFailureReleasesListener(t *testing.T) {
	binary := buildTransportPanel(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.key"), []byte("invalid key"), 0600); err != nil {
		t.Fatal(err)
	}
	_, stderr, err := runTransportPanel(t, binary, dir, "-addr", addr)
	if err == nil || !strings.Contains(stderr, "secret key:") {
		t.Fatalf("expected secret initialization failure: err=%v stderr=%s", err, stderr)
	}
	rebound, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("failed startup retained listener: %v", err)
	}
	rebound.Close()
}

func TestTLSCLIInitExitsBeforeState(t *testing.T) {
	binary := buildTransportPanel(t)
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	// Init is independent from service origin/bind/proxy configuration.
	out, stderr, err := runTransportPanel(t, binary, dir, "-init-tls", "-tls-host", "127.0.0.1", "-tls-cert", cert, "-tls-key", key, "-origin", "invalid", "-addr", "invalid", "-trusted-proxy", "invalid")
	if err != nil {
		t.Fatalf("init: %v\nstdout=%s\nstderr=%s", err, out, stderr)
	}
	assertNoPanelState(t, dir)
	data, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	for _, want := range []string{"SHA-256", hex.EncodeToString(fingerprint[:]), leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339)} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q: %s", want, out)
		}
	}
	if stderr != "" {
		t.Fatalf("init diagnostics not stdout-only: %s", stderr)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("key leaked to stdout")
	}
	out, stderr, err = runTransportPanel(t, binary, dir, "-init-tls", "-tls-host", "127.0.0.1", "-tls-cert", cert, "-tls-key", key)
	if err == nil {
		t.Fatal("reinitialization accepted")
	}
	if strings.Contains(out+stderr, "PRIVATE KEY") {
		t.Fatal("key leaked on refusal")
	}
	again, _ := os.ReadFile(cert)
	if !bytes.Equal(data, again) {
		t.Fatal("reinit replaced certificate")
	}
}

func TestTLSCLIInitRejectsBrowserNumericHostsBeforeState(t *testing.T) {
	binary := buildTransportPanel(t)
	for _, tc := range []struct{ host, hint string }{
		{"127.1", "127.0.0.1"}, {"0177.0.0.1", "127.0.0.1"},
		{"0x7f000001", "127.0.0.1"}, {"0X7F000001", "127.0.0.1"}, {"0x7F.1", "127.0.0.1"},
		{"2130706433", "127.0.0.1"}, {"127.0.0.1.", "127.0.0.1"},
		{"example.123", ""}, {"example.0XFF", ""}, {"1.2.3.4.5", ""},
		{"0x100000000", ""}, {"0X10000000000000000", ""}, {"example.0XFFFFFFFFFFFFFFFFF", ""},
		{"4294967296", ""}, {"09", ""},
	} {
		t.Run(tc.host, func(t *testing.T) {
			dir := t.TempDir()
			out, stderr, err := runTransportPanel(t, binary, dir,
				"-init-tls", "-tls-host", tc.host, "-tls-cert", "cert", "-tls-key", "key")
			if err == nil || !strings.Contains(stderr, "-tls-host") || !strings.Contains(stderr, "browser IPv4") {
				t.Errorf("numeric host needs actionable refusal: err=%v stdout=%s stderr=%s", err, out, stderr)
			}
			if tc.hint != "" && !strings.Contains(stderr, `use -tls-host "`+tc.hint+`"`) {
				t.Errorf("missing canonical hint %q: %s", tc.hint, stderr)
			}
			assertNoPanelState(t, dir)
			entries, readErr := os.ReadDir(dir)
			if readErr != nil || len(entries) != 0 {
				t.Errorf("rejected init created files: %v, %v", entries, readErr)
			}
		})
	}
}

func TestTLSCLIInitRejectsMappedIPv6BeforeState(t *testing.T) {
	binary := buildTransportPanel(t)
	for _, host := range []string{"::ffff:127.0.0.1", "::ffff:7f00:1", "0:0:0:0:0:ffff:7f00:1", "0000:0000:0000:0000:0000:FFFF:7F00:0001"} {
		t.Run(host, func(t *testing.T) {
			dir := t.TempDir()
			out, stderr, err := runTransportPanel(t, binary, dir,
				"-init-tls", "-tls-host", host, "-tls-cert", "cert", "-tls-key", "key")
			if err == nil || !strings.Contains(stderr, "IPv4-mapped IPv6") || !strings.Contains(stderr, "use IPv4 or native IPv6") {
				t.Errorf("mapped init needs actionable refusal: err=%v stdout=%s stderr=%s", err, out, stderr)
			}
			assertNoPanelState(t, dir)
			entries, readErr := os.ReadDir(dir)
			if readErr != nil || len(entries) != 0 {
				t.Errorf("rejected init created files: %v, %v", entries, readErr)
			}
		})
	}
}

func TestTLSCLIInitCanonicalHostsWorkWithServerTLS(t *testing.T) {
	binary := buildTransportPanel(t)
	for _, host := range []string{"127.0.0.1", "::1", "panel.example.com", "123.example", "0xgg.example"} {
		t.Run(host, func(t *testing.T) {
			dir := t.TempDir()
			cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
			out, stderr, err := runTransportPanel(t, binary, dir, "-init-tls", "-tls-host", host, "-tls-cert", cert, "-tls-key", key)
			if err != nil {
				t.Fatalf("valid init refused: %v stdout=%s stderr=%s", err, out, stderr)
			}
			if _, err := serverTLS(":8443", "https://"+net.JoinHostPort(host, "8443"), cert, key); err != nil {
				t.Fatalf("initialized certificate unusable: %v", err)
			}
			assertNoPanelState(t, dir)
		})
	}
}

func TestTLSCLIInvalidStartupLeavesNoState(t *testing.T) {
	binary := buildTransportPanel(t)
	for _, args := range [][]string{
		{"-tls-cert", "absent"},
		{"-tls-key", "absent"},
		{"-tls-cert", "absent", "-tls-key", "absent-key"},
		{"-tls-host", "localhost"},
		{"-init-tls", "-tls-host", "localhost"},
		{"-init-tls", "-tls-cert", "cert", "-tls-key", "key"},
		{"-addr", "0.0.0.0:7800"},
		{"-addr", "0.0.0.0:7800", "-trusted-proxy", "127.0.0.1/32"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := t.TempDir()
			_, _, err := runTransportPanel(t, binary, dir, args...)
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			assertNoPanelState(t, dir)
		})
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{{"-insecure-loopback"}, {"-origin", "http://127.0.0.1:7800"}, {"-origin", "https://127.0.0.1:8443"}, {"-origin", "https://127.0.0.2:7800"}} {
		args := append([]string{"-addr", "127.0.0.1:7800", "-origin", "https://127.0.0.1:7800", "-tls-cert", cert, "-tls-key", key}, extra...)
		_, _, err := runTransportPanel(t, binary, dir, args...)
		if err == nil {
			t.Fatalf("invalid TLS config accepted %v", extra)
		}
		assertNoPanelState(t, dir)
	}
}

func TestTLSCLIRejectsMappedIPv6BeforeState(t *testing.T) {
	binary := buildTransportPanel(t)
	for _, host := range []string{"::ffff:7f00:1", "::ffff:127.0.0.1", "0:0:0:0:0:ffff:7f00:1", "0000:0000:0000:0000:0000:FFFF:7F00:0001"} {
		for _, material := range []string{"valid", "absent"} {
			t.Run(host+"/"+material, func(t *testing.T) {
				dir := t.TempDir()
				cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
				args := []string{"-addr", "127.0.0.1:8443", "-origin", "https://[" + host + "]:8443", "-tls-cert", cert, "-tls-key", key}
				if material == "valid" {
					if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
						t.Fatal(err)
					}
					// Bootstrap exits even if mapped validation regresses, while
					// exercising the same startup checks as a normal listener.
					args = append(args, "-bootstrap-admin", "admin")
				}
				out, stderr, err := runTransportPanel(t, binary, dir, args...)
				if err == nil || !strings.Contains(stderr, "IPv4-mapped IPv6") || !strings.Contains(stderr, "use IPv4 or native IPv6") {
					t.Errorf("mapped startup needs actionable refusal before material/state: err=%v stdout=%s stderr=%s", err, out, stderr)
				}
				assertNoPanelState(t, dir)
			})
		}
	}
}

func TestTLSCLIRejectsNoncanonicalOriginBeforeState(t *testing.T) {
	binary := buildTransportPanel(t)
	for _, tc := range []struct{ name, addr, origin, canonical, certHost string }{
		{"padded port", "127.0.0.1:044579", "https://127.0.0.1:044579", "https://127.0.0.1:44579", "127.0.0.1"},
		{"explicit default port", "127.0.0.1:443", "https://127.0.0.1:443", "https://127.0.0.1", "127.0.0.1"},
		{"expanded IPv6", "[::1]:8443", "https://[0:0:0:0:0:0:0:1]:8443", "https://[::1]:8443", "::1"},
		{"uppercase DNS", "127.0.0.1:8443", "https://PANEL.EXAMPLE.COM:8443", "https://panel.example.com:8443", "panel.example.com"},
		{"legacy IPv4", "127.0.0.1:8443", "https://127.1:8443", "https://127.0.0.1:8443", "127.0.0.1"},
		{"octal IPv4", "127.0.0.1:8443", "https://0177.0.0.1:8443", "https://127.0.0.1:8443", "127.0.0.1"},
		{"hex IPv4", "127.0.0.1:8443", "https://0x7f000001:8443", "https://127.0.0.1:8443", "127.0.0.1"},
		{"integer IPv4", "127.0.0.1:8443", "https://2130706433:8443", "https://127.0.0.1:8443", "127.0.0.1"},
		{"trailing dot IPv4", "127.0.0.1:8443", "https://127.0.0.1.:8443", "https://127.0.0.1:8443", "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
			if _, err := paneltls.Init(cert, key, tc.certHost); err != nil {
				t.Fatal(err)
			}
			_, stderr, err := runTransportPanel(t, binary, dir, "-addr", tc.addr, "-origin", tc.origin, "-tls-cert", cert, "-tls-key", key, "-bootstrap-admin", "admin")
			if err == nil || !strings.Contains(stderr, `use -origin "`+tc.canonical+`"`) {
				t.Errorf("noncanonical config needs refusal and canonical hint; err=%v stderr=%s", err, stderr)
			}
			assertNoPanelState(t, dir)
		})
	}
}

func TestTLSCLIRejectsForbiddenHostCharactersBeforeState(t *testing.T) {
	binary := buildTransportPanel(t)
	for _, char := range []string{"<", ">", "]"} {
		host := "panel" + char + ".example"
		t.Run(char, func(t *testing.T) {
			dir := t.TempDir()
			cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
			// Third-party certificates can contain browser-invalid DNS SANs;
			// bypass Init's stricter DNS policy to exercise startup validation.
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1), DNSNames: []string{host},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
				t.Fatal(err)
			}
			_, stderr, err := runTransportPanel(t, binary, dir,
				"-addr", "127.0.0.1:8443", "-origin", "https://"+host+":8443",
				"-tls-cert", cert, "-tls-key", key, "-bootstrap-admin", "admin")
			if err == nil || !strings.Contains(stderr, "invalid -origin") {
				t.Errorf("browser-invalid host needs origin refusal before state; err=%v stderr=%s", err, stderr)
			}
			assertNoPanelState(t, dir)
		})
	}
}

func TestTLSCLIRejectsUnknownOnlyEKUBeforeState(t *testing.T) {
	binary := buildTransportPanel(t)
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	// Bootstrap exits promptly even if validation regresses; normal startup must
	// reject the same material without creating state or retaining a listener.
	for _, extra := range [][]string{{"-bootstrap-admin", "admin"}, nil} {
		_, stderr, err := runTransportPanel(t, binary, dir,
			append([]string{"-addr", addr, "-origin", "https://localhost:" + strings.Split(addr, ":")[1], "-tls-cert", cert, "-tls-key", key}, extra...)...)
		if err == nil || !strings.Contains(stderr, "does not permit server authentication") {
			t.Errorf("unknown-only EKU needs refusal: err=%v stderr=%s", err, stderr)
		}
		assertNoPanelState(t, dir)
		conn, dialErr := net.DialTimeout("tcp4", addr, 100*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			t.Fatal("invalid EKU opened listener")
		}
	}
}

func TestTLSCLIRejectsOverflowingHexOriginBeforeState(t *testing.T) {
	binary := buildTransportPanel(t)
	for _, label := range []string{
		"0x100000000", "0X100000000",
		"0x10000000000000000", "0X10000000000000000",
		"0xfffffffffffffffff", "0XFFFFFFFFFFFFFFFFF",
	} {
		for _, prefix := range []string{"", "example."} {
			host := prefix + label
			t.Run(host, func(t *testing.T) {
				dir := t.TempDir()
				cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
				// Init now rejects these hosts too. Absent certificate paths prove
				// startup still reports the origin error before loading material.
				_, stderr, err := runTransportPanel(t, binary, dir,
					"-addr", "127.0.0.1:8443", "-origin", "https://"+host+":8443",
					"-tls-cert", cert, "-tls-key", key, "-bootstrap-admin", "admin")
				if err == nil || !strings.Contains(stderr, "invalid browser IPv4 host") {
					t.Errorf("overflowing hex origin needs IPv4 refusal; err=%v stderr=%s", err, stderr)
				}
				assertNoPanelState(t, dir)
			})
		}
	}
}

func TestTLSCLIDefaultOriginMismatchLeavesNoState(t *testing.T) {
	binary := buildTransportPanel(t)
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	// No -origin: the built-in default https://localhost:7800 must still be
	// checked against the TLS bind before any DB or key is created.
	_, stderr, err := runTransportPanel(t, binary, dir, "-addr", "127.0.0.1:8443", "-tls-cert", cert, "-tls-key", key)
	if err == nil || !strings.Contains(stderr, "does not match -origin") {
		t.Errorf("missing origin needs refusal, err=%v stderr=%s", err, stderr)
	}
	assertNoPanelState(t, dir)
}

// A reverse proxy may terminate TLS on https://<name>:443 while the panel
// listens on plain loopback; the native-TLS port equality rule must not leak
// into that documented mode.
func TestPlainLoopbackAcceptsExternalOriginOnDifferentPort(t *testing.T) {
	binary := buildTransportPanel(t)
	dir := t.TempDir()
	out, stderr, err := runTransportPanel(t, binary, dir,
		"-addr", "127.0.0.1:7800", "-origin", "https://panel.example.com",
		"-db", filepath.Join(dir, "panel.db"), "-secret-key", filepath.Join(dir, "secret.key"),
		"-bootstrap-admin", "proxyadmin")
	if err != nil {
		t.Fatalf("proxy-mode config refused: %v\nstdout=%s\nstderr=%s", err, out, stderr)
	}
	if !strings.Contains(out, "Password (shown once") {
		t.Fatalf("bootstrap did not run: %s", out)
	}
}

func TestTLSCLIServesHTTPSAndShutdown(t *testing.T) {
	binary := buildTransportPanel(t)
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	origin := "https://" + addr
	bootstrapOut, bootstrapErr, err := runTransportPanel(t, binary, dir,
		"-addr", addr, "-origin", origin, "-tls-cert", cert, "-tls-key", key,
		"-db", filepath.Join(dir, "panel.db"), "-secret-key", filepath.Join(dir, "secret.key"),
		"-bootstrap-admin", "tlsadmin")
	if err != nil {
		t.Fatalf("bootstrap failed: %v %s", err, bootstrapErr)
	}
	_, password, found := strings.Cut(bootstrapOut, "Password (shown once, not stored in plain text): ")
	if !found || strings.TrimSpace(password) == "" {
		t.Fatal("bootstrap did not return password")
	}
	password = strings.TrimSpace(password)
	logPath := filepath.Join(dir, "panel.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command(binary, "-addr", addr, "-origin", origin, "-tls-cert", cert, "-tls-key", key, "-db", filepath.Join(dir, "panel.db"), "-secret-key", filepath.Join(dir, "secret.key"))
	cmd.Dir = dir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	exited := false
	t.Cleanup(func() {
		if !exited {
			cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			t.Logf("panel output:\n%s", data)
		}
	})
	ca, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid root")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case err := <-done:
			exited = true
			t.Fatalf("panel exited: %v", err)
		default:
		}
		resp, err := client.Get(origin + "/api/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("health status %d", resp.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTPS never ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Native listener never falls back to application HTTP.
	plain := &http.Client{Timeout: time.Second}
	resp, err := plain.Get("http://" + addr + "/api/health")
	if err == nil {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 || strings.Contains(string(data), `"status":"ok"`) {
			t.Fatal("plaintext reached health")
		}
	}
	for _, path := range []string{"/api/health", "/api/v1/auth/me", "/api/v1/system/summary"} {
		req, _ := http.NewRequest(http.MethodGet, origin+path, nil)
		req.Host = "evil.example:7800"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("wrong Host bypass %s: %d", path, resp.StatusCode)
		}
	}
	// Real session over native TLS: Secure cookie accepted, API authenticated.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	authTransport := transport.Clone()
	authTransport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	authClient := &http.Client{Transport: authTransport, Jar: jar, Timeout: 2 * time.Second}
	loginBody, _ := json.Marshal(map[string]string{"username": "tlsadmin", "password": password})
	req, _ := http.NewRequest(http.MethodPost, origin+"/api/v1/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	resp, err = authClient.Do(req)
	if err != nil {
		t.Fatalf("login over HTTPS: %v", err)
	}
	var login struct {
		CSRF string `json:"csrf_token"`
	}
	json.NewDecoder(resp.Body).Decode(&login)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || login.CSRF == "" {
		t.Fatalf("login over HTTPS = %d csrf=%q", resp.StatusCode, login.CSRF)
	}
	secure := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == auth.SessionCookie {
			secure = cookie.Secure && cookie.HttpOnly && cookie.SameSite == http.SameSiteStrictMode
		}
	}
	if !secure {
		t.Fatal("session cookie lacks Secure/HttpOnly/SameSite=Strict over native TLS")
	}
	resp, err = authClient.Get(origin + "/api/v1/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated /me = %d", resp.StatusCode)
	}
	anonymous, err := client.Get(origin + "/api/v1/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous /me = %d, want 401", anonymous.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, origin+"/api/v1/auth/login", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || result.Error.Code != "invalid_request" {
		t.Fatalf("valid HTTPS origin auth = %d %s", resp.StatusCode, result.Error.Code)
	}
	for _, requestOrigin := range []string{"https://evil.example", ""} {
		req, _ = http.NewRequest(http.MethodPost, origin+"/api/v1/auth/login", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		if requestOrigin != "" {
			req.Header.Set("Origin", requestOrigin)
		}
		resp, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("login with Origin %q = %d", requestOrigin, resp.StatusCode)
		}
	}
	for _, tc := range []struct {
		csrf, requestOrigin string
		status              int
	}{
		{"", origin, http.StatusForbidden},
		{"wrong-token", origin, http.StatusForbidden},
		{login.CSRF, "https://evil.example", http.StatusForbidden},
		{login.CSRF, origin, http.StatusOK},
	} {
		req, _ := http.NewRequest(http.MethodPost, origin+"/api/v1/auth/logout", nil)
		req.Header.Set("Origin", tc.requestOrigin)
		if tc.csrf != "" {
			req.Header.Set("X-CSRF-Token", tc.csrf)
		}
		resp, err := authClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("HTTPS logout CSRF/origin status = %d, want %d", resp.StatusCode, tc.status)
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		exited = true
		if err != nil {
			t.Fatalf("shutdown exit %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("TLS shutdown hung")
	}
}
