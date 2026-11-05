package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"axionpanel/internal/paneltls"
)

func TestServerTLSRequiresBothFlags(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ cert, key string }{{filepath.Join(dir, "cert"), ""}, {"", filepath.Join(dir, "key")}} {
		if _, err := serverTLS("127.0.0.1:8443", "https://127.0.0.1:8443", tc.cert, tc.key); err == nil {
			t.Fatalf("accepted cert=%q key=%q", tc.cert, tc.key)
		}
	}
}

func TestServerTLSAcceptsValidIPOrigin(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := serverTLS("127.0.0.1:8443", "https://127.0.0.1:8443", cert, key); err != nil {
		t.Fatalf("valid native TLS rejected: %v", err)
	}
}

func TestServerTLSAcceptsCanonicalDefault443Origin(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	cfg, err := serverTLS("127.0.0.1:443", "https://127.0.0.1", cert, key)
	if err != nil {
		t.Fatalf("canonical default-443 origin rejected: %v", err)
	}
	if cfg == nil {
		t.Fatal("nil tls config")
	}
}

func TestServerTLSRejectsNonHTTPSOrigin(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://127.0.0.1:8443", "https://127.0.0.1:9443", "https://127.0.0.2:8443", "https://127.0.0.1:8443/path", "https://127.0.0.1"} {
		if _, err := serverTLS("127.0.0.1:8443", origin, cert, key); err == nil {
			t.Fatalf("origin %q accepted", origin)
		}
	}
}

func TestServerTLSBindCompatibility(t *testing.T) {
	dir := t.TempDir()
	dnsCert, dnsKey := filepath.Join(dir, "dns-cert"), filepath.Join(dir, "dns-key")
	ipCert, ipKey := filepath.Join(dir, "ip-cert"), filepath.Join(dir, "ip-key")
	if _, err := paneltls.Init(dnsCert, dnsKey, "panel.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := paneltls.Init(ipCert, ipKey, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, addr, origin, cert, key string
		wantErr                       bool
	}{
		{"wildcard with DNS origin", "0.0.0.0:7800", "https://panel.example.com:7800", dnsCert, dnsKey, false},
		{"ipv6 wildcard with DNS origin", "[::]:7800", "https://panel.example.com:7800", dnsCert, dnsKey, false},
		{"explicit NAT ip with DNS origin", "192.0.2.10:7800", "https://panel.example.com:7800", dnsCert, dnsKey, false},
		{"explicit loopback with loopback dns origin", "127.0.0.1:7800", "https://localhost:7800", ipCert, ipKey, true},
		{"wildcard with ip origin", "0.0.0.0:7800", "https://192.0.2.10:7800", ipCert, ipKey, false},
		{"explicit foreign ip", "192.0.2.20:7800", "https://192.0.2.10:7800", ipCert, ipKey, true},
		{"explicit ip vs dns cert", "192.0.2.10:7800", "https://192.0.2.10:7800", dnsCert, dnsKey, true},
		{"localhost alias", "127.0.0.1:7800", "https://localhost:7800", dnsCert, dnsKey, true},
		{"port mismatch", "0.0.0.0:7800", "https://panel.example.com:8443", dnsCert, dnsKey, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := serverTLS(tc.addr, tc.origin, tc.cert, tc.key)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && (cfg == nil || cfg.MinVersion != tls.VersionTLS12 || len(cfg.Certificates) != 1) {
				t.Fatalf("bad config %+v", cfg)
			}
		})
	}
}

func TestPlainBindMustBeLoopback(t *testing.T) {
	for _, tc := range []struct {
		addr    string
		wantErr bool
	}{
		{"127.0.0.1:7800", false}, {"[::1]:7800", false}, {"localhost:7800", false},
		{"127.0.0.1:0", false}, {"[::1]:0", false},
		{"127.0.0.1:not-a-port", true}, {"127.0.0.1:", true},
		{"127.0.0.1:-1", true}, {"127.0.0.1:65536", true},
		{"0.0.0.0:7800", true}, {"[::]:7800", true}, {":7800", true}, {"192.0.2.10:7800", true}, {"panel.example.com:7800", true},
	} {
		if err := validatePlainBind(tc.addr); (err != nil) != tc.wantErr {
			t.Fatalf("addr %q err=%v wantErr=%v", tc.addr, err, tc.wantErr)
		}
	}
}

func TestHostGuardRejectsWrongAuthority(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true; io.WriteString(w, "ok") })
	guard, err := newHostGuard("https://panel.example.com:7800", next)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"panel.example.com:7800", "PANEL.EXAMPLE.COM:7800"} {
		reached = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://panel.example.com/api/health", nil)
		req.Host = host
		guard.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !reached {
			t.Fatalf("host %q status %d reached=%v", host, rec.Code, reached)
		}
	}
	for _, host := range []string{"evil.example.com:7800", "panel.example.com:7801", "panel.example.com", "127.0.0.1:7800", ""} {
		reached = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://panel.example.com/api/health", nil)
		req.Host = host
		guard.ServeHTTP(rec, req)
		if rec.Code != http.StatusMisdirectedRequest || reached {
			t.Fatalf("host %q status %d reached=%v", host, rec.Code, reached)
		}
	}
	if _, err := newHostGuard("http://panel.example.com", next); err == nil {
		t.Fatal("http origin guard accepted")
	}
}

func TestHostGuardDefaultPort(t *testing.T) {
	// Configured origins must match browser serialization; request Host may
	// still include the equivalent explicit default port.
	for _, origin := range []string{"https://panel.example.com"} {
		guard, err := newHostGuard(origin, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range []string{"panel.example.com", "panel.example.com:443", "PANEL.example.com"} {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://panel.example.com/", nil)
			req.Host = host
			guard.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("origin %q host %q status %d", origin, host, rec.Code)
			}
		}
	}
}

func TestHostGuardIPv6(t *testing.T) {
	guard, err := newHostGuard("https://[2001:db8::1]:8443", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"[2001:db8::1]:8443", "[2001:DB8::1]:8443"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://[2001:db8::1]/", nil)
		req.Host = host
		guard.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("host %q status %d", host, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://[2001:db8::1]/", nil)
	req.Host = "[2001:db8::2]:8443"
	guard.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("wrong ipv6 status %d", rec.Code)
	}
}

func TestOriginAuthority(t *testing.T) {
	cases := []struct {
		origin, host, port, authority string
		wantErr                       bool
	}{
		{"https://panel.example.com", "panel.example.com", "443", "panel.example.com", false},
		{"https://127.0.0.1", "127.0.0.1", "443", "127.0.0.1", false},
		{"https://127.0.0.1:44579", "127.0.0.1", "44579", "127.0.0.1:44579", false},
		{"https://[::1]", "::1", "443", "[::1]", false},
		{"https://[::ffff:7f00:1]:8443", "", "", "", true},
		{"https://123.example.com:8443", "123.example.com", "8443", "123.example.com:8443", false},
		{"https://panel.example.com.:8443", "panel.example.com.", "8443", "panel.example.com.:8443", false},
		{"https://panel.example.com:8443/", "", "", "", true},
		{"https://[2001:db8::1]:8443", "2001:db8::1", "8443", "[2001:db8::1]:8443", false},
		{"https://panel.example.com?", "", "", "", true},
		{"https://panel.example.com#", "", "", "", true},
		{"https://panel.example.com:", "", "", "", true},
		{"https://2001:db8::1:8443", "", "", "", true},
		{"https://panel.example.com\\bad", "", "", "", true},
		{"http://panel.example.com", "", "", "", true},
		{"https://user@panel.example.com", "", "", "", true},
	}
	for _, tc := range cases {
		host, port, authority, err := originAuthority(tc.origin)
		if (err != nil) != tc.wantErr || host != tc.host || port != tc.port || authority != tc.authority {
			t.Fatalf("%q => %q %q %q %v", tc.origin, host, port, authority, err)
		}
	}
}

func TestNativeTLSRejectsMappedIPv6BeforeMaterial(t *testing.T) {
	for _, host := range []string{"::ffff:7f00:1", "::ffff:127.0.0.1", "0:0:0:0:0:ffff:7f00:1", "0000:0000:0000:0000:0000:FFFF:7F00:0001"} {
		t.Run(host, func(t *testing.T) {
			origin := "https://[" + host + "]:8443"
			_, _, _, err := originAuthority(origin)
			if err == nil || !strings.Contains(err.Error(), "IPv4-mapped IPv6") || !strings.Contains(err.Error(), "use IPv4 or native IPv6") {
				t.Errorf("mapped origin needs actionable refusal: %v", err)
			}
			dir := t.TempDir()
			_, err = serverTLS("127.0.0.1:8443", origin, filepath.Join(dir, "absent-cert"), filepath.Join(dir, "absent-key"))
			if err == nil || !strings.Contains(err.Error(), "IPv4-mapped IPv6") || !strings.Contains(err.Error(), "use IPv4 or native IPv6") {
				t.Errorf("mapped origin must fail before reading material: %v", err)
			}
		})
	}
}

func TestOriginAuthorityRejectsExplicitDefaultPort(t *testing.T) {
	_, _, _, err := originAuthority("https://panel.example.com:443")
	if err == nil || !strings.Contains(err.Error(), `use -origin "https://panel.example.com"`) {
		t.Fatalf("explicit default port needs canonical origin hint, got %v", err)
	}
}

func TestOriginAuthorityRejectsPaddedPort(t *testing.T) {
	for _, tc := range []struct{ origin, canonical string }{
		{"https://127.0.0.1:044579", "https://127.0.0.1:44579"},
		{"https://panel.example.com:00443", "https://panel.example.com"},
	} {
		_, _, _, err := originAuthority(tc.origin)
		if err == nil || !strings.Contains(err.Error(), `use -origin "`+tc.canonical+`"`) {
			t.Errorf("%q needs canonical origin hint %q, got %v", tc.origin, tc.canonical, err)
		}
	}
}

func TestOriginAuthorityRejectsNoncanonicalIPSerialization(t *testing.T) {
	for _, tc := range []struct{ origin, canonical string }{
		// Browsers compress IPv6 and drop leading zeros in every group.
		{"https://[0:0:0:0:0:0:0:1]:8443", "https://[::1]:8443"},
		{"https://[2001:0db8:0000:0000:0000:0000:0000:0001]:8443", "https://[2001:db8::1]:8443"},
	} {
		_, _, _, err := originAuthority(tc.origin)
		if err == nil || !strings.Contains(err.Error(), `use -origin "`+tc.canonical+`"`) {
			t.Errorf("%q needs canonical origin hint %q, got %v", tc.origin, tc.canonical, err)
		}
	}
}

func TestOriginAuthorityRejectsLegacyIPv4Forms(t *testing.T) {
	// WHATWG URL parsing canonicalizes all of these to 127.0.0.1, so a
	// configured origin in any other spelling can never match the browser.
	for _, origin := range []string{
		"https://127.1:8443",
		"https://0177.0.0.1:8443",
		"https://0x7f000001:8443",
		"https://2130706433:8443",
		"https://127.0.0.1.:8443",
	} {
		_, _, _, err := originAuthority(origin)
		if err == nil || !strings.Contains(err.Error(), "canonical browser origin") {
			t.Errorf("%q accepted, want canonical browser origin refusal; err=%v", origin, err)
		}
	}
}

func TestOriginAuthorityRejectsOverflowingHexHosts(t *testing.T) {
	for _, label := range []string{
		"0x100000000", "0X100000000",
		"0x10000000000000000", "0X10000000000000000",
		"0xfffffffffffffffff", "0XFFFFFFFFFFFFFFFFF",
	} {
		for _, prefix := range []string{"", "example."} {
			origin := "https://" + prefix + label + ":8443"
			t.Run(origin, func(t *testing.T) {
				_, _, _, err := originAuthority(origin)
				if err == nil || !strings.Contains(err.Error(), "invalid browser IPv4 host") {
					t.Fatalf("overflowing hex host needs IPv4 refusal, got %v", err)
				}
			})
		}
	}
}

func TestOriginAuthorityAllowsNonnumericHexLikeDNS(t *testing.T) {
	for _, label := range []string{"0x100000000g", "0x10000000000000000g", "0xfffffffffffffffffg"} {
		for _, prefix := range []string{"", "example."} {
			host := prefix + label
			origin := "https://" + host + ":8443"
			gotHost, port, authority, err := originAuthority(origin)
			if err != nil || gotHost != host || port != "8443" || authority != host+":8443" {
				t.Errorf("nonnumeric DNS %q rejected: %q %q %q %v", origin, gotHost, port, authority, err)
			}
		}
	}
}

func TestOriginAuthorityRejectsNoncanonicalCase(t *testing.T) {
	for _, tc := range []struct{ origin, canonical string }{
		{"https://PANEL.EXAMPLE.COM:8443", "https://panel.example.com:8443"},
		{"https://[2001:DB8::1]:8443", "https://[2001:db8::1]:8443"},
		{"https://[0:0:0:0:0:0:0:1]:00443", "https://[::1]"},
	} {
		_, _, _, err := originAuthority(tc.origin)
		if err == nil || !strings.Contains(err.Error(), `use -origin "`+tc.canonical+`"`) {
			t.Errorf("%q needs canonical origin hint %q, got %v", tc.origin, tc.canonical, err)
		}
	}
}

func TestOriginAuthorityRejectsBrowserInvalidHosts(t *testing.T) {
	for _, origin := range []string{"https://[fe80::1%25eth0]:8443", "https://bücher.example:8443"} {
		if _, _, _, err := originAuthority(origin); err == nil {
			t.Errorf("browser cannot serialize configured host unchanged: %q", origin)
		}
	}
}

func TestOriginAuthorityRejectsForbiddenHostCharacters(t *testing.T) {
	// Include the complete WHATWG forbidden host set, plus percent escapes:
	// Go's URL parser and browser percent-decoding must not disagree.
	for _, tc := range []struct{ name, char string }{
		{"less than", "<"}, {"greater than", ">"},
		{"NUL", "\x00"}, {"TAB", "	"}, {"LF", "\n"}, {"CR", "\r"},
		{"space", " "}, {"hash", "#"}, {"slash", "/"}, {"colon", ":"},
		{"question mark", "?"}, {"at", "@"}, {"left bracket", "["},
		{"backslash", "\\"}, {"right bracket", "]"}, {"caret", "^"}, {"pipe", "|"},
		{"percent", "%"}, {"encoded less than", "%3c"}, {"encoded greater than", "%3e"},
		{"encoded dot", "%2e"}, {"encoded percent", "%25"},
	} {
		origin := "https://panel" + tc.char + ".example:8443"
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := originAuthority(origin); err == nil || !strings.Contains(err.Error(), "invalid -origin") {
				t.Fatalf("browser-invalid host needs origin refusal: %q err=%v", origin, err)
			}
		})
	}
}

func TestOriginAuthorityPreservesBrowserValidHosts(t *testing.T) {
	for _, tc := range []struct{ host, authority string }{
		{"panel.example.com", "panel.example.com:8443"},
		{"panel_name.example", "panel_name.example:8443"},
		{"127.0.0.1", "127.0.0.1:8443"},
		{"192.0.2.10", "192.0.2.10:8443"},
		{"2001:db8::1", "[2001:db8::1]:8443"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			host, port, authority, err := originAuthority("https://" + tc.authority)
			if err != nil || host != tc.host || port != "8443" || authority != tc.authority {
				t.Fatalf("valid browser host rejected: host=%q port=%q authority=%q err=%v", host, port, authority, err)
			}
		})
	}
}

func TestServerTLSDoesNotLeakMaterial(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if _, err := paneltls.Init(cert, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	_, err := serverTLS("127.0.0.1:8443", "https://127.0.0.1:8443", cert, key)
	if err == nil {
		t.Fatal("permissive key accepted")
	}
	data, _ := os.ReadFile(key)
	if strings.Contains(err.Error(), strings.TrimSpace(string(data))) {
		t.Fatal("private key leaked in error")
	}
}
