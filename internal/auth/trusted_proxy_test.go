package auth

import (
	"fmt"
	"net"
	"net/http/httptest"
	"testing"
)

func mustProxies(t *testing.T, specs ...string) []*net.IPNet {
	parsed, err := ParseTrustedProxies(specs)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%v): %v", specs, err)
	}
	return parsed
}

func TestParseTrustedProxies(t *testing.T) {
	if _, err := ParseTrustedProxies(nil); err != nil {
		t.Fatalf("nil spec: %v", err)
	}
	if _, err := ParseTrustedProxies([]string{"127.0.0.1/32", "::1/128"}); err != nil {
		t.Fatalf("valid spec: %v", err)
	}
	for _, bad := range []string{"", "localhost", "127.0.0.1", "10.0.0.0/33", "1.2.3.4/24/8"} {
		if _, err := ParseTrustedProxies([]string{bad}); err == nil {
			t.Fatalf("accepted invalid spec %q", bad)
		}
	}
}

func TestClientIPIgnoresForwardingHeadersFromUntrustedPeer(t *testing.T) {
	s := New(nil, DefaultConfig(), nil)
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "198.51.100.4:5555"
	r.Header.Set("CF-Connecting-IP", "203.0.113.99")
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	if got := s.clientIP(r); got != "198.51.100.4" {
		t.Fatalf("untrusted peer IP = %q, want 198.51.100.4", got)
	}
}

func TestClientIPUsesCFHeaderFromTrustedProxy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxies = mustProxies(t, "127.0.0.1/32", "::1/128")
	s := New(nil, cfg, nil)
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("CF-Connecting-IP", "203.0.113.7")
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := s.clientIP(r); got != "203.0.113.7" {
		t.Fatalf("trusted peer IP = %q, want 203.0.113.7", got)
	}
	r6 := httptest.NewRequest("POST", "/", nil)
	r6.RemoteAddr = "[::1]:40000"
	r6.Header.Set("X-Forwarded-For", "2001:db8:abcd::7")
	if got := s.clientIP(r6); got != "2001:db8:abcd::7" {
		t.Fatalf("trusted v6 peer IP = %q", got)
	}
}

func TestClientIPWalksForwardedChainPastTrustedHops(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxies = mustProxies(t, "127.0.0.1/32", "10.0.0.0/8")
	s := New(nil, cfg, nil)
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.1.2.3")
	if got := s.clientIP(r); got != "203.0.113.7" {
		t.Fatalf("chain IP = %q, want rightmost untrusted 203.0.113.7", got)
	}
	// A spoofed left-most entry must not win when the right-most hop is untrusted.
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.RemoteAddr = "127.0.0.1:40000"
	r2.Header.Set("X-Forwarded-For", "192.0.2.66, 203.0.113.7")
	if got := s.clientIP(r2); got != "203.0.113.7" {
		t.Fatalf("spoofed chain IP = %q, want 203.0.113.7", got)
	}
}

func TestClientIPRejectsDuplicateXFFHeadersFromTrustedProxy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxies = mustProxies(t, "127.0.0.1/32")
	s := New(nil, cfg, nil)
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	// Header.Get would accept the attacker-controlled first header while
	// ignoring the second header; ambiguous duplicate headers must fail closed.
	r.Header.Add("X-Forwarded-For", "192.0.2.66")
	r.Header.Add("X-Forwarded-For", "203.0.113.7")
	if got := s.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("duplicate XFF IP = %q, want peer 127.0.0.1", got)
	}
}

func TestClientIPRejectsMalformedRightmostHop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxies = mustProxies(t, "127.0.0.1/32")
	s := New(nil, cfg, nil)
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	// Right-to-left parse hits the malformed hop first and must fail closed,
	// never skipping past it to accept the attacker-controlled left entry.
	r.Header.Set("X-Forwarded-For", "203.0.113.7, garbage")
	if got := s.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("malformed rightmost XFF IP = %q, want peer 127.0.0.1", got)
	}
}

func TestClientIPRejectsMalformedIntermediateHop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxies = mustProxies(t, "127.0.0.1/32", "10.0.0.0/8")
	s := New(nil, cfg, nil)
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	// Right-to-left: trusted 10.1.2.3 skipped, then malformed hop found before
	// the untrusted attacker entry; must fail closed instead of skipping it.
	r.Header.Set("X-Forwarded-For", "192.0.2.66, garbage, 10.1.2.3")
	if got := s.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("malformed intermediate XFF IP = %q, want peer 127.0.0.1", got)
	}
}

func TestClientIPCFStillWinsOverDuplicateXFF(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxies = mustProxies(t, "127.0.0.1/32")
	s := New(nil, cfg, nil)
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("CF-Connecting-IP", "203.0.113.7")
	r.Header.Add("X-Forwarded-For", "192.0.2.66")
	r.Header.Add("X-Forwarded-For", "198.51.100.8")
	if got := s.clientIP(r); got != "203.0.113.7" {
		t.Fatalf("CF over duplicate XFF IP = %q, want 203.0.113.7", got)
	}
}

func TestClientIPFallsBackOnMalformedForwardingHeaders(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxies = mustProxies(t, "127.0.0.1/32")
	s := New(nil, cfg, nil)
	cases := []struct {
		name   string
		cf     []string
		xff    []string
		want   string
		remote string
	}{
		{"garbage CF ignored", []string{"not-an-ip"}, nil, "127.0.0.1", "127.0.0.1:40000"},
		{"duplicate CF ignored", []string{"203.0.113.7", "203.0.113.8"}, nil, "127.0.0.1", "127.0.0.1:40000"},
		{"garbage XFF ignored", nil, []string{"nope"}, "127.0.0.1", "127.0.0.1:40000"},
		{"CF wins over XFF", []string{"203.0.113.7"}, []string{"198.51.100.1"}, "203.0.113.7", "127.0.0.1:40000"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.cf {
			r.Header.Add("CF-Connecting-IP", v)
		}
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := s.clientIP(r); got != c.want {
			t.Fatalf("%s: IP = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestThrottleSeparatesClientsBehindTrustedProxy(t *testing.T) {
	e := newMFAEnv(t, true, func(c *Config) {
		c.IPFailureLimit = 2
		c.TrustedProxies = mustProxies(t, "127.0.0.1/32")
	})
	viaProxy := func(ip, body string) resp {
		return e.client("127.0.0.1:40000").do("POST", "login", body, map[string]string{"CF-Connecting-IP": ip})
	}
	for i := 0; i < 2; i++ {
		if r := viaProxy("203.0.113.10", fmt.Sprintf(`{"username":"ghost%d","password":"x"}`, i)); r.code != 401 {
			t.Fatalf("failure %d code = %d", i, r.code)
		}
	}
	if r := viaProxy("203.0.113.10", `{"username":"admin","password":"sekret-1"}`); r.code != 429 {
		t.Fatalf("same client not throttled: %d", r.code)
	}
	if r := viaProxy("203.0.113.11", `{"username":"admin","password":"sekret-1"}`); r.code != 200 {
		t.Fatalf("other client locked out by neighbour: %d", r.code)
	}
}
