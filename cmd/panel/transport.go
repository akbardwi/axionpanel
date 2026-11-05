package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"axionpanel/internal/browserhost"
	"axionpanel/internal/paneltls"
)

func resolveTLSSettings(certPath, keyPath string, insecureLoopback bool) (bool, error) {
	if certPath == "" && keyPath == "" {
		return false, nil
	}
	if certPath == "" || keyPath == "" {
		return false, errors.New("-tls-cert and -tls-key must be provided together")
	}
	if insecureLoopback {
		return false, errors.New("-insecure-loopback cannot be combined with native TLS")
	}
	return true, nil
}

// validatePlainBind refuses plaintext on any non-loopback address. Reverse
// proxies must connect over loopback; a wildcard bind is never acceptable.
func validatePlainBind(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid -addr %q: %w", addr, err)
	}
	// Reject service names and empty ports before state creation. Explicit
	// port 0 remains valid for ephemeral loopback development.
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("invalid -addr %q: port must be a decimal number from 0 to 65535", addr)
	}
	if host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return nil
	}
	return fmt.Errorf("-addr %q: plaintext panel binds must be loopback; use -tls-cert/-tls-key for a public listener", addr)
}

// serverTLS builds a preloaded TLS config after checking that the origin,
// certificate identity, listen address and port describe the same endpoint.
func serverTLS(addr, origin, certPath, keyPath string) (*tls.Config, error) {
	if certPath == "" || keyPath == "" {
		return nil, errors.New("-tls-cert and -tls-key must be provided together")
	}
	host, port, _, err := originAuthority(origin)
	if err != nil {
		return nil, err
	}
	bindHost, bindPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid -addr %q: %w", addr, err)
	}
	if bindPort != port {
		return nil, fmt.Errorf("-addr port %s does not match -origin port %s; native TLS has no redirect listener", bindPort, port)
	}
	if err := checkBindHost(bindHost, host); err != nil {
		return nil, err
	}
	cfg, err := paneltls.Load(certPath, keyPath, strings.ToLower(host), time.Now())
	if err != nil {
		return nil, fmt.Errorf("native TLS: %w", err)
	}
	return cfg, nil
}

func checkBindHost(bindHost, originHost string) error {
	ip := net.ParseIP(bindHost)
	if bindHost == "" || (ip != nil && ip.IsUnspecified()) {
		return nil // wildcard can serve any origin covered by the certificate
	}
	if strings.EqualFold(bindHost, "localhost") {
		if strings.EqualFold(originHost, "localhost") || originHost == "127.0.0.1" || originHost == "::1" {
			return nil
		}
		return fmt.Errorf("-addr host localhost does not match -origin host %q", originHost)
	}
	originIP := net.ParseIP(originHost)
	if ip != nil {
		// An IP bind may serve a DNS origin (NAT/hostname), but not a different IP.
		if originIP != nil && !ip.Equal(originIP) {
			return fmt.Errorf("-addr host %s does not match -origin host %s", bindHost, originHost)
		}
		return nil
	}
	if originIP != nil || !strings.EqualFold(bindHost, originHost) {
		return fmt.Errorf("-addr host %q does not match -origin host %q", bindHost, originHost)
	}
	return nil
}

const (
	// WHATWG forbids these code points in a host: NUL, TAB, LF, CR, space and
	// # / : < > ? @ [ \ ] ^ |. Browsers reject them, and a configured origin
	// must be one the browser can actually send.
	forbiddenHostRunes = "\x00\t\n\r #/:<>?@[\\]^|"
	// Inside brackets, ':' separates IPv6 groups and the brackets delimit the
	// literal, so those three are structural there rather than forbidden.
	forbiddenIPv6HostRunes = "\x00\t\n\r #/<>?@\\^|"
)

// originAuthority validates the configured origin and returns its lowercase
// host, port and authority. Hosts are rejected before any listener, database
// or key work happens, so a browser-invalid spelling can never create state
// that the browser cannot reach.
func originAuthority(origin string) (host, port, authority string, err error) {
	u, err := url.Parse(origin)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid -origin %q: %w", origin, err)
	}
	if u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || origin != "https://"+u.Host || strings.ContainsAny(u.Host, "\\ 	\r\n") || strings.HasSuffix(u.Host, ":") {
		return "", "", "", fmt.Errorf("invalid -origin %q: native TLS requires scheme, host and optional port only, with https", origin)
	}
	// Also reject '%' so browser percent-decoding cannot change host identity
	// or hide forbidden code points. Check the authority before extracting the
	// hostname, including IPv6 zone escapes that Go accepts but browsers do not.
	if strings.Contains(u.Host, "%") {
		return "", "", "", fmt.Errorf("invalid -origin %q: native TLS requires a plain hostname; percent-encoded hosts are rejected because browsers percent-decode them before validation", origin)
	}
	forbidden := forbiddenHostRunes
	if strings.HasPrefix(u.Host, "[") {
		forbidden = forbiddenIPv6HostRunes
	}
	host = strings.ToLower(u.Hostname())
	if strings.ContainsAny(host, forbidden) {
		return "", "", "", fmt.Errorf("invalid -origin %q: host contains a character browsers forbid in hostnames (NUL, whitespace, # / : < > ? @ [ \\ ] ^ |); use the ASCII hostname the browser reports", origin)
	}
	if host == "" {
		return "", "", "", fmt.Errorf("invalid -origin %q: empty host", origin)
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(u.Host, "[") {
		return "", "", "", errors.New("invalid -origin: IPv6 address must be bracketed")
	}
	port = u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", "", fmt.Errorf("invalid -origin %q: invalid port", origin)
	}
	// Browsers always serialize ports without leading zeros and omit :443.
	canonicalPort := strconv.Itoa(n)
	if n == 443 {
		canonicalPort = ""
	}
	for _, r := range host {
		if r > 127 {
			return "", "", "", fmt.Errorf("invalid -origin %q: native TLS requires canonical browser origin; use the ASCII punycode hostname reported by the browser", origin)
		}
	}
	canonicalHost := host
	if strings.Contains(host, ":") {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid -origin %q: invalid IPv6 host", origin)
		}
		if addr.Is4In6() {
			return "", "", "", fmt.Errorf("invalid -origin %q: IPv4-mapped IPv6 TLS identities are not supported; use IPv4 or native IPv6", origin)
		}
		canonicalHost = addr.String()
	} else if canonical, numeric, err := browserhost.IPv4(host); numeric {
		if err != nil {
			return "", "", "", fmt.Errorf("invalid -origin %q: invalid browser IPv4 host: %w", origin, err)
		}
		canonicalHost = canonical
	}
	if canonical := originHref(canonicalHost, canonicalPort); canonical != origin {
		return "", "", "", fmt.Errorf("invalid -origin %q: native TLS requires canonical browser origin; use -origin %q", origin, canonical)
	}
	return host, port, u.Host, nil
}

func originHref(host, port string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return "https://" + host
}

func splitAuthority(authority, defaultPort string) (string, string, error) {
	if authority == "" {
		return "", "", errors.New("empty authority")
	}
	if strings.HasPrefix(authority, "[") {
		if host, port, err := net.SplitHostPort(authority); err == nil {
			return strings.ToLower(host), port, nil
		}
		if strings.HasSuffix(authority, "]") {
			return strings.ToLower(strings.Trim(authority, "[]")), defaultPort, nil
		}
		return "", "", errors.New("invalid bracketed authority")
	}
	switch strings.Count(authority, ":") {
	case 0:
		return strings.ToLower(authority), defaultPort, nil
	case 1:
		host, port, err := net.SplitHostPort(authority)
		if err != nil || host == "" || port == "" {
			return "", "", errors.New("invalid authority")
		}
		return strings.ToLower(host), port, nil
	default:
		return "", "", errors.New("IPv6 authority must be bracketed")
	}
}

// newHostGuard rejects TLS requests whose Host authority is not the configured
// origin, including /api/health, so a certificate shared by another vhost cannot
// reach the panel API.
func newHostGuard(origin string, next http.Handler) (http.Handler, error) {
	wantHost, wantPort, _, err := originAuthority(origin)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPort, err := splitAuthority(r.Host, "443")
		if err != nil || gotHost != wantHost || gotPort != wantPort {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusMisdirectedRequest)
			fmt.Fprintln(w, "Misdirected Request")
			return
		}
		next.ServeHTTP(w, r)
	}), nil
}
