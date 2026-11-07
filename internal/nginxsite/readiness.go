package nginxsite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// probeAddress never resolves a domain or dials a wildcard. Host is sent
// separately, so IPv6 and wildcard listeners use the same verification path.
func probeAddress(listen string) string {
	host, port, _ := net.SplitHostPort(listen)
	ip := net.ParseIP(host)
	if ip.IsUnspecified() {
		if ip.To4() != nil {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	return net.JoinHostPort(host, port)
}

func (m *Manager) expectedContent(domain string) ([]byte, error) {
	site, e := openPinnedDir(m.cfg.ContentDir + "/" + domain + "/public")
	if e != nil {
		return nil, e
	}
	defer site.Close()
	return readAt(site, "index.html")
}

// ready verifies the complete remaining managed set as well as the changed
// Host. Refusal proves absence only when no managed vhosts remain; timeouts,
// redirects, foreign responses and other transport failures never do.
func (m *Manager) ready(ctx context.Context, domain string, applied bool) error {
	if m.cfg.Readiness != nil {
		return m.cfg.Readiness(ctx, domain, applied)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	names, e := namesAt(m.conf)
	if e != nil {
		return e
	}
	expected := map[string][]byte{}
	for _, name := range names {
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		d := strings.TrimSuffix(name, ".conf")
		if validateDomain(d) != nil {
			return ErrUnsafePath
		}
		if e := m.verifyContent(d); e != nil {
			return e
		}
		b, e := m.expectedContent(d)
		if e != nil {
			return e
		}
		expected[d] = b
	}
	var removed []byte
	if !applied {
		removed, e = m.expectedContent(domain)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 150 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(host string) ([]byte, int, error) {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+probeAddress(m.cfg.Listen)+"/", nil)
		if e != nil {
			return nil, 0, e
		}
		req.Host = host
		resp, e := client.Do(req)
		if e != nil {
			return nil, 0, e
		}
		defer resp.Body.Close()
		b, e := io.ReadAll(io.LimitReader(resp.Body, fileLimit+1))
		return b, resp.StatusCode, e
	}
	check := func() error {
		for d, want := range expected {
			b, status, e := request(d)
			if e != nil {
				return fmt.Errorf("%w: %v", ErrNotServing, e)
			}
			if status != http.StatusOK || !bytes.Equal(b, want) {
				return ErrNotServing
			}
		}
		if applied {
			if _, ok := expected[domain]; !ok {
				return ErrNotServing
			}
			return nil
		}
		b, status, e := request(domain)
		if e != nil {
			if len(expected) == 0 && errors.Is(e, syscall.ECONNREFUSED) {
				return nil
			}
			return fmt.Errorf("%w: %v", ErrReadinessUnknown, e)
		}
		if status != http.StatusOK {
			return ErrReadinessUnknown
		}
		if len(removed) > 0 && bytes.Equal(b, removed) {
			return ErrStillServing
		}
		for _, want := range expected {
			if bytes.Equal(b, want) {
				return nil
			}
		}
		return ErrReadinessUnknown
	}
	var last error
	for {
		if last = check(); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ErrReadinessUnknown, last, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
