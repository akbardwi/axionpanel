package nginxsite

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// The configured listener is the only address probed: an IPv6 literal must not
// be rewritten to IPv4 or dialled through DNS.
func TestRealIPv6LoopbackReadiness(t *testing.T) {
	c := fixture(t)
	l, e := net.Listen("tcp6", "[::1]:0")
	if e != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	c.Listen = l.Addr().String()
	l.Close()
	startNginx(t, c)
	m := manager(t, c)
	ctx := testCtx(t)
	if _, e := m.Apply(ctx, op1, "ipv6.example.com"); e != nil {
		t.Fatalf("ipv6 apply: %v", e)
	}
	if code, body, ok := fetch(t, c, "ipv6.example.com"); !ok || code != 200 {
		t.Fatalf("ipv6 serve %d %s", code, body)
	}
	if _, e := m.Remove(ctx, op2, "ipv6.example.com"); e != nil {
		t.Fatalf("ipv6 remove: %v", e)
	}
}

// A redirect is not the site. Following it (or trusting the redirecting host)
// would let an unrelated occupant or login page satisfy the probe.
func TestRedirectingOccupantIsNotServing(t *testing.T) {
	c := unitFixture(t)
	c.Readiness = nil
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	c.Listen = l.Addr().String()
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})}
	go s.Serve(l)
	defer s.Close()
	m := manager(t, c)
	if _, e := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(e, ErrNotServing) {
		t.Fatalf("redirect accepted as serving: %v", e)
	}
}

// Close must not release descriptors under an operation that still holds the
// gate, and must still succeed afterwards.
func TestCloseWaitsForInFlightOperation(t *testing.T) {
	c := unitFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	c.Reloader = func(context.Context) error { close(entered); <-release; return nil }
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	applied := make(chan error, 1)
	go func() { _, e := m.Apply(testCtx(t), op1, "example.com"); applied <- e }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	select {
	case e := <-closed:
		t.Fatalf("Close returned %v while an operation held the manager", e)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if e := <-applied; e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close never returned after the operation finished")
	}
}
