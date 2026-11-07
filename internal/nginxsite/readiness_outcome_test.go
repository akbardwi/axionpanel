package nginxsite

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func startNginx(t *testing.T, c Config) {
	t.Helper()
	if out, e := exec.Command(c.NginxBinary, "-p", c.Prefix, "-c", c.NginxConfig, "-e", "stderr").CombinedOutput(); e != nil {
		t.Fatalf("start nginx: %v: %s", e, out)
	}
	t.Cleanup(func() {
		exec.Command(c.NginxBinary, "-p", c.Prefix, "-c", c.NginxConfig, "-s", "quit", "-e", "stderr").Run()
	})
}
func fetch(t *testing.T, c Config, host string) (int, string, bool) {
	t.Helper()
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, "http://"+c.Listen+"/", nil)
	req.Host = host
	resp, e := client.Do(req)
	if e != nil {
		var oe *net.OpError
		if errors.As(e, &oe) {
			return 0, "", false
		}
		return 0, "", false
	}
	defer resp.Body.Close()
	b := make([]byte, 2048)
	n, _ := resp.Body.Read(b)
	return resp.StatusCode, string(b[:n]), true
}
func TestNoopApplyCannotReportUnservedSite(t *testing.T) {
	c := unitFixture(t)
	serving := true
	c.Readiness = func(context.Context, string, bool) error {
		if !serving {
			return ErrNotServing
		}
		return nil
	}
	m := manager(t, c)
	if _, e := m.Apply(testCtx(t), op1, "example.com"); e != nil {
		t.Fatal(e)
	}
	serving = false
	if _, e := m.Apply(testCtx(t), op2, "example.com"); !errors.Is(e, ErrNotServing) {
		t.Fatalf("unserved noop reported success: %v", e)
	}
}

func TestNoopRemoveVerifiesAbsence(t *testing.T) {
	c := unitFixture(t)
	calls := 0
	c.Readiness = func(_ context.Context, _ string, applied bool) error {
		calls++
		if applied {
			t.Error("remove asked for applied state")
		}
		return ErrReadinessUnknown
	}
	m := manager(t, c)
	if _, e := m.Remove(testCtx(t), op1, "example.com"); !errors.Is(e, ErrReadinessUnknown) {
		t.Fatalf("unverified absence reported success: %v", e)
	}
	if calls != 1 {
		t.Fatalf("probe calls=%d", calls)
	}
}

func TestRepeatedRemoveVerifiesAbsence(t *testing.T) {
	c := unitFixture(t)
	unknown := false
	c.Readiness = func(context.Context, string, bool) error {
		if unknown {
			return ErrReadinessUnknown
		}
		return nil
	}
	m := manager(t, c)
	if _, e := m.Apply(testCtx(t), op1, "example.com"); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Remove(testCtx(t), op2, "example.com"); e != nil {
		t.Fatal(e)
	}
	unknown = true
	if _, e := m.Remove(testCtx(t), op3, "example.com"); !errors.Is(e, ErrReadinessUnknown) {
		t.Fatalf("retained no-op removal accepted unknown listener: %v", e)
	}
}

func TestReadinessFailureRollsBackAndJournals(t *testing.T) {
	c := unitFixture(t)
	c.Readiness = func(_ context.Context, _ string, applied bool) error {
		if applied {
			return errors.New("injected readiness failure")
		}
		return nil
	}
	m := manager(t, c)
	_, e := m.Apply(testCtx(t), op1, "example.com")
	if !errors.Is(e, ErrNotServing) {
		t.Fatalf("apply: %v", e)
	}
	if _, e := os.Stat(filepath.Join(c.ConfigDir, "example.com.conf")); !os.IsNotExist(e) {
		t.Fatal("failed readiness left a published vhost")
	}
	j := readJournalFile(t, filepath.Join(c.StateDir, op1+".json"))
	if j.Phase != phaseDone || j.Code != "readiness" {
		t.Fatalf("journal: %+v", j)
	}
	if _, e := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(e, ErrNotServing) {
		t.Fatalf("replay not durable: %v", e)
	}
}
func TestAmbiguousRollbackStaysPending(t *testing.T) {
	c := unitFixture(t)
	c.Readiness = func(context.Context, string, bool) error { return errors.New("serving state unknown") }
	m := manager(t, c)
	if _, e := m.Apply(testCtx(t), op1, "example.com"); !errors.Is(e, ErrInterruptedOp) {
		t.Fatalf("apply: %v", e)
	}
	if j := readJournalFile(t, filepath.Join(c.StateDir, op1+".json")); j.Phase != phasePending {
		t.Fatalf("journal: %+v", j)
	}
	if _, e := m.Status(testCtx(t), "example.com"); !errors.Is(e, ErrInterruptedOp) {
		t.Fatalf("read after ambiguity: %v", e)
	}
}
func TestRemoveLastVhostAcceptsConnectionRefusal(t *testing.T) {
	c := fixture(t)
	startNginx(t, c)
	m := manager(t, c)
	ctx := testCtx(t)
	if _, e := m.Apply(ctx, op1, "example.com"); e != nil {
		t.Fatal(e)
	}
	if code, body, ok := fetch(t, c, "example.com"); !ok || code != 200 {
		code, body, _ = fetch(t, c, "example.com")
		t.Fatalf("pre-remove serve %d %s", code, body)
	}
	if _, e := m.Remove(ctx, op2, "example.com"); e != nil {
		t.Fatalf("remove with refusal: %v", e)
	}
	if _, _, ok := fetch(t, c, "example.com"); ok {
		t.Fatal("removal reported but a listener still answers")
	}
	if s, e := m.Status(ctx, "example.com"); e != nil || s.Status != "removed" {
		t.Fatalf("status %v %v", s, e)
	}
}
func TestRemoveKeepsOtherManagedSiteServing(t *testing.T) {
	c := fixture(t)
	startNginx(t, c)
	m := manager(t, c)
	ctx := testCtx(t)
	if _, e := m.Apply(ctx, op1, "a.example.com"); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Apply(ctx, op2, "b.example.com"); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Remove(ctx, op3, "a.example.com"); e != nil {
		t.Fatalf("remove: %v", e)
	}
	code, body, ok := fetch(t, c, "b.example.com")
	if !ok || code != 200 {
		defer func() { code, body, _ = fetch(t, c, "b.example.com") }()
		t.Fatalf("surviving site %d %s", code, body)
	}
	if e := m.verifyContent("b.example.com"); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(c.ConfigDir, "a.example.com.conf")); !os.IsNotExist(e) {
		t.Fatal("removed vhost still published")
	}
	if _, e := m.Remove(ctx, op4, "b.example.com"); e != nil {
		t.Fatalf("remove last: %v", e)
	}
}
func TestProbeAddressMapsWildcardsToLoopback(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:8080":    "127.0.0.1:8080",
		"[::]:8080":       "[::1]:8080",
		"127.0.0.1:8080":  "127.0.0.1:8080",
		"[::1]:8080":      "[::1]:8080",
		"192.0.2.10:8080": "192.0.2.10:8080",
	} {
		if got := probeAddress(in); got != want {
			t.Errorf("probeAddress(%q)=%q want %q", in, got, want)
		}
	}
}
