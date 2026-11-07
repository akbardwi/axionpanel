package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"axionpanel/internal/nginxsite"
)

// Compile-time contract against the real adapter, not a parallel DTO model.
var _ StaticSitesBackend = (*nginxsite.Manager)(nil)

type siteBackendProbe struct {
	calls      int
	domain, id string
	err        error
	deadline   time.Time
}

func (b *siteBackendProbe) Plan(d string) (nginxsite.Plan, error) {
	b.calls++
	b.domain = d
	return nginxsite.Plan{Domain: d, WouldDo: "create"}, b.err
}
func (b *siteBackendProbe) Apply(ctx context.Context, id, d string) (nginxsite.Result, error) {
	return b.result(ctx, id, d)
}
func (b *siteBackendProbe) Remove(ctx context.Context, id, d string) (nginxsite.Result, error) {
	return b.result(ctx, id, d)
}
func (b *siteBackendProbe) Status(ctx context.Context, d string) (nginxsite.Result, error) {
	return b.result(ctx, "", d)
}
func (b *siteBackendProbe) result(ctx context.Context, id, d string) (nginxsite.Result, error) {
	b.calls++
	b.domain = d
	b.id = id
	b.deadline, _ = ctx.Deadline()
	return nginxsite.Result{Domain: d, OperationID: id, Status: "applied", Changed: true}, b.err
}

func TestStaticSitesNotInDefaultCatalog(t *testing.T) {
	def := NewRegistry()
	RegisterBuiltins(def)
	optIn := NewRegistry()
	RegisterBuiltins(optIn)
	RegisterStaticSites(optIn, &siteBackendProbe{})
	for _, name := range []string{"site.plan", "site.apply", "site.remove", "site.status"} {
		if def.Has(name) {
			t.Fatalf("default registry gained %s", name)
		}
		if !defaultSnapshotHas(t, optIn, name) {
			t.Fatalf("opt-in snapshot missing %s", name)
		}
	}
}

func defaultSnapshotHas(t *testing.T, r *Registry, name string) bool {
	t.Helper()
	_, ok := r.snapshot()[name]
	return ok
}

func TestStaticSitesDedicatedPolicyAndOptIn(t *testing.T) {
	r := NewRegistry()
	RegisterBuiltins(r)
	for _, name := range []string{"site.plan", "site.apply", "site.remove", "site.status"} {
		if r.Has(name) {
			t.Fatal("builtin widened", name)
		}
	}
	b := &siteBackendProbe{}
	RegisterStaticSites(r, b)
	for _, name := range []string{"site.plan", "site.apply", "site.remove", "site.status"} {
		op, ok := r.lookup(name)
		if !ok || op.permission != StaticSites {
			t.Fatalf("classification %s: %+v", name, op)
		}
	}
	for _, policy := range []Policy{{}, {AllowRootFiles: true}, {AllowedServices: []string{"nginx"}}, {AllowRootTerminal: true}} {
		s := &Server{Registry: r, Policy: policy}
		_, err := s.dispatch(context.Background(), "site.plan", Params(`{"domain":"example.test"}`), RequestMeta{})
		requireCode(t, err, ErrForbiddenByPolicy)
	}
	_, err := r.Run(context.Background(), "site.plan", Params(`{"domain":"example.test"}`), RequestMeta{})
	requireCode(t, err, ErrForbiddenByPolicy)
	if b.calls != 0 {
		t.Fatal("policy denial called backend")
	}
	s := &Server{Registry: r, Policy: Policy{AllowStaticSites: true}}
	got, err := s.dispatch(context.Background(), "site.plan", Params(`{"domain":"example.test"}`), RequestMeta{})
	if err != nil || got.(nginxsite.Plan).Domain != "example.test" || b.calls != 1 {
		t.Fatalf("got=%+v err=%v calls=%d", got, err, b.calls)
	}
	s.Policy.AllowStaticSites = false
	if !s.policyAllows(StaticSites) {
		t.Fatal("startup snapshot changed")
	}
}

func TestStaticSitesMutationRequiresValidIDAndDeadline(t *testing.T) {
	r := NewRegistry()
	b := &siteBackendProbe{}
	RegisterStaticSites(r, b)
	s := &Server{Registry: r, Policy: Policy{AllowStaticSites: true}}
	for _, raw := range []string{`{"domain":"example.test","listen":"0.0.0.0:8080"}`, `{"path":"/etc"}`, `{"domain":""}`} {
		_, err := s.dispatch(context.Background(), "site.apply", Params(raw), RequestMeta{})
		requireCode(t, err, ErrInvalidParams)
	}
	_, err := s.dispatch(context.Background(), "site.apply", Params(`{"domain":"example.test","operation_id":"ABCDEF"}`), RequestMeta{})
	requireCode(t, err, ErrInvalidParams)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = s.dispatch(ctx, "site.apply", Params(`{"domain":"example.test","operation_id":"0123456789abcdef0123456789abcdef"}`), RequestMeta{})
	if err != nil || b.domain != "example.test" || b.id != "0123456789abcdef0123456789abcdef" || b.deadline.IsZero() {
		t.Fatalf("mutation dispatch: %+v err=%v deadline=%v", b, err, b.deadline)
	}
	ctx = ContextWithCanceledDeadline()
	b.calls = 0
	_, err = s.dispatch(ctx, "site.remove", Params(`{"domain":"example.test","operation_id":"0123456789abcdef0123456789abcdef"}`), RequestMeta{})
	requireCode(t, err, ErrInvalidParams)
	if b.calls != 0 {
		t.Fatal("expired deadline reached backend")
	}
}

func TestStaticSitesMapsBackendErrorsToSafeCodes(t *testing.T) {
	r := NewRegistry()
	b := &siteBackendProbe{}
	RegisterStaticSites(r, b)
	s := &Server{Registry: r, Policy: Policy{AllowStaticSites: true}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, backendErr := range []error{nginxsite.ErrInvalidDomain, nginxsite.ErrRetainedContent, nginxsite.ErrPreexistingConfig, nginxsite.ErrConfigTestFailed, nginxsite.ErrReloadFailed} {
		b.err = backendErr
		_, err := s.dispatch(ctx, "site.status", Params(`{"domain":"example.test"}`), RequestMeta{})
		switch backendErr {
		case nginxsite.ErrInvalidDomain:
			requireCode(t, err, ErrInvalidParams)
		case nginxsite.ErrRetainedContent:
			requireCode(t, err, ErrConflict)
		case nginxsite.ErrPreexistingConfig:
			requireCode(t, err, ErrPreexistingConfig)
		case nginxsite.ErrConfigTestFailed:
			requireCode(t, err, ErrConfigTestFailed)
		case nginxsite.ErrReloadFailed:
			requireCode(t, err, ErrInternal)
		}
		b.err = nil
	}
}

func TestStaticSitesRejectsMalformedParamsBeforeBackend(t *testing.T) {
	badParams := []string{
		`null`, `[]`, `{}`, `{"domain":null}`, `{"Domain":"example.test"}`,
		`{"domain":"example.test","path":"/secret"}`, `{"domain":"example.test","listen":"0.0.0.0:8080"}`,
		`{"domain":"example.test","domain":"other.test"}`, `{"domain":"example.test"} {}`,
		`{"domain":"../secret"}`, `{"domain":"EXAMPLE.test"}`, `{"domain":"127.0.0.1"}`,
		`{"domain":"-bad.test"}`, `{"domain":"a"}`, `{"domain":"*.example.test"}`,
		`{"domain":"example.test."}`, `{"domain":""}`, `{"domain":"example.test","operation_id":""}`,
	}
	for _, action := range []string{"plan", "status", "apply", "remove"} {
		for _, raw := range badParams {
			action, raw := action, raw
			t.Run(action+":"+raw, func(t *testing.T) {
				b := &siteBackendProbe{}
				r := NewRegistry()
				RegisterStaticSites(r, b)
				s := &Server{Registry: r, Policy: Policy{AllowStaticSites: true}}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				_, err := s.dispatch(ctx, "site."+action, Params(raw), RequestMeta{})
				requireCode(t, err, ErrInvalidParams)
				if b.calls != 0 {
					t.Fatal("invalid params reached backend")
				}
			})
		}
	}
}

func TestStaticSitesRejectsInvalidMutationIDs(t *testing.T) {
	for _, action := range []string{"apply", "remove"} {
		for _, id := range []string{"", "0123", "0123456789ABCDEF0123456789ABCDEF", strings.Repeat("0", 31), strings.Repeat("0", 33), "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "0123456789abcdef0123456789abcde-"} {
			action, id := action, id
			t.Run(action+id, func(t *testing.T) {
				b := &siteBackendProbe{}
				r := NewRegistry()
				RegisterStaticSites(r, b)
				s := &Server{Registry: r, Policy: Policy{AllowStaticSites: true}}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				_, err := s.dispatch(ctx, "site."+action, Params(`{"domain":"example.test","operation_id":"`+id+`"}`), RequestMeta{})
				requireCode(t, err, ErrInvalidParams)
				if b.calls != 0 {
					t.Fatal("invalid op id reached backend")
				}
			})
		}
	}
}

func TestStaticSitesHTTPDeadlineDoesNotWidenReadOnly(t *testing.T) {
	b := &siteBackendProbe{}
	r := NewRegistry()
	RegisterStaticSites(r, b)
	var readDeadline time.Time
	r.Register("test.deadline", func(ctx context.Context, _ Params, _ RequestMeta) (any, error) {
		readDeadline, _ = ctx.Deadline()
		return nil, nil
	}, ReadOnly)
	s := &Server{Registry: r, Policy: Policy{AllowStaticSites: true}, StaticSitesTimeout: 90 * time.Second}
	before := time.Now()
	res, data := doReq(t, s, "POST", "/v1/ops/site.apply", strings.NewReader(`{"params":{"domain":"example.test","operation_id":"0123456789abcdef0123456789abcdef"}}`), nil)
	res.Body.Close()
	if res.StatusCode != 200 || b.deadline.Sub(before) < 89*time.Second || b.deadline.Sub(before) > 91*time.Second {
		t.Fatalf("deadline=%v status=%d body=%s", b.deadline.Sub(before), res.StatusCode, data)
	}
	res, _ = doReq(t, s, "POST", "/v1/ops/test.deadline", strings.NewReader(`{"params":{}}`), nil)
	res.Body.Close()
	if readDeadline.Sub(before) > 61*time.Second {
		t.Fatal("read-only default widened")
	}
	if s.httpWriteTimeout() != 120*time.Second {
		t.Fatalf("write timeout=%v", s.httpWriteTimeout())
	}
	if (&Server{}).httpWriteTimeout() != 120*time.Second {
		t.Fatal("default write timeout changed")
	}
}

func TestStaticSitesRejectsUnknownPathKeyWithoutEcho(t *testing.T) {
	b := &siteBackendProbe{}
	r := NewRegistry()
	RegisterStaticSites(r, b)
	s := &Server{Registry: r, Policy: Policy{AllowStaticSites: true}}
	_, err := s.dispatch(context.Background(), "site.plan", Params(`{"domain":"example.test","/root/secret":"x"}`), RequestMeta{})
	requireCode(t, err, ErrInvalidParams)
	var oe *OpError
	if !errors.As(err, &oe) {
		t.Fatalf("not an OpError: %v", err)
	}
	if strings.Contains(fmt.Sprint(oe.Details), "/root/secret") || strings.Contains(oe.Message, "/root/secret") {
		t.Fatal("raw path key echoed in error")
	}
	if b.calls != 0 {
		t.Fatal("unknown key reached backend")
	}
}

func TestStaticSitesErrorsNeverEchoHostPaths(t *testing.T) {
	b := &siteBackendProbe{}
	r := NewRegistry()
	RegisterStaticSites(r, b)
	s := &Server{Registry: r, Policy: Policy{AllowStaticSites: true}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	raw := fmt.Errorf("nginx -t failed: %w at /etc/nginx/sites-enabled/x.conf", nginxsite.ErrConfigTestFailed)
	for _, backendErr := range []error{raw, fmt.Errorf("%w: /var/lib/axionpanel/state", nginxsite.ErrUnsafePath), errors.New("SECRET /root/private")} {
		b.err = backendErr
		_, err := s.dispatch(ctx, "site.status", Params(`{"domain":"example.test"}`), RequestMeta{})
		if err == nil {
			t.Fatal("error swallowed")
		}
		msg := err.Error()
		var oe *OpError
		if !errors.As(err, &oe) {
			t.Fatalf("not an OpError: %v", err)
		}
		if oe.Details != nil {
			t.Fatalf("details leaked: %#v", oe.Details)
		}
		if strings.Contains(msg, "/") || strings.Contains(msg, "SECRET") || strings.Contains(msg, "sites-enabled") {
			t.Fatalf("message echoed host detail: %q", msg)
		}
	}
}

type canceledDeadline struct{ context.Context }

func (canceledDeadline) Deadline() (time.Time, bool) { return time.Now().Add(-time.Second), true }
func ContextWithCanceledDeadline() context.Context   { return canceledDeadline{context.Background()} }
