package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var oe *OpError
	if !errors.As(err, &oe) || oe.Code != code {
		t.Fatalf("err=%v want %s", err, code)
	}
}

func TestRegistrationRejectsUnknownPermission(t *testing.T) {
	for _, permissions := range [][]Permission{{Permission("sudo")}, {ReadOnly, ReadOnly}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("invalid permission metadata accepted")
				}
			}()
			NewRegistry().Register("test.bad", func(context.Context, Params, RequestMeta) (any, error) { return nil, nil }, permissions...)
		}()
	}
}

func TestServiceTargetValidation(t *testing.T) {
	bad := []string{"", "*", "*.service", "nginx*", "ngin/x", "../nginx", "/etc/nginx", "-nginx", "--nginx", "nginx x", "nginx;id", "nginx|id", "nginx&id", "nginx`id`", "nginx$(id)", "nginx\n", strings.Repeat("a", 65)}
	for _, target := range bad {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("invalid service target %q accepted", target)
				}
			}()
			NewRegistry().Register("test.svc", func(context.Context, Params, RequestMeta) (any, error) { return nil, nil }, Service(target))
		}()
	}
	good := []string{"nginx", "nginx.service", "postgres@main", "a-b_c.d", "svc1", "apache2", "php8.3-fpm"}
	for _, target := range good {
		NewRegistry().Register("test.svc", func(context.Context, Params, RequestMeta) (any, error) { return nil, nil }, Service(target))
	}
}

func TestUnclassifiedOperationDeniedEveryEntry(t *testing.T) {
	r := NewRegistry()
	called := false
	r.Register("system.info", func(context.Context, Params, RequestMeta) (any, error) { called = true; return "unsafe", nil })
	_, err := r.Run(context.Background(), "system.info", nil, RequestMeta{})
	requireCode(t, err, ErrForbiddenByPolicy)
	for _, path := range []string{"/v1/info", "/v1/ops/system.info"} {
		method := "POST"
		if path == "/v1/info" {
			method = "GET"
		}
		res, _ := doReq(t, &Server{Registry: r}, method, path, strings.NewReader(`{"params":{}}`), nil)
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("%s status=%d", path, res.StatusCode)
		}
	}
	if called {
		t.Fatal("unsafe operation executed")
	}
}

func TestMutationUnavailableEvenWhenPolicyAllowsAndLoggerPanics(t *testing.T) {
	r := NewRegistry()
	called := false
	r.Register("test.mutate", func(context.Context, Params, RequestMeta) (any, error) { called = true; return nil, nil }, RootTerminal)
	s := &Server{Registry: r, Policy: Policy{AllowRootTerminal: true}, Logger: func(string, ...any) { panic("SECRET sink failure") }}
	res, _ := doReq(t, s, "POST", "/v1/ops/test.mutate", strings.NewReader(`{"params":{}}`), nil)
	defer res.Body.Close()
	if res.StatusCode != 501 {
		t.Fatalf("status=%d want unsupported", res.StatusCode)
	}
	if called {
		t.Fatal("non-read-only handler executed without durable audit support")
	}
}

func TestRootTerminalPolicyGate(t *testing.T) {
	handler := func(context.Context, Params, RequestMeta) (any, error) { return "shell", nil }
	for _, tc := range []struct {
		name   string
		pol    Policy
		log    bool
		wantOK bool
	}{
		{"deny-by-default", Policy{}, false, false},
		{"allowed-no-audit-still-unimplemented", Policy{AllowRootTerminal: true}, false, true},
		{"allowed-with-audit", Policy{AllowRootTerminal: true}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			r.Register("terminal.open", handler, RootTerminal)
			s := &Server{Registry: r, Policy: tc.pol}
			if tc.log {
				s.Logger = func(string, ...any) {}
			}
			_, err := s.dispatch(context.Background(), "terminal.open", nil, RequestMeta{})
			if tc.wantOK {
				requireCode(t, err, ErrUnsupported)
			}
			if !tc.wantOK {
				requireCode(t, err, ErrForbiddenByPolicy)
			}
		})
	}
}

func TestRootFilesPolicyGate(t *testing.T) {
	r := NewRegistry()
	r.Register("files.open", func(context.Context, Params, RequestMeta) (any, error) { return "f", nil }, RootFiles)
	s := &Server{Registry: r, Policy: Policy{AllowRootFiles: true}, Logger: func(string, ...any) {}}
	_, err := s.dispatch(context.Background(), "files.open", nil, RequestMeta{})
	requireCode(t, err, ErrUnsupported)
	s2 := &Server{Registry: r, Policy: Policy{AllowRootFiles: true}}
	_, err = s2.dispatch(context.Background(), "files.open", nil, RequestMeta{})
	requireCode(t, err, ErrUnsupported)
}

func TestServiceExactAllowlistGate(t *testing.T) {
	r := NewRegistry()
	register := func(name, target string) {
		r.Register(name, func(context.Context, Params, RequestMeta) (any, error) { return name, nil }, Service(target))
	}
	register("svc.nginx", "nginx")
	register("svc.mysql", "mysql")
	register("svc.suffix", "nginx.service")
	register("svc.case", "NGINX")
	pol := Policy{AllowedServices: []string{"nginx", "mysql"}}
	for _, tc := range []struct {
		op     string
		pol    Policy
		log    bool
		wantOK bool
	}{
		{"svc.nginx", pol, true, true},
		{"svc.mysql", pol, true, true},
		{"svc.suffix", pol, true, false}, // exact match, no expansion
		{"svc.case", pol, true, false},   // case-sensitive
		{"svc.nginx", pol, false, true},  // permission alone never enables execution
		{"svc.nginx", Policy{AllowedServices: []string{"other"}}, true, false},
	} {
		s := &Server{Registry: r, Policy: tc.pol}
		if tc.log {
			s.Logger = func(string, ...any) {}
		}
		_, err := s.dispatch(context.Background(), tc.op, nil, RequestMeta{})
		if tc.wantOK {
			requireCode(t, err, ErrUnsupported)
		}
		if !tc.wantOK {
			requireCode(t, err, ErrForbiddenByPolicy)
		}
	}
}

func TestPolicySnapshotImmutable(t *testing.T) {
	r := NewRegistry()
	r.Register("svc.nginx", func(context.Context, Params, RequestMeta) (any, error) { return "ok", nil }, Service("nginx"))
	pol := Policy{AllowRootTerminal: true, AllowedServices: []string{"nginx"}}
	s := &Server{Registry: r, Policy: pol, Logger: func(string, ...any) {}}
	_, err := s.dispatch(context.Background(), "svc.nginx", nil, RequestMeta{})
	requireCode(t, err, ErrUnsupported)
	if !s.policyAllows(Service("nginx")) {
		t.Fatal("initial permission denied")
	}
	pol.AllowedServices[0] = "evil"
	pol.AllowRootTerminal = false
	if !s.policyAllows(Service("nginx")) {
		t.Fatal("snapshot mutated by caller")
	}
}

func TestInfoRequiresReadOnlyClassification(t *testing.T) {
	r := NewRegistry()
	called := false
	r.Register("system.info", func(context.Context, Params, RequestMeta) (any, error) { called = true; return "x", nil }, RootTerminal)
	s := &Server{Registry: r, Logger: func(string, ...any) {}}
	res, _ := doReq(t, s, "GET", "/v1/info", nil, nil)
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("status=%d", res.StatusCode)
	}
	if called {
		t.Fatal("info ran a non-read-only operation")
	}
}
