package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestHandlerCatalogCannotWidenAfterInitialization(t *testing.T) {
	r := NewRegistry()
	calls := 0
	r.Register("test.original", func(context.Context, Params, RequestMeta) (any, error) {
		calls++
		return "original", nil
	}, ReadOnly)
	var line string
	s := &Server{Registry: r, Logger: func(f string, args ...any) { line = fmt.Sprintf(f, args...) }}
	h := s.Handler()
	r.Register("test.late", func(context.Context, Params, RequestMeta) (any, error) {
		calls++
		return "late", nil
	}, ReadOnly)
	for _, tc := range []struct {
		name, body                string
		status                    int
		operation, classification string
	}{
		{"test.late", `{"params":{}}`, http.StatusNotFound, "unknown", "unclassified"},
		{"test.late", `broken`, http.StatusBadRequest, "unknown", "unclassified"},
		{"test.original", `{"params":{}}`, http.StatusOK, "test.original", "read_only"},
	} {
		req := httptest.NewRequest("POST", "/v1/ops/"+tc.name, strings.NewReader(tc.body))
		req.Header.Set("Axion-Protocol", "1")
		req.Header.Set("Axion-Actor", "1")
		req.Header.Set("Axion-Request-ID", "snapshot:1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Errorf("%s %q status=%d want=%d body=%s", tc.name, tc.body, w.Code, tc.status, w.Body.String())
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record["operation"] != tc.operation || record["classification"] != tc.classification {
			t.Errorf("%s %q audit=%s", tc.name, tc.body, line)
		}
	}
	if calls != 1 {
		t.Fatalf("handlers called %d times; only original must execute", calls)
	}
}

func TestDispatchCatalogCannotWidenAfterInitialization(t *testing.T) {
	r := NewRegistry()
	r.Register("test.original", func(context.Context, Params, RequestMeta) (any, error) { return "original", nil }, ReadOnly)
	s := &Server{Registry: r}
	if res, err := s.dispatch(context.Background(), "test.original", nil, RequestMeta{}); err != nil || res != "original" {
		t.Fatalf("original res=%v err=%v", res, err)
	}
	r.Register("test.late", func(context.Context, Params, RequestMeta) (any, error) {
		t.Fatal("late handler executed")
		return nil, nil
	}, ReadOnly)
	_, err := s.dispatch(context.Background(), "test.late", nil, RequestMeta{})
	requireCode(t, err, ErrNotFound)
}

func TestCatalogConcurrentRegistrationAndInitialization(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		r := NewRegistry()
		op := func(context.Context, Params, RequestMeta) (any, error) { return "original", nil }
		r.Register("test.original", op, ReadOnly)
		s := &Server{Registry: r}
		start := make(chan struct{})
		var wg sync.WaitGroup
		// Multiple initializers compete with registration. Registration either
		// precedes the snapshot or does not; no map races or partial catalog.
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; s.Handler() }()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for n := 0; n < 16; n++ {
				r.Register(fmt.Sprintf("test.race%d", n), op, ReadOnly)
			}
		}()
		close(start)
		wg.Wait()
		for n := 0; n < 16; n++ {
			name := fmt.Sprintf("test.race%d", n)
			_, included := s.operations[name]
			res, err := s.dispatch(context.Background(), name, nil, RequestMeta{})
			if included {
				if err != nil || res != "original" {
					t.Fatalf("included %s res=%v err=%v", name, res, err)
				}
			} else {
				requireCode(t, err, ErrNotFound)
			}
		}
		r.Register("test.after", op, ReadOnly)
		_, err := s.dispatch(context.Background(), "test.after", nil, RequestMeta{})
		requireCode(t, err, ErrNotFound)
		if res, err := s.dispatch(context.Background(), "test.original", nil, RequestMeta{}); err != nil || res != "original" {
			t.Fatalf("original res=%v err=%v", res, err)
		}
	}
}

func TestBuiltinCatalogAndRegistryRunPolicyChecked(t *testing.T) {
	r := NewRegistry()
	RegisterBuiltins(r)
	for _, name := range []string{"system.info", "system.stats", "system.metrics", "capabilities.refresh"} {
		op, exists := r.lookup(name)
		if !exists || op.permission != ReadOnly {
			t.Fatalf("builtin %s missing read-only classification", name)
		}
		if _, err := r.Run(context.Background(), name, nil, RequestMeta{}); err != nil {
			t.Fatalf("builtin %s: %v", name, err)
		}
	}
	for i, permissions := range [][]Permission{nil, {RootTerminal}, {RootFiles}, {Service("nginx")}} {
		name := fmt.Sprintf("test.denied%d", i)
		r.Register(name, func(context.Context, Params, RequestMeta) (any, error) { t.Fatal("policy bypass"); return nil, nil }, permissions...)
		_, err := r.Run(context.Background(), name, nil, RequestMeta{})
		requireCode(t, err, ErrForbiddenByPolicy)
	}
}
