package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func discoverySnapshotRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Axion-Protocol", "1")
	req.Header.Set("Axion-Actor", "1")
	req.Header.Set("Axion-Request-ID", "discovery:1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func discoverySnapshotNames(t *testing.T, h http.Handler, method string) []string {
	t.Helper()
	path, body := "/v1/info", ""
	if method == http.MethodPost {
		path, body = "/v1/ops/system.info", `{"params":{}}`
	}
	w := discoverySnapshotRequest(h, method, path, body)
	if w.Code != http.StatusOK {
		t.Errorf("%s discovery status=%d body=%s", method, w.Code, w.Body.String())
		return nil
	}
	var doc struct {
		Operations []string `json:"operations"`
		Result     struct {
			Operations []string `json:"operations"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Error(err)
		return nil
	}
	if method == http.MethodPost {
		return doc.Result.Operations
	}
	return doc.Operations
}

func TestDiscoveryResponseCannotMutateCatalog(t *testing.T) {
	r := NewRegistry()
	RegisterBuiltins(r)
	s := &Server{Registry: r}
	want := r.Names()
	res, err := s.dispatch(context.Background(), "system.info", nil, RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	res.(map[string]any)["operations"].([]string)[0] = "test.injected"
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		if got := discoverySnapshotNames(t, s.Handler(), method); !reflect.DeepEqual(got, want) {
			t.Errorf("%s operations=%v want=%v", method, got, want)
		}
	}
	for _, params := range []Params{
		Params(`{"operations":["test.injected"]}`),
		Params(`{"catalog":["test.injected"]}`),
	} {
		_, err := s.dispatch(context.Background(), "system.info", params, RequestMeta{})
		requireCode(t, err, ErrInvalidParams)
	}
	_, err = s.dispatch(context.Background(), "test.injected", nil, RequestMeta{})
	requireCode(t, err, ErrNotFound)
}

func TestDiscoveryBindingPreservesCustomInfoHandler(t *testing.T) {
	r := NewRegistry()
	r.Register("system.info", func(context.Context, Params, RequestMeta) (any, error) {
		return "custom info", nil
	}, ReadOnly)
	res, err := (&Server{Registry: r}).dispatch(context.Background(), "system.info", nil, RequestMeta{})
	if err != nil || res != "custom info" {
		t.Fatalf("custom handler result=%v err=%v", res, err)
	}
}

func TestDiscoveryCatalogStableUnderConcurrentRegistration(t *testing.T) {
	r := NewRegistry()
	RegisterBuiltins(r)
	op := func(context.Context, Params, RequestMeta) (any, error) { return "read", nil }
	r.Register("test.before", op, ReadOnly)
	s := &Server{Registry: r}
	h := s.Handler()
	want := r.Names()
	const registrations = 32
	start := make(chan struct{})
	errs := make(chan string, 8)
	var wg sync.WaitGroup
	for i := 0; i < registrations; i++ {
		name := fmt.Sprintf("test.late%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r.Register(name, op, ReadOnly)
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 8; j++ {
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					got := discoverySnapshotNames(t, h, method)
					if !reflect.DeepEqual(got, want) {
						select {
						case errs <- fmt.Sprintf("%s operations=%v want=%v", method, got, want):
						default:
						}
						return
					}
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if len(r.Names()) != len(want)+registrations {
		t.Fatalf("source registry names=%d want=%d", len(r.Names()), len(want)+registrations)
	}
	res, err := r.Run(context.Background(), "system.info", nil, RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any)["operations"]; !reflect.DeepEqual(got, r.Names()) {
		t.Errorf("standalone Registry.Run operations=%v want %v", got, r.Names())
	}
}

func TestDiscoveryUsesImmutableServerCatalog(t *testing.T) {
	for _, initialize := range []string{"handler", "dispatch"} {
		t.Run(initialize, func(t *testing.T) {
			r := NewRegistry()
			RegisterBuiltins(r)
			var readCalls, privilegedCalls atomic.Int32
			read := func(context.Context, Params, RequestMeta) (any, error) {
				readCalls.Add(1)
				return "read", nil
			}
			r.Register("test.before", read, ReadOnly)
			r.Register("test.root", func(context.Context, Params, RequestMeta) (any, error) {
				privilegedCalls.Add(1)
				return nil, nil
			}, RootTerminal)
			want := r.Names()
			s := &Server{Registry: r, Policy: Policy{AllowRootTerminal: true}}
			if initialize == "handler" {
				s.Handler()
			} else if _, err := s.dispatch(context.Background(), "test.before", nil, RequestMeta{}); err != nil {
				t.Fatal(err)
			}
			r.Register("test.late", read, ReadOnly)
			h := s.Handler()
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				t.Run(method, func(t *testing.T) {
					if got := discoverySnapshotNames(t, h, method); !reflect.DeepEqual(got, want) {
						t.Errorf("operations=%v want frozen catalog=%v", got, want)
					}
				})
			}
			if !r.Has("test.late") {
				t.Fatal("source registry no longer mutable")
			}
			res, err := r.Run(context.Background(), "system.info", nil, RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			if got := res.(map[string]any)["operations"]; !reflect.DeepEqual(got, r.Names()) {
				t.Errorf("standalone Registry.Run operations=%v want current registry=%v", got, r.Names())
			}
			if _, err := r.Run(context.Background(), "test.late", nil, RequestMeta{}); err != nil {
				t.Fatal(err)
			}
			before := readCalls.Load()
			if w := discoverySnapshotRequest(h, http.MethodPost, "/v1/ops/test.late", `{"params":{}}`); w.Code != http.StatusNotFound {
				t.Errorf("late dispatch status=%d body=%s", w.Code, w.Body.String())
			}
			if readCalls.Load() != before {
				t.Error("late handler executed through frozen server")
			}
			if w := discoverySnapshotRequest(h, http.MethodPost, "/v1/ops/test.before", `{"params":{}}`); w.Code != http.StatusOK {
				t.Errorf("pre-start read-only operation status=%d body=%s", w.Code, w.Body.String())
			}
			if w := discoverySnapshotRequest(h, http.MethodPost, "/v1/ops/test.root", `{"params":{}}`); w.Code != http.StatusNotImplemented {
				t.Errorf("privileged dispatch status=%d body=%s", w.Code, w.Body.String())
			}
			if privilegedCalls.Load() != 0 {
				t.Fatal("discovery enabled privileged execution")
			}
		})
	}
}
