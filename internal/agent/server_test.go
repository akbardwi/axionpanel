package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerRejectsNonObjectEnvelope(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `1`, `"x"`, `{}`, `{"params":null}`, `{"params":[]}`, `{"params":1}`, `{"params":{}} {}`, `{"params":{}} x`, `{"Params":{}}`, `{"params":{},"params":{}}`} {
		t.Run(body, func(t *testing.T) {
			res, data := doReq(t, testServer(t), "POST", "/v1/ops/system.info", strings.NewReader(body), nil)
			defer res.Body.Close()
			if res.StatusCode != 400 {
				t.Fatalf("status=%d body=%s", res.StatusCode, data)
			}
		})
	}
}

func TestHandlerStrictHeaders(t *testing.T) {
	for _, hdr := range []string{"Axion-Protocol", "Axion-Actor", "Axion-Request-ID"} {
		t.Run("duplicate-"+hdr, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/v1/info", nil)
			req.Header.Set("Axion-Protocol", "1")
			req.Header.Set("Axion-Actor", "1")
			req.Header.Set("Axion-Request-ID", "test")
			req.Header.Add(hdr, req.Header.Get(hdr))
			w := httptest.NewRecorder()
			testServer(t).Handler().ServeHTTP(w, req)
			if w.Code != 400 {
				t.Fatalf("duplicate accepted: %d", w.Code)
			}
		})
	}
	for _, actor := range []string{"root", "0", "-1", "+1", "1 2", "1,2", "18446744073709551616"} {
		res, _ := doReq(t, testServer(t), "GET", "/v1/info", nil, map[string]string{"Axion-Actor": actor})
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Errorf("actor %q accepted", actor)
		}
	}
	for _, id := range []string{"a b", "a,b", "é", "<script>", strings.Repeat("a", 129)} {
		res, _ := doReq(t, testServer(t), "GET", "/v1/info", nil, map[string]string{"Axion-Request-ID": id})
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Errorf("request ID %q accepted", id)
		}
	}
}

func TestHandlerJSONMethodErrors(t *testing.T) {
	for _, path := range []string{"/v1/info", "/v1/ops/system.info"} {
		for _, method := range []string{"PUT", "DELETE", "PATCH", "OPTIONS"} {
			res, data := doReq(t, testServer(t), method, path, nil, nil)
			res.Body.Close()
			var out errorEnvelope
			if res.StatusCode != 405 || json.Unmarshal(data, &out) != nil || out.Error.Code != ErrMethodNotAllowed {
				t.Errorf("%s %s status=%d body=%s", method, path, res.StatusCode, data)
			}
		}
	}
}

func TestHandlerProtocolResponseHeaders(t *testing.T) {
	for _, path := range []string{"/v1/info", "/missing"} {
		res, _ := doReq(t, testServer(t), "GET", path, nil, nil)
		res.Body.Close()
		if res.Header.Get("Axion-Protocol") != "1" || res.Header.Get("Axion-Request-ID") != "req-1" {
			t.Errorf("response headers: %v", res.Header)
		}
	}
	res, _ := doReq(t, testServer(t), "GET", "/v1/info", nil, map[string]string{"Axion-Protocol": "9"})
	res.Body.Close()
	if res.Header.Get("Axion-Request-ID") != "req-1" || res.Header.Get("Axion-Protocol") != "1" {
		t.Fatalf("error headers: %v", res.Header)
	}
}

func TestHandlerPreservesUnsupportedCode(t *testing.T) {
	r := NewRegistry()
	r.Register("test.unsupported", func(context.Context, Params, RequestMeta) (any, error) {
		return nil, newOpError(ErrUnsupported, "operation unsupported", nil)
	}, ReadOnly)
	res, data := doReq(t, &Server{Registry: r}, "POST", "/v1/ops/test.unsupported", strings.NewReader(`{"params":{}}`), nil)
	defer res.Body.Close()
	var out errorEnvelope
	if res.StatusCode != 501 || json.Unmarshal(data, &out) != nil || out.Error.Code != ErrUnsupported {
		t.Fatalf("status=%d body=%s", res.StatusCode, data)
	}
}

// Local extension code, but still a protocol-level 501: writeError must pass
// non-500 statuses through instead of rewriting them to internal.
func TestHandlerPreservesCapabilityUnavailableCode(t *testing.T) {
	r := NewRegistry()
	r.Register("test.capability", func(context.Context, Params, RequestMeta) (any, error) {
		return nil, newOpError(ErrCapabilityUnavailable, "capability unavailable", map[string]string{"capability": "docker"})
	}, ReadOnly)
	res, data := doReq(t, &Server{Registry: r}, "POST", "/v1/ops/test.capability", strings.NewReader(`{"params":{}}`), nil)
	defer res.Body.Close()
	var out errorEnvelope
	if res.StatusCode != 501 || json.Unmarshal(data, &out) != nil || out.Error.Code != ErrCapabilityUnavailable {
		t.Fatalf("status=%d body=%s", res.StatusCode, data)
	}
}

func TestHandlerSanitizesInternalErrors(t *testing.T) {
	for _, mode := range []string{"panic", "error", "operror", "encode"} {
		t.Run(mode, func(t *testing.T) {
			r := NewRegistry()
			r.Register("test.fail", func(context.Context, Params, RequestMeta) (any, error) {
				switch mode {
				case "panic":
					panic("SECRET /root/password")
				case "error":
					return nil, errors.New("SECRET /root/password")
				case "operror":
					return nil, newOpError(ErrInternal, "SECRET /root/password", map[string]string{"secret": "SECRET"})

				default:
					return make(chan int), nil
				}
			}, ReadOnly)
			s := &Server{Registry: r}
			res, data := doReq(t, s, "POST", "/v1/ops/test.fail", strings.NewReader(`{"params":{}}`), nil)
			res.Body.Close()
			var out errorEnvelope
			if res.StatusCode != 500 || json.Unmarshal(data, &out) != nil || out.Error.Code != ErrInternal || strings.Contains(string(data), "SECRET") {
				t.Fatalf("status=%d body=%s", res.StatusCode, data)
			}
		})
	}
}

// Duplicate object keys are ambiguous (encoding/json keeps the last one), so
// a validator and an executor could disagree. params must reject them at any
// depth before an operation decodes anything.
func TestHandlerRejectsDuplicateParamsKeys(t *testing.T) {
	for name, body := range map[string]string{
		"top-level":     `{"params":{"a":1,"a":2}}`,
		"nested-object": `{"params":{"o":{"x":1,"x":2}}}`,
		"array-element": `{"params":{"l":[{"k":1},{"k":2,"k":3}]}}`,
		"escaped-alias": `{"params":{"a":1,"\u0061":2}}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := NewRegistry()
			called := false
			r.Register("test.echo", func(context.Context, Params, RequestMeta) (any, error) {
				called = true
				return map[string]any{}, nil
			}, ReadOnly)
			res, data := doReq(t, &Server{Registry: r}, "POST", "/v1/ops/test.echo", strings.NewReader(body), nil)
			res.Body.Close()
			var out errorEnvelope
			if res.StatusCode != 400 || json.Unmarshal(data, &out) != nil || out.Error.Code != ErrInvalidParams {
				t.Fatalf("status=%d body=%s", res.StatusCode, data)
			}
			if called {
				t.Fatal("operation ran on duplicate-key params")
			}
		})
	}
}

func TestRejectDuplicateJSONKeys(t *testing.T) {
	for _, tc := range []struct {
		in  string
		dup bool
	}{
		{`{"a":1,"a":2}`, true},
		{`{"o":{"x":1,"y":{"z":1,"z":2}}}`, true},
		{`{"l":[1,{"k":1,"k":2}]}`, true},
		{`[{"a":1},{"a":1,"a":1}]`, true},
		// Same key in different objects is legitimate.
		{`{"a":{"a":1},"b":{"a":2},"l":[{"a":1},{"a":2}]}`, false},
		{`{"a":[[{"x":1}],[{"x":2}]],"x":3}`, false},
		{`{}`, false},
	} {
		err := rejectDuplicateJSONKeys([]byte(tc.in))
		if tc.dup && err == nil {
			t.Errorf("%s: duplicate accepted", tc.in)
		}
		if !tc.dup && err != nil {
			t.Errorf("%s: legitimate JSON rejected: %v", tc.in, err)
		}
	}
}

func TestHandlerAcceptsRepeatedKeysInDifferentObjects(t *testing.T) {
	r := NewRegistry()
	r.Register("test.echo", func(context.Context, Params, RequestMeta) (any, error) { return map[string]any{}, nil }, ReadOnly)
	body := `{"params":{"a":{"id":1},"b":{"id":2},"l":[{"id":3},{"id":4}]}}`
	res, data := doReq(t, &Server{Registry: r}, "POST", "/v1/ops/test.echo", strings.NewReader(body), nil)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", res.StatusCode, data)
	}
}

func testServer(t *testing.T) *Server {
	t.Helper()
	r := NewRegistry()
	RegisterBuiltins(r)
	return &Server{Registry: r, AllowedUID: uint32(0)}
}

func doReq(t *testing.T, s *Server, method, path string, body io.Reader, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Axion-Protocol", "1")
	req.Header.Set("Axion-Request-ID", "req-1")
	req.Header.Set("Axion-Actor", "1")
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	res := rec.Result()
	data, _ := io.ReadAll(res.Body)
	return res, data
}

func TestHandlerRequiresProtocolHeader(t *testing.T) {
	res, body := doReq(t, testServer(t), "GET", "/v1/info", nil, map[string]string{"Axion-Protocol": ""})
	if res.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	var e errorEnvelope
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("bad body %q: %v", body, err)
	}
	if e.Error.Code != ErrProtocolMismatch {
		t.Fatalf("code = %q", e.Error.Code)
	}
}

func TestHandlerRejectsWrongProtocolVersion(t *testing.T) {
	res, _ := doReq(t, testServer(t), "GET", "/v1/info", nil, map[string]string{"Axion-Protocol": "2"})
	if res.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

func TestHandlerRequiresActorAndRequestID(t *testing.T) {
	for _, hdr := range []string{"Axion-Actor", "Axion-Request-ID"} {
		res, body := doReq(t, testServer(t), "GET", "/v1/info", nil, map[string]string{hdr: ""})
		if res.StatusCode != 400 {
			t.Fatalf("%s missing: status = %d, want 400", hdr, res.StatusCode)
		}
		if !strings.Contains(string(body), "invalid_params") {
			t.Fatalf("%s missing: body = %s", hdr, body)
		}
	}
}

func TestHandlerInfoShape(t *testing.T) {
	res, body := doReq(t, testServer(t), "GET", "/v1/info", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", res.StatusCode, body)
	}
	var info map[string]any
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatal(err)
	}
	if info["protocol"] != float64(1) {
		t.Fatalf("protocol = %v", info["protocol"])
	}
	if _, ok := info["capabilities"].(map[string]any); !ok {
		t.Fatalf("capabilities missing: %v", info["capabilities"])
	}
	if _, ok := info["capability_revision"].(string); !ok {
		t.Fatal("capability_revision missing")
	}
	if _, ok := info["observed_at"].(string); !ok {
		t.Fatal("observed_at missing")
	}
}

func TestHandlerRunsCatalogOperation(t *testing.T) {
	res, body := doReq(t, testServer(t), "POST", "/v1/ops/system.info", strings.NewReader(`{"params":{}}`), nil)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", res.StatusCode, body)
	}
	var out struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Result["hostname"] == "" {
		t.Fatalf("result = %v", out.Result)
	}
	if got := res.Header.Get("Axion-Request-ID"); got != "req-1" {
		t.Fatalf("echoed request id = %q", got)
	}
}

func TestHandlerUnknownOperationNotFound(t *testing.T) {
	res, body := doReq(t, testServer(t), "POST", "/v1/ops/shell.exec", strings.NewReader(`{"params":{}}`), nil)
	if res.StatusCode != 404 {
		t.Fatalf("status = %d body=%s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "not_found") {
		t.Fatalf("body = %s", body)
	}
}

func TestHandlerRejectsOversizedBody(t *testing.T) {
	big := `{"params":{"x":"` + strings.Repeat("a", maxOpBodyBytes) + `"}}`
	res, _ := doReq(t, testServer(t), "POST", "/v1/ops/system.info", strings.NewReader(big), nil)
	if res.StatusCode != http.StatusRequestEntityTooLarge && res.StatusCode != 400 {
		t.Fatalf("status = %d, want 413/400", res.StatusCode)
	}
}

func TestHandlerRejectsWrongMethod(t *testing.T) {
	res, _ := doReq(t, testServer(t), "GET", "/v1/ops/system.info", nil, nil)
	if res.StatusCode != 405 {
		t.Fatalf("status = %d, want 405", res.StatusCode)
	}
}

func TestTerminalIsNotAnOperation(t *testing.T) {
	// The PTY terminal is a WebSocket endpoint (spec 6.1), never a POST
	// operation; exposing one would imply a generic privileged RPC.
	s := testServer(t)
	for _, name := range []string{"terminal.open", "shell.exec", "exec"} {
		res, body := doReq(t, s, "POST", "/v1/ops/"+name, strings.NewReader(`{"params":{}}`), nil)
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status = %d body=%s", name, res.StatusCode, body)
		}
	}
}
