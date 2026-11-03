package agentclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startStub serves h on a private Unix socket for the duration of the test.
func startStub(t *testing.T, h http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "agenttest-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func actorCtx() context.Context { return WithActor(context.Background(), 42) }

func infoJSON() string {
	return `{"version":"0.1.0-dev","protocol":1,"os":"Ubuntu 26.04","arch":"arm64",
"kernel":"7.0.0","hostname":"node-01","detected_tools":{"nginx":true},
"capabilities":{"docker":{"available":false,"reason":"unimplemented"}},
"capability_revision":"abc123","observed_at":"2026-11-03T10:00:00Z",
"operations":["system.info"]}`
}

func TestInfoSendsProtocolHeadersAndDecodes(t *testing.T) {
	var got http.Header
	var method, path string
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, method, path = r.Header.Clone(), r.Method, r.URL.Path
		w.Header().Set("Axion-Protocol", "1")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, infoJSON())
	}))

	info, err := New(sock).Info(actorCtx())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if method != "GET" || path != "/v1/info" {
		t.Fatalf("request = %s %s, want GET /v1/info", method, path)
	}
	if v := got.Get("Axion-Protocol"); v != "1" {
		t.Fatalf("Axion-Protocol = %q", v)
	}
	if v := got.Get("Axion-Request-ID"); len(v) < 8 || len(v) > 128 {
		t.Fatalf("Axion-Request-ID = %q", v)
	}
	if v := got.Get("Axion-Actor"); v != "42" {
		t.Fatalf("Axion-Actor = %q, want 42", v)
	}
	if info.Version != "0.1.0-dev" || info.Protocol != 1 || info.Hostname != "node-01" {
		t.Fatalf("decoded info = %+v", info)
	}
	if !info.DetectedTools["nginx"] {
		t.Fatalf("detected tools = %v", info.DetectedTools)
	}
	if cap := info.Capabilities["docker"]; cap.Available || cap.Reason != "unimplemented" {
		t.Fatalf("capability = %+v", cap)
	}
	if len(info.Operations) != 1 || info.Operations[0] != "system.info" {
		t.Fatalf("operations = %v", info.Operations)
	}
}

func TestInfoRejectsIncompleteDocuments(t *testing.T) {
	cases := map[string]string{"null": "null", "empty": "{}", "array": "[]"}
	var valid map[string]json.RawMessage
	if err := json.Unmarshal([]byte(infoJSON()), &valid); err != nil {
		t.Fatal(err)
	}
	for key := range valid {
		for _, mode := range []string{"missing", "null"} {
			var doc map[string]json.RawMessage
			_ = json.Unmarshal([]byte(infoJSON()), &doc)
			if mode == "missing" {
				delete(doc, key)
			} else {
				doc[key] = json.RawMessage("null")
			}
			body, _ := json.Marshal(doc)
			cases[key+"_"+mode] = string(body)
		}
	}
	cases["body_protocol_mismatch"] = strings.Replace(infoJSON(), `"protocol":1`, `"protocol":2`, 1)
	cases["invalid_timestamp"] = strings.Replace(infoJSON(), "2026-11-03T10:00:00Z", "yesterday", 1)
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Axion-Protocol", "1")
				_, _ = io.WriteString(w, body)
			}))
			info, err := New(sock).Info(actorCtx())
			if !errors.Is(err, ErrInvalidResponse) || info != nil {
				t.Fatalf("Info = %+v, %v; want nil, ErrInvalidResponse", info, err)
			}
		})
	}
}

func TestStatsDecodesNumbers(t *testing.T) {
	var method, path string
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		w.Header().Set("Axion-Protocol", "1")
		io.WriteString(w, `{"result":{"load1":0.5,"load5":0.4,"load15":0.3,"mem_total_bytes":8589934592,
"mem_available_bytes":4294967296,"uptime_seconds":1234.5,"observed_at":"2026-11-03T10:00:00Z"}}`)
	}))
	st, err := New(sock).Stats(actorCtx())
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if method != "POST" || path != "/v1/ops/system.stats" {
		t.Fatalf("request = %s %s, want POST /v1/ops/system.stats", method, path)
	}
	if st.Load1 != 0.5 || st.MemTotalBytes != 8589934592 || st.MemAvailableBytes != 4294967296 || st.UptimeSeconds != 1234.5 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestStatsRejectsMissingOrNullResult(t *testing.T) {
	for name, body := range map[string]string{
		"null_result":   `{"result":null}`,
		"missing_field": `{"other":1}`,
		"empty_object":  `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Axion-Protocol", "1")
				io.WriteString(w, body)
			}))
			st, err := New(sock).Stats(actorCtx())
			if !errors.Is(err, ErrInvalidResponse) || st != nil {
				t.Fatalf("Stats = %+v, %v; want nil, ErrInvalidResponse", st, err)
			}
		})
	}
}

func TestStatsRejectsInvalidFields(t *testing.T) {
	valid := `{"load1":0.5,"load5":0.4,"load15":0.3,"mem_total_bytes":8589934592,
"mem_available_bytes":4294967296,"uptime_seconds":1234.5,"observed_at":"2026-11-03T10:00:00Z"}`
	cases := map[string]string{
		"load1_negative":     strings.Replace(valid, `"load1":0.5`, `"load1":-1`, 1),
		"load1_nan":          strings.Replace(valid, `"load1":0.5`, `"load1":NaN`, 1),
		"mem_negative":       strings.Replace(valid, `"mem_total_bytes":8589934592`, `"mem_total_bytes":-1`, 1),
		"mem_negative_avail": strings.Replace(valid, `"mem_available_bytes":4294967296`, `"mem_available_bytes":-5`, 1),
		"mem_avail_gt_total": strings.Replace(valid, `"mem_available_bytes":4294967296`, `"mem_available_bytes":99999999999`, 1),
		"uptime_negative":    strings.Replace(valid, `"uptime_seconds":1234.5`, `"uptime_seconds":-0.5`, 1),
		"observed_at_bad":    strings.Replace(valid, `"observed_at":"2026-11-03T10:00:00Z"`, `"observed_at":""`, 1),
		"missing_observed":   strings.Replace(valid, `,"observed_at":"2026-11-03T10:00:00Z"`, ``, 1),
		"missing_load5":      strings.Replace(valid, `,"load5":0.4`, ``, 1),
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(valid), &fields); err != nil {
		t.Fatal(err)
	}
	for field := range fields {
		for _, mode := range []string{"missing", "null"} {
			var doc map[string]json.RawMessage
			_ = json.Unmarshal([]byte(valid), &doc)
			if mode == "missing" {
				delete(doc, field)
			} else {
				doc[field] = json.RawMessage("null")
			}
			body, _ := json.Marshal(doc)
			cases[field+"_"+mode] = string(body)
		}
	}
	for _, field := range []string{"load1", "load5", "load15", "uptime_seconds"} {
		for _, value := range []string{"-1", "1e309", `"NaN"`} {
			var doc map[string]json.RawMessage
			_ = json.Unmarshal([]byte(valid), &doc)
			doc[field] = json.RawMessage(value)
			body, _ := json.Marshal(doc)
			cases[field+"_"+value] = string(body)
		}
	}
	cases["zero_total"] = strings.ReplaceAll(strings.ReplaceAll(valid, "8589934592", "0"), "4294967296", "0")
	cases["fractional_memory"] = strings.ReplaceAll(valid, "8589934592", "8589934592.5")
	for name, resultJSON := range cases {
		t.Run(name, func(t *testing.T) {
			sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Axion-Protocol", "1")
				io.WriteString(w, `{"result":`+resultJSON+`}`)
			}))
			st, err := New(sock).Stats(actorCtx())
			if !errors.Is(err, ErrInvalidResponse) || st != nil {
				t.Fatalf("Stats = %+v, %v; want nil, ErrInvalidResponse", st, err)
			}
		})
	}
}

func TestDuplicateProtocolHeaderRejected(t *testing.T) {
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Axion-Protocol", "1")
		w.Header().Add("Axion-Protocol", "1")
		io.WriteString(w, infoJSON())
	}))
	_, err := New(sock).Info(actorCtx())
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("err = %v, want ErrProtocol", err)
	}
}

func TestAgentErrorRejectsMalformedBodies(t *testing.T) {
	for name, body := range map[string]string{
		"empty":       "",
		"garbage":     "not json",
		"truncated":   `{"error":{"code":"x"`,
		"no_code":     `{"error":{"message":"m"}}`,
		"null_error":  `{"error":null}`,
		"array":       `[]`,
		"wrong_shape": `{"error":"boom"}`,
	} {
		t.Run(name, func(t *testing.T) {
			sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Axion-Protocol", "1")
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, body)
			}))
			_, err := New(sock).Stats(actorCtx())
			var opErr *Error
			if errors.As(err, &opErr) {
				t.Fatalf("err = %+v, want not *Error", opErr)
			}
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("err = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestAgentErrorOversizedBodyRejected(t *testing.T) {
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Axion-Protocol", "1")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":{"code":"x","message":"`+strings.Repeat("a", maxResponseBytes)+`"}}`)
	}))
	_, err := New(sock).Stats(actorCtx())
	var opErr *Error
	if errors.As(err, &opErr) {
		t.Fatalf("err = %+v, want not *Error", opErr)
	}
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("err = %v, want ErrInvalidResponse", err)
	}
}

func TestCallRejectsNonObjectResultsWithoutOutput(t *testing.T) {
	for _, body := range []string{`{"result":null}`, `{"result":[]}`, `{"result":1}`} {
		sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Axion-Protocol", "1")
			_, _ = io.WriteString(w, body)
		}))
		if err := New(sock).Call(actorCtx(), "system.stats", nil, nil); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("Call(%s) = %v, want ErrInvalidResponse", body, err)
		}
	}
}

func TestAgentErrorTruncatedTransportRejected(t *testing.T) {
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Axion-Protocol", "1")
		// Even a complete JSON prefix is invalid if HTTP promised more bytes.
		w.Header().Set("Content-Length", "500")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"code":"internal","message":"failure"}}`)
	}))
	_, err := New(sock).Stats(actorCtx())
	var opErr *Error
	if errors.As(err, &opErr) || !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("err = %v, want ErrInvalidResponse, not *Error", err)
	}
}

func TestCallSendsEnvelopeAndUnwrapsResult(t *testing.T) {
	var method, path, actor string
	var body map[string]any
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		actor = r.Header.Get("Axion-Actor")
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Axion-Protocol", "1")
		io.WriteString(w, `{"result":{"detected_tools":{"docker":false},"capability_revision":"z"}}`)
	}))

	var out struct {
		DetectedTools      map[string]bool `json:"detected_tools"`
		CapabilityRevision string          `json:"capability_revision"`
	}
	if err := New(sock).Call(actorCtx(), "capabilities.refresh", struct{}{}, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if method != "POST" || path != "/v1/ops/capabilities.refresh" {
		t.Fatalf("request = %s %s", method, path)
	}
	if actor != "42" {
		t.Fatalf("actor = %q, want 42", actor)
	}
	if _, ok := body["params"]; !ok {
		t.Fatalf("body missing params: %v", body)
	}
	if _, ok := out.DetectedTools["docker"]; !ok || out.CapabilityRevision != "z" {
		t.Fatalf("decoded result = %+v", out)
	}
}

func TestAgentErrorBecomesTypedError(t *testing.T) {
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Axion-Protocol", "1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		io.WriteString(w, `{"error":{"code":"capability_unavailable","message":"docker is not managed"}}`)
	}))
	_, err := New(sock).Stats(actorCtx())
	var opErr *Error
	if !errors.As(err, &opErr) {
		t.Fatalf("err = %v, want *Error", err)
	}
	if opErr.Code != "capability_unavailable" || opErr.Status != http.StatusNotImplemented {
		t.Fatalf("opErr = %+v", opErr)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Fatal("agent-reported error must not be classified as transport unavailable")
	}
}

func TestMissingSocketIsUnavailable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")
	_, err := New(sock).Info(actorCtx())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestProtocolMismatchRejected(t *testing.T) {
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Axion-Protocol", "2")
		io.WriteString(w, infoJSON())
	}))
	_, err := New(sock).Info(actorCtx())
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("err = %v, want ErrProtocol", err)
	}
}

func TestMissingResponseProtocolRejected(t *testing.T) {
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, infoJSON())
	}))
	_, err := New(sock).Info(actorCtx())
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("err = %v, want ErrProtocol", err)
	}
}

func TestOversizedResponseRejected(t *testing.T) {
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Axion-Protocol", "1")
		io.WriteString(w, `{"hostname":"`+strings.Repeat("a", maxResponseBytes)+`"}`)
	}))
	_, err := New(sock).Info(actorCtx())
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("err = %v, want ErrInvalidResponse", err)
	}
}

func TestMalformedResponseRejected(t *testing.T) {
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Axion-Protocol", "1")
		io.WriteString(w, `{"hostname":`)
	}))
	_, err := New(sock).Info(actorCtx())
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("err = %v, want ErrInvalidResponse", err)
	}
}

func TestContextCancellationAbortsCall(t *testing.T) {
	release := make(chan struct{})
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer close(release)
	c := New(sock)
	c.Timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(actorCtx(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Info(ctx)
	if err == nil {
		t.Fatal("expected error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancellation took %v", elapsed)
	}
}

func TestTimeoutIsBounded(t *testing.T) {
	release := make(chan struct{})
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer close(release)
	c := New(sock)
	c.Timeout = 150 * time.Millisecond
	start := time.Now()
	_, err := c.Info(actorCtx())
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
}

func TestCallRejectsOperationNameOutsideRegistryShape(t *testing.T) {
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request for %s", r.URL.Path)
	}))
	for _, name := range []string{"", "system", "system.info/../x", "System.Info", "system..info"} {
		if err := New(sock).Call(actorCtx(), name, nil, nil); err == nil {
			t.Fatalf("Call(%q) accepted an invalid operation name", name)
		}
	}
}

// The agent audit log attributes every request to a panel user. A request
// without a positive actor ID must fail before any byte reaches the agent.
func TestMissingActorRejectedBeforeDial(t *testing.T) {
	hits := 0
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	c := New(sock)
	if _, err := c.Info(context.Background()); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Info without actor err = %v, want ErrInvalidRequest", err)
	}
	if err := c.Call(context.Background(), "system.stats", nil, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Call without actor err = %v, want ErrInvalidRequest", err)
	}
	for _, id := range []int64{0, -1} {
		if _, err := c.Info(WithActor(context.Background(), id)); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Info with actor %d err = %v, want ErrInvalidRequest", id, err)
		}
	}
	if hits != 0 {
		t.Fatalf("agent received %d requests without a valid actor", hits)
	}
}
