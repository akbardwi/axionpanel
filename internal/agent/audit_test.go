package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceAuditUsesStartupTarget(t *testing.T) {
	r := NewRegistry()
	r.Register("test.service", func(context.Context, Params, RequestMeta) (any, error) {
		t.Fatal("service handler ran")
		return nil, nil
	}, Service("nginx.service"))
	var line string
	s := &Server{Registry: r, Logger: func(f string, a ...any) { line = fmt.Sprintf(f, a...) }}
	res, _ := doReq(t, s, "POST", "/v1/ops/test.service", strings.NewReader(`{"params":{"target":"SECRET /etc/password"}}`), nil)
	res.Body.Close()
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["target"] != "nginx.service" || rec["classification"] != "service" || strings.Contains(line, "SECRET") {
		t.Fatalf("record=%s", line)
	}
}

func TestRequestAuditSafeOutcomes(t *testing.T) {
	for _, mode := range []string{"success", "denied", "unknown", "panic", "error", "invalid-code", "encode", "malformed", "headers"} {
		t.Run(mode, func(t *testing.T) {
			r := NewRegistry()
			op := func(context.Context, Params, RequestMeta) (any, error) {
				switch mode {
				case "panic":
					panic("SECRET /root/password\nforged")
				case "error":
					return nil, errors.New("SECRET /root/password")
				case "invalid-code":
					return nil, newOpError("SECRET /root/password", "secret", nil)
				case "encode":
					return make(chan int), nil
				}
				return "SECRET-result", nil
			}
			if mode == "denied" {
				r.Register("test.audit", op)
			} else {
				r.Register("test.audit", op, ReadOnly)
			}
			var lines []string
			s := &Server{Registry: r, AllowedUID: 424242, Logger: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }}
			path := "/v1/ops/test.audit"
			body := `{"params":{"secret":"SECRET-body"}}`
			if mode == "unknown" {
				path = "/v1/ops/secret.attacker"
			}
			if mode == "malformed" {
				body = "SECRET-not-json"
			}
			req := httptest.NewRequest("POST", path, strings.NewReader(body))
			req.Header.Set("Axion-Protocol", "1")
			req.Header.Set("Axion-Actor", "9")
			req.Header.Set("Axion-Request-ID", "safe:1")
			if mode == "headers" {
				req.Header.Set("Axion-Actor", "SECRET-header")
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			if len(lines) != 1 {
				t.Fatalf("audit lines=%v", lines)
			}
			line := lines[0]
			for _, forbidden := range []string{"SECRET", "/root/password", "secret.attacker", "424242"} {
				if strings.Contains(line, forbidden) {
					t.Fatalf("audit leaked %q: %s", forbidden, line)
				}
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("not structured JSON: %s: %v", line, err)
			}
			expected := "failed"
			if mode == "success" {
				expected = "success"
			}
			if mode == "denied" || mode == "unknown" {
				expected = "denied"
			}
			if rec["outcome"] != expected {
				t.Fatalf("outcome=%v want=%s record=%s", rec["outcome"], expected, line)
			}
			if rec["duration_ms"] == nil || rec["event"] != "agent.request" {
				t.Fatalf("incomplete record %s", line)
			}
			if mode != "headers" && (rec["actor"] != "9" || rec["request_id"] != "safe:1") {
				t.Fatalf("lost validated context: %s", line)
			}
			if rec["peer_uid"] != nil {
				t.Fatalf("fabricated kernel peer: %s", line)
			}
			if mode == "malformed" && (rec["operation"] != "test.audit" || rec["classification"] != "read_only") {
				t.Fatalf("lost fixed operation classification: %s", line)
			}
			if mode == "unknown" && rec["operation"] != "unknown" {
				t.Fatalf("unknown operation logged raw: %s", line)
			}
			if mode == "panic" || mode == "error" || mode == "encode" || mode == "invalid-code" {
				if rec["error_code"] != ErrInternal {
					t.Fatalf("code=%v", rec["error_code"])
				}
			}
		})
	}
}
