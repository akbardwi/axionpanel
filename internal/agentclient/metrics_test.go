package agentclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const metricsJSON = `{"cpu":{"usage_percent":0,"logical_cpus":2},"cpu_reason":"","disk":{"mount":"/","total_bytes":1000,"used_bytes":600,"available_bytes":300},"disk_reason":"","network":{"interface":"ens3","rx_bytes_per_second":2000,"tx_bytes_per_second":0},"network_reason":"","observed_at":"2026-11-04T12:00:00Z"}`

func TestMetricsCallsClosedOperation(t *testing.T) {
	sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/ops/system.metrics" || r.Header.Get("Axion-Actor") != "42" {
			t.Errorf("unexpected request %s %s %v", r.Method, r.URL.Path, r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"params":{}}` {
			t.Errorf("body=%s", body)
		}
		w.Header().Set("Axion-Protocol", "1")
		io.WriteString(w, `{"result":`+metricsJSON+`}`)
	}))
	m, err := New(sock).Metrics(actorCtx())
	if err != nil {
		t.Fatal(err)
	}
	if m.CPU == nil || m.CPU.UsagePercent != 0 || m.CPU.LogicalCPUs != 2 || m.Disk == nil || m.Disk.UsedBytes != 600 || m.Network == nil || m.Network.Interface != "ens3" || m.Network.TxBytesPerSecond != 0 {
		t.Fatalf("metrics=%+v", m)
	}
}

func TestMetricsAllowsPartialFailures(t *testing.T) {
	for _, body := range []string{
		`{"cpu":null,"cpu_reason":"read_failed","disk":null,"disk_reason":"invalid_data","network":null,"network_reason":"no_default_route","observed_at":"2026-11-04T12:00:00Z"}`,
		metricsJSON,
	} {
		sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Axion-Protocol", "1")
			io.WriteString(w, `{"result":`+body+`}`)
		}))
		if _, err := New(sock).Metrics(actorCtx()); err != nil {
			t.Fatalf("body=%s err=%v", body, err)
		}
	}
}

func TestMetricsRejectsMalformedDocuments(t *testing.T) {
	cases := map[string]string{"missing result": `{}`, "null result": `{"result":null}`, "null envelope": `null`, "array": `[]`, "bad json": `{"result":`, "empty result": `{"result":{}}`}
	var base map[string]json.RawMessage
	json.Unmarshal([]byte(metricsJSON), &base)
	for field := range base {
		var doc map[string]json.RawMessage
		json.Unmarshal([]byte(metricsJSON), &doc)
		delete(doc, field)
		b, _ := json.Marshal(doc)
		cases["missing "+field] = `{"result":` + string(b) + `}`
	}
	replacements := [][2]string{
		{`"usage_percent":0`, `"usage_percent":-1`}, {`"usage_percent":0`, `"usage_percent":101`}, {`"usage_percent":0`, `"usage_percent":1e309`}, {`"usage_percent":0`, `"usage_percent":NaN`},
		{`"logical_cpus":2`, `"logical_cpus":0`}, {`"logical_cpus":2`, `"logical_cpus":-1`}, {`"logical_cpus":2`, `"logical_cpus":1.5`},
		{`"mount":"/"`, `"mount":"/etc"`}, {`"total_bytes":1000`, `"total_bytes":0`}, {`"total_bytes":1000`, `"total_bytes":-1`}, {`"used_bytes":600`, `"used_bytes":-1`}, {`"available_bytes":300`, `"available_bytes":-1`}, {`"available_bytes":300`, `"available_bytes":401`}, {`"used_bytes":600`, `"used_bytes":1001`},
		{`"interface":"ens3"`, `"interface":""`}, {`"interface":"ens3"`, `"interface":"lo"`}, {`"interface":"ens3"`, `"interface":"../etc"`},
		{`"rx_bytes_per_second":2000`, `"rx_bytes_per_second":-1`}, {`"tx_bytes_per_second":0`, `"tx_bytes_per_second":-1`}, {`"tx_bytes_per_second":0`, `"tx_bytes_per_second":1e309`},
		{`"cpu_reason":""`, `"cpu_reason":"read_failed"`}, {`"disk_reason":""`, `"disk_reason":"read_failed"`}, {`"network_reason":""`, `"network_reason":"read_failed"`},
		{`"cpu_reason":""`, `"cpu_reason":null`}, {`"observed_at":"2026-11-04T12:00:00Z"`, `"observed_at":"yesterday"`},
	}
	for _, pair := range replacements {
		cases[pair[1]] = `{"result":` + strings.Replace(metricsJSON, pair[0], pair[1], 1) + `}`
	}
	for _, resource := range []string{"cpu", "disk", "network"} {
		var obj map[string]json.RawMessage
		json.Unmarshal(base[resource], &obj)
		for field := range obj {
			for _, mode := range []string{"missing", "null"} {
				var doc map[string]json.RawMessage
				json.Unmarshal([]byte(metricsJSON), &doc)
				var sub map[string]json.RawMessage
				json.Unmarshal(doc[resource], &sub)
				if mode == "missing" {
					delete(sub, field)
				} else {
					sub[field] = json.RawMessage(`null`)
				}
				doc[resource], _ = json.Marshal(sub)
				b, _ := json.Marshal(doc)
				cases[resource+" "+field+" "+mode] = `{"result":` + string(b) + `}`
			}
		}
		var doc map[string]json.RawMessage
		json.Unmarshal([]byte(metricsJSON), &doc)
		doc[resource] = json.RawMessage(`null`)
		b, _ := json.Marshal(doc)
		cases[resource+" null without reason"] = `{"result":` + string(b) + `}`
		doc[resource+"_reason"] = json.RawMessage(`"   "`)
		b, _ = json.Marshal(doc)
		cases[resource+" blank reason"] = `{"result":` + string(b) + `}`
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Axion-Protocol", "1")
				io.WriteString(w, body)
			}))
			m, err := New(sock).Metrics(actorCtx())
			if m != nil || !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Metrics=%+v, %v; body=%s", m, err, body)
			}
		})
	}
}

func TestMetricsRequiresActorAndHonorsContext(t *testing.T) {
	c := New("/nonexistent.sock")
	if _, err := c.Metrics(context.Background()); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing actor: %v", err)
	}
	ctx, cancel := context.WithCancel(actorCtx())
	cancel()
	start := time.Now()
	if m, err := c.Metrics(ctx); err == nil || m != nil {
		t.Fatalf("cancelled call = %v, %v", m, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancelled call blocked")
	}
}

func TestMetricsRejectsUnsanitizedReasons(t *testing.T) {
	for _, reason := range []string{`"open /proc/stat: permission denied"`, `"unknown"`, `"READ_FAILED"`} {
		body := `{"result":{"cpu":null,"cpu_reason":` + reason + `,"disk":null,"disk_reason":"read_failed","network":null,"network_reason":"no_default_route","observed_at":"2026-11-04T12:00:00Z"}}`
		sock := startStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Axion-Protocol", "1")
			io.WriteString(w, body)
		}))
		if m, err := New(sock).Metrics(actorCtx()); m != nil || !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("reason %s accepted: %+v, %v", reason, m, err)
		}
	}
}
