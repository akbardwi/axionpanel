package agent

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestSystemInfoReturnsHostFields(t *testing.T) {
	res, err := opSystemInfo(context.Background(), nil, RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", res)
	}
	for _, k := range []string{"os", "arch", "kernel", "hostname", "version", "observed_at"} {
		if v, _ := m[k].(string); v == "" {
			t.Fatalf("%s empty", k)
		}
	}
	if m["protocol"] != Protocol {
		t.Fatalf("protocol = %v, want %d", m["protocol"], Protocol)
	}
}

func TestSystemInfoRejectsUnknownParams(t *testing.T) {
	_, err := opSystemInfo(context.Background(), json.RawMessage(`{"x":1}`), RequestMeta{})
	var oe *OpError
	if !errors.As(err, &oe) {
		t.Fatalf("expected *OpError, got %T", err)
	}
	if oe.Code != ErrInvalidParams {
		t.Fatalf("code = %q, want invalid_params", oe.Code)
	}
}

// TestRegisterBuiltinsCatalogIsExactlyFour guards against a hardcoded alias
// catalog drifting from what is actually registered.
func TestRegisterBuiltinsCatalogIsExactlyFour(t *testing.T) {
	r := NewRegistry()
	RegisterBuiltins(r)
	want := []string{"capabilities.refresh", "system.info", "system.metrics", "system.stats"}
	if got := r.Names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("registry names = %v, want %v", got, want)
	}
}

func TestSystemInfoOperationsMatchRegistry(t *testing.T) {
	r := NewRegistry()
	RegisterBuiltins(r)
	res, err := r.Run(context.Background(), "system.info", nil, RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	ops, ok := m["operations"].([]string)
	if !ok {
		t.Fatalf("operations = %T, want []string", m["operations"])
	}
	if !reflect.DeepEqual(ops, r.Names()) {
		t.Fatalf("operations = %v, registry = %v", ops, r.Names())
	}
	for _, name := range ops {
		if !r.Has(name) {
			t.Fatalf("info advertises unregistered operation %q", name)
		}
	}
}

func TestSystemInfoSeparatesToolsFromCapabilities(t *testing.T) {
	res, err := opSystemInfo(context.Background(), nil, RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)

	tools, ok := m["detected_tools"].(map[string]bool)
	if !ok {
		t.Fatalf("detected_tools = %T, want map", m["detected_tools"])
	}
	for _, want := range []string{"git", "docker", "tar"} {
		if _, ok := tools[want]; !ok {
			t.Fatalf("detected_tools missing %q: %v", want, tools)
		}
	}

	caps, ok := m["capabilities"].(map[string]capability)
	if !ok {
		t.Fatalf("capabilities = %T, want map", m["capabilities"])
	}
	for _, feature := range []string{
		"php", "database", "firewall", "docker", "compose",
		"build_sandbox", "backup", "fail2ban", "ssh",
	} {
		entry, ok := caps[feature]
		if !ok {
			t.Fatalf("capabilities missing feature %q: %v", feature, caps)
		}
		if entry.Available {
			t.Fatalf("%s.available = %v, must be false in this build", feature, entry.Available)
		}
		if entry.Reason != "unimplemented" {
			t.Fatalf("%s.reason = %v, want unimplemented", feature, entry.Reason)
		}
	}
}

// TestCapabilityPresenceNeverImpliesManagedAbility pins the anti-implication
// rule: finding /usr/bin/git does not mean a build sandbox exists, and finding
// docker does not mean compose management exists.
func TestCapabilityPresenceNeverImpliesManagedAbility(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"git", "docker"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not executable code\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)

	caps := detectCapabilities()
	tools := detectTools()
	if tools["git"] != true || tools["docker"] != true {
		t.Fatalf("tools = %v, want all present", tools)
	}
	for feature, entry := range caps {
		if entry.Available {
			t.Fatalf("%s available with only binaries present: %v", feature, entry)
		}
	}
	if entry := caps["build_sandbox"]; entry.Reason != "unimplemented" {
		t.Fatalf("build_sandbox = %v", entry)
	}
	if entry := caps["compose"]; entry.Reason != "unimplemented" {
		t.Fatalf("compose = %v", entry)
	}
}

// TestDetectedToolsMirrorsLookPath swaps PATH so only a fake "git" binary is
// discoverable, then checks the inventory reflects exactly that.
func TestDetectedToolsMirrorsLookPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte("x\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	tools := detectTools()
	if !tools["git"] {
		t.Fatal("git not detected")
	}
	if tools["docker"] {
		t.Fatal("docker falsely detected")
	}
	if len(tools) < 3 {
		t.Fatalf("too few tools reported: %v", tools)
	}
}

func TestSystemStatsReturnsRealHostValues(t *testing.T) {
	res, err := opSystemStats(context.Background(), nil, RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", res)
	}
	total, ok := m["mem_total_bytes"].(int64)
	if !ok {
		t.Fatalf("mem_total_bytes = %T", m["mem_total_bytes"])
	}
	avail, ok := m["mem_available_bytes"].(int64)
	if !ok {
		t.Fatalf("mem_available_bytes = %T", m["mem_available_bytes"])
	}
	// Cross-check against the real /proc/meminfo instead of trusting the parser.
	realTotal, realAvail := realMeminfo(t)
	if total != realTotal {
		t.Fatalf("mem_total_bytes = %d, real = %d", total, realTotal)
	}
	// Available memory changes between reads; both readings must be plausible.
	if realAvail <= 0 || realAvail > total {
		t.Fatalf("real available memory = %d, total = %d", realAvail, total)
	}
	if total <= 0 || avail <= 0 {
		t.Fatalf("non-positive memory: total=%d avail=%d", total, avail)
	}
	if avail > total {
		t.Fatalf("available %d exceeds total %d", avail, total)
	}
	for _, k := range []string{"load1", "load5", "load15", "uptime_seconds"} {
		v, ok := m[k].(float64)
		if !ok {
			t.Fatalf("%s = %T", k, m[k])
		}
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			t.Fatalf("%s = %v", k, v)
		}
	}
	if up := m["uptime_seconds"].(float64); up <= 0 {
		t.Fatalf("uptime_seconds = %v, want > 0", up)
	}
}

func TestSystemStatsRejectsBadProcFiles(t *testing.T) {
	dir := t.TempDir()
	good := map[string]string{
		"loadavg": "0.10 0.20 0.30 1/100 1234\n",
		"meminfo": "MemTotal:       1000 kB\nMemAvailable:    400 kB\n",
		"uptime":  "1234.56 9999.00\n",
	}
	writeProc := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]string{
		"meminfo missing MemAvailable": "MemTotal: 1000 kB\nMemFree: 10 kB\n",
		"meminfo available > total":    "MemTotal: 1000 kB\nMemAvailable: 2000 kB\n",
		"meminfo negative":             "MemTotal: 1000 kB\nMemAvailable: -5 kB\n",
		"meminfo garbage":              "MemTotal: 1000 kB\nMemAvailable: lots kB\n",
		"meminfo no unit":              "MemTotal: 1000\nMemAvailable: 400\n",
		"meminfo empty":                "",
		"loadavg nan":                  "NaN NaN NaN 1/1 1\n",
		"loadavg inf":                  "+Inf 0 0 1/1 1\n",
		"loadavg negative":             "-1.0 0 0 1/1 1\n",
		"loadavg short":                "0.1 0.2\n",
		"uptime negative":              "-1.0 0.0\n",
		"uptime nan":                   "NaN 0.0\n",
		"uptime empty":                 "",
	}
	for name, body := range cases {
		loadPath := writeProc("loadavg", good["loadavg"])
		memPath := writeProc("meminfo", good["meminfo"])
		upPath := writeProc("uptime", good["uptime"])
		switch {
		case strings.HasPrefix(name, "meminfo"):
			memPath = writeProc("meminfo", body)
		case strings.HasPrefix(name, "loadavg"):
			loadPath = writeProc("loadavg", body)
		case strings.HasPrefix(name, "uptime"):
			upPath = writeProc("uptime", body)
		}
		restore := setProcPaths(loadPath, memPath, upPath)
		_, err := opSystemStats(context.Background(), nil, RequestMeta{})
		restore()
		var oe *OpError
		if !errors.As(err, &oe) {
			t.Fatalf("%s: expected *OpError, got %v", name, err)
		}
		if oe.Code != ErrInternal {
			t.Fatalf("%s: code = %q, want internal", name, oe.Code)
		}
	}
}

func TestParseMemInfo(t *testing.T) {
	total, avail, err := parseMemInfo(strings.NewReader("MemTotal:       2048 kB\nMemFree: 10 kB\nMemAvailable:    1024 kB\n"))
	if err != nil {
		t.Fatal(err)
	}
	if total != 2048*1024 || avail != 1024*1024 {
		t.Fatalf("total=%d avail=%d", total, avail)
	}
	// Values are bytes and must never look like a parse failure of zero.
	if total == 0 || avail == 0 {
		t.Fatal("zero memory parsed as success")
	}
}

func TestParseMemInfoRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"MemTotal: 2048 kB\n",
		"MemAvailable: 1024 kB\n",
		"MemTotal: 2048 kB\nMemAvailable: 4096 kB\n",
		"MemTotal: 2048 kB\nMemAvailable: 1024 kB\nMemAvailable: 512 kB\n",
		"MemTotal: 0 kB\nMemAvailable: 0 kB\n",
		"MemTotal: 2048 MB\nMemAvailable: 1024 MB\n",
		"MemTotal: 2048\nMemAvailable: 1024\n",
		"MemTotal: 2048 kB extra\nMemAvailable: 1024 kB\n",
	}
	for _, body := range cases {
		if _, _, err := parseMemInfo(strings.NewReader(body)); err == nil {
			t.Fatalf("parseMemInfo(%q) = nil error", body)
		}
	}
}

func TestParseLoadAvg(t *testing.T) {
	l1, l5, l15, err := parseLoadAvg(strings.NewReader("0.50 1.25 2.75 2/345 6789\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l1 != 0.5 || l5 != 1.25 || l15 != 2.75 {
		t.Fatalf("got %v %v %v", l1, l5, l15)
	}
	bad := []string{"", "0.5", "0.5 0.5", "NaN 0 0 1/1 1", "Inf 0 0 1/1 1", "-0.5 0 0 1/1 1", "x y z 1/1 1", "0 0 0 1/1 1 extra", "0 0 0 bad 1", "0 0 0 1/1 bad", "0 0 0 1/1 -1", "0 0 0 -1/1 1", "0 0 0 2/1 1"}
	for _, body := range bad {
		if _, _, _, err := parseLoadAvg(strings.NewReader(body)); err == nil {
			t.Fatalf("parseLoadAvg(%q) = nil error", body)
		}
	}
}

func TestParseUptime(t *testing.T) {
	up, err := parseUptime(strings.NewReader("1234.56 9876.54\n"))
	if err != nil {
		t.Fatal(err)
	}
	if up != 1234.56 {
		t.Fatalf("uptime = %v", up)
	}
	for _, body := range []string{"", "abc", "-1.0 0.0", "NaN 0.0", "Inf 0.0"} {
		if _, err := parseUptime(strings.NewReader(body)); err == nil {
			t.Fatalf("parseUptime(%q) = nil error", body)
		}
	}
}

// realMeminfo parses /proc/meminfo independently of production code.
func realMeminfo(t *testing.T) (int64, int64) {
	t.Helper()
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Skipf("no /proc/meminfo: %v", err)
	}
	var total, avail int64
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	if total == 0 || avail == 0 {
		t.Skip("real /proc/meminfo lacks fields")
	}
	return total, avail
}

// setProcPaths points the stats readers at scratch files and returns a restore
// func so no test ever reads or writes the real /proc.
func setProcPaths(load, mem, uptime string) func() {
	oldLoad, oldMem, oldUp := procLoadAvgPath, procMemInfoPath, procUptimePath
	procLoadAvgPath, procMemInfoPath, procUptimePath = load, mem, uptime
	return func() {
		procLoadAvgPath, procMemInfoPath, procUptimePath = oldLoad, oldMem, oldUp
	}
}

func TestCatalogSnapshotIsACopy(t *testing.T) {
	r := NewRegistry()
	RegisterBuiltins(r)
	a := catalogNames()
	if len(a) != 4 {
		t.Fatalf("catalog = %v", a)
	}
	a[0] = "mutated"
	if b := catalogNames(); b[0] == "mutated" {
		t.Fatal("catalogNames leaks its backing slice")
	}
}
