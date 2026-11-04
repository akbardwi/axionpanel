package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func version() string { return Version }

// Builtins have one source of truth for registration and standalone info.
func builtinOperations() []struct {
	name string
	op   Operation
} {
	return []struct {
		name string
		op   Operation
	}{
		{"system.info", opSystemInfo},
		{"system.stats", opSystemStats},
		{"system.metrics", opSystemMetrics},
		{"capabilities.refresh", opCapabilitiesRefresh},
	}
}

// RegisterBuiltins installs only implemented, read-only operations. The info
// handler captures this registry, so its catalog includes actual registrations
// without a global snapshot or a separate hardcoded alias list.
func RegisterBuiltins(r *Registry) {
	for _, entry := range builtinOperations() {
		op := entry.op
		if entry.name == "system.info" {
			op = func(ctx context.Context, params Params, meta RequestMeta) (any, error) {
				res, err := opSystemInfo(ctx, params, meta)
				if err != nil {
					return nil, err
				}
				res.(map[string]any)["operations"] = r.Names()
				return res, nil
			}
		}
		r.Register(entry.name, op)
	}
}

func opSystemInfo(ctx context.Context, params Params, meta RequestMeta) (any, error) {
	if err := decodeParams(params, &struct{}{}); err != nil {
		return nil, err
	}
	caps, tools := detectCapabilities(), detectTools()
	host, _ := os.Hostname()
	return map[string]any{
		"version":             version(),
		"protocol":            Protocol,
		"os":                  osPrettyName(),
		"arch":                runtime.GOARCH,
		"kernel":              readTrimmed("/proc/sys/kernel/osrelease"),
		"hostname":            host,
		"detected_tools":      tools,
		"capabilities":        caps,
		"capability_revision": capabilityRevision(caps, tools),
		"observed_at":         time.Now().UTC().Format(time.RFC3339),
		"operations":          catalogNames(),
	}, nil
}

// Detection uses only PATH lookups, never tool execution.
func opCapabilitiesRefresh(ctx context.Context, params Params, meta RequestMeta) (any, error) {
	if err := decodeParams(params, &struct{}{}); err != nil {
		return nil, err
	}
	caps, tools := detectCapabilities(), detectTools()
	return map[string]any{
		"detected_tools":      tools,
		"capabilities":        caps,
		"capability_revision": capabilityRevision(caps, tools),
		"observed_at":         time.Now().UTC().Format(time.RFC3339),
	}, nil
}

var (
	procLoadAvgPath = "/proc/loadavg"
	procMemInfoPath = "/proc/meminfo"
	procUptimePath  = "/proc/uptime"
)

func opSystemStats(ctx context.Context, params Params, meta RequestMeta) (any, error) {
	if err := decodeParams(params, &struct{}{}); err != nil {
		return nil, err
	}
	load1, load5, load15, err := readLoadAvg()
	if err != nil {
		return nil, newOpError(ErrInternal, "cannot read load average", nil)
	}
	total, available, err := readMemInfo()
	if err != nil {
		return nil, newOpError(ErrInternal, "cannot read memory information", nil)
	}
	uptime, err := readUptime()
	if err != nil {
		return nil, newOpError(ErrInternal, "cannot read uptime", nil)
	}
	return map[string]any{
		"load1": load1, "load5": load5, "load15": load15,
		"mem_total_bytes": total, "mem_available_bytes": available,
		"uptime_seconds": uptime,
		"observed_at":    time.Now().UTC().Format(time.RFC3339),
	}, nil
}

type capability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

// Binary presence is not a managed capability. Git cannot prove a sandbox;
// Docker cannot prove Compose. None of these management features exist yet.
func detectCapabilities() map[string]capability {
	out := make(map[string]capability)
	for _, name := range []string{"php", "database", "firewall", "docker", "compose", "build_sandbox", "backup", "fail2ban", "ssh", "systemd"} {
		out[name] = capability{Available: false, Reason: "unimplemented"}
	}
	return out
}

func detectTools() map[string]bool {
	out := make(map[string]bool)
	for _, bin := range []string{"git", "docker", "docker-compose", "tar", "php", "mariadb", "mysqld", "mysql", "nft", "fail2ban-client", "sshd", "systemctl"} {
		_, err := exec.LookPath(bin)
		out[bin] = err == nil
	}
	return out
}

func capabilityRevision(caps map[string]capability, tools map[string]bool) string {
	enc, err := json.Marshal(struct {
		Capabilities map[string]capability `json:"capabilities"`
		Tools        map[string]bool       `json:"detected_tools"`
	}{caps, tools})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte(runtime.GOOS+"/"+runtime.GOARCH+"/"), enc...))
	return hex.EncodeToString(sum[:8])
}

func catalogNames() []string {
	out := make([]string, 0, len(builtinOperations()))
	for _, entry := range builtinOperations() {
		out = append(out, entry.name)
	}
	sortStrings(out)
	return out
}

func osPrettyName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				return strings.Trim(v, `"`)
			}
		}
	}
	return runtime.GOOS
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readLoadAvg() (float64, float64, float64, error) {
	f, err := os.Open(procLoadAvgPath)
	if err != nil {
		return 0, 0, 0, err
	}
	defer f.Close()
	return parseLoadAvg(f)
}

func parseLoadAvg(r io.Reader) (float64, float64, float64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) != 5 {
		return 0, 0, 0, errUnexpectedFormat
	}
	var vals [3]float64
	for i := range vals {
		v, err := nonnegativeFloat(fields[i])
		if err != nil {
			return 0, 0, 0, err
		}
		vals[i] = v
	}
	// field 4 is "runnable/total" threads; both must be non-negative and total
	// must cover runnable. field 5 is the last PID.
	runnable, total, err := parseSlashPair(fields[3])
	if err != nil {
		return 0, 0, 0, err
	}
	if _, err := parseNonNegativeInt(fields[4]); err != nil {
		return 0, 0, 0, err
	}
	if runnable > total {
		return 0, 0, 0, errUnexpectedFormat
	}
	return vals[0], vals[1], vals[2], nil
}

func parseSlashPair(raw string) (int64, int64, error) {
	l, r, ok := strings.Cut(raw, "/")
	if !ok {
		return 0, 0, errUnexpectedFormat
	}
	left, err := parseNonNegativeInt(l)
	if err != nil {
		return 0, 0, err
	}
	right, err := parseNonNegativeInt(r)
	if err != nil {
		return 0, 0, err
	}
	return left, right, nil
}

func parseNonNegativeInt(raw string) (int64, error) {
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return 0, errUnexpectedFormat
	}
	return v, nil
}

func readMemInfo() (int64, int64, error) {
	f, err := os.Open(procMemInfoPath)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	return parseMemInfo(f)
}

func parseMemInfo(r io.Reader) (int64, int64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, 0, err
	}
	values := make(map[string]int64, 2)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "MemTotal:" && fields[0] != "MemAvailable:") {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return 0, 0, errUnexpectedFormat
		}
		if _, duplicate := values[fields[0]]; duplicate {
			return 0, 0, errUnexpectedFormat
		}
		v, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || v < 0 || v > math.MaxInt64/1024 {
			return 0, 0, errUnexpectedFormat
		}
		values[fields[0]] = v * 1024
	}
	total, hasTotal := values["MemTotal:"]
	avail, hasAvail := values["MemAvailable:"]
	if !hasTotal || !hasAvail || total <= 0 || avail > total {
		return 0, 0, errUnexpectedFormat
	}
	return total, avail, nil
}

func readUptime() (float64, error) {
	f, err := os.Open(procUptimePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return parseUptime(f)
}

func parseUptime(r io.Reader) (float64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, errUnexpectedFormat
	}
	return nonnegativeFloat(fields[0])
}

func nonnegativeFloat(raw string) (float64, error) {
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, errUnexpectedFormat
	}
	return v, nil
}

var errUnexpectedFormat = &unexpectedFormatError{}

type unexpectedFormatError struct{}

func (e *unexpectedFormatError) Error() string { return "agent: unexpected /proc format" }
