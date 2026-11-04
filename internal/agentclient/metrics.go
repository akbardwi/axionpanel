package agentclient

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"

	"time"
)

// maxJSONSafeInteger is the largest integer a JavaScript number holds exactly.
const maxJSONSafeInteger = 1<<53 - 1

// Metrics is the live sampled host telemetry from system.metrics. A nil
// resource means the agent could not measure it; its reason says why.
type Metrics struct {
	CPU           *CPUMetrics     `json:"cpu"`
	CPUReason     string          `json:"cpu_reason"`
	Disk          *DiskMetrics    `json:"disk"`
	DiskReason    string          `json:"disk_reason"`
	Network       *NetworkMetrics `json:"network"`
	NetworkReason string          `json:"network_reason"`
	ObservedAt    string          `json:"observed_at"`
}

// CPUMetrics is aggregate CPU utilization over the sampling interval.
type CPUMetrics struct {
	UsagePercent float64 `json:"usage_percent"`
	LogicalCPUs  int     `json:"logical_cpus"`
}

// DiskMetrics describes the root filesystem. Used is total minus free, so
// used+available may be below total when blocks are reserved for root.
type DiskMetrics struct {
	Mount          string `json:"mount"`
	TotalBytes     uint64 `json:"total_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

// NetworkMetrics is throughput on the default-route interface.
type NetworkMetrics struct {
	Interface        string  `json:"interface"`
	RxBytesPerSecond float64 `json:"rx_bytes_per_second"`
	TxBytesPerSecond float64 `json:"tx_bytes_per_second"`
}

var ifaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)

// Metrics runs the read-only system.metrics operation.
func (c *Client) Metrics(ctx context.Context) (*Metrics, error) {
	var out Metrics
	if err := c.Call(ctx, "system.metrics", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func invalidMetrics(what string) error {
	return fmt.Errorf("%w: invalid metrics %s", ErrInvalidResponse, what)
}

// decodeMetrics validates the metrics document field by field. Resources may
// be null, but only with a non-blank reason; present resources must carry an
// empty reason and in-range values.
func decodeMetrics(body []byte, out *Metrics) error {
	if err := requiredObject(body, "cpu_reason", "disk_reason", "network_reason", "observed_at"); err != nil {
		return err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return invalidMetrics("document")
	}
	required := map[string][]string{
		"cpu":     {"usage_percent", "logical_cpus"},
		"disk":    {"mount", "total_bytes", "used_bytes", "available_bytes"},
		"network": {"interface", "rx_bytes_per_second", "tx_bytes_per_second"},
	}
	for resource, fields := range required {
		raw, ok := top[resource]
		if !ok {
			return invalidMetrics(resource + " missing")
		}
		if string(raw) == "null" {
			continue
		}
		if err := requiredObject(raw, fields...); err != nil {
			return err
		}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if _, err := time.Parse(time.RFC3339, out.ObservedAt); err != nil {
		return invalidMetrics("observed_at")
	}
	for _, pair := range []struct {
		name    string
		present bool
		reason  string
	}{{"cpu", out.CPU != nil, out.CPUReason}, {"disk", out.Disk != nil, out.DiskReason}, {"network", out.Network != nil, out.NetworkReason}} {
		if pair.present != (pair.reason == "") {
			return invalidMetrics(pair.name + " reason mismatch")
		}
		if pair.present {
			continue
		}
		if !validReason(pair.name, pair.reason) {
			return invalidMetrics(pair.name + " reason")
		}
	}
	if cpu := out.CPU; cpu != nil {
		if !finite(cpu.UsagePercent) || cpu.UsagePercent < 0 || cpu.UsagePercent > 100 || cpu.LogicalCPUs <= 0 {
			return invalidMetrics("cpu")
		}
	}
	if d := out.Disk; d != nil {
		if d.Mount != "/" || d.TotalBytes == 0 || d.TotalBytes > maxJSONSafeInteger ||
			d.UsedBytes > d.TotalBytes || d.AvailableBytes > d.TotalBytes-d.UsedBytes {
			return invalidMetrics("disk")
		}
	}
	if n := out.Network; n != nil {
		if !ifaceNamePattern.MatchString(n.Interface) || n.Interface == "lo" || n.Interface == "." || n.Interface == ".." {
			return invalidMetrics("network interface")
		}
		for _, v := range []float64{n.RxBytesPerSecond, n.TxBytesPerSecond} {
			if !finite(v) || v < 0 {
				return invalidMetrics("network rate")
			}
		}
	}
	return nil
}

// validReason accepts only the closed set of sanitized reasons the agent may
// publish; error text and host paths are never part of the contract.
func validReason(resource, reason string) bool {
	switch reason {
	case "read_failed", "invalid_data":
		return true
	case "no_default_route":
		return resource == "network"
	}
	return false
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
