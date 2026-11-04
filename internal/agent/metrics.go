package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// maxProcLineBytes bounds a single line of a parsed /proc file. Real files have
// short per-cpu lines; a longer one means the file is not what we expect.
const maxProcLineBytes = 1 << 20

// cpuTimes is one aggregate /proc/stat cpu snapshot. busy holds the ticks spent
// doing work, idle holds the ticks spent idle or waiting on I/O. The guest and
// guest_nice columns are deliberately excluded: the kernel already counts them
// inside user and nice.
type cpuTimes struct {
	busy, idle uint64
}

// parseCPUTimes reads the aggregate cpu line and counts the logical (per-cpu)
// lines. It returns an error on missing, malformed, negative, overflowing or
// duplicated input rather than guessing a value.
func parseCPUTimes(r io.Reader) (cpuTimes, int, error) {
	var out cpuTimes
	aggregate := false
	logical := 0
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), maxProcLineBytes)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		name, rest, _ := strings.Cut(line, " ")
		if name != "cpu" && !isPerCPUName(name) {
			// The cpu block leads the file; anything else ends it.
			break
		}
		fields := strings.Fields(rest)
		if len(fields) < 4 {
			return cpuTimes{}, 0, errUnexpectedFormat
		}
		ticks := make([]uint64, 0, len(fields))
		for _, f := range fields {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				return cpuTimes{}, 0, errUnexpectedFormat
			}
			ticks = append(ticks, v)
		}
		if name == "cpu" {
			if aggregate {
				return cpuTimes{}, 0, errUnexpectedFormat
			}
			aggregate = true
			// user nice system idle iowait irq softirq steal, optional beyond.
			busy := addTicks(ticks, 0, 1, 2, 5, 6, 7)
			idle := addTicks(ticks, 3, 4)
			if busy == math.MaxUint64 || idle == math.MaxUint64 {
				return cpuTimes{}, 0, errUnexpectedFormat
			}
			out = cpuTimes{busy: busy, idle: idle}
		} else {
			logical++
		}
	}
	if err := s.Err(); err != nil {
		return cpuTimes{}, 0, errUnexpectedFormat
	}
	if !aggregate || logical == 0 {
		return cpuTimes{}, 0, errUnexpectedFormat
	}
	return out, logical, nil
}

func isPerCPUName(name string) bool {
	digits, ok := strings.CutPrefix(name, "cpu")
	if !ok || digits == "" {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// addTicks sums the indexed tick columns, saturating to math.MaxUint64 so an
// overflow is detectable by the caller as an invalid snapshot.
func addTicks(ticks []uint64, idx ...int) uint64 {
	var sum uint64
	for _, i := range idx {
		if i >= len(ticks) {
			continue
		}
		if sum > math.MaxUint64-ticks[i] {
			return math.MaxUint64
		}
		sum += ticks[i]
	}
	return sum
}

// cpuUsagePercent computes the busy fraction of elapsed ticks between two
// snapshots. A zero result is a legitimate fully-idle sample, but a zero
// elapsed-tick total or a decreasing counter is not: it means the data cannot
// support a real measurement.
func cpuUsagePercent(prev, cur cpuTimes) (float64, error) {
	if cur.busy < prev.busy || cur.idle < prev.idle {
		return 0, errUnexpectedFormat
	}
	busyDelta := cur.busy - prev.busy
	idleDelta := cur.idle - prev.idle
	total := busyDelta + idleDelta
	if total == 0 {
		return 0, errUnexpectedFormat
	}
	return float64(busyDelta) / float64(total) * 100, nil
}

// Linux interface names: at most IFNAMSIZ-1 bytes, no '/', ':' or whitespace.
var ifaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)

func validIfaceName(name string) bool {
	return ifaceNamePattern.MatchString(name) && name != "." && name != ".."
}

const (
	rtfUp       = 0x1
	routeFields = 11
)

// parseDefaultRoute picks the IPv4 default-route interface from
// /proc/net/route: destination and mask 0.0.0.0, RTF_UP set, not loopback.
// The lowest metric wins; ties keep the first entry, matching kernel order.
// Any malformed line rejects the whole file rather than guessing.
func parseDefaultRoute(r io.Reader) (string, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), maxProcLineBytes)
	if !s.Scan() {
		return "", errUnexpectedFormat
	}
	header := strings.Fields(s.Text())
	if len(header) < 3 || header[0] != "Iface" || header[1] != "Destination" || header[2] != "Gateway" {
		return "", errUnexpectedFormat
	}
	best, bestMetric := "", uint64(0)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != routeFields || !validIfaceName(fields[0]) {
			return "", errUnexpectedFormat
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil {
			return "", errUnexpectedFormat
		}
		metric, err := strconv.ParseUint(fields[6], 10, 32)
		if err != nil {
			return "", errUnexpectedFormat
		}
		dest, err1 := strconv.ParseUint(fields[1], 16, 32)
		mask, err2 := strconv.ParseUint(fields[7], 16, 32)
		if err1 != nil || err2 != nil {
			return "", errUnexpectedFormat
		}
		if dest != 0 || mask != 0 || flags&rtfUp == 0 || fields[0] == "lo" {
			continue
		}
		if best == "" || metric < bestMetric {
			best, bestMetric = fields[0], metric
		}
	}
	if s.Err() != nil {
		return "", errUnexpectedFormat
	}
	if best == "" {
		return "", errNoDefaultRoute
	}
	return best, nil
}

type netCounters struct {
	rx, tx uint64
}

const netDevFields = 16

// parseNetDev returns the receive and transmit byte counters for iface from
// /proc/net/dev. Missing, duplicated or malformed entries are errors.
func parseNetDev(r io.Reader, iface string) (netCounters, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), maxProcLineBytes)
	for _, prefix := range []string{"Inter-|", " face |"} {
		if !s.Scan() || !strings.HasPrefix(s.Text(), prefix) {
			return netCounters{}, errUnexpectedFormat
		}
	}
	var out netCounters
	found := false
	for s.Scan() {
		name, rest, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue
		}
		if strings.TrimSpace(name) != iface {
			continue
		}
		if found {
			return netCounters{}, errUnexpectedFormat
		}
		fields := strings.Fields(rest)
		if len(fields) != netDevFields {
			return netCounters{}, errUnexpectedFormat
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			return netCounters{}, errUnexpectedFormat
		}
		out, found = netCounters{rx: rx, tx: tx}, true
	}
	if s.Err() != nil || !found {
		return netCounters{}, errUnexpectedFormat
	}
	return out, nil
}

// networkRates converts paired counter snapshots into bytes per second. A
// counter that went backwards (wrap, interface reset) cannot be measured, so
// it is an error rather than a fabricated zero.
func networkRates(prev, cur netCounters, elapsed time.Duration) (float64, float64, error) {
	if elapsed <= 0 || cur.rx < prev.rx || cur.tx < prev.tx {
		return 0, 0, errUnexpectedFormat
	}
	secs := elapsed.Seconds()
	return float64(cur.rx-prev.rx) / secs, float64(cur.tx-prev.tx) / secs, nil
}

const (
	// maxProcFileBytes bounds every whole-file read. /proc/stat on very large
	// hosts and long routing tables stay far below this.
	maxProcFileBytes = 1 << 20
	// metricsInterval separates the paired cpu and network snapshots.
	metricsInterval = 250 * time.Millisecond
	// maxJSONSafeInteger keeps byte counts exact for JavaScript consumers.
	maxJSONSafeInteger = 1<<53 - 1

	reasonReadFailed     = "read_failed"
	reasonInvalidData    = "invalid_data"
	reasonNoDefaultRoute = "no_default_route"
)

var (
	errNoDefaultRoute = errors.New("agent: no default route")
	errProcTooLarge   = errors.New("agent: /proc file exceeds size limit")
)

// metricsDocument is the system.metrics result. Every resource is either a
// measured value with an empty reason or null with a fixed, sanitized reason;
// a failed read is never reported as zero.
type metricsDocument struct {
	CPU           *cpuMetrics     `json:"cpu"`
	CPUReason     string          `json:"cpu_reason"`
	Disk          *diskMetrics    `json:"disk"`
	DiskReason    string          `json:"disk_reason"`
	Network       *networkMetrics `json:"network"`
	NetworkReason string          `json:"network_reason"`
	ObservedAt    string          `json:"observed_at"`
}

type cpuMetrics struct {
	UsagePercent float64 `json:"usage_percent"`
	LogicalCPUs  int     `json:"logical_cpus"`
}

type diskMetrics struct {
	Mount          string `json:"mount"`
	TotalBytes     uint64 `json:"total_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

type networkMetrics struct {
	Interface        string  `json:"interface"`
	RxBytesPerSecond float64 `json:"rx_bytes_per_second"`
	TxBytesPerSecond float64 `json:"tx_bytes_per_second"`
}

// metricsCollector holds fixed, compile-time sources. Fields exist only as a
// test seam; no request input ever reaches a path.
type metricsCollector struct {
	statPath, netDevPath, routePath string
	statfs                          func(string, *unix.Statfs_t) error
	interval                        time.Duration
	now                             func() time.Time
	wait                            func(context.Context, time.Duration) error
}

func defaultMetricsCollector() metricsCollector {
	return metricsCollector{
		statPath:   "/proc/stat",
		netDevPath: "/proc/net/dev",
		routePath:  "/proc/net/route",
		statfs:     unix.Statfs,
		interval:   metricsInterval,
		now:        time.Now,
		wait:       sleepContext,
	}
}

func opSystemMetrics(ctx context.Context, params Params, meta RequestMeta) (any, error) {
	if err := decodeParams(params, &struct{}{}); err != nil {
		return nil, err
	}
	doc, err := defaultMetricsCollector().collect(ctx)
	if err != nil {
		return nil, newOpError(ErrInternal, "metrics sampling interrupted", nil)
	}
	if err := validateMetricsDocument(doc); err != nil {
		return nil, newOpError(ErrInternal, "inconsistent metrics", nil)
	}
	return doc, nil
}

// collect samples cpu and network twice, one interval apart, and the root
// filesystem once. Only cancellation fails the whole document; each resource
// failure is reported in place.
func (c metricsCollector) collect(ctx context.Context) (metricsDocument, error) {
	if err := ctx.Err(); err != nil {
		return metricsDocument{}, err
	}
	cpu1, logical1, cpuErr := c.readCPU()
	iface, netErr := c.defaultInterface()
	var net1 netCounters
	if netErr == nil {
		net1, netErr = c.readNet(iface)
	}
	start := c.now()
	if err := c.wait(ctx, c.interval); err != nil {
		return metricsDocument{}, err
	}
	if err := ctx.Err(); err != nil {
		return metricsDocument{}, err
	}

	var doc metricsDocument
	if cpuErr == nil {
		cpu2, logical2, err := c.readCPU()
		cpuErr = err
		if err == nil {
			if logical2 != logical1 {
				cpuErr = errUnexpectedFormat
			} else if pct, err := cpuUsagePercent(cpu1, cpu2); err != nil {
				cpuErr = err
			} else {
				doc.CPU = &cpuMetrics{UsagePercent: pct, LogicalCPUs: logical2}
			}
		}
	}
	if netErr == nil {
		net2, err := c.readNet(iface)
		elapsed := c.now().Sub(start)
		netErr = err
		if err == nil {
			if rx, tx, err := networkRates(net1, net2, elapsed); err != nil {
				netErr = err
			} else {
				doc.Network = &networkMetrics{Interface: iface, RxBytesPerSecond: rx, TxBytesPerSecond: tx}
			}
		}
	}
	disk, diskErr := c.readDisk()
	if diskErr == nil {
		doc.Disk = &disk
	}
	doc.CPUReason = metricsReason(cpuErr)
	doc.NetworkReason = metricsReason(netErr)
	doc.DiskReason = metricsReason(diskErr)
	doc.ObservedAt = c.now().UTC().Format(time.RFC3339)
	return doc, nil
}

func (c metricsCollector) readCPU() (cpuTimes, int, error) {
	data, err := readBoundedProcFile(c.statPath)
	if err != nil {
		return cpuTimes{}, 0, err
	}
	return parseCPUTimes(bytes.NewReader(data))
}

func (c metricsCollector) defaultInterface() (string, error) {
	data, err := readBoundedProcFile(c.routePath)
	if err != nil {
		return "", err
	}
	return parseDefaultRoute(bytes.NewReader(data))
}

func (c metricsCollector) readNet(iface string) (netCounters, error) {
	data, err := readBoundedProcFile(c.netDevPath)
	if err != nil {
		return netCounters{}, err
	}
	return parseNetDev(bytes.NewReader(data), iface)
}

// readDisk reports the root filesystem. Blocks are in f_frsize units. "Free"
// includes blocks reserved for root, "available" excludes them, so used is
// total minus free and used+available can be less than total.
func (c metricsCollector) readDisk() (diskMetrics, error) {
	var st unix.Statfs_t
	if err := c.statfs("/", &st); err != nil {
		return diskMetrics{}, err
	}
	size := st.Frsize
	if size <= 0 {
		size = st.Bsize
	}
	if size <= 0 || st.Blocks == 0 || st.Bfree > st.Blocks || st.Bavail > st.Bfree {
		return diskMetrics{}, errUnexpectedFormat
	}
	unit := uint64(size)
	if st.Blocks > maxJSONSafeInteger/unit {
		return diskMetrics{}, errUnexpectedFormat
	}
	total := st.Blocks * unit
	free := st.Bfree * unit
	return diskMetrics{
		Mount:          "/",
		TotalBytes:     total,
		UsedBytes:      total - free,
		AvailableBytes: st.Bavail * unit,
	}, nil
}

func metricsReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errNoDefaultRoute):
		return reasonNoDefaultRoute
	case errors.Is(err, errUnexpectedFormat), errors.Is(err, errProcTooLarge):
		return reasonInvalidData
	default:
		return reasonReadFailed
	}
}

// readBoundedProcFile reads at most maxProcFileBytes from a fixed path.
func readBoundedProcFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProcFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProcFileBytes {
		return nil, errProcTooLarge
	}
	return data, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// validateMetricsDocument enforces the published contract before a result
// leaves the agent.
func validateMetricsDocument(doc metricsDocument) error {
	if _, err := time.Parse(time.RFC3339, doc.ObservedAt); err != nil {
		return errUnexpectedFormat
	}
	if (doc.CPU == nil) == (doc.CPUReason == "") ||
		(doc.Disk == nil) == (doc.DiskReason == "") ||
		(doc.Network == nil) == (doc.NetworkReason == "") {
		return errUnexpectedFormat
	}
	if c := doc.CPU; c != nil {
		if math.IsNaN(c.UsagePercent) || c.UsagePercent < 0 || c.UsagePercent > 100 || c.LogicalCPUs <= 0 {
			return errUnexpectedFormat
		}
	}
	if d := doc.Disk; d != nil {
		if d.Mount != "/" || d.TotalBytes == 0 || d.TotalBytes > maxJSONSafeInteger ||
			d.UsedBytes > d.TotalBytes || d.AvailableBytes > d.TotalBytes-d.UsedBytes {
			return errUnexpectedFormat
		}
	}
	if n := doc.Network; n != nil {
		for _, v := range []float64{n.RxBytesPerSecond, n.TxBytesPerSecond} {
			if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
				return errUnexpectedFormat
			}
		}
		if !validIfaceName(n.Interface) || n.Interface == "lo" {
			return errUnexpectedFormat
		}
	}
	return nil
}
