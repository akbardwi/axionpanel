package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseCPUTimesCountsAggregateAndLogicalCPUs(t *testing.T) {
	const body = `cpu  100 10 50 800 20 5 5 10 0 0
cpu0 50 5 25 400 10 2 3 5 0 0
cpu1 50 5 25 400 10 3 2 5 0 0
intr 12345 0 0
ctxt 999
`
	got, logical, err := parseCPUTimes(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseCPUTimes: %v", err)
	}
	if logical != 2 {
		t.Fatalf("logical = %d, want 2", logical)
	}
	// busy = user+nice+system+irq+softirq+steal = 100+10+50+5+5+10
	// idle = idle+iowait = 800+20. Guest fields are already inside user.
	if got.busy != 180 || got.idle != 820 {
		t.Fatalf("times = %+v, want busy=180 idle=820", got)
	}
}

func TestParseCPUTimesRejectsMissingOrInvalidTicks(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"no aggregate":     "cpu0 1 2 3 4\ncpu1 1 2 3 4\n",
		"too few ticks":    "cpu  1 2 3\ncpu0 1 2 3 4\n",
		"garbage tick":     "cpu  1 2 x 4\ncpu0 1 2 3 4\n",
		"negative tick":    "cpu  1 2 -3 4\ncpu0 1 2 3 4\n",
		"overflow tick":    "cpu  18446744073709551615 2 3 4 5 6 7 8\ncpu0 1 2 3 4\n",
		"duplicate global": "cpu  1 2 3 4\ncpu  1 2 3 4\ncpu0 1 2 3 4\n",
		"no logical cpus":  "cpu  1 2 3 4\nintr 1\n",
		"nan tick":         "cpu  1 2 NaN 4\ncpu0 1 2 3 4\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseCPUTimes(strings.NewReader(body)); err == nil {
				t.Fatalf("parseCPUTimes(%q) accepted malformed input", body)
			}
		})
	}
}

func TestParseCPUTimesAcceptsShortTickLists(t *testing.T) {
	// Older kernels expose only user+nice+system+idle. That is still a valid,
	// complete snapshot; missing optional columns are zeros, not failures.
	got, logical, err := parseCPUTimes(strings.NewReader("cpu  10 0 10 80\ncpu0 10 0 10 80\n"))
	if err != nil {
		t.Fatal(err)
	}
	if logical != 1 || got.busy != 20 || got.idle != 80 {
		t.Fatalf("times=%+v logical=%d", got, logical)
	}
}

func TestCPUUsagePercentFromDeltas(t *testing.T) {
	cases := []struct {
		name      string
		prev, cur cpuTimes
		want      float64
	}{
		{"quarter busy", cpuTimes{busy: 100, idle: 300}, cpuTimes{busy: 125, idle: 375}, 25},
		{"fully idle is a valid zero", cpuTimes{busy: 100, idle: 300}, cpuTimes{busy: 100, idle: 400}, 0},
		{"fully busy", cpuTimes{busy: 100, idle: 300}, cpuTimes{busy: 200, idle: 300}, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cpuUsagePercent(tc.prev, tc.cur)
			if err != nil {
				t.Fatalf("cpuUsagePercent: %v", err)
			}
			if got != tc.want {
				t.Fatalf("percent = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCPUUsagePercentRejectsImpossibleDeltas(t *testing.T) {
	cases := map[string][2]cpuTimes{
		"busy decreasing":  {{busy: 200, idle: 300}, {busy: 100, idle: 400}},
		"idle decreasing":  {{busy: 100, idle: 300}, {busy: 200, idle: 200}},
		"no elapsed ticks": {{busy: 100, idle: 300}, {busy: 100, idle: 300}},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			if v, err := cpuUsagePercent(pair[0], pair[1]); err == nil {
				t.Fatalf("accepted impossible delta, percent = %v", v)
			}
		})
	}
}

const routeHeader = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

func TestParseDefaultRouteSelectsLowestMetricUpGateway(t *testing.T) {
	body := routeHeader +
		"lo\t00000000\t00000000\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" + // loopback default is ignored
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"enp0s6\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" + // not a default route
		"ens3\t00000000\t0100000A\t0001\t0\t0\t50\t00000000\t0\t0\t0\n" + // up default route without RTF_GATEWAY (point-to-point)
		"enp0s6\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"tun0\t00000000\t00000000\t0002\t0\t0\t1\t00000000\t0\t0\t0\n" // RTF_GATEWAY but not RTF_UP
	got, err := parseDefaultRoute(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseDefaultRoute: %v", err)
	}
	// ens3 (metric 50) is an up default route even without a gateway flag
	// (e.g. point-to-point). It wins over enp0s6 (100) and wlan0 (600).
	if got != "ens3" {
		t.Fatalf("interface = %q, want ens3", got)
	}
}

func TestParseDefaultRouteRealShape(t *testing.T) {
	body := routeHeader +
		"enp0s6\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"enp0s6\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	got, err := parseDefaultRoute(strings.NewReader(body))
	if err != nil || got != "enp0s6" {
		t.Fatalf("parseDefaultRoute = %q, %v; want enp0s6", got, err)
	}
}

func TestParseDefaultRouteRejectsMissingOrMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"header only":     routeHeader,
		"no default":      routeHeader + "eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
		"loopback only":   routeHeader + "lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n",
		"bad flags":       routeHeader + "eth0\t00000000\t0100000A\tzz\t0\t0\t0\t00000000\t0\t0\t0\n",
		"short line":      routeHeader + "eth0\t00000000\n",
		"bad metric":      routeHeader + "eth0\t00000000\t0100000A\t0003\t0\t0\tx\t00000000\t0\t0\t0\n",
		"unsafe name":     routeHeader + "../etc\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
		"overlong name":   routeHeader + "abcdefghijklmnopq\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
		"wrong header":    "Nope\n" + "eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
		"default netmask": routeHeader + "eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := parseDefaultRoute(strings.NewReader(body)); err == nil {
				t.Fatalf("parseDefaultRoute accepted %q -> %q", body, got)
			}
		})
	}
}

const netDevHeader = "Inter-|   Receive                                                |  Transmit\n" +
	" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"

func TestParseNetDevCountersForInterface(t *testing.T) {
	body := netDevHeader +
		"    lo: 1374072873  853982    0    0    0     0          0         0 1374072873  853982    0    0    0     0       0          0\n" +
		"enp0s6: 1970717820 1513273    0    0    0     0          0         0 1021471656 1477160    0    0    0     0       0          0\n"
	got, err := parseNetDev(strings.NewReader(body), "enp0s6")
	if err != nil {
		t.Fatalf("parseNetDev: %v", err)
	}
	if got.rx != 1970717820 || got.tx != 1021471656 {
		t.Fatalf("counters = %+v", got)
	}
}

func TestParseNetDevRejectsMissingOrMalformed(t *testing.T) {
	good := "eth0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n"
	cases := map[string]string{
		"empty":         "",
		"missing iface": netDevHeader + "wlan0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n",
		"short":         netDevHeader + "eth0: 100 1 0 0\n",
		"garbage":       netDevHeader + "eth0: abc 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n",
		"negative":      netDevHeader + "eth0: -1 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n",
		"duplicate":     netDevHeader + good + good,
		"no header":     good,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := parseNetDev(strings.NewReader(body), "eth0"); err == nil {
				t.Fatalf("parseNetDev accepted %q -> %+v", body, got)
			}
		})
	}
}

func TestNetworkRatesFromDeltas(t *testing.T) {
	prev := netCounters{rx: 1000, tx: 5000}
	cur := netCounters{rx: 1250, tx: 5000}
	rx, tx, err := networkRates(prev, cur, 250*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if rx != 1000 || tx != 0 {
		t.Fatalf("rates rx=%v tx=%v, want 1000 and a legitimate 0", rx, tx)
	}
}

func TestNetworkRatesRejectDecreasingCountersAndBadInterval(t *testing.T) {
	cases := map[string]struct {
		prev, cur netCounters
		elapsed   time.Duration
	}{
		"rx decreased": {netCounters{rx: 10, tx: 10}, netCounters{rx: 5, tx: 20}, time.Second},
		"tx decreased": {netCounters{rx: 10, tx: 10}, netCounters{rx: 20, tx: 5}, time.Second},
		"zero elapsed": {netCounters{rx: 10, tx: 10}, netCounters{rx: 20, tx: 20}, 0},
		"neg elapsed":  {netCounters{rx: 10, tx: 10}, netCounters{rx: 20, tx: 20}, -time.Second},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if rx, tx, err := networkRates(tc.prev, tc.cur, tc.elapsed); err == nil {
				t.Fatalf("accepted rx=%v tx=%v", rx, tx)
			}
		})
	}
}

func TestParseDefaultRouteDistinguishesNoDefaultRoute(t *testing.T) {
	for name, body := range map[string]string{
		"no default":    routeHeader + "eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
		"loopback only": routeHeader + "lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n",
		"down only":     routeHeader + "eth0\t00000000\t0100000A\t0002\t0\t0\t0\t00000000\t0\t0\t0\n",
	} {
		if _, err := parseDefaultRoute(strings.NewReader(body)); !errors.Is(err, errNoDefaultRoute) {
			t.Fatalf("%s: err = %v, want errNoDefaultRoute", name, err)
		}
	}
	if _, err := parseDefaultRoute(strings.NewReader("garbage\n")); errors.Is(err, errNoDefaultRoute) {
		t.Fatal("malformed file must not look like a missing default route")
	}
}

// metricsFixture is a deterministic collector: fixture files under a temp
// dir, a fake clock, and a fake wait that swaps in the second snapshot.
type metricsFixture struct {
	t       *testing.T
	dir     string
	clock   time.Time
	waited  []time.Duration
	second  map[string]string // file -> body written during wait
	statfs  func(string, *unix.Statfs_t) error
	paths   []string
	waitErr error
}

const (
	statSnap1 = "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0 0 0\nintr 1\n"
	statSnap2 = "cpu  150 0 150 900 0 0 0 0 0 0\ncpu0 75 0 75 450 0 0 0 0 0 0\ncpu1 75 0 75 450 0 0 0 0 0 0\nintr 2\n"
	devSnap1  = "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n" +
		"    lo: 999999 1 0 0 0 0 0 0 999999 1 0 0 0 0 0 0\n  ens3: 1000 1 0 0 0 0 0 0 4000 1 0 0 0 0 0 0\n"
	devSnap2 = "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n" +
		"    lo: 9999999 1 0 0 0 0 0 0 9999999 1 0 0 0 0 0 0\n  ens3: 1500 1 0 0 0 0 0 0 4000 1 0 0 0 0 0 0\n"
	routeOK = routeHeader + "ens3\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
)

func newMetricsFixture(t *testing.T) *metricsFixture {
	t.Helper()
	f := &metricsFixture{
		t:     t,
		dir:   t.TempDir(),
		clock: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC),
		second: map[string]string{
			"stat": statSnap2,
			"dev":  devSnap2,
		},
		statfs: func(path string, st *unix.Statfs_t) error {
			*st = unix.Statfs_t{Bsize: 4096, Frsize: 4096, Blocks: 1000, Bfree: 400, Bavail: 300}
			return nil
		},
	}
	f.write("stat", statSnap1)
	f.write("dev", devSnap1)
	f.write("route", routeOK)
	return f
}

func (f *metricsFixture) write(name, body string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *metricsFixture) collector() metricsCollector {
	return metricsCollector{
		statPath:   filepath.Join(f.dir, "stat"),
		netDevPath: filepath.Join(f.dir, "dev"),
		routePath:  filepath.Join(f.dir, "route"),
		statfs: func(path string, st *unix.Statfs_t) error {
			f.paths = append(f.paths, path)
			return f.statfs(path, st)
		},
		interval: 250 * time.Millisecond,
		now:      func() time.Time { return f.clock },
		wait: func(ctx context.Context, d time.Duration) error {
			f.waited = append(f.waited, d)
			if f.waitErr != nil {
				return f.waitErr
			}
			for name, body := range f.second {
				f.write(name, body)
			}
			f.clock = f.clock.Add(d)
			return nil
		},
	}
}

func TestCollectMetricsFromDeterministicSnapshots(t *testing.T) {
	f := newMetricsFixture(t)
	doc, err := f.collector().collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(f.waited) != 1 || f.waited[0] != 250*time.Millisecond {
		t.Fatalf("waited = %v, want one 250ms interval shared by cpu and network", f.waited)
	}
	// busy delta 100, idle delta 100 -> 50%.
	if doc.CPU == nil || doc.CPU.UsagePercent != 50 || doc.CPU.LogicalCPUs != 2 || doc.CPUReason != "" {
		t.Fatalf("cpu = %+v reason=%q", doc.CPU, doc.CPUReason)
	}
	// rx 500 bytes over 250ms -> 2000 B/s; tx unchanged -> legitimate 0.
	// The busier loopback must not be selected.
	if doc.Network == nil || doc.Network.Interface != "ens3" || doc.Network.RxBytesPerSecond != 2000 ||
		doc.Network.TxBytesPerSecond != 0 || doc.NetworkReason != "" {
		t.Fatalf("network = %+v reason=%q", doc.Network, doc.NetworkReason)
	}
	// free=400 blocks, avail=300 blocks (reserved blocks are not available).
	want := diskMetrics{Mount: "/", TotalBytes: 1000 * 4096, UsedBytes: 600 * 4096, AvailableBytes: 300 * 4096}
	if doc.Disk == nil || *doc.Disk != want || doc.DiskReason != "" {
		t.Fatalf("disk = %+v reason=%q, want %+v", doc.Disk, doc.DiskReason, want)
	}
	if len(f.paths) != 1 || f.paths[0] != "/" {
		t.Fatalf("statfs paths = %v, want only /", f.paths)
	}
	if doc.ObservedAt != "2026-11-04T12:00:00Z" {
		t.Fatalf("observed_at = %q", doc.ObservedAt)
	}
}

func TestCollectMetricsIdleCPUIsValidZero(t *testing.T) {
	f := newMetricsFixture(t)
	f.second["stat"] = "cpu  100 0 100 900 0 0 0 0 0 0\ncpu0 50 0 50 450 0 0 0 0 0 0\ncpu1 50 0 50 450 0 0 0 0 0 0\n"
	doc, err := f.collector().collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if doc.CPU == nil || doc.CPU.UsagePercent != 0 || doc.CPUReason != "" {
		t.Fatalf("cpu = %+v reason=%q, want measured 0", doc.CPU, doc.CPUReason)
	}
}

func TestCollectMetricsPartialFailuresAreNullWithReason(t *testing.T) {
	cases := map[string]struct {
		mutate     func(f *metricsFixture)
		cpu        string
		disk       string
		network    string
		cpuPresent bool
	}{
		"stat missing": {mutate: func(f *metricsFixture) {
			os.Remove(filepath.Join(f.dir, "stat"))
			delete(f.second, "stat")
		}, cpu: "read_failed"},
		"stat malformed": {mutate: func(f *metricsFixture) { f.write("stat", "cpu  x\n") }, cpu: "invalid_data"},
		"cpu counters decrease": {mutate: func(f *metricsFixture) {
			f.second["stat"] = "cpu  50 0 50 700 0 0 0 0 0 0\ncpu0 1 1 1 1\ncpu1 1 1 1 1\n"
		}, cpu: "invalid_data"},
		"cpu no elapsed ticks": {mutate: func(f *metricsFixture) { f.second["stat"] = statSnap1 }, cpu: "invalid_data"},
		"cpu count changes": {mutate: func(f *metricsFixture) {
			f.second["stat"] = "cpu  150 0 150 900 0 0 0 0 0 0\ncpu0 75 0 75 450 0 0 0 0 0 0\n"
		}, cpu: "invalid_data"},
		"route missing": {mutate: func(f *metricsFixture) { os.Remove(filepath.Join(f.dir, "route")) }, network: "read_failed"},
		"no default route": {mutate: func(f *metricsFixture) {
			f.write("route", routeHeader+"lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n")
		}, network: "no_default_route"},
		"route malformed":  {mutate: func(f *metricsFixture) { f.write("route", "junk\n") }, network: "invalid_data"},
		"net dev missing":  {mutate: func(f *metricsFixture) { os.Remove(filepath.Join(f.dir, "dev")); delete(f.second, "dev") }, network: "read_failed"},
		"iface not in dev": {mutate: func(f *metricsFixture) { f.write("route", strings.ReplaceAll(routeOK, "ens3", "eth9")) }, network: "invalid_data"},
		"net counters decrease": {mutate: func(f *metricsFixture) {
			f.second["dev"] = strings.Replace(devSnap2, "ens3: 1500", "ens3: 10", 1)
		}, network: "invalid_data"},
		"statfs fails": {mutate: func(f *metricsFixture) {
			f.statfs = func(string, *unix.Statfs_t) error { return unix.EACCES }
		}, disk: "read_failed"},
		"statfs zero blocks": {mutate: func(f *metricsFixture) {
			f.statfs = func(_ string, st *unix.Statfs_t) error { *st = unix.Statfs_t{Bsize: 4096, Frsize: 4096}; return nil }
		}, disk: "invalid_data"},
		"statfs free exceeds total": {mutate: func(f *metricsFixture) {
			f.statfs = func(_ string, st *unix.Statfs_t) error {
				*st = unix.Statfs_t{Bsize: 4096, Frsize: 4096, Blocks: 10, Bfree: 11, Bavail: 5}
				return nil
			}
		}, disk: "invalid_data"},
		"statfs avail exceeds free": {mutate: func(f *metricsFixture) {
			f.statfs = func(_ string, st *unix.Statfs_t) error {
				*st = unix.Statfs_t{Bsize: 4096, Frsize: 4096, Blocks: 10, Bfree: 4, Bavail: 5}
				return nil
			}
		}, disk: "invalid_data"},
		"statfs overflow": {mutate: func(f *metricsFixture) {
			f.statfs = func(_ string, st *unix.Statfs_t) error {
				*st = unix.Statfs_t{Bsize: 1 << 20, Frsize: 1 << 20, Blocks: 1 << 60, Bfree: 1, Bavail: 1}
				return nil
			}
		}, disk: "invalid_data"},
		"statfs zero block size": {mutate: func(f *metricsFixture) {
			f.statfs = func(_ string, st *unix.Statfs_t) error {
				*st = unix.Statfs_t{Blocks: 10, Bfree: 4, Bavail: 3}
				return nil
			}
		}, disk: "invalid_data"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newMetricsFixture(t)
			tc.mutate(f)
			doc, err := f.collector().collect(context.Background())
			if err != nil {
				t.Fatalf("partial failure must not fail the document: %v", err)
			}
			check := func(resource string, present bool, reason, want string) {
				t.Helper()
				if want == "" {
					if !present || reason != "" {
						t.Fatalf("%s: present=%v reason=%q, want healthy", resource, present, reason)
					}
					return
				}
				if present || reason != want {
					t.Fatalf("%s: present=%v reason=%q, want null with %q", resource, present, reason, want)
				}
			}
			check("cpu", doc.CPU != nil, doc.CPUReason, tc.cpu)
			check("disk", doc.Disk != nil, doc.DiskReason, tc.disk)
			check("network", doc.Network != nil, doc.NetworkReason, tc.network)
			if err := validateMetricsDocument(doc); err != nil {
				t.Fatalf("document violates contract: %v", err)
			}
		})
	}
}

func TestCollectMetricsHonorsCancellation(t *testing.T) {
	f := newMetricsFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.collector().collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled collect err = %v, want context.Canceled", err)
	}
	f.waitErr = context.DeadlineExceeded
	if _, err := f.collector().collect(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("interrupted wait err = %v, want context.DeadlineExceeded", err)
	}
}

func TestSleepContextReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	start := time.Now()
	if err := sleepContext(ctx, 10*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("sleepContext ignored cancellation")
	}
	if err := sleepContext(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("short sleep err = %v", err)
	}
}

func TestReadBoundedProcFileRejectsOversize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(p, []byte(strings.Repeat("a", maxProcFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedProcFile(p); err == nil {
		t.Fatal("oversized proc file accepted")
	}
	if err := os.WriteFile(p, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readBoundedProcFile(p); err != nil || string(b) != "ok" {
		t.Fatalf("read = %q, %v", b, err)
	}
}

func TestOpSystemMetricsRejectsParamsAndCancellation(t *testing.T) {
	var oe *OpError
	if _, err := opSystemMetrics(context.Background(), json.RawMessage(`{"path":"/etc"}`), RequestMeta{}); !errors.As(err, &oe) || oe.Code != ErrInvalidParams {
		t.Fatalf("unknown params err = %v, want invalid_params", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if res, err := opSystemMetrics(ctx, nil, RequestMeta{}); err == nil || res != nil {
		t.Fatalf("cancelled op = %v, %v; want error", res, err)
	}
}

func TestOpSystemMetricsRealHost(t *testing.T) {
	res, err := opSystemMetrics(context.Background(), nil, RequestMeta{})
	if err != nil {
		t.Fatalf("opSystemMetrics: %v", err)
	}
	doc, ok := res.(metricsDocument)
	if !ok {
		t.Fatalf("result = %T", res)
	}
	if err := validateMetricsDocument(doc); err != nil {
		t.Fatalf("real host document invalid: %v (%+v)", err, doc)
	}
	if doc.CPU == nil || doc.Disk == nil {
		t.Fatalf("this Linux host must expose cpu and disk: %+v", doc)
	}
	if doc.Network != nil && doc.Network.Interface == "lo" {
		t.Fatal("loopback selected as default-route interface")
	}
	enc, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(enc, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cpu", "cpu_reason", "disk", "disk_reason", "network", "network_reason", "observed_at"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("encoded document missing %q: %s", key, enc)
		}
	}
	if len(raw) != 7 {
		t.Fatalf("encoded document has extra keys: %s", enc)
	}
}

func TestMetricsResourceJSONShape(t *testing.T) {
	doc := metricsDocument{
		CPU:           &cpuMetrics{UsagePercent: 12.5, LogicalCPUs: 4},
		Disk:          &diskMetrics{Mount: "/", TotalBytes: 10, UsedBytes: 4, AvailableBytes: 5},
		Network:       nil,
		NetworkReason: "no_default_route",
		ObservedAt:    "2026-11-04T12:00:00Z",
	}
	enc, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"cpu":{"usage_percent":12.5,"logical_cpus":4},"cpu_reason":"","disk":{"mount":"/","total_bytes":10,"used_bytes":4,"available_bytes":5},"disk_reason":"","network":null,"network_reason":"no_default_route","observed_at":"2026-11-04T12:00:00Z"}`
	if string(enc) != want {
		t.Fatalf("json =\n%s\nwant\n%s", enc, want)
	}
}

// The production collector reads only fixed kernel sources; nothing about a
// request can redirect it.
func TestDefaultMetricsCollectorUsesFixedSources(t *testing.T) {
	c := defaultMetricsCollector()
	if c.statPath != "/proc/stat" || c.netDevPath != "/proc/net/dev" || c.routePath != "/proc/net/route" {
		t.Fatalf("collector paths = %q %q %q", c.statPath, c.netDevPath, c.routePath)
	}
	if c.interval != 250*time.Millisecond {
		t.Fatalf("interval = %v, want 250ms", c.interval)
	}
	if c.statfs == nil || c.now == nil || c.wait == nil {
		t.Fatal("collector dependencies missing")
	}
}
