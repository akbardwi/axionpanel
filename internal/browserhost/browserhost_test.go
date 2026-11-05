package browserhost

import "testing"

func TestIPv4ClassifiesBrowserNumericHosts(t *testing.T) {
	for _, tc := range []struct{ host, canonical string }{
		{"127.0.0.1", "127.0.0.1"},
		{"127.1", "127.0.0.1"},
		{"127.0.1", "127.0.0.1"},
		{"0177.0.0.1", "127.0.0.1"},
		{"0x7f.1", "127.0.0.1"},
		{"0x7f000001", "127.0.0.1"},
		{"0X7F000001", "127.0.0.1"},
		{"0X7f.1", "127.0.0.1"},
		{"2130706433", "127.0.0.1"},
		{"127.0.0.1.", "127.0.0.1"},
		{"0", "0.0.0.0"},
		{"0.0", "0.0.0.0"},
		{"0x", "0.0.0.0"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			canonical, numeric, err := IPv4(tc.host)
			if !numeric || err != nil {
				t.Fatalf("numeric=%v err=%v, want numeric canonical", numeric, err)
			}
			if canonical != tc.canonical {
				t.Fatalf("canonical = %q, want %q", canonical, tc.canonical)
			}
		})
	}
}

func TestIPv4RejectsNumericHostsWithoutCanonicalForm(t *testing.T) {
	// Numeric syntax stays numeric for every magnitude: browsers never fall
	// back to DNS for these, so a caller must not accept them as DNS names.
	for _, host := range []string{
		"1.2.3.4.5", "0x100000000", "0X100000000", "0x10000000000000000",
		"0XFFFFFFFFFFFFFFFFF", "4294967296", "09", "example.123", "example.0XFF",
		"1.2.3.256", "08.0.0.1",
	} {
		t.Run(host, func(t *testing.T) {
			if canonical, numeric, err := IPv4(host); !numeric || err == nil || canonical != "" {
				t.Fatalf("canonical=%q numeric=%v err=%v, want numeric failure", canonical, numeric, err)
			}
		})
	}
}

func TestIPv4LeavesDNSNamesUnchanged(t *testing.T) {
	for _, host := range []string{"panel.example.com", "localhost", "123.example", "example.0xgg", "1.2.3.example", "xn--bcher-kva.example"} {
		t.Run(host, func(t *testing.T) {
			canonical, numeric, err := IPv4(host)
			if numeric || err != nil {
				t.Fatalf("numeric=%v err=%v, want DNS passthrough", numeric, err)
			}
			if canonical != host {
				t.Fatalf("canonical = %q, want unchanged DNS name %q", canonical, host)
			}
		})
	}
}
