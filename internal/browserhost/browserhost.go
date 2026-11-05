// Package browserhost shares numeric-host rules between certificate
// initialization and browser origin validation.
package browserhost

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// IPv4 follows WHATWG's numeric-host rules, including inet_aton
// spellings (127.1, octal, hex and integer) and an optional trailing dot.
// DNS names not ending in a number are left unchanged.
func IPv4(host string) (canonical string, numeric bool, err error) {
	// Origin validation already lowercases hosts. Do the same here so direct
	// certificate initialization classifies case-insensitive hex identically.
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(host), "."), ".")
	parseNumber := func(s string) (uint64, error) {
		base := 10
		if strings.HasPrefix(s, "0x") {
			base, s = 16, s[2:]
		} else if len(s) >= 2 && s[0] == '0' {
			base, s = 8, s[1:]
		}
		if s == "" {
			return 0, nil
		}
		return strconv.ParseUint(s, base, 32)
	}
	last := parts[len(parts)-1]
	// Classify numeric syntax independently of magnitude: even a hex literal
	// overflowing uint64 is a numeric host, never a DNS fallback.
	digits := last != "" && strings.Trim(last, "0123456789") == ""
	hex := strings.HasPrefix(last, "0x") && strings.Trim(last[2:], "0123456789abcdef") == ""
	if !digits && !hex {
		return host, false, nil
	}
	invalid := errors.New("use a four-part dotted decimal IP address")
	if len(parts) > 4 {
		return "", true, invalid
	}
	var value uint64
	for i, part := range parts {
		n, err := parseNumber(part)
		if err != nil || part == "" {
			return "", true, invalid
		}
		if i == len(parts)-1 {
			if n >= uint64(1)<<uint(8*(5-len(parts))) {
				return "", true, invalid
			}
			value += n
		} else {
			if n > 255 {
				return "", true, invalid
			}
			value += n << uint(8*(3-i))
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d", value>>24, value>>16&255, value>>8&255, value&255), true, nil
}
