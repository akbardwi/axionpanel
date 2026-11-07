package siteapi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"regexp"
	"strings"
)

// domainPattern is the panel-side static domain validator: ASCII, lowercase,
// at least two DNS labels. Wildcards and IP literals are rejected; the agent
// validates independently again.
var domainPattern = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain returns the validated lowercase domain.
func NormalizeDomain(in string) (string, error) {
	for _, c := range []byte(in) {
		if c > 127 {
			return "", errors.New("siteapi: domain must be ASCII")
		}
	}
	d := strings.ToLower(in)
	if d == "" {
		return "", errors.New("siteapi: domain is required")
	}
	if strings.ContainsAny(d, "* \t\r\n") {
		return "", errors.New("siteapi: wildcard or control-character domains are not supported")
	}
	if d == "localhost" || d == "localhost.localdomain" {
		return "", errors.New("siteapi: the panel hostname is not a static domain")
	}
	if ip := net.ParseIP(strings.TrimSuffix(d, ".")); ip != nil {
		return "", errors.New("siteapi: IP addresses are not supported")
	}
	if len(d) > 253 {
		return "", errors.New("siteapi: domain is too long")
	}
	if !domainPattern.MatchString(d) {
		return "", errors.New("siteapi: invalid domain format")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", errors.New("siteapi: domain needs at least two labels")
	}
	if isNumericLabels(d) {
		return "", errors.New("siteapi: IP addresses are not supported")
	}
	for _, l := range labels {
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", errors.New("siteapi: invalid domain label")
		}
	}
	return d, nil
}

func isNumericLabels(d string) bool {
	for _, l := range strings.Split(d, ".") {
		if l == "" {
			return true
		}
		for _, c := range l {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// NewOperationID is the durable 32-hex random agent operation identity. The
// job row stores the same value so an interrupted request reconciles by ID.
func NewOperationID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

var opIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidOperationID enforces the exact 32-hex shape.
func ValidOperationID(id string) bool { return opIDPattern.MatchString(id) }
