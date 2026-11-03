package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"
)

const maxPolicyBytes = 64 << 10

// policyOwnerOK reports whether a policy file may be trusted given the agent's
// euid. A root agent accepts only root-owned files; a non-root agent accepts
// files it owns. An unrelated uid is never accepted.
func policyOwnerOK(owner, euid uint32) bool { return owner == euid }

// Policy is host-local policy the panel cannot change (spec §5.3). It lives in
// a root-owned file; requests cannot relax it.
type Policy struct {
	AllowRootTerminal bool
	AllowRootFiles    bool
	AllowedServices   []string
}

var policyAllowedKeys = map[string]bool{
	"allow_root_terminal": true,
	"allow_root_files":    true,
	"allowed_services":    true,
}

// LoadPolicy reads the flat TOML subset agent.toml uses. An empty path means
// "no file configured", which yields deny-by-default settings. Any other path
// is opened with O_NOFOLLOW (symlinks rejected) and validated on the open
// descriptor before reading a bounded amount of data.
func LoadPolicy(path string) (Policy, error) {
	p := Policy{}
	if path == "" {
		return p, nil
	}

	fd, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return p, fmt.Errorf("agent policy: %s must not be a symlink", path)
		}
		return p, fmt.Errorf("agent policy: %w", err)
	}
	defer fd.Close()

	// fstat the descriptor we already hold, so no stat/read swap can redirect
	// us to a different file after validation.
	info, err := fd.Stat()
	if err != nil {
		return p, fmt.Errorf("agent policy: %w", err)
	}
	if !info.Mode().IsRegular() {
		return p, fmt.Errorf("agent policy: %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return p, fmt.Errorf("agent policy: %s must not be group/world accessible (chmod 600)", path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if !policyOwnerOK(st.Uid, uint32(os.Geteuid())) {
			return p, fmt.Errorf("agent policy: %s must be owned by uid %d", path, os.Geteuid())
		}
	}

	data, err := readBoundedPolicy(fd)
	if err != nil {
		return p, err
	}
	values, err := parsePolicyFile(string(data))
	if err != nil {
		return p, err
	}
	for key, val := range values {
		switch key {
		case "allow_root_terminal":
			v, ok := val.(bool)
			if !ok {
				return p, fmt.Errorf("agent policy: allow_root_terminal must be a boolean")
			}
			p.AllowRootTerminal = v
		case "allow_root_files":
			v, ok := val.(bool)
			if !ok {
				return p, fmt.Errorf("agent policy: allow_root_files must be a boolean")
			}
			p.AllowRootFiles = v
		case "allowed_services":
			v, ok := val.([]string)
			if !ok {
				return p, fmt.Errorf("agent policy: allowed_services must be a string array")
			}
			for _, name := range v {
				if !validServiceName(name) {
					return p, fmt.Errorf("agent policy: invalid service name %q", name)
				}
			}
			p.AllowedServices = v
		}
	}
	return p, nil
}

// readBoundedPolicy reads at most maxPolicyBytes+1 bytes so an oversized file
// is rejected without ever allocating more than the bound.
func readBoundedPolicy(f *os.File) ([]byte, error) {
	lr := io.LimitReader(f, maxPolicyBytes+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("agent policy: %w", err)
	}
	if len(data) > maxPolicyBytes {
		return nil, fmt.Errorf("agent policy: file exceeds %d bytes", maxPolicyBytes)
	}
	return data, nil
}

func validServiceName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == '@' || r == ':' || r == '#':
		default:
			return false
		}
	}
	return true
}

// parsePolicyFile parses the restricted flat subset: one `key = value` per
// line, bare snake_case keys, boolean or single-line string values, and string
// arrays. Escapes, tables, dotted keys, and any non-ASCII key are rejected.
func parsePolicyFile(text string) (map[string]any, error) {
	if !utf8.ValidString(text) {
		return nil, fmt.Errorf("agent policy: file is not valid UTF-8")
	}
	out := make(map[string]any)
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		line = stripComment(line)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("agent policy: line %d: expected key = value", i+1)
		}
		key = strings.TrimSpace(key)
		if !validKeyName(key) {
			return nil, fmt.Errorf("agent policy: line %d: invalid key %q", i+1, key)
		}
		val, err := parsePolicyValue(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("agent policy: line %d: %w", i+1, err)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("agent policy: line %d: duplicate key %q", i+1, key)
		}
		out[key] = val
	}
	for key := range out {
		if !policyAllowedKeys[key] {
			return nil, fmt.Errorf("agent policy: unknown key %q", key)
		}
	}
	return out, nil
}

func validKeyName(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		case r == '_':
		default:
			return false
		}
	}
	return true
}

func stripComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}

func parsePolicyValue(raw string) (any, error) {
	switch {
	case raw == "true":
		return true, nil
	case raw == "false":
		return false, nil
	case strings.HasPrefix(raw, "["):
		return parsePolicyArray(raw)
	case strings.HasPrefix(raw, `"`):
		return parsePolicyString(raw)
	}
	return nil, fmt.Errorf("invalid value %q", raw)
}

// parsePolicyString accepts only a single-line double-quoted string with no
// escapes. Backslashes are rejected outright so escaped quotes cannot smuggle
// control characters or unbalanced delimiters.
func parsePolicyString(raw string) (string, error) {
	if len(raw) < 2 || raw[len(raw)-1] != '"' {
		return "", fmt.Errorf("unterminated string %q", raw)
	}
	inner := raw[1 : len(raw)-1]
	for _, r := range inner {
		if r == '\\' {
			return "", fmt.Errorf("escapes are not allowed in policy strings")
		}
		if r == '"' {
			return "", fmt.Errorf("unescaped quote in string")
		}
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("control character in string")
		}
	}
	// Reject surrogate escapes that unquote would silently materialize.
	if strings.ContainsRune(inner, utf8.RuneError) && !utf8.ValidString(inner) {
		return "", fmt.Errorf("invalid UTF-8 in string")
	}
	return inner, nil
}

func parsePolicyArray(raw string) ([]string, error) {
	if !strings.HasSuffix(raw, "]") {
		return nil, fmt.Errorf("unterminated array")
	}
	inner := strings.TrimSpace(raw[1 : len(raw)-1])
	if inner == "" {
		return []string{}, nil
	}
	parts := strings.Split(inner, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty array element")
		}
		if !strings.HasPrefix(part, `"`) {
			return nil, fmt.Errorf("array values must be strings")
		}
		s, err := parsePolicyString(part)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
