package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// rfcSecret is the ASCII secret "12345678901234567890" from RFC 6238 Appendix B.
var rfcSecret = base32.StdEncoding.WithPadding(base32.NoPadding).
	EncodeToString([]byte("12345678901234567890"))

var rfc8Digits = Params{Period: 30, Digits: 8}

// TestRFC6238Vectors checks the published SHA-1 test vectors from RFC 6238
// Appendix B, so the implementation is standard TOTP, not a lookalike.
func TestRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		got, err := Code(rfcSecret, time.Unix(c.unix, 0).UTC(), rfc8Digits)
		if err != nil {
			t.Fatalf("code at %d: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("code at %d = %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestVerifyWindow(t *testing.T) {
	now := time.Unix(1234567890, 0).UTC() // matches an RFC vector time
	prev, _ := Code(rfcSecret, now.Add(-30*time.Second), rfc8Digits)
	cur, _ := Code(rfcSecret, now, rfc8Digits)

	if !Verify(rfcSecret, cur, now, rfc8Digits, 1) {
		t.Error("current code must verify")
	}
	if !Verify(rfcSecret, prev, now, rfc8Digits, 1) {
		t.Error("previous step's code must verify within window 1")
	}
	if Verify(rfcSecret, cur, now.Add(-60*time.Second), rfc8Digits, 1) {
		t.Error("code from two steps back must not verify with window 1")
	}
	if Verify(rfcSecret, "00000000", now, rfc8Digits, 1) {
		t.Error("wrong code must not verify")
	}
	if Verify(rfcSecret, "", now, rfc8Digits, 1) {
		t.Error("empty code must not verify")
	}
	if Verify("not-base32!!", cur, now, rfc8Digits, 1) {
		t.Error("invalid secret must not verify")
	}
}

func TestMatchReturnsStep(t *testing.T) {
	now := time.Unix(1234567890, 0).UTC()
	step := now.Unix() / 30
	prev, _ := Code(rfcSecret, now.Add(-30*time.Second), rfc8Digits)

	got, ok := Match(rfcSecret, prev, now, rfc8Digits, 1)
	if !ok || got != step-1 {
		t.Errorf("Match(prev) = %d,%v want %d,true", got, ok, step-1)
	}
	if _, ok := Match(rfcSecret, "00000000", now, rfc8Digits, 1); ok {
		t.Error("wrong code must not match")
	}
}

func TestGenerateSecret(t *testing.T) {
	s1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	s2, _ := GenerateSecret()
	if s1 == s2 {
		t.Error("two generated secrets must differ")
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s1)
	if err != nil {
		t.Fatalf("secret must be valid base32: %v", err)
	}
	if len(raw) < 16 {
		t.Errorf("secret decoded to %d bytes, want >= 16", len(raw))
	}
}

func TestOTPAuthURL(t *testing.T) {
	u := OTPAuthURL("AxionPanel", "akbar", "MFRGGZDF", Default)
	for _, want := range []string{
		"otpauth://totp/AxionPanel:akbar?",
		"secret=MFRGGZDF",
		"issuer=AxionPanel",
	} {
		if !contains(u, want) {
			t.Errorf("otpauth url %q missing %q", u, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
