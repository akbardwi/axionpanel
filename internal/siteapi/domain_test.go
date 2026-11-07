package siteapi

import "testing"

func TestDomainRejectsNonASCIIInputBeforeLowercase(t *testing.T) {
	for _, domain := range []string{"K.example", "İ.example", "münich.example"} {
		if got, err := NormalizeDomain(domain); err == nil {
			t.Fatalf("non-ASCII %q normalized to %q", domain, got)
		}
	}
}
