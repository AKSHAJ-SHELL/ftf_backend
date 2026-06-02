package subscribers

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", false},
		{"plainstring", "", false},
		{"a@b", "", false},
		{"a@b.c", "a@b.c", true},
		{" Foo@Example.ORG ", "foo@example.org", true},
		{"too-long-" + strings.Repeat("x", 260) + "@example.org", "", false},
		{"<>@example.org", "", false},
		// IP-literal forms must be rejected (M5).
		{"user@[127.0.0.1]", "", false},
		{"user@[IPv6:::1]", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeEmail(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("normalizeEmail(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSanitizeSource(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"  homepage  ", "homepage"},
		{"hero_cta", "hero_cta"},
		{"hero-cta", "hero-cta"},
		{"<script>alert(1)</script>", "scriptalert1script"},
		{strings.Repeat("a", 100), strings.Repeat("a", 32)},
		{"campaign/launch+v2", "campaignlaunchv2"},
	}
	for _, c := range cases {
		if got := sanitizeSource(c.in); got != c.want {
			t.Errorf("sanitizeSource(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNewConfirmTokenSeparatesRawAndHash(t *testing.T) {
	raw, hash := newConfirmToken()
	if bytes.Equal(raw[:], hash) {
		t.Fatal("raw and hash must not be equal — that defeats the purpose")
	}
	expected := sha256.Sum256(raw[:])
	if !bytes.Equal(hash, expected[:]) {
		t.Fatal("hash is not sha256(raw)")
	}
	if !bytes.Equal(hashRawToken(raw[:]), hash) {
		t.Fatal("hashRawToken round-trips")
	}
}
