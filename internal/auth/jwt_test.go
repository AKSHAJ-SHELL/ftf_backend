package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testProjectRef = "abcdef"
const testSecret = "test-secret-long-enough-for-hs256-12345"

func newTestVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{Secret: testSecret, ProjectRef: testProjectRef})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func issue(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = "https://" + testProjectRef + ".supabase.co/auth/v1"
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = "authenticated"
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(5 * time.Minute).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestVerifyValid(t *testing.T) {
	v := newTestVerifier(t)
	tok := issue(t, jwt.MapClaims{
		"sub":   "11111111-1111-4111-8111-111111111111",
		"email": "User@Example.org",
		"role":  "authenticated",
	})
	c, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Email != "user@example.org" {
		t.Errorf("email not lowercased: %q", c.Email)
	}
	if c.Role != "authenticated" {
		t.Errorf("role: %q", c.Role)
	}
}

func TestVerifyExpired(t *testing.T) {
	v := newTestVerifier(t)
	tok := issue(t, jwt.MapClaims{
		"sub": "11111111-1111-4111-8111-111111111111",
		"exp": time.Now().Add(-time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestVerifyWrongIssuer(t *testing.T) {
	v := newTestVerifier(t)
	tok := issue(t, jwt.MapClaims{
		"sub": "11111111-1111-4111-8111-111111111111",
		"iss": "https://evil.example.com/auth/v1",
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected issuer mismatch")
	}
}

func TestVerifyWrongAudience(t *testing.T) {
	v := newTestVerifier(t)
	tok := issue(t, jwt.MapClaims{
		"sub": "11111111-1111-4111-8111-111111111111",
		"aud": "anon",
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected aud mismatch")
	}
}

func TestVerifyMissingSub(t *testing.T) {
	v := newTestVerifier(t)
	tok := issue(t, jwt.MapClaims{
		"email": "x@example.org",
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected missing sub")
	}
}

func TestVerifyMissingExp(t *testing.T) {
	v := newTestVerifier(t)
	// Build a token without exp by signing directly (bypass issue() which sets exp).
	mc := jwt.MapClaims{
		"sub": "11111111-1111-4111-8111-111111111111",
		"iss": "https://" + testProjectRef + ".supabase.co/auth/v1",
		"aud": "authenticated",
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, mc).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected exp-required rejection")
	}
}

func TestVerifierRejectsBothSecretAndJWKS(t *testing.T) {
	_, err := NewVerifier(Config{
		Secret:     testSecret,
		JWKSURL:    "https://example.com/.well-known/jwks.json",
		ProjectRef: testProjectRef,
	})
	if err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("expected both-set rejection, got %v", err)
	}
}

func TestVerifyWrongAlg(t *testing.T) {
	v := newTestVerifier(t)
	mc := jwt.MapClaims{
		"sub": "11111111-1111-4111-8111-111111111111",
		"iss": "https://" + testProjectRef + ".supabase.co/auth/v1",
		"aud": "authenticated",
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, mc)
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), signed); err == nil {
		t.Fatal("expected alg rejection")
	}
}

func TestBearerFromHeader(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"Bearer ":              "",
		"bearer abc":           "abc",
		"Bearer   token-123  ": "token-123",
		"Basic dXNlcjpwYXNz":   "",
	}
	for h, want := range cases {
		got := BearerFromHeader(h)
		if got != want {
			t.Errorf("BearerFromHeader(%q) = %q want %q", h, got, want)
		}
	}
	// sanity
	if !strings.EqualFold("Bearer", "BEARER") {
		t.Fatal("string assumption broken")
	}
}
