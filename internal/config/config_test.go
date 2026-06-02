package config

import (
	"strings"
	"testing"
)

func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func validBase() map[string]string {
	return map[string]string{
		"DATABASE_URL":              "postgres://user:pass@localhost:5432/db",
		"DATABASE_URL_SERVICE_ROLE": "postgres://service:pass@localhost:5432/db",
		"SUPABASE_PROJECT_REF":      "abcdef",
		"SUPABASE_JWT_SECRET":       "super-secret-jwt-key-which-is-long-enough-12345",
		"RESEND_API_KEY":            "re_test",
		"RESEND_FROM_ADDRESS":       "hello@fundthefuture.org",
		"APP_BASE_URL":              "https://example.org",
		"TOKEN_SIGNING_KEY":         "0123456789abcdef0123456789abcdef",
		"EMAIL_HASH_KEY":            "fedcba9876543210fedcba9876543210",
		"ALLOWED_ORIGINS":           "https://example.org,https://www.example.org",
	}
}

func TestLoadOK(t *testing.T) {
	setEnv(t, validBase())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if cfg.Port != "8080" {
		t.Errorf("default port wrong: %s", cfg.Port)
	}
	if len(cfg.AllowedOrigins) != 2 {
		t.Errorf("expected 2 origins, got %d", len(cfg.AllowedOrigins))
	}
}

func TestLoadMissingRequired(t *testing.T) {
	env := validBase()
	delete(env, "DATABASE_URL")
	delete(env, "APP_BASE_URL")
	setEnv(t, env)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error")
	}
	keys, ok := IsMissing(err)
	if !ok {
		t.Fatalf("expected missing error, got %v", err)
	}
	if !contains(keys, "DATABASE_URL") || !contains(keys, "APP_BASE_URL") {
		t.Errorf("missing keys: %v", keys)
	}
}

func TestLoadMissingJWTAndJWKS(t *testing.T) {
	env := validBase()
	delete(env, "SUPABASE_JWT_SECRET")
	setEnv(t, env)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when both JWT_SECRET and JWKS_URL missing")
	}
	if !strings.Contains(err.Error(), "SUPABASE_JWT_SECRET or SUPABASE_JWKS_URL") {
		t.Errorf("unexpected message: %v", err)
	}
}

func TestLoadJWKSAccepted(t *testing.T) {
	env := validBase()
	delete(env, "SUPABASE_JWT_SECRET")
	env["SUPABASE_JWKS_URL"] = "https://example.com/.well-known/jwks.json"
	setEnv(t, env)
	if _, err := Load(); err != nil {
		t.Fatalf("expected ok with JWKS only, got %v", err)
	}
}

func TestRejectsBothJWTAndJWKS(t *testing.T) {
	env := validBase()
	env["SUPABASE_JWKS_URL"] = "https://example.com/.well-known/jwks.json"
	setEnv(t, env)
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "only one of") {
		t.Fatalf("expected both-set rejection, got %v", err)
	}
}

func TestEmailHashKeyTooShort(t *testing.T) {
	env := validBase()
	env["EMAIL_HASH_KEY"] = "tooshort"
	setEnv(t, env)
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "EMAIL_HASH_KEY") {
		t.Fatalf("expected email hash key error, got %v", err)
	}
}

func TestEmailHashKeyMissing(t *testing.T) {
	env := validBase()
	delete(env, "EMAIL_HASH_KEY")
	setEnv(t, env)
	_, err := Load()
	if err == nil {
		t.Fatal("expected missing-env error")
	}
	keys, ok := IsMissing(err)
	if !ok || !contains(keys, "EMAIL_HASH_KEY") {
		t.Fatalf("expected missing EMAIL_HASH_KEY, got %v", err)
	}
}

func TestTrustedProxyCIDRs(t *testing.T) {
	env := validBase()
	env["TRUSTED_PROXY_CIDRS"] = "10.0.0.0/8, 192.168.1.1"
	setEnv(t, env)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("expected 2 CIDRs, got %d", len(cfg.TrustedProxyCIDRs))
	}
}

func TestTrustedProxyCIDRsInvalid(t *testing.T) {
	env := validBase()
	env["TRUSTED_PROXY_CIDRS"] = "not-an-ip"
	setEnv(t, env)
	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid CIDR rejection")
	}
}

func TestTokenSigningKeyTooShort(t *testing.T) {
	env := validBase()
	env["TOKEN_SIGNING_KEY"] = "short"
	setEnv(t, env)
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "TOKEN_SIGNING_KEY") {
		t.Fatalf("expected token signing key error, got %v", err)
	}
}

func TestWildcardOriginRejected(t *testing.T) {
	env := validBase()
	env["ALLOWED_ORIGINS"] = "*"
	setEnv(t, env)
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "*") {
		t.Fatalf("expected wildcard rejection, got %v", err)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
