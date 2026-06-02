// Package auth verifies Supabase-issued JWTs and exposes middleware for chi.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// Claims is the minimum we trust from a Supabase JWT.
type Claims struct {
	Sub   string
	Email string
	Role  string
}

// Config controls which verification mode is active.
//   - When JWKSURL is set we run asymmetric verification (RS/EC keys, JWKS cached + rotated).
//   - Otherwise we use HS256 with Secret.
//
// Exactly one of Secret or JWKSURL must be set; config-level validation
// rejects both-set so we cannot fall into algorithm-confusion territory.
type Config struct {
	Secret     string
	JWKSURL    string
	ProjectRef string
}

// Verifier is goroutine-safe.
type Verifier struct {
	cfg         Config
	expectedIss string
	jwks        keyfunc.Keyfunc
}

// NewVerifier constructs a Verifier and validates the config.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.ProjectRef == "" {
		return nil, errors.New("supabase project ref is required")
	}
	if cfg.Secret == "" && cfg.JWKSURL == "" {
		return nil, errors.New("either SUPABASE_JWT_SECRET or SUPABASE_JWKS_URL is required")
	}
	if cfg.Secret != "" && cfg.JWKSURL != "" {
		return nil, errors.New("set only one of SUPABASE_JWT_SECRET or SUPABASE_JWKS_URL")
	}
	v := &Verifier{
		cfg:         cfg,
		expectedIss: fmt.Sprintf("https://%s.supabase.co/auth/v1", cfg.ProjectRef),
	}
	if cfg.JWKSURL != "" {
		jwks, err := keyfunc.NewDefault([]string{cfg.JWKSURL})
		if err != nil {
			return nil, fmt.Errorf("jwks fetch: %w", err)
		}
		v.jwks = jwks
	}
	return v, nil
}

// Verify parses + validates the bearer token and returns claims.
func (v *Verifier) Verify(_ context.Context, raw string) (*Claims, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty token")
	}

	keyFn := v.keyFunc()

	parser := jwt.NewParser(
		jwt.WithIssuer(v.expectedIss),
		jwt.WithAudience("authenticated"),
		jwt.WithValidMethods(v.validMethods()),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithIssuedAt(),
	)

	tok, err := parser.Parse(raw, keyFn)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("token invalid")
	}
	mc, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unexpected claims shape")
	}

	sub, _ := mc["sub"].(string)
	if sub == "" {
		return nil, errors.New("missing sub")
	}
	email, _ := mc["email"].(string)
	role, _ := mc["role"].(string)
	if role == "" {
		role = "authenticated"
	}
	return &Claims{Sub: sub, Email: strings.ToLower(email), Role: role}, nil
}

func (v *Verifier) keyFunc() jwt.Keyfunc {
	if v.jwks != nil {
		return v.jwks.Keyfunc
	}
	secret := []byte(v.cfg.Secret)
	return func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return secret, nil
	}
}

func (v *Verifier) validMethods() []string {
	if v.jwks != nil {
		return []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
	}
	return []string{"HS256"}
}

// BearerFromHeader extracts the token from an `Authorization: Bearer …` header.
func BearerFromHeader(h string) string {
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
