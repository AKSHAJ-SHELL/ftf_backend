package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port                       string
	LogLevel                   slog.Level
	DatabaseURL                string
	DatabaseURLServiceRole     string
	SupabaseProjectRef         string
	SupabaseJWTSecret          string
	SupabaseJWKSURL            string
	ResendAPIKey               string
	ResendFromAddress          string
	AppBaseURL                 string
	TokenSigningKey            string
	EmailHashKey               string
	AllowedOrigins             []string
	TrustedProxyCIDRs          []*net.IPNet
	RateLimitSubscribersPerMin int
	RateLimitConfirmPerMin     int
	RateLimitDefaultPerMin     int
	WorkerConcurrency          int
	OutboundEmailRPS           int
	MaxDailyEmails             int
	PoolMaxConns               int32
	SubscribeEmailThrottleSec  int
	UnsubscribeTokenTTLDays    int
}

type missingErr struct{ keys []string }

func (m *missingErr) Error() string {
	return "missing required environment variables: " + strings.Join(m.keys, ", ")
}

// Load reads and validates configuration from environment variables.
// It fails fast on missing required values or bad shapes.
func Load() (*Config, error) {
	c := &Config{
		Port:                       getOr("PORT", "8080"),
		LogLevel:                   parseLevel(getOr("LOG_LEVEL", "info")),
		DatabaseURL:                os.Getenv("DATABASE_URL"),
		DatabaseURLServiceRole:     os.Getenv("DATABASE_URL_SERVICE_ROLE"),
		SupabaseProjectRef:         os.Getenv("SUPABASE_PROJECT_REF"),
		SupabaseJWTSecret:          os.Getenv("SUPABASE_JWT_SECRET"),
		SupabaseJWKSURL:            os.Getenv("SUPABASE_JWKS_URL"),
		ResendAPIKey:               os.Getenv("RESEND_API_KEY"),
		ResendFromAddress:          os.Getenv("RESEND_FROM_ADDRESS"),
		AppBaseURL:                 os.Getenv("APP_BASE_URL"),
		TokenSigningKey:            os.Getenv("TOKEN_SIGNING_KEY"),
		EmailHashKey:               os.Getenv("EMAIL_HASH_KEY"),
		AllowedOrigins:             splitCSV(os.Getenv("ALLOWED_ORIGINS")),
		RateLimitSubscribersPerMin: getInt("RATE_LIMIT_SUBSCRIBERS_PER_MIN", 10),
		RateLimitConfirmPerMin:     getInt("RATE_LIMIT_CONFIRM_PER_MIN", 30),
		RateLimitDefaultPerMin:     getInt("RATE_LIMIT_DEFAULT_PER_MIN", 60),
		WorkerConcurrency:          getInt("WORKER_CONCURRENCY", 2),
		OutboundEmailRPS:           getInt("OUTBOUND_EMAIL_RPS", 5),
		MaxDailyEmails:             getInt("MAX_DAILY_EMAILS", 5000),
		PoolMaxConns:               int32(getInt("POOL_MAX_CONNS", 10)),
		SubscribeEmailThrottleSec:  getInt("SUBSCRIBE_EMAIL_THROTTLE_SEC", 600),
		UnsubscribeTokenTTLDays:    getInt("UNSUBSCRIBE_TOKEN_TTL_DAYS", 365),
	}

	required := map[string]string{
		"DATABASE_URL":              c.DatabaseURL,
		"DATABASE_URL_SERVICE_ROLE": c.DatabaseURLServiceRole,
		"SUPABASE_PROJECT_REF":      c.SupabaseProjectRef,
		"RESEND_FROM_ADDRESS":       c.ResendFromAddress,
		"APP_BASE_URL":              c.AppBaseURL,
		"TOKEN_SIGNING_KEY":         c.TokenSigningKey,
		"EMAIL_HASH_KEY":            c.EmailHashKey,
	}
	var missing []string
	for k, v := range required {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if c.SupabaseJWTSecret == "" && c.SupabaseJWKSURL == "" {
		missing = append(missing, "SUPABASE_JWT_SECRET or SUPABASE_JWKS_URL")
	}
	if len(missing) > 0 {
		return nil, &missingErr{keys: missing}
	}

	if c.SupabaseJWTSecret != "" && c.SupabaseJWKSURL != "" {
		return nil, errors.New("set only one of SUPABASE_JWT_SECRET or SUPABASE_JWKS_URL, not both")
	}
	if len(c.TokenSigningKey) < 32 {
		return nil, errors.New("TOKEN_SIGNING_KEY must be at least 32 bytes")
	}
	if len(c.EmailHashKey) < 32 {
		return nil, errors.New("EMAIL_HASH_KEY must be at least 32 bytes")
	}
	if len(c.AllowedOrigins) == 0 {
		return nil, errors.New("ALLOWED_ORIGINS must contain at least one origin")
	}
	for _, o := range c.AllowedOrigins {
		if o == "*" {
			return nil, errors.New("ALLOWED_ORIGINS must not include '*'")
		}
	}
	if c.WorkerConcurrency < 1 {
		return nil, errors.New("WORKER_CONCURRENCY must be >= 1")
	}
	if c.OutboundEmailRPS < 1 {
		return nil, errors.New("OUTBOUND_EMAIL_RPS must be >= 1")
	}
	if c.MaxDailyEmails < 1 {
		return nil, errors.New("MAX_DAILY_EMAILS must be >= 1")
	}
	if c.PoolMaxConns < 1 {
		return nil, errors.New("POOL_MAX_CONNS must be >= 1")
	}

	cidrs, err := parseCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS: %w", err)
	}
	c.TrustedProxyCIDRs = cidrs

	return c, nil
}

func getOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// parseCIDRs accepts a comma-separated list of CIDRs or bare IPs. Bare IPs are
// promoted to /32 (IPv4) or /128 (IPv6). Empty input yields an empty slice.
func parseCIDRs(s string) ([]*net.IPNet, error) {
	parts := splitCSV(s)
	out := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		if !strings.Contains(p, "/") {
			if ip := net.ParseIP(p); ip != nil {
				if ip.To4() != nil {
					p += "/32"
				} else {
					p += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", p, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// IsMissing reports whether err is a missing-vars error and returns the names.
func IsMissing(err error) ([]string, bool) {
	var m *missingErr
	if errors.As(err, &m) {
		return m.keys, true
	}
	return nil, false
}

// Describe returns a human description for logs/UX.
func Describe(c *Config) string {
	return fmt.Sprintf("port=%s origins=%d worker=%d", c.Port, len(c.AllowedOrigins), c.WorkerConcurrency)
}
