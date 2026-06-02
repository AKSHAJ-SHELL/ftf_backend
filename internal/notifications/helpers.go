package notifications

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/fundthefuture/ftf-backend/internal/httpx"
)

func ptr[T any](v T) *T { return &v }

// emailHashBytes returns the keyed HMAC hash bytes for an email. The key is
// configured at startup via httpx.InitEmailHash. Using HMAC instead of a bare
// SHA-256 makes the email_log meaningfully un-rainbow-tableable.
func emailHashBytes(email string) []byte {
	return httpx.HashEmailBytes(email)
}

func pgxTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}
