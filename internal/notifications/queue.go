// Package notifications owns the durable outbound mail queue. Enqueue is the
// only surface other packages talk to. The worker (run from cmd/server) drains
// the queue with retry/backoff and outbound rate limiting.
package notifications

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/fundthefuture/ftf-backend/internal/db"
	"github.com/fundthefuture/ftf-backend/internal/db/dbq"
)

// Kind identifies the template/template-renderer to use at send time.
type Kind string

const (
	KindConfirmEmail Kind = "confirm_email"
	KindBroadcast    Kind = "broadcast"
)

// ConfirmEmailPayload is the shape stored on `payload` for confirm emails.
type ConfirmEmailPayload struct {
	ConfirmURL     string `json:"confirm_url"`
	UnsubscribeURL string `json:"unsubscribe_url"`
}

// Queue wraps the service pool and exposes type-safe enqueue helpers.
// It deliberately takes a *db.ServicePool, not a generic interface, so the
// compiler enforces that only privileged code paths can enqueue.
type Queue struct {
	pool *db.ServicePool
}

func NewQueue(pool *db.ServicePool) *Queue { return &Queue{pool: pool} }

// Enqueue persists a pending notification. The worker picks it up on its next tick.
func (q *Queue) Enqueue(ctx context.Context, kind Kind, toEmail string, payload any) (pgtype.UUID, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("marshal payload: %w", err)
	}
	var id pgtype.UUID
	err = q.pool.WithTx(ctx, func(s *dbq.Queries) error {
		var qerr error
		id, qerr = s.EnqueueNotification(ctx, dbq.EnqueueNotificationParams{
			Kind:    string(kind),
			ToEmail: toEmail,
			Payload: body,
		})
		return qerr
	})
	return id, err
}
