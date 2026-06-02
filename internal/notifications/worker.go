package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/fundthefuture/ftf-backend/internal/db"
	"github.com/fundthefuture/ftf-backend/internal/db/dbq"
	"github.com/fundthefuture/ftf-backend/internal/email"
	"github.com/fundthefuture/ftf-backend/internal/httpx"
)

// WorkerConfig is required to construct a Worker.
type WorkerConfig struct {
	Pool           *db.ServicePool
	Sender         email.Sender
	Concurrency    int
	OutboundRPS    int
	MaxAttempts    int
	LeaseDuration  time.Duration
	Logger         *slog.Logger
	BaseSleep      time.Duration // poll interval when idle
	MaxDailyEmails int           // global cap; 0 disables the cap
}

// Worker drains the notifications table and dispatches via email.Sender.
type Worker struct {
	cfg     WorkerConfig
	limiter *rate.Limiter
}

func NewWorker(cfg WorkerConfig) *Worker {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.OutboundRPS < 1 {
		cfg.OutboundRPS = 1
	}
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 6
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = 60 * time.Second
	}
	if cfg.BaseSleep <= 0 {
		cfg.BaseSleep = 1 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Worker{
		cfg:     cfg,
		limiter: rate.NewLimiter(rate.Limit(cfg.OutboundRPS), cfg.OutboundRPS),
	}
}

// Run blocks until ctx is cancelled. Spawns Concurrency goroutines.
func (w *Worker) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < w.cfg.Concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			w.loop(ctx, id)
		}(i)
	}
	wg.Wait()
}

func (w *Worker) loop(ctx context.Context, id int) {
	logger := w.cfg.Logger.With("worker", id)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		processed, err := w.tick(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("worker tick error", "err", err)
		}
		if processed == 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(w.cfg.BaseSleep):
			}
		}
	}
}

func (w *Worker) tick(ctx context.Context) (int, error) {
	// Check the daily cap before claiming. If we are over, drop the tick;
	// claimed rows stay pending and will be picked up after the cap rolls.
	if w.cfg.MaxDailyEmails > 0 {
		var total int64
		err := w.cfg.Pool.WithTx(ctx, func(q *dbq.Queries) error {
			n, qerr := q.CountSendsLastDay(ctx)
			if qerr != nil {
				return qerr
			}
			total = n
			return nil
		})
		if err != nil {
			return 0, err
		}
		if total >= int64(w.cfg.MaxDailyEmails) {
			w.cfg.Logger.Warn("daily send cap reached; skipping tick", "sent_last_day", total, "cap", w.cfg.MaxDailyEmails)
			return 0, nil
		}
	}

	var rows []dbq.ClaimDueNotificationsRow
	err := w.cfg.Pool.WithTx(ctx, func(q *dbq.Queries) error {
		r, qerr := q.ClaimDueNotifications(ctx, dbq.ClaimDueNotificationsParams{
			Limit:        5,
			LeaseSeconds: int32(w.cfg.LeaseDuration / time.Second),
		})
		if qerr != nil {
			return qerr
		}
		rows = r
		return nil
	})
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	for _, row := range rows {
		if err := w.limiter.Wait(ctx); err != nil {
			return 0, err
		}
		w.dispatch(ctx, row)
	}
	return len(rows), nil
}

func (w *Worker) dispatch(ctx context.Context, row dbq.ClaimDueNotificationsRow) {
	logger := w.cfg.Logger.With(
		"notification_id", row.ID.String(),
		"kind", row.Kind,
		"attempts", row.Attempts,
		"to_hash", httpx.HashEmail(row.ToEmail),
	)

	msg, err := w.buildMessage(row)
	if err != nil {
		logger.Error("build message", "err", err)
		w.markFailed(ctx, row, err.Error(), logger)
		return
	}

	providerID, sendErr := w.cfg.Sender.Send(ctx, msg)
	if sendErr == nil {
		w.markSent(ctx, row, providerID, logger)
		logger.Info("notification sent", "provider_id", providerID)
		return
	}
	logger.Warn("send failed", "err", sendErr)

	if errors.Is(sendErr, email.ErrRetryable) && int(row.Attempts) < w.cfg.MaxAttempts {
		next := backoff(int(row.Attempts))
		w.scheduleRetry(ctx, row, sendErr.Error(), next, logger)
		return
	}
	if int(row.Attempts) >= w.cfg.MaxAttempts {
		w.markDead(ctx, row, sendErr.Error(), logger)
		return
	}
	w.markFailed(ctx, row, sendErr.Error(), logger)
}

func (w *Worker) buildMessage(row dbq.ClaimDueNotificationsRow) (email.Message, error) {
	switch Kind(row.Kind) {
	case KindConfirmEmail:
		var p ConfirmEmailPayload
		if err := json.Unmarshal(row.Payload, &p); err != nil {
			return email.Message{}, err
		}
		subject, text, html := renderConfirmEmail(p)
		return email.Message{
			To:             row.ToEmail,
			Subject:        subject,
			Text:           text,
			HTML:           html,
			Tag:            string(KindConfirmEmail),
			IdempotencyKey: row.ID.String(),
			Headers: map[string]string{
				"List-Unsubscribe":      "<" + p.UnsubscribeURL + ">",
				"List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
			},
		}, nil
	case KindBroadcast:
		var p BroadcastPayload
		if err := json.Unmarshal(row.Payload, &p); err != nil {
			return email.Message{}, err
		}
		return email.Message{
			To:             row.ToEmail,
			Subject:        p.Subject,
			Text:           p.Text,
			HTML:           p.HTML,
			Tag:            string(KindBroadcast),
			IdempotencyKey: row.ID.String(),
			Headers: map[string]string{
				"List-Unsubscribe":      "<" + p.UnsubscribeURL + ">",
				"List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
			},
		}, nil
	default:
		return email.Message{}, errors.New("unknown notification kind: " + row.Kind)
	}
}

// BroadcastPayload is the payload shape for `broadcast` notifications.
type BroadcastPayload struct {
	Subject        string `json:"subject"`
	Text           string `json:"text"`
	HTML           string `json:"html"`
	UnsubscribeURL string `json:"unsubscribe_url"`
}

// markSent flips the notification to 'sent' and inserts an email_log row.
// If the DB write fails we retry up to a small bound; after that we log a
// critical error so the lease can expire and another worker re-claims. With
// the provider-side idempotency key the re-claim won't duplicate the email.
func (w *Worker) markSent(ctx context.Context, row dbq.ClaimDueNotificationsRow, providerID string, logger *slog.Logger) {
	hash := emailHashBytes(row.ToEmail)
	err := withRetry(ctx, 3, 50*time.Millisecond, func() error {
		return w.cfg.Pool.WithTx(ctx, func(q *dbq.Queries) error {
			if err := q.MarkNotificationSent(ctx, row.ID); err != nil {
				return err
			}
			return q.InsertEmailLog(ctx, dbq.InsertEmailLogParams{
				NotificationID:    row.ID,
				ToEmailHash:       hash,
				Provider:          "resend",
				ProviderMessageID: ptr(providerID),
				Status:            "sent",
			})
		})
	})
	if err != nil {
		logger.Error("markSent failed after retries", "err", err, "provider_id", providerID)
	}
}

// markFailed is a non-retryable failure (bad payload, unknown kind).
// We write status='failed' and a matching email_log row so the audit trail
// has the recipient hash and the error for triage.
func (w *Worker) markFailed(ctx context.Context, row dbq.ClaimDueNotificationsRow, errMsg string, logger *slog.Logger) {
	hash := emailHashBytes(row.ToEmail)
	trunc := truncate(errMsg, 1000)
	err := withRetry(ctx, 3, 50*time.Millisecond, func() error {
		return w.cfg.Pool.WithTx(ctx, func(q *dbq.Queries) error {
			if qerr := q.MarkNotificationFailed(ctx, dbq.MarkNotificationFailedParams{
				ID:        row.ID,
				LastError: ptr(trunc),
			}); qerr != nil {
				return qerr
			}
			return q.InsertEmailLog(ctx, dbq.InsertEmailLogParams{
				NotificationID: row.ID,
				ToEmailHash:    hash,
				Provider:       "resend",
				Status:         "failed",
				Error:          ptr(trunc),
			})
		})
	})
	if err != nil {
		logger.Error("markFailed write failed after retries", "err", err)
	}
}

// markDead is the terminal state after retry exhaustion. Same audit-log
// invariant as markFailed: the recipient hash and the error are recorded.
func (w *Worker) markDead(ctx context.Context, row dbq.ClaimDueNotificationsRow, errMsg string, logger *slog.Logger) {
	hash := emailHashBytes(row.ToEmail)
	trunc := truncate(errMsg, 1000)
	err := withRetry(ctx, 3, 50*time.Millisecond, func() error {
		return w.cfg.Pool.WithTx(ctx, func(q *dbq.Queries) error {
			if qerr := q.MarkNotificationDead(ctx, dbq.MarkNotificationDeadParams{
				ID:        row.ID,
				LastError: ptr(trunc),
			}); qerr != nil {
				return qerr
			}
			return q.InsertEmailLog(ctx, dbq.InsertEmailLogParams{
				NotificationID: row.ID,
				ToEmailHash:    hash,
				Provider:       "resend",
				Status:         "dead",
				Error:          ptr(trunc),
			})
		})
	})
	if err != nil {
		logger.Error("markDead write failed after retries", "err", err)
	}
}

func (w *Worker) scheduleRetry(ctx context.Context, row dbq.ClaimDueNotificationsRow, errMsg string, delay time.Duration, logger *slog.Logger) {
	next := time.Now().Add(delay)
	trunc := truncate(errMsg, 1000)
	err := withRetry(ctx, 3, 50*time.Millisecond, func() error {
		return w.cfg.Pool.WithTx(ctx, func(q *dbq.Queries) error {
			return q.ScheduleNotificationRetry(ctx, dbq.ScheduleNotificationRetryParams{
				ID:            row.ID,
				NextAttemptAt: pgxTimestamptz(next),
				LastError:     ptr(trunc),
			})
		})
	})
	if err != nil {
		logger.Error("scheduleRetry write failed after retries", "err", err)
	}
}

// withRetry retries fn up to `attempts` times with a fixed delay between
// attempts. Returns the last error if all attempts fail. Honors ctx
// cancellation between attempts.
func withRetry(ctx context.Context, attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
	}
	return err
}

// backoff returns the wait duration for the Nth attempt. Exponential with
// jitter, capped at 30 minutes. Shift is clamped to 30 so an unexpectedly
// large attempt value cannot overflow `1<<uint(attempt)`.
func backoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 30 {
		attempt = 30
	}
	base := time.Duration(1<<uint(attempt)) * 30 * time.Second
	if base > 30*time.Minute {
		base = 30 * time.Minute
	}
	// rand/v2 is auto-seeded per process; no manual seeding required.
	jit := time.Duration(rand.Int64N(int64(base) / 4))
	return base + jit
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
