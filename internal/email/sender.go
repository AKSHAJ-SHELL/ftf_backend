// Package email defines a transport-agnostic Sender so the worker and the
// production Resend client are decoupled. Tests use the in-memory fake.
package email

import (
	"context"
	"errors"
)

// Message is the minimal envelope we send. Headers cover RFC-compliant
// list-mail expectations (List-Unsubscribe, List-Unsubscribe-Post).
//
// IdempotencyKey, when non-empty, is forwarded to the provider as an
// idempotency token so retries from the worker do not result in duplicate
// sends. The notification worker sets this to the notification row UUID.
type Message struct {
	From           string
	To             string
	Subject        string
	HTML           string
	Text           string
	Headers        map[string]string
	ReplyTo        string
	Tag            string
	IdempotencyKey string
}

// Sender is the only thing the notification worker depends on.
type Sender interface {
	// Send returns (providerMessageID, error). A retryable error MUST satisfy
	// errors.Is(err, ErrRetryable). Anything else is permanent.
	Send(ctx context.Context, m Message) (string, error)
}

// ErrRetryable signals to the worker that this attempt should be re-scheduled.
var ErrRetryable = errors.New("email: retryable")

// RetryableError wraps cause as retryable.
func RetryableError(cause error) error {
	if cause == nil {
		return nil
	}
	return retryableErr{cause: cause}
}

type retryableErr struct{ cause error }

func (e retryableErr) Error() string { return "retryable: " + e.cause.Error() }
func (e retryableErr) Unwrap() error { return e.cause }
func (e retryableErr) Is(target error) bool {
	return target == ErrRetryable
}
