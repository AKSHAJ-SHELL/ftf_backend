package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/fundthefuture/ftf-backend/internal/httpx"
)

// Resend is a minimal HTTP client for api.resend.com/emails. We intentionally
// avoid pulling in the official SDK so the dependency surface stays small.
type Resend struct {
	apiKey     string
	from       string
	httpClient *http.Client
	logger     *slog.Logger
	baseURL    string
}

func NewResend(apiKey, defaultFrom string, logger *slog.Logger) *Resend {
	if logger == nil {
		logger = slog.Default()
	}
	return &Resend{
		apiKey:  apiKey,
		from:    defaultFrom,
		logger:  logger,
		baseURL: "https://api.resend.com",
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

type resendBody struct {
	From    string            `json:"from"`
	To      []string          `json:"to"`
	Subject string            `json:"subject"`
	HTML    string            `json:"html,omitempty"`
	Text    string            `json:"text,omitempty"`
	ReplyTo string            `json:"reply_to,omitempty"`
	Tags    []resendTag       `json:"tags,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type resendTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type resendResp struct {
	ID string `json:"id"`
}

type resendErrResp struct {
	Message    string `json:"message"`
	Name       string `json:"name"`
	StatusCode int    `json:"statusCode"`
}

func (r *Resend) Send(ctx context.Context, m Message) (string, error) {
	from := m.From
	if from == "" {
		from = r.from
	}
	body := resendBody{
		From:    from,
		To:      []string{m.To},
		Subject: m.Subject,
		HTML:    m.HTML,
		Text:    m.Text,
		ReplyTo: m.ReplyTo,
		Headers: m.Headers,
	}
	if m.Tag != "" {
		body.Tags = []resendTag{{Name: "kind", Value: m.Tag}}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/emails", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")
	if m.IdempotencyKey != "" {
		// Resend deduplicates POSTs that carry the same Idempotency-Key within
		// a provider-controlled window, so a worker retry after a DB hiccup
		// does not result in a second email to the recipient.
		req.Header.Set("Idempotency-Key", m.IdempotencyKey)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", RetryableError(err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var ok resendResp
		_ = json.Unmarshal(raw, &ok)
		return ok.ID, nil
	}

	var perr resendErrResp
	_ = json.Unmarshal(raw, &perr)
	msg := perr.Message
	if msg == "" {
		msg = fmt.Sprintf("resend http %d", resp.StatusCode)
	}
	r.logger.Warn("resend send failed",
		"status", resp.StatusCode,
		"to_hash", httpx.HashEmail(m.To),
		"msg", msg,
	)

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return "", RetryableError(errors.New(msg))
	}
	return "", errors.New(msg)
}
