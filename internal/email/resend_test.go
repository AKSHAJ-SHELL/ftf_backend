package email

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/fundthefuture/ftf-backend/internal/httpx"
)

// TestMain seeds the per-process email-hash key so the Resend error-log
// HashEmail call inside Send() does not panic with "init before use".
func TestMain(m *testing.M) {
	httpx.InitEmailHash([]byte("email-test-hash-key-aaaaaaaaaaaaaaaaaaaaaa"))
	os.Exit(m.Run())
}

func newTestResend(t *testing.T, h http.HandlerFunc) *Resend {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	r := NewResend("re_test", "Test <test@example.org>", slog.Default())
	r.baseURL = srv.URL
	return r
}

func TestResendSuccess(t *testing.T) {
	r := newTestResend(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"abc"}`))
	})
	id, err := r.Send(context.Background(), Message{To: "x@example.org", Subject: "hi", Text: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "abc" {
		t.Fatalf("id: %q", id)
	}
}

func TestResend5xxIsRetryable(t *testing.T) {
	r := newTestResend(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"message":"upstream"}`))
	})
	_, err := r.Send(context.Background(), Message{To: "x@example.org"})
	if err == nil || !errors.Is(err, ErrRetryable) {
		t.Fatalf("expected retryable, got %v", err)
	}
}

func TestResend4xxIsPermanent(t *testing.T) {
	r := newTestResend(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"bad to address"}`))
	})
	_, err := r.Send(context.Background(), Message{To: "bad@example.org"})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrRetryable) {
		t.Fatal("4xx should not be retryable")
	}
}

func TestResend429IsRetryable(t *testing.T) {
	r := newTestResend(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"slow down"}`))
	})
	_, err := r.Send(context.Background(), Message{To: "x@example.org"})
	if err == nil || !errors.Is(err, ErrRetryable) {
		t.Fatalf("expected retryable, got %v", err)
	}
}

func TestResendSendsIdempotencyKey(t *testing.T) {
	var got string
	r := newTestResend(t, func(w http.ResponseWriter, req *http.Request) {
		got = req.Header.Get("Idempotency-Key")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"ok"}`))
	})
	_, err := r.Send(context.Background(), Message{
		To:             "x@example.org",
		IdempotencyKey: "notification-uuid-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "notification-uuid-123" {
		t.Fatalf("Idempotency-Key not forwarded: %q", got)
	}
}

func TestResendOmitsIdempotencyKeyWhenEmpty(t *testing.T) {
	var got string
	var present bool
	r := newTestResend(t, func(w http.ResponseWriter, req *http.Request) {
		got = req.Header.Get("Idempotency-Key")
		_, present = req.Header["Idempotency-Key"]
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"ok"}`))
	})
	_, err := r.Send(context.Background(), Message{To: "x@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "" || present {
		t.Fatal("expected no Idempotency-Key header when key is empty")
	}
}

func TestFakeRecords(t *testing.T) {
	f := NewFake()
	if _, err := f.Send(context.Background(), Message{To: "x@example.org"}); err != nil {
		t.Fatal(err)
	}
	if got := f.Drain(); len(got) != 1 || got[0].To != "x@example.org" {
		t.Fatalf("drain: %+v", got)
	}
}
