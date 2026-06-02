package notifications

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/fundthefuture/ftf-backend/internal/email"
	"github.com/fundthefuture/ftf-backend/internal/httpx"
)

func TestMain(m *testing.M) {
	httpx.InitEmailHash([]byte("notifications-test-hash-key-zzzzzzzzzzzzzz"))
	os.Exit(m.Run())
}

func TestBackoffGrows(t *testing.T) {
	prev := time.Duration(0)
	for i := 0; i < 5; i++ {
		d := backoff(i)
		if d < prev {
			t.Fatalf("backoff(%d)=%v not >= prev %v", i, d, prev)
		}
		prev = d
	}
	if backoff(20) > 40*time.Minute {
		t.Fatal("backoff cap broken")
	}
}

func TestRetryableErrorWrapping(t *testing.T) {
	e := email.RetryableError(errors.New("boom"))
	if !errors.Is(e, email.ErrRetryable) {
		t.Fatal("expected retryable")
	}
}

func TestRenderConfirmEmail(t *testing.T) {
	subject, text, html := renderConfirmEmail(ConfirmEmailPayload{
		ConfirmURL:     "https://example.org/confirm?token=abc",
		UnsubscribeURL: "https://example.org/unsub?token=def",
	})
	if subject == "" {
		t.Fatal("missing subject")
	}
	for _, h := range []string{"https://example.org/confirm?token=abc", "https://example.org/unsub?token=def"} {
		if !contains(text, h) || !contains(html, h) {
			t.Fatalf("missing %q in render", h)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
