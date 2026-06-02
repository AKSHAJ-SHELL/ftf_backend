//go:build integration

package subscribers_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fundthefuture/ftf-backend/internal/db"
	"github.com/fundthefuture/ftf-backend/internal/email"
	"github.com/fundthefuture/ftf-backend/internal/httpx"
	"github.com/fundthefuture/ftf-backend/internal/notifications"
	"github.com/fundthefuture/ftf-backend/internal/subscribers"
	"github.com/fundthefuture/ftf-backend/internal/testutil"
	"github.com/fundthefuture/ftf-backend/internal/tokens"
)

func TestSubscriberE2E(t *testing.T) {
	pool, dsn := testutil.StartPostgres(t)
	_ = pool

	// The integration test runs the worker which calls helpers (HashEmail,
	// HashEmailBytes) that require the email-hash key to be initialized.
	httpx.InitEmailHash([]byte("integration-test-email-hash-key-12345"))
	httpx.InitTrustedProxies(nil)

	ctx := context.Background()
	poolOpts := db.PoolOpts{MaxConns: 4}
	userPool, err := db.NewUserPool(ctx, dsn, poolOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(userPool.Close)
	servicePool, err := db.NewServicePool(ctx, dsn, poolOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(servicePool.Close)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	signer := tokens.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	queue := notifications.NewQueue(servicePool)
	fake := email.NewFake()
	worker := notifications.NewWorker(notifications.WorkerConfig{
		Pool:        servicePool,
		Sender:      fake,
		Concurrency: 1,
		OutboundRPS: 100,
		Logger:      logger,
		BaseSleep:   50 * time.Millisecond,
	})

	svc := subscribers.NewService(subscribers.Deps{
		UserPool:    userPool,
		ServicePool: servicePool,
		Signer:      signer,
		Queue:       queue,
		AppBaseURL:  "https://api.example.org",
		FromAddress: "test@example.org",
		Logger:      logger,
		// Throttle is the defense against token-invalidation via repeated
		// subscribe calls. Use a long window so the second subscribe in this
		// test takes the throttle branch (and the first email's URL keeps
		// pointing at the row currently in DB).
		EmailThrottleWindow: 10 * time.Minute,
	})

	r := chi.NewRouter()
	r.Post("/v1/subscribers", svc.HandleSubscribe)
	r.Get("/v1/subscribers/confirm", svc.HandleConfirmGET)
	r.Post("/v1/subscribers/confirm", svc.HandleConfirmPOST)
	r.Get("/v1/subscribers/unsubscribe", svc.HandleUnsubscribeGET)
	r.Post("/v1/subscribers/unsubscribe", svc.HandleUnsubscribePOST)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	wctx, wcancel := context.WithCancel(ctx)
	go worker.Run(wctx)
	t.Cleanup(wcancel)

	// 1. Subscribe (fresh).
	subscribePost(t, srv.URL, "alice@example.org")

	// 2. Subscribe again — uniform response.
	subscribePost(t, srv.URL, "alice@example.org")

	// 3. Wait for the worker to ship the (first) confirm email.
	msg := waitForMessage(t, fake, "alice@example.org")

	// 4. GET on the confirm URL returns interstitial HTML, not JSON.
	confirm := extractURL(t, msg.Text, "/v1/subscribers/confirm?token=")
	confirmTarget := replaceHost(t, confirm, srv.URL)
	got := mustGet(t, confirmTarget)
	if got.status != http.StatusOK {
		t.Fatalf("confirm GET status: %d body=%s", got.status, got.body)
	}
	if !strings.Contains(string(got.body), "<form method=\"POST\"") {
		t.Fatalf("confirm GET should render interstitial form; body=%s", got.body)
	}

	// 5. POST the confirm token (mimicking the form submission).
	got = mustPostForm(t, confirmTarget, url.Values{"token": []string{queryToken(t, confirm)}})
	if got.status != http.StatusOK {
		t.Fatalf("confirm POST status: %d body=%s", got.status, got.body)
	}

	// 6. Unsubscribe via POST (idempotent on re-click).
	unsub := extractURL(t, msg.Text, "/v1/subscribers/unsubscribe?token=")
	unsubTarget := replaceHost(t, unsub, srv.URL)
	got = mustPostForm(t, unsubTarget, url.Values{"token": []string{queryToken(t, unsub)}})
	if got.status != http.StatusOK {
		t.Fatalf("unsubscribe POST status: %d body=%s", got.status, got.body)
	}

	// 7. Re-unsubscribe is a no-op (idempotent).
	got = mustPostForm(t, unsubTarget, url.Values{"token": []string{queryToken(t, unsub)}})
	if got.status != http.StatusOK {
		t.Fatalf("re-unsubscribe POST status: %d body=%s", got.status, got.body)
	}
}

func subscribePost(t *testing.T, base, email string) {
	t.Helper()
	body := strings.NewReader(`{"email":"` + email + `"}`)
	resp, err := http.Post(base+"/v1/subscribers", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("subscribe status %d: %s", resp.StatusCode, raw)
	}
}

func waitForMessage(t *testing.T, fake *email.Fake, to string) email.Message {
	t.Helper()
	for i := 0; i < 200; i++ {
		for _, m := range fake.Drain() {
			if m.To == to {
				return m
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("never saw a message for %s", to)
	return email.Message{}
}

func extractURL(t *testing.T, text, marker string) string {
	t.Helper()
	idx := strings.Index(text, marker)
	if idx < 0 {
		t.Fatalf("marker %q not found in %q", marker, text)
	}
	rest := text[idx:]
	end := strings.IndexAny(rest, " \n\r\t")
	if end < 0 {
		end = len(rest)
	}
	return "https://api.example.org" + rest[:end]
}

func queryToken(t *testing.T, full string) string {
	t.Helper()
	u, err := url.Parse(full)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("token")
}

func replaceHost(t *testing.T, target, base string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	bu, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = bu.Scheme
	u.Host = bu.Host
	return u.String()
}

type httpResp struct {
	status int
	body   []byte
}

func mustGet(t *testing.T, urlStr string) httpResp {
	t.Helper()
	resp, err := http.Get(urlStr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return httpResp{status: resp.StatusCode, body: b}
}

func mustPostForm(t *testing.T, urlStr string, values url.Values) httpResp {
	t.Helper()
	// Use a base URL without query so the form data is what carries the token,
	// matching what a real interstitial-page submission would look like.
	u, err := url.Parse(urlStr)
	if err != nil {
		t.Fatal(err)
	}
	u.RawQuery = ""
	resp, err := http.PostForm(u.String(), values)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return httpResp{status: resp.StatusCode, body: b}
}

var _ = json.Marshal
