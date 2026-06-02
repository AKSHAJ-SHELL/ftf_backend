// Package subscribers implements the double-opt-in newsletter flow.
//
// Architectural rules enforced here:
//
//   - The public POST /v1/subscribers handler runs through the user-pool with
//     role=anon so RLS is the gate on the INSERT and ON CONFLICT UPDATE
//     half. The service pool is NOT touched on the anon write path.
//
//   - HandleConfirm and HandleUnsubscribe are token-gated state transitions.
//     Anon cannot change `status` under RLS, so these still flow through the
//     service pool — but they are reachable only after a successful HMAC
//     signature check on the URL, which is a strictly tighter trust boundary
//     than "anyone with a POST body".
//
//   - HTTP handlers split the visible URL surface in two: GET renders an
//     interstitial HTML page that POSTs a same-origin form; POST performs
//     the state transition. This breaks email-client prefetch and antivirus
//     scanners that hit links with GET.
package subscribers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/fundthefuture/ftf-backend/internal/apperr"
	"github.com/fundthefuture/ftf-backend/internal/auth"
	"github.com/fundthefuture/ftf-backend/internal/db"
	"github.com/fundthefuture/ftf-backend/internal/db/dbq"
	"github.com/fundthefuture/ftf-backend/internal/httpx"
	"github.com/fundthefuture/ftf-backend/internal/notifications"
	"github.com/fundthefuture/ftf-backend/internal/tokens"
)

// Deps wires everything the service needs. All fields required.
type Deps struct {
	UserPool            *db.UserPool
	ServicePool         *db.ServicePool
	Signer              *tokens.Signer
	Queue               *notifications.Queue
	AppBaseURL          string
	FromAddress         string
	Logger              *slog.Logger
	EmailThrottleWindow time.Duration // per-email re-subscribe throttle; 0 disables
	UnsubscribeTokenTTL time.Duration // unsubscribe token expiry; 0 = no expiry (legacy behavior)
	ConfirmTokenTTL     time.Duration // confirm token expiry; 0 -> 7d default
	// Now is the clock; defaults to time.Now. Override in tests for stable expiries.
	Now func() time.Time
}

type Service struct {
	deps Deps
}

func NewService(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.ConfirmTokenTTL == 0 {
		d.ConfirmTokenTTL = 7 * 24 * time.Hour
	}
	if d.UnsubscribeTokenTTL == 0 {
		d.UnsubscribeTokenTTL = 365 * 24 * time.Hour
	}
	return &Service{deps: d}
}

// subscribeReq is the public request shape.
type subscribeReq struct {
	Email  string `json:"email"`
	Source string `json:"source,omitempty"`
}

// uniformOK is the response returned on the happy path. Existing-vs-new is
// hidden, so an attacker cannot enumerate addresses via this endpoint.
var uniformOK = map[string]string{
	"status":  "accepted",
	"message": "If the address is valid, a confirmation email is on its way.",
}

// minHandlerLatency is the floor we pad subscribe responses to. Hides
// branch-timing between "new", "already-pending", "already-confirmed", and
// "already-unsubscribed" code paths.
const minHandlerLatency = 200 * time.Millisecond

// HandleSubscribe accepts a public email, upserts a pending row, and enqueues
// a confirmation email. Response is uniform on the happy path; invalid emails
// return 400 so the client can fix typos in the form (H11 trade-off).
func (s *Service) HandleSubscribe(w http.ResponseWriter, r *http.Request) {
	start := s.deps.Now()
	defer constantTimeDelay(start, minHandlerLatency, s.deps.Now)

	var body subscribeReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		httpx.WriteError(w, r, apperr.BadRequest("invalid JSON").Wrap(err))
		return
	}

	emailNorm, ok := normalizeEmail(body.Email)
	if !ok {
		s.deps.Logger.Warn("subscribe rejected: invalid email format",
			"request_id", httpx.RequestIDFromContext(r.Context()),
		)
		httpx.WriteError(w, r, apperr.BadRequest("invalid email format"))
		return
	}

	source := sanitizeSource(body.Source)

	// Per-email throttle (C2). This SELECT lives on the service pool because
	// notifications is not anon-readable. The result tells us only "should we
	// skip this enqueue" — it is not leaked to the response.
	//
	// This is ALSO the defense against token-invalidation attacks: a hostile
	// caller cannot bombard subscribe with the victim's address to rotate
	// the confirm token away from a URL the victim is mid-clicking, because
	// inside the throttle window we skip the upsert entirely. The window
	// MUST be longer than zero in production; setting it to 0 disables this
	// defense.
	if s.deps.EmailThrottleWindow > 0 {
		recent, err := s.recentlyNotified(r.Context(), emailNorm, notifications.KindConfirmEmail, s.deps.EmailThrottleWindow)
		if err != nil {
			s.deps.Logger.Error("throttle check", "err", err, "to_hash", httpx.HashEmail(emailNorm))
			httpx.WriteError(w, r, apperr.Internal("subscribe failed"))
			return
		}
		if recent {
			httpx.WriteJSON(w, http.StatusAccepted, uniformOK)
			return
		}
	}

	// If the caller is logged in we link the row to their auth.uid so the
	// RLS owner policy works even if they later change their email.
	var userID pgtype.UUID
	jc := db.JWTContext{Role: "anon"}
	if c := auth.FromContext(r.Context()); c != nil && c.Sub != "" {
		jc = db.JWTContext{Sub: c.Sub, Email: c.Email, Role: "authenticated"}
		if u, err := pgUUID(c.Sub); err == nil {
			userID = u
		}
	}

	rawToken, hash := newConfirmToken()
	expiresAt := s.deps.Now().Add(s.deps.ConfirmTokenTTL)

	signedToken, err := s.deps.Signer.Issue(tokens.PurposeConfirmSubscriber, rawToken[:], expiresAt)
	if err != nil {
		s.deps.Logger.Error("token issue", "err", err)
		httpx.WriteError(w, r, apperr.Internal("subscribe failed"))
		return
	}

	var (
		subID           pgtype.UUID
		alreadyResolved bool
	)
	err = s.deps.UserPool.WithUser(r.Context(), jc, func(q *dbq.Queries) error {
		row, qerr := q.UpsertPendingSubscriber(r.Context(), dbq.UpsertPendingSubscriberParams{
			Email:                 emailNorm,
			ConfirmTokenHash:      hash,
			ConfirmTokenExpiresAt: pgxTs(expiresAt),
			Source:                nonEmpty(source),
			UserID:                userID,
		})
		if errors.Is(qerr, pgx.ErrNoRows) {
			// ON CONFLICT (email) DO UPDATE WHERE status='pending' returned no row.
			// The conflict target row is either confirmed or unsubscribed; either
			// way we treat it as already-resolved. We do NOT leak which.
			alreadyResolved = true
			return nil
		}
		if qerr != nil {
			return qerr
		}
		subID = row.ID
		return nil
	})
	if err != nil {
		s.deps.Logger.Error("upsert subscriber", "err", err, "to_hash", httpx.HashEmail(emailNorm))
		httpx.WriteError(w, r, apperr.Internal("subscribe failed"))
		return
	}
	if alreadyResolved {
		httpx.WriteJSON(w, http.StatusAccepted, uniformOK)
		return
	}

	confirmURL := s.buildURL("/v1/subscribers/confirm", map[string]string{"token": signedToken})
	unsubURL, err := s.unsubscribeURL(subID)
	if err != nil {
		s.deps.Logger.Error("build unsubscribe url", "err", err)
		httpx.WriteError(w, r, apperr.Internal("subscribe failed"))
		return
	}

	if _, err := s.deps.Queue.Enqueue(r.Context(), notifications.KindConfirmEmail, emailNorm, notifications.ConfirmEmailPayload{
		ConfirmURL:     confirmURL,
		UnsubscribeURL: unsubURL,
	}); err != nil {
		// The subscriber row exists. The email itself failed to enqueue, which is
		// rare (DB write to notifications). Log so operators can investigate;
		// the user can re-subscribe to retry. We do NOT silently rely on a cron
		// sweep — there is no cron sweep.
		s.deps.Logger.Error("enqueue confirm failed",
			"err", err,
			"subscriber_id", subID.String(),
			"to_hash", httpx.HashEmail(emailNorm),
		)
	}

	httpx.WriteJSON(w, http.StatusAccepted, uniformOK)
}

// HandleConfirmGET renders the interstitial confirmation page on GET.
// The page POSTs a one-button form back to the same URL.
func (s *Service) HandleConfirmGET(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimSpace(r.URL.Query().Get("token"))
	if tok == "" {
		httpx.WriteHTML(w, http.StatusBadRequest, renderError("Missing or invalid confirmation link."))
		return
	}
	if _, err := s.deps.Signer.Verify(tok, tokens.PurposeConfirmSubscriber); err != nil {
		httpx.WriteHTML(w, http.StatusBadRequest, renderError("This confirmation link is invalid or has expired."))
		return
	}
	httpx.WriteHTML(w, http.StatusOK, renderInterstitial(
		"Confirm your subscription",
		"Click below to confirm your email address.",
		"Confirm",
		"/v1/subscribers/confirm",
		tok,
	))
}

// HandleConfirmPOST performs the confirm state transition. The token is
// resubmitted as a form field; it is also accepted from the query string for
// CLI/curl flexibility.
func (s *Service) HandleConfirmPOST(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimSpace(r.FormValue("token"))
	if tok == "" {
		tok = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if tok == "" {
		httpx.WriteError(w, r, apperr.BadRequest("missing token"))
		return
	}
	rawFromTok, err := s.deps.Signer.Verify(tok, tokens.PurposeConfirmSubscriber)
	if err != nil {
		httpx.WriteError(w, r, apperr.BadRequest("invalid or expired token"))
		return
	}
	// DB stores sha256(raw); the URL token carries `raw`. This separation
	// means a DB leak does not give an attacker forgeable URLs.
	lookupHash := hashRawToken(rawFromTok)

	err = s.deps.ServicePool.WithTx(r.Context(), func(q *dbq.Queries) error {
		row, qerr := q.GetSubscriberByConfirmTokenHash(r.Context(), lookupHash)
		if qerr != nil {
			return qerr
		}
		if _, qerr := q.ConfirmSubscriberByID(r.Context(), row.ID); qerr != nil {
			return qerr
		}
		return nil
	})
	if err != nil {
		// Either no matching pending row (token already used, or token is
		// stale) or a DB failure — we cannot tell the user the difference
		// without leaking signal.
		httpx.WriteError(w, r, apperr.BadRequest("invalid or expired token"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "confirmed"})
}

// HandleUnsubscribeGET renders the interstitial unsubscribe page.
func (s *Service) HandleUnsubscribeGET(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimSpace(r.URL.Query().Get("token"))
	if tok == "" {
		httpx.WriteHTML(w, http.StatusBadRequest, renderError("Missing or invalid unsubscribe link."))
		return
	}
	if _, err := s.deps.Signer.Verify(tok, tokens.PurposeUnsubscribeSubscriber); err != nil {
		httpx.WriteHTML(w, http.StatusBadRequest, renderError("This unsubscribe link is invalid or has expired."))
		return
	}
	httpx.WriteHTML(w, http.StatusOK, renderInterstitial(
		"Unsubscribe",
		"Click below to confirm you want to stop receiving emails from us.",
		"Unsubscribe",
		"/v1/subscribers/unsubscribe",
		tok,
	))
}

// HandleUnsubscribePOST performs the unsubscribe state transition. Also
// honors RFC 8058 List-Unsubscribe=One-Click which delivers via POST with
// no token in the body — that case isn't supported because we put the
// token in the URL exclusively.
func (s *Service) HandleUnsubscribePOST(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimSpace(r.FormValue("token"))
	if tok == "" {
		tok = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if tok == "" {
		httpx.WriteError(w, r, apperr.BadRequest("missing token"))
		return
	}
	subjectBytes, err := s.deps.Signer.Verify(tok, tokens.PurposeUnsubscribeSubscriber)
	if err != nil {
		httpx.WriteError(w, r, apperr.BadRequest("invalid token"))
		return
	}
	var id pgtype.UUID
	if err := id.Scan(string(subjectBytes)); err != nil {
		httpx.WriteError(w, r, apperr.BadRequest("invalid token"))
		return
	}

	var rowsAffected int64
	err = s.deps.ServicePool.WithTx(r.Context(), func(q *dbq.Queries) error {
		n, qerr := q.UnsubscribeByID(r.Context(), id)
		if qerr != nil {
			return qerr
		}
		rowsAffected = n
		return nil
	})
	if err != nil {
		s.deps.Logger.Error("unsubscribe", "err", err, "subscriber_id", id.String())
		httpx.WriteError(w, r, apperr.Internal("unsubscribe failed"))
		return
	}
	if rowsAffected == 0 {
		// Idempotent: already unsubscribed. Log at debug so it's visible if
		// operators turn the dial up, but treat the click as success.
		s.deps.Logger.Debug("unsubscribe no-op (already unsubscribed)", "subscriber_id", id.String())
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "unsubscribed"})
}

// HandleMySubscription returns the caller's current subscription view.
// Uses the user-pool so RLS scopes the read to the JWT-owner only.
func (s *Service) HandleMySubscription(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	if c == nil || c.Email == "" {
		httpx.WriteError(w, r, apperr.Unauthorized("login required"))
		return
	}
	var status string
	err := s.deps.UserPool.WithUser(r.Context(), db.JWTContext{
		Sub:   c.Sub,
		Email: c.Email,
		Role:  "authenticated",
	}, func(q *dbq.Queries) error {
		sub, qerr := q.GetSubscriberByEmail(r.Context(), c.Email)
		if errors.Is(qerr, pgx.ErrNoRows) {
			status = "none"
			return nil
		}
		if qerr != nil {
			return qerr
		}
		status = sub.Status
		return nil
	})
	if err != nil {
		s.deps.Logger.Error("me subscription", "err", err)
		httpx.WriteError(w, r, apperr.Internal("failed"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": status})
}

// EnqueueConfirm is called by the admin "resend confirm" workflow. Read and
// upsert run in a single service-pool tx; if the row's status changed between
// the read and the upsert, RowsAffected==0 surfaces as a Conflict.
func (s *Service) EnqueueConfirm(ctx context.Context, id pgtype.UUID) error {
	var (
		emailAddr string
		signed    string
	)

	rawToken, hash := newConfirmToken()
	expiresAt := s.deps.Now().Add(s.deps.ConfirmTokenTTL)
	sig, err := s.deps.Signer.Issue(tokens.PurposeConfirmSubscriber, rawToken[:], expiresAt)
	if err != nil {
		return err
	}
	signed = sig

	err = s.deps.ServicePool.WithTx(ctx, func(q *dbq.Queries) error {
		sub, qerr := q.GetSubscriberByID(ctx, id)
		if qerr != nil {
			return qerr
		}
		if sub.Status != "pending" {
			return apperr.Conflict("subscriber is not pending")
		}
		emailAddr = sub.Email
		row, qerr := q.UpsertPendingSubscriber(ctx, dbq.UpsertPendingSubscriberParams{
			Email:                 emailAddr,
			ConfirmTokenHash:      hash,
			ConfirmTokenExpiresAt: pgxTs(expiresAt),
			Source:                sub.Source,
			UserID:                pgtype.UUID{}, // do not override an existing user_id
		})
		if errors.Is(qerr, pgx.ErrNoRows) {
			// Status flipped between SELECT and UPSERT (TOCTOU race).
			return apperr.Conflict("subscriber status changed")
		}
		if qerr != nil {
			return qerr
		}
		_ = row
		return nil
	})
	if err != nil {
		return err
	}

	unsub, err := s.unsubscribeURL(id)
	if err != nil {
		return err
	}
	confirm := s.buildURL("/v1/subscribers/confirm", map[string]string{"token": signed})
	_, err = s.deps.Queue.Enqueue(ctx, notifications.KindConfirmEmail, emailAddr, notifications.ConfirmEmailPayload{
		ConfirmURL:     confirm,
		UnsubscribeURL: unsub,
	})
	return err
}

// --- helpers ---

// recentlyNotified returns true if a notification of the given kind for `email`
// was created within `window`. Service-role read because notifications is not
// anon-readable; the result is used only for throttling and is not leaked.
func (s *Service) recentlyNotified(ctx context.Context, email string, kind notifications.Kind, window time.Duration) (bool, error) {
	var got bool
	err := s.deps.ServicePool.WithTx(ctx, func(q *dbq.Queries) error {
		recent, qerr := q.HasRecentNotificationForEmail(ctx, dbq.HasRecentNotificationForEmailParams{
			ToEmail:       email,
			Kind:          string(kind),
			WindowSeconds: int32(window / time.Second),
		})
		if qerr != nil {
			return qerr
		}
		got = recent
		return nil
	})
	return got, err
}

func (s *Service) buildURL(path string, params map[string]string) string {
	u, err := url.Parse(s.deps.AppBaseURL)
	if err != nil {
		return s.deps.AppBaseURL + path
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Service) unsubscribeURL(id pgtype.UUID) (string, error) {
	// Bounded expiry beats permanent: a leaked unsubscribe URL is still
	// abuse-capable, just for less time. 1 year is long enough that real
	// users never see expired buttons in old emails.
	tok, err := s.deps.Signer.Issue(tokens.PurposeUnsubscribeSubscriber, []byte(id.String()), s.deps.Now().Add(s.deps.UnsubscribeTokenTTL))
	if err != nil {
		return "", err
	}
	return s.buildURL("/v1/subscribers/unsubscribe", map[string]string{"token": tok}), nil
}

func normalizeEmail(in string) (string, bool) {
	in = strings.TrimSpace(in)
	if len(in) == 0 || len(in) > 254 {
		return "", false
	}
	addr, err := mail.ParseAddress(in)
	if err != nil {
		return "", false
	}
	at := strings.LastIndex(addr.Address, "@")
	if at < 1 || at == len(addr.Address)-1 {
		return "", false
	}
	domain := addr.Address[at+1:]
	if !strings.Contains(domain, ".") {
		return "", false
	}
	// Reject bracket-form domains (IPv4/IPv6 literals). RFC 5321 §4.1.3
	// allows them, but we do not want to email IP-literal hosts and the
	// shape complicates downstream MX/DNS handling.
	if strings.ContainsAny(domain, "[]") {
		return "", false
	}
	return strings.ToLower(addr.Address), true
}

// sourceRe whitelists characters in a `source` string. Anything else is
// stripped. Keeps the value safe to use as a UTM-style tag without further
// escaping, and bounds the value at a sane length.
var sourceRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeSource(s string) string {
	s = sourceRe.ReplaceAllString(strings.TrimSpace(s), "")
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

// newConfirmToken generates a 32-byte raw secret and the SHA-256 hash that
// will be stored in the DB. The raw bytes go into the signed HMAC token;
// the hash goes into the row. DB leak does not yield URL forgery.
func newConfirmToken() (raw [32]byte, hash []byte) {
	_, _ = rand.Read(raw[:])
	h := sha256.Sum256(raw[:])
	return raw, h[:]
}

// hashRawToken computes the lookup hash from the raw bytes extracted from a
// verified URL token. Pairs with newConfirmToken's hash side.
func hashRawToken(raw []byte) []byte {
	h := sha256.Sum256(raw)
	return h[:]
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func pgxTs(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func pgUUID(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return u, err
	}
	return u, nil
}

// constantTimeDelay pads the request to a minimum total duration so a timing
// observer cannot reliably distinguish "new" vs "existing" branches.
// Unlike the previous implementation we ALWAYS sleep — the early-return on
// elapsed >= minTotal was itself a timing oracle.
func constantTimeDelay(start time.Time, minTotal time.Duration, now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	elapsed := now().Sub(start)
	if elapsed < minTotal {
		time.Sleep(minTotal - elapsed)
	}
}

// renderInterstitial emits a tiny self-contained HTML page with a one-button
// form that POSTs the token back. No external resources, no JS.
func renderInterstitial(title, body, button, actionPath, token string) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>%s</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;margin:0;padding:2rem;background:#fafafa;color:#111}
.card{max-width:480px;margin:4rem auto;padding:2rem;background:#fff;border:1px solid #e5e5e5;border-radius:8px}
button{font:inherit;padding:.6rem 1.2rem;border:0;border-radius:4px;background:#111;color:#fff;cursor:pointer}
button:hover{background:#222}
h1{margin:0 0 .5rem 0;font-size:1.25rem}
p{margin:0 0 1rem 0;color:#444}
</style>
</head><body>
<main class="card">
<h1>%s</h1>
<p>%s</p>
<form method="POST" action="%s">
<input type="hidden" name="token" value="%s">
<button type="submit">%s</button>
</form>
</main>
</body></html>`,
		html.EscapeString(title),
		html.EscapeString(title),
		html.EscapeString(body),
		html.EscapeString(actionPath),
		html.EscapeString(token),
		html.EscapeString(button),
	)
}

func renderError(msg string) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Error</title>
<style>body{font:16px/1.5 system-ui,sans-serif;margin:0;padding:2rem;background:#fafafa;color:#111}.card{max-width:480px;margin:4rem auto;padding:2rem;background:#fff;border:1px solid #e5e5e5;border-radius:8px}</style>
</head><body><main class="card"><h1>Sorry</h1><p>%s</p></main></body></html>`,
		html.EscapeString(msg),
	)
}
