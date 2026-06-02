// Package admins exposes admin-only HTTP handlers for managing subscribers
// and observing the notification queue. Reads happen through the user pool so
// RLS via public.admins is the actual gate. Writes that need privileged
// access (resend-confirm) go through the subscribers service via the queue.
package admins

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/fundthefuture/ftf-backend/internal/apperr"
	"github.com/fundthefuture/ftf-backend/internal/auth"
	"github.com/fundthefuture/ftf-backend/internal/db"
	"github.com/fundthefuture/ftf-backend/internal/db/dbq"
	"github.com/fundthefuture/ftf-backend/internal/httpx"
)

// SubscribersResender is the narrow surface admins.Service consumes from
// subscribers.Service so the cycle/coupling is contained.
type SubscribersResender interface {
	EnqueueConfirm(ctx context.Context, id pgtype.UUID) error
}

type Deps struct {
	UserPool    *db.UserPool
	ServicePool *db.ServicePool
	Subscribers SubscribersResender
	Logger      *slog.Logger
}

type Service struct {
	deps Deps
}

func NewService(d Deps) *Service { return &Service{deps: d} }

func (s *Service) HandleListSubscribers(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	if c == nil {
		httpx.WriteError(w, r, apperr.Unauthorized("login required"))
		return
	}
	limit, offset := paginate(r)
	statusFilter := nilString(r.URL.Query().Get("status"))

	var rows []dbq.ListSubscribersRow
	var total int64
	ctx := r.Context()
	err := s.deps.UserPool.WithUser(ctx, db.JWTContext{
		Sub: c.Sub, Email: c.Email, Role: "authenticated",
	}, func(q *dbq.Queries) error {
		got, qerr := q.ListSubscribers(ctx, dbq.ListSubscribersParams{
			Limit: int32(limit), Offset: int32(offset), StatusFilter: statusFilter,
		})
		if qerr != nil {
			return qerr
		}
		rows = got
		t, qerr := q.CountSubscribers(ctx, statusFilter)
		if qerr != nil {
			return qerr
		}
		total = t
		return nil
	})
	if err != nil {
		s.deps.Logger.Error("admin list subscribers", "err", err)
		httpx.WriteError(w, r, apperr.Internal("failed"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":  rows,
		"total": total,
		"limit": limit,
		"offset": offset,
	})
}

func (s *Service) HandleListNotifications(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	if c == nil {
		httpx.WriteError(w, r, apperr.Unauthorized("login required"))
		return
	}
	limit, offset := paginate(r)
	statusFilter := nilString(r.URL.Query().Get("status"))

	var rows []dbq.ListNotificationsRow
	var total int64
	ctx := r.Context()
	err := s.deps.UserPool.WithUser(ctx, db.JWTContext{
		Sub: c.Sub, Email: c.Email, Role: "authenticated",
	}, func(q *dbq.Queries) error {
		got, qerr := q.ListNotifications(ctx, dbq.ListNotificationsParams{
			Limit: int32(limit), Offset: int32(offset), StatusFilter: statusFilter,
		})
		if qerr != nil {
			return qerr
		}
		rows = got
		t, qerr := q.CountNotifications(ctx, statusFilter)
		if qerr != nil {
			return qerr
		}
		total = t
		return nil
	})
	if err != nil {
		s.deps.Logger.Error("admin list notifications", "err", err)
		httpx.WriteError(w, r, apperr.Internal("failed"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":   rows,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Service) HandleResendConfirm(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	var id pgtype.UUID
	if err := id.Scan(idStr); err != nil {
		httpx.WriteError(w, r, apperr.BadRequest("bad subscriber id"))
		return
	}
	if err := s.deps.Subscribers.EnqueueConfirm(r.Context(), id); err != nil {
		if ae, ok := apperr.As(err); ok {
			httpx.WriteError(w, r, ae)
			return
		}
		if errors.Is(err, context.Canceled) {
			return
		}
		s.deps.Logger.Error("resend confirm", "err", err)
		httpx.WriteError(w, r, apperr.Internal("resend failed"))
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func paginate(r *http.Request) (limit, offset int) {
	limit = 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

func nilString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
