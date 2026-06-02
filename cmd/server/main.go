package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fundthefuture/ftf-backend/internal/admins"
	"github.com/fundthefuture/ftf-backend/internal/auth"
	"github.com/fundthefuture/ftf-backend/internal/config"
	"github.com/fundthefuture/ftf-backend/internal/db"
	"github.com/fundthefuture/ftf-backend/internal/email"
	"github.com/fundthefuture/ftf-backend/internal/httpx"
	"github.com/fundthefuture/ftf-backend/internal/notifications"
	"github.com/fundthefuture/ftf-backend/internal/subscribers"
	"github.com/fundthefuture/ftf-backend/internal/tokens"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := httpx.NewLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	// Process-wide one-time init for helpers that pull from config.
	httpx.InitEmailHash([]byte(cfg.EmailHashKey))
	httpx.InitTrustedProxies(cfg.TrustedProxyCIDRs)

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	poolOpts := db.PoolOpts{MaxConns: cfg.PoolMaxConns}

	userPool, err := db.NewUserPool(rootCtx, cfg.DatabaseURL, poolOpts)
	if err != nil {
		return fmt.Errorf("user pool: %w", err)
	}
	defer userPool.Close()

	servicePool, err := db.NewServicePool(rootCtx, cfg.DatabaseURLServiceRole, poolOpts)
	if err != nil {
		return fmt.Errorf("service pool: %w", err)
	}
	defer servicePool.Close()

	signer := tokens.NewSigner([]byte(cfg.TokenSigningKey))

	var sender email.Sender
	if cfg.ResendAPIKey == "" {
		logger.Warn("RESEND_API_KEY missing; using in-memory fake email sender")
		sender = email.NewFake()
	} else {
		sender = email.NewResend(cfg.ResendAPIKey, cfg.ResendFromAddress, logger)
	}

	queue := notifications.NewQueue(servicePool)
	worker := notifications.NewWorker(notifications.WorkerConfig{
		Pool:           servicePool,
		Sender:         sender,
		Concurrency:    cfg.WorkerConcurrency,
		OutboundRPS:    cfg.OutboundEmailRPS,
		Logger:         logger,
		LeaseDuration:  60 * time.Second,
		MaxAttempts:    6,
		MaxDailyEmails: cfg.MaxDailyEmails,
	})

	subSvc := subscribers.NewService(subscribers.Deps{
		UserPool:            userPool,
		ServicePool:         servicePool,
		Signer:              signer,
		Queue:               queue,
		AppBaseURL:          cfg.AppBaseURL,
		FromAddress:         cfg.ResendFromAddress,
		Logger:              logger,
		EmailThrottleWindow: time.Duration(cfg.SubscribeEmailThrottleSec) * time.Second,
		UnsubscribeTokenTTL: time.Duration(cfg.UnsubscribeTokenTTLDays) * 24 * time.Hour,
	})

	adminSvc := admins.NewService(admins.Deps{
		UserPool:    userPool,
		ServicePool: servicePool,
		Subscribers: subSvc,
		Logger:      logger,
	})

	jwtVerifier, err := auth.NewVerifier(auth.Config{
		Secret:     cfg.SupabaseJWTSecret,
		JWKSURL:    cfg.SupabaseJWKSURL,
		ProjectRef: cfg.SupabaseProjectRef,
	})
	if err != nil {
		return fmt.Errorf("jwt verifier: %w", err)
	}
	authMW := auth.NewMiddleware(jwtVerifier, userPool, logger)

	r := chi.NewRouter()

	r.Use(httpx.RequestID)
	r.Use(httpx.Recover(logger))
	r.Use(httpx.Logging(logger))
	r.Use(httpx.SecurityHeaders)
	r.Use(httpx.CORS(cfg.AllowedOrigins))

	r.Get("/healthz", httpx.HealthOK)
	// Readyz pings both pools (M2). A degraded service pool is just as fatal
	// to read traffic in the long run as a degraded user pool, because the
	// worker stops draining and the notifications table backs up.
	r.Get("/readyz", httpx.Readyz(userPool.Pool(), servicePool.Pool()))

	r.Route("/v1", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(httpx.RateLimit(cfg.RateLimitSubscribersPerMin, time.Minute))
			r.Use(authMW.OptionalUser)
			r.Post("/subscribers", subSvc.HandleSubscribe)
		})

		r.Group(func(r chi.Router) {
			r.Use(httpx.RateLimit(cfg.RateLimitConfirmPerMin, time.Minute))
			r.Get("/subscribers/confirm", subSvc.HandleConfirmGET)
			r.Post("/subscribers/confirm", subSvc.HandleConfirmPOST)
		})

		r.Group(func(r chi.Router) {
			r.Use(httpx.RateLimit(cfg.RateLimitDefaultPerMin, time.Minute))
			r.Get("/subscribers/unsubscribe", subSvc.HandleUnsubscribeGET)
			r.Post("/subscribers/unsubscribe", subSvc.HandleUnsubscribePOST)
		})

		r.Group(func(r chi.Router) {
			r.Use(httpx.RateLimit(cfg.RateLimitDefaultPerMin, time.Minute))
			r.Use(authMW.RequireUser)
			r.Get("/me/subscription", subSvc.HandleMySubscription)
		})

		r.Group(func(r chi.Router) {
			r.Use(httpx.RateLimit(cfg.RateLimitDefaultPerMin, time.Minute))
			r.Use(authMW.RequireAdmin)
			r.Get("/admin/subscribers", adminSvc.HandleListSubscribers)
			r.Get("/admin/notifications", adminSvc.HandleListNotifications)
			r.Post("/admin/subscribers/{id}/resend-confirm", adminSvc.HandleResendConfirm)
		})
	})

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// 64KiB cap mirrors common reverse-proxy defaults and is more than
		// enough for our auth/CORS/Forwarded headers. Anything larger is
		// abusive.
		MaxHeaderBytes: 64 * 1024,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		worker.Run(rootCtx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server error", "err", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("shutdown signal received")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown error", "err", err)
	}
	rootCancel()
	wg.Wait()
	logger.Info("clean shutdown complete")
	return nil
}
