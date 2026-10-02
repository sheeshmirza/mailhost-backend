package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"mailhost/internal/api"
	"mailhost/internal/broker"
	"mailhost/internal/config"
	"mailhost/internal/db"
	"mailhost/internal/delivery"
	"mailhost/internal/docstore"
	"mailhost/internal/imap"
	"mailhost/internal/inbound"
	"mailhost/internal/pop3"
	"mailhost/internal/queue"
	"mailhost/internal/rediscache"
	"mailhost/internal/secretbox"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.AllowPrivateDelivery {
		log.Warn("ALLOW_PRIVATE_DELIVERY=true: webhooks and outbound delivery may target private networks. Never enable this in production.")
	}
	if cfg.SkipDNSVerification {
		log.Warn("SKIP_DNS_VERIFICATION=true: domains are verified without DNS checks. Never enable this in production.")
	}

	pool, err := db.Connect(ctx, cfg.DatabaseURL, cfg.DBMaxConns)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	// Create the current and upcoming event partitions before the API can accept
	// sends. This keeps events out of the default partition and allows later
	// monthly partitions to be attached without a data migration.
	if err := db.MaintainPartitions(ctx, pool, cfg.RetentionMonths); err != nil {
		return err
	}
	readPool := pool
	if cfg.DatabaseReadURL != "" {
		readPool, err = db.Connect(ctx, cfg.DatabaseReadURL, cfg.DBMaxConns)
		if err != nil {
			return err
		}
		defer readPool.Close()
	}
	box, err := secretbox.New(cfg.MasterKey)
	if err != nil {
		return err
	}

	var rClient *rediscache.Client
	if cfg.RedisURL != "" {
		rc, err := rediscache.New(cfg.RedisURL)
		if err != nil {
			log.Warn("redis connection failed, operating with in-memory cache", "err", err)
		} else {
			rClient = rc
			defer rClient.Close()
			log.Info("redis connected")
		}
	}

	var queueConsumer delivery.BrokerConsumer
	if cfg.RabbitMQURL != "" {
		bc, err := broker.New(cfg.RabbitMQURL)
		if err != nil {
			log.Warn("rabbitmq connection failed, operating with postgres queue", "err", err)
		} else {
			queue.SetBroker(bc)
			queueConsumer = bc
			defer bc.Close()
			log.Info("rabbitmq broker connected")
		}
	} else if rClient != nil {
		rsClient := broker.NewRedisStream(rClient.RawClient())
		queue.SetBroker(rsClient)
		queueConsumer = rsClient
		log.Info("redis streams queue broker connected (bullmq/stream pattern)")
	}

	var docClient *docstore.Client
	if cfg.MongoDBURI != "" {
		dc, err := docstore.New(cfg.MongoDBURI, cfg.MongoDBDatabase)
		if err != nil {
			log.Warn("mongodb connection failed, operating with postgres document storage", "err", err)
		} else {
			docClient = dc
			defer docClient.Close(context.Background())
			log.Info("mongodb document store connected", "database", cfg.MongoDBDatabase)
		}
	}

	errc := make(chan error, 8)
	var wg sync.WaitGroup

	if cfg.Roles["api"] {
		apiServer := api.New(pool, readPool, box, cfg, log)
		if rClient != nil {
			apiServer.SetRedis(rClient)
		}
		if docClient != nil {
			apiServer.SetDocstore(docClient)
		}
		apiServer.StartBackgroundSchedulers(ctx)
		srv := &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           apiServer.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       2 * time.Minute,
			WriteTimeout:      2 * time.Minute,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    1 << 20,
		}
		go func() {
			log.Info("http api listening", "addr", cfg.HTTPAddr)
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			srv.Shutdown(sctx)
		}()
	}

	if cfg.Roles["smtp"] {
		ss, err := inbound.NewServer(pool, box, cfg, log)
		if err != nil {
			return err
		}
		if docClient != nil {
			ss.SetDocstore(docClient)
		}
		go func() {
			log.Info("smtp server listening", "addr", cfg.SMTPAddr)
			if err := ss.ListenAndServe(); !errors.Is(err, smtp.ErrServerClosed) {
				errc <- err
			}
		}()
		defer ss.Close()

		if cfg.SubmissionAddr != "" && cfg.SubmissionAddr != cfg.SMTPAddr {
			subCfg := *cfg
			subCfg.SMTPAddr = cfg.SubmissionAddr
			subServer, err := inbound.NewSubmissionServer(pool, box, &subCfg, log)
			if err != nil {
				return err
			}
			if docClient != nil {
				subServer.SetDocstore(docClient)
			}
			go func() {
				log.Info("smtp submission server listening", "addr", cfg.SubmissionAddr)
				if err := subServer.ListenAndServe(); !errors.Is(err, smtp.ErrServerClosed) {
					errc <- err
				}
			}()
			defer subServer.Close()
		}
	}

	if cfg.Roles["imap"] {
		imapSrv, err := imap.NewServer(pool, cfg, log)
		if err != nil {
			return err
		}
		go func() {
			if err := imapSrv.ListenAndServe(); err != nil {
				errc <- err
			}
		}()
		defer imapSrv.Close()
	}

	if cfg.Roles["pop"] {
		popSrv, err := pop3.NewServer(pool, cfg, log)
		if err != nil {
			return err
		}
		go func() {
			if err := popSrv.ListenAndServe(); err != nil {
				errc <- err
			}
		}()
		defer popSrv.Close()
	}

	if cfg.Roles["worker"] {
		wk := delivery.New(pool, cfg, log)
		if queueConsumer != nil {
			wk.SetBroker(queueConsumer)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			wk.Run(ctx)
		}()
	}

	if cfg.DebugAddr != "" {
		debugSrv := &http.Server{
			Addr:              cfg.DebugAddr,
			Handler:           http.DefaultServeMux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Info("debug pprof server listening", "addr", cfg.DebugAddr)
			if err := debugSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				log.Error("debug server failed", "err", err)
			}
		}()
		defer debugSrv.Close()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	log.Info("shutting down")
	stop()
	wg.Wait()
	return runErr
}
