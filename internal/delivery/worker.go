// Package delivery runs the outbound MTA: it claims queued deliveries and hands them to remote MX hosts.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"mailhost/internal/broker"
	"mailhost/internal/cache"
	"mailhost/internal/config"
	"mailhost/internal/db"
	"mailhost/internal/queue"
)

type BrokerConsumer interface {
	Consume(ctx context.Context, queueName string, prefetch int) (<-chan broker.DeliveryJob, error)
}

type job struct {
	ID, AccountID, DomainID, EmailID string
	Recipient                        string
	Attempts                         int
	DomainName                       string
	Raw                              []byte
}

// Claims per priority so a large backlog of bulk mail never delays transactional mail.
const claimSQL = `
WITH due AS (
    SELECT id FROM deliveries
    WHERE status IN ('queued', 'deferred', 'scheduled') AND priority = $2 AND next_attempt_at <= now()
    ORDER BY next_attempt_at
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
UPDATE deliveries d
SET status = 'sending', attempts = d.attempts + 1, locked_until = now() + interval '15 minutes', updated_at = now()
FROM due, emails e, domains dm
WHERE d.id = due.id AND e.id = d.email_id AND dm.id = d.domain_id
RETURNING d.id, d.account_id, d.domain_id, d.email_id, d.recipient, d.attempts, dm.name, e.raw`

type Worker struct {
	db       *pgxpool.Pool
	cfg      *config.Config
	log      *slog.Logger
	resolver *net.Resolver
	conns    *connPool
	mx       *cache.Cache[[]string]
	results  chan queue.Completion
	limiters *cache.Cache[*rate.Limiter] // per-destination host token bucket
	broker   BrokerConsumer
}

func (w *Worker) SetBroker(b BrokerConsumer) {
	w.broker = b
}

func makeResolver(dnsServer string) *net.Resolver {
	if dnsServer == "" {
		return net.DefaultResolver
	}
	if !strings.Contains(dnsServer, ":") {
		dnsServer = net.JoinHostPort(dnsServer, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
}

func New(db *pgxpool.Pool, cfg *config.Config, log *slog.Logger) *Worker {
	return &Worker{
		db: db, cfg: cfg, log: log, resolver: makeResolver(cfg.DNSServer),
		conns:    newConnPool(cfg.MaxConnsPerHost),
		mx:       cache.New[[]string](5*time.Minute, 200_000),
		limiters: cache.New[*rate.Limiter](30*time.Minute, 100_000),
	}
}

func (w *Worker) hostLimiter(host string) *rate.Limiter {
	l, _ := w.limiters.GetOrLoad(host, func() (*rate.Limiter, error) {
		return rate.NewLimiter(rate.Limit(w.cfg.DestRateLimitRPS), w.cfg.DestRateLimitBurst), nil
	})
	return l
}

func (w *Worker) claim(ctx context.Context, n int) ([]job, error) {
	var out []job
	for _, prio := range []int16{queue.PriorityTransactional, queue.PriorityBulk} {
		if len(out) >= n {
			break
		}
		rows, err := w.db.Query(ctx, claimSQL, n-len(out), prio)
		if err != nil {
			return out, err
		}
		js, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (job, error) {
			var j job
			err := r.Scan(&j.ID, &j.AccountID, &j.DomainID, &j.EmailID, &j.Recipient, &j.Attempts, &j.DomainName, &j.Raw)
			return j, err
		})
		if err != nil {
			return out, err
		}
		out = append(out, js...)
	}
	return out, nil
}

// Run blocks until ctx is cancelled, then waits for in-flight deliveries and flushes their results.
func (w *Worker) Run(ctx context.Context) {
	jobs := make(chan job, w.cfg.Workers)
	w.results = make(chan queue.Completion, w.cfg.Workers*4)
	flushed := make(chan struct{})
	go func() {
		w.flushLoop()
		close(flushed)
	}()
	var wg sync.WaitGroup
	for range w.cfg.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				w.process(j)
			}
		}()
	}
	var prodWg sync.WaitGroup
	if w.broker != nil {
		prodWg.Add(2)
		go func() {
			defer prodWg.Done()
			w.consumeBroker(ctx, broker.QueueTransactional, jobs)
		}()
		go func() {
			defer prodWg.Done()
			w.consumeBroker(ctx, broker.QueueBulk, jobs)
		}()
	}
	defer func() {
		prodWg.Wait()
		close(jobs)
		wg.Wait()
		close(w.results)
		<-flushed
		w.conns.closeAll()
	}()
	go w.maintenance(ctx)

	w.log.Info("delivery worker started", "workers", w.cfg.Workers)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		free := cap(jobs) - len(jobs)
		claimed := 0
		if free > 0 {
			js, err := w.claim(ctx, free)
			if err != nil && ctx.Err() == nil {
				w.log.Error("claim deliveries", "err", err)
			}
			for _, j := range js {
				jobs <- j
			}
			claimed = len(js)
		}
		if free > 0 && claimed == free {
			timer.Reset(10 * time.Millisecond)
		} else {
			timer.Reset(w.cfg.PollInterval)
		}
	}
}

func (w *Worker) consumeBroker(ctx context.Context, queueName string, jobs chan<- job) {
	ch, err := w.broker.Consume(ctx, queueName, w.cfg.Workers)
	if err != nil {
		w.log.Error("failed to start rabbitmq consumer", "queue", queueName, "err", err)
		return
	}
	w.log.Info("rabbitmq consumer started", "queue", queueName)
	for {
		select {
		case <-ctx.Done():
			return
		case djob, ok := <-ch:
			if !ok {
				return
			}
			var attempts int
			err := w.db.QueryRow(ctx, `
UPDATE deliveries SET status = 'sending', attempts = attempts + 1, locked_until = now() + interval '15 minutes', updated_at = now()
WHERE id = $1 AND status IN ('queued', 'deferred')
RETURNING attempts`, djob.Msg.DeliveryID).Scan(&attempts)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					_ = djob.Ack()
				} else {
					w.log.Error("failed to lock delivery from broker", "delivery_id", djob.Msg.DeliveryID, "err", err)
					_ = djob.Nack(true)
				}
				continue
			}
			domName := djob.Msg.DomainName
			if domName == "" {
				if err := w.db.QueryRow(ctx, `SELECT name FROM domains WHERE id = $1`, djob.Msg.DomainID).Scan(&domName); err != nil {
					w.log.Warn("delivery domain lookup failed", "delivery_id", djob.Msg.DeliveryID, "err", err)
					_, _ = w.db.Exec(ctx, `UPDATE deliveries SET status = 'deferred', next_attempt_at = now() + interval '1 minute', locked_until = NULL, updated_at = now(), last_error = $2 WHERE id = $1`, djob.Msg.DeliveryID, "domain lookup failed")
					_ = djob.Ack()
					continue
				}
			}
			raw := djob.Msg.Raw
			if len(raw) == 0 {
				if err := w.db.QueryRow(ctx, `SELECT raw FROM emails WHERE id = $1`, djob.Msg.EmailID).Scan(&raw); err != nil {
					w.log.Warn("delivery message lookup failed", "delivery_id", djob.Msg.DeliveryID, "err", err)
					_, _ = w.db.Exec(ctx, `UPDATE deliveries SET status = 'deferred', next_attempt_at = now() + interval '1 minute', locked_until = NULL, updated_at = now(), last_error = $2 WHERE id = $1`, djob.Msg.DeliveryID, "message lookup failed")
					_ = djob.Ack()
					continue
				}
			}
			j := job{
				ID:         djob.Msg.DeliveryID,
				AccountID:  djob.Msg.AccountID,
				DomainID:   djob.Msg.DomainID,
				DomainName: domName,
				EmailID:    djob.Msg.EmailID,
				Recipient:  djob.Msg.Recipient,
				Attempts:   attempts,
				Raw:        raw,
			}
			select {
			case <-ctx.Done():
				_ = djob.Nack(true)
				return
			case jobs <- j:
				_ = djob.Ack()
			}
		}
	}
}

func (w *Worker) process(j job) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// VERP envelope sender lets asynchronous bounces be matched back to this delivery.
	from := "bounce+" + j.ID + "@" + j.DomainName
	err := w.send(ctx, from, j.Recipient, j.Raw)

	c := queue.Completion{DeliveryID: j.ID}
	switch {
	case err == nil:
		c.Status = "delivered"
	case isPermanent(err):
		c.Status, c.Detail = "bounced", errText(err)
	case j.Attempts >= w.cfg.MaxAttempts:
		c.Status, c.Detail = "failed", errText(err)
	default:
		next := time.Now().Add(backoff(j.Attempts))
		c.Status, c.Detail, c.Next = "deferred", errText(err), &next
	}
	if err != nil {
		w.log.Warn("delivery attempt failed", "delivery_id", j.ID, "attempt", j.Attempts, "err", err)
	}
	w.results <- c
}

// flushLoop groups outcomes into one transaction per 500 results or 50ms, whichever comes first.
func (w *Worker) flushLoop() {
	const maxBatch = 500
	buf := make([]queue.Completion, 0, maxBatch)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case c, ok := <-w.results:
			if !ok {
				w.flush(buf)
				return
			}
			if buf = append(buf, c); len(buf) >= maxBatch {
				w.flush(buf)
				buf = buf[:0]
			}
		case <-tick.C:
			if len(buf) > 0 {
				w.flush(buf)
				buf = buf[:0]
			}
		}
	}
}

func (w *Worker) flush(cs []queue.Completion) {
	if len(cs) == 0 {
		return
	}
	for attempt := range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := queue.CompleteBatch(ctx, w.db, cs)
		cancel()
		if err == nil {
			return
		}
		w.log.Error("flush delivery results", "count", len(cs), "attempt", attempt+1, "err", err)
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
	// Unflushed rows stay 'sending' and are retried by the stale reaper after locked_until.
}

func (w *Worker) maintenance(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	var lastPartition time.Time
	var lastIdempotencyCleanup time.Time
	for {
		if _, err := w.db.Exec(ctx, `
UPDATE deliveries SET status = 'deferred', locked_until = NULL, updated_at = now()
WHERE id IN (SELECT id FROM deliveries WHERE status = 'sending' AND locked_until < now() LIMIT 10000 FOR UPDATE SKIP LOCKED)`); err != nil && ctx.Err() == nil {
			w.log.Error("reap stale deliveries", "err", err)
		}
		if time.Since(lastPartition) > time.Hour {
			if err := db.MaintainPartitions(ctx, w.db, w.cfg.RetentionMonths); err != nil && ctx.Err() == nil {
				w.log.Error("maintain partitions", "err", err)
			} else {
				lastPartition = time.Now()
			}
		}
		if time.Since(lastIdempotencyCleanup) > time.Minute {
			if err := db.ExpireIdempotencyKeys(ctx, w.db, 10_000); err != nil && ctx.Err() == nil {
				w.log.Error("expire idempotency keys", "err", err)
			} else {
				lastIdempotencyCleanup = time.Now()
			}
		}
		w.conns.prune()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func backoff(attempt int) time.Duration {
	d := time.Minute << min(attempt, 10)
	d = min(d, 4*time.Hour)
	// Spread retries from a widespread transient failure, preventing a retry
	// stampede against one recipient provider or the database.
	return time.Duration(float64(d) * (0.9 + rand.Float64()*0.2))
}

func errText(err error) string {
	s := strings.ToValidUTF8(err.Error(), "?")
	if len(s) > 1000 {
		s = s[:1000]
	}
	return s
}

type permanentError struct{ msg string }

func (e permanentError) Error() string { return e.msg }

func isPermanent(err error) bool {
	var p permanentError
	if errors.As(err, &p) {
		return true
	}
	var te *textproto.Error
	return errors.As(err, &te) && te.Code >= 500 && te.Code < 600
}

func (w *Worker) send(ctx context.Context, from, rcpt string, raw []byte) error {
	if w.cfg.RelayHost != "" {
		host, port, err := net.SplitHostPort(w.cfg.RelayHost)
		if err != nil {
			return fmt.Errorf("invalid RELAY_HOST: %w", err)
		}
		return w.deliverTo(ctx, host, port, from, rcpt, raw, true)
	}
	at := strings.LastIndexByte(rcpt, '@')
	if at < 0 {
		return permanentError{"invalid recipient address"}
	}
	hosts, err := w.mxHosts(ctx, strings.ToLower(rcpt[at+1:]))
	if err != nil {
		return err
	}
	var lastErr error
	port := w.cfg.OutboundSMTPPort
	if port == "" {
		port = "25"
	}
	for _, h := range hosts {
		err := w.deliverTo(ctx, h, port, from, rcpt, raw, false)
		if err == nil || isPermanent(err) {
			return err
		}
		lastErr = err
	}
	return lastErr
}

func (w *Worker) mxHosts(ctx context.Context, domain string) ([]string, error) {
	return w.mx.GetOrLoad(domain, func() ([]string, error) {
		mxs, err := w.resolver.LookupMX(ctx, domain)
		if err != nil {
			var dnsErr *net.DNSError
			if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
				return nil, fmt.Errorf("mx lookup: %w", err)
			}
			// RFC 5321 §5.1: no MX records means the domain itself is the implicit MX.
			if _, herr := w.resolver.LookupHost(ctx, domain); herr != nil {
				if errors.As(herr, &dnsErr) && dnsErr.IsNotFound {
					return nil, permanentError{"recipient domain does not exist"}
				}
				return nil, fmt.Errorf("host lookup: %w", herr)
			}
			return []string{domain}, nil
		}
		if len(mxs) == 1 && (mxs[0].Host == "." || mxs[0].Host == "") {
			return nil, permanentError{"recipient domain does not accept mail (null MX)"}
		}
		hosts := make([]string, 0, len(mxs))
		for _, mx := range mxs {
			hosts = append(hosts, strings.TrimSuffix(mx.Host, "."))
		}
		return hosts, nil
	})
}

// deliverTo reuses a pooled connection when possible, falling back to a fresh one if it went stale.
func (w *Worker) deliverTo(ctx context.Context, host, port, from, rcpt string, raw []byte, relay bool) error {
	if w.cfg.DestRateLimitRPS > 0 {
		if err := w.hostLimiter(host).Wait(ctx); err != nil {
			return err
		}
	}
	key := net.JoinHostPort(host, port)
	release, err := w.conns.acquire(ctx, key)
	if err != nil {
		return err
	}
	defer release()

	if pc := w.conns.get(key); pc != nil {
		err := pc.transact(ctx, from, rcpt, raw)
		if err == nil || (isSMTPReply(err) && !isClosing(err)) {
			w.recycle(key, pc, err)
			return err
		}
		pc.close()
	}
	pc, err := w.dial(ctx, host, port, relay)
	if err != nil {
		return err
	}
	err = pc.transact(ctx, from, rcpt, raw)
	w.recycle(key, pc, err)
	return err
}

func (w *Worker) recycle(key string, pc *pooledConn, err error) {
	if err != nil && (!isSMTPReply(err) || isClosing(err) || pc.c.Reset() != nil) {
		pc.close()
		return
	}
	w.conns.put(key, pc)
}

func isSMTPReply(err error) bool {
	var te *textproto.Error
	return errors.As(err, &te)
}

func isClosing(err error) bool {
	var te *textproto.Error
	return errors.As(err, &te) && te.Code == 421
}
