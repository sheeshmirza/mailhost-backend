// Package queue persists outbound emails and their per-recipient deliveries in Postgres.
// Workers on any number of nodes claim deliveries with FOR UPDATE SKIP LOCKED.
package queue

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"mailhost/internal/broker"
)

const (
	PriorityTransactional int16 = 0
	PriorityBulk          int16 = 1
	rollupShards                = 16
)

// ErrIdempotencyConflict means a caller reused a key with a different request.
var ErrIdempotencyConflict = errors.New("idempotency key was already used for a different request")

// Email contains the persisted message and recipient data needed to enqueue delivery jobs.
type Email struct {
	ID          uuid.UUID
	DomainID    uuid.UUID
	DomainName  string
	BatchID     uuid.UUID // uuid.Nil when not part of a batch
	Priority    int16
	From        string
	Subject     string
	MessageID   string
	Raw         []byte
	Recipients  []string
	Tags        []byte
	ScheduledAt *time.Time
	TemplateID  *uuid.UUID
}

// BrokerPublisher publishes delivery jobs to an optional external transport.
type BrokerPublisher interface {
	Publish(ctx context.Context, msg broker.DeliveryMessage) error
	PublishBatch(ctx context.Context, msgs []broker.DeliveryMessage) error
}

var (
	brokerMu      sync.RWMutex
	defaultBroker BrokerPublisher
)

func SetBroker(b BrokerPublisher) {
	brokerMu.Lock()
	defer brokerMu.Unlock()
	defaultBroker = b
}

func getBroker() BrokerPublisher {
	brokerMu.RLock()
	defer brokerMu.RUnlock()
	return defaultBroker
}

func pgUUID(u uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: u, Valid: u != uuid.Nil} }

// Enqueue stores emails and their deliveries in one transaction using COPY for throughput.
// Suppressed recipients are recorded as failed instead of queued.
func Enqueue(ctx context.Context, db *pgxpool.Pool, accountID uuid.UUID, emails []Email) error {
	if len(emails) == 0 {
		return nil
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	queuedMsgs, err := enqueue(ctx, tx, accountID, emails)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if b := getBroker(); b != nil && len(queuedMsgs) > 0 {
		_ = b.PublishBatch(ctx, queuedMsgs)
	}
	return nil
}

// EnqueueIdempotent atomically stores an API response and enqueues the messages.
// A repeat with the same account, key and request hash returns the original
// response; a different request with that key is rejected.
func EnqueueIdempotent(ctx context.Context, db *pgxpool.Pool, accountID uuid.UUID, emails []Email, keyHash, requestHash, response []byte, ttl time.Duration) ([]byte, bool, error) {
	if len(emails) == 0 {
		return nil, false, errors.New("cannot idempotently enqueue an empty email list")
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)

	var storedResponse string
	err = tx.QueryRow(ctx, `
INSERT INTO idempotency_keys (account_id, key_hash, request_hash, response, expires_at)
VALUES ($1, $2, $3, $4::jsonb, $5)
ON CONFLICT (account_id, key_hash) DO NOTHING
RETURNING response::text`, accountID, keyHash, requestHash, string(response), time.Now().Add(ttl)).Scan(&storedResponse)
	if errors.Is(err, pgx.ErrNoRows) {
		var storedHash []byte
		err = tx.QueryRow(ctx, `
SELECT request_hash, response::text
FROM idempotency_keys
WHERE account_id = $1 AND key_hash = $2`, accountID, keyHash).Scan(&storedHash, &storedResponse)
		if err != nil {
			return nil, false, err
		}
		if !bytes.Equal(storedHash, requestHash) {
			return nil, false, ErrIdempotencyConflict
		}
		return []byte(storedResponse), true, nil
	}
	if err != nil {
		return nil, false, err
	}
	queuedMsgs, err := enqueue(ctx, tx, accountID, emails)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	if b := getBroker(); b != nil && len(queuedMsgs) > 0 {
		_ = b.PublishBatch(ctx, queuedMsgs)
	}
	return []byte(storedResponse), false, nil
}

func enqueue(ctx context.Context, tx pgx.Tx, accountID uuid.UUID, emails []Email) ([]broker.DeliveryMessage, error) {
	var all []string
	for _, e := range emails {
		for _, r := range e.Recipients {
			all = append(all, strings.ToLower(r))
		}
	}
	suppressed := map[string]bool{}
	rows, err := tx.Query(ctx, `SELECT address FROM suppressions WHERE account_id = $1 AND address = ANY($2)`, accountID.String(), all)
	if err != nil {
		return nil, err
	}
	addrs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		suppressed[a] = true
	}

	now := time.Now()
	acct := pgUUID(accountID)
	emailRows := make([][]any, 0, len(emails))
	var deliveryRows, eventRows [][]any
	var hooks []webhookEvent
	deltas := map[RollupKey]int64{}
	var queuedMsgs []broker.DeliveryMessage
	for _, e := range emails {
		eid, did := pgUUID(e.ID), pgUUID(e.DomainID)
		sentKey := RollupKey{accountID.String(), e.DomainID.String(), "sent"}
		failedKey := RollupKey{accountID.String(), e.DomainID.String(), "failed"}
		tags := e.Tags
		if len(tags) == 0 {
			tags = []byte("[]")
		}
		status := "queued"
		nextAttempt := now
		if e.ScheduledAt != nil && e.ScheduledAt.After(now) {
			status = "scheduled"
			nextAttempt = *e.ScheduledAt
		}
		var templateID any = nil
		if e.TemplateID != nil {
			templateID = pgUUID(*e.TemplateID)
		}
		emailRows = append(emailRows, []any{eid, acct, did, pgUUID(e.BatchID), e.From, e.Subject, e.MessageID, e.Raw, tags, e.ScheduledAt, status, templateID, now})
		for _, r := range e.Recipients {
			dlvID := uuid.New()
			if len(e.Recipients) == 1 {
				dlvID = e.ID
			}
			dlv := pgUUID(dlvID)
			if suppressed[strings.ToLower(r)] {
				msg := "recipient is on the suppression list"
				deliveryRows = append(deliveryRows, []any{dlv, eid, acct, did, r, "failed", e.Priority, &msg, now, now, now})
				eventRows = append(eventRows, []any{acct, did, eid, dlv, "failed", &msg, now})
				deltas[failedKey]++
				continue
			}
			deliveryRows = append(deliveryRows, []any{dlv, eid, acct, did, r, status, e.Priority, nil, nextAttempt, now, now})
			eventRows = append(eventRows, []any{acct, did, eid, dlv, "sent", nil, now})
			hooks = append(hooks, webhookEvent{accountID.String(), "email.sent", e.ID.String(), dlvID.String(), r, ""})
			deltas[sentKey]++
			if e.ScheduledAt == nil || !e.ScheduledAt.After(now) {
				queuedMsgs = append(queuedMsgs, broker.DeliveryMessage{
					DeliveryID: dlvID.String(),
					AccountID:  accountID.String(),
					DomainID:   e.DomainID.String(),
					DomainName: e.DomainName,
					EmailID:    e.ID.String(),
					Recipient:  r,
					Priority:   e.Priority,
					Attempts:   0,
					Raw:        e.Raw,
					CreatedAt:  now,
				})
			}
		}
	}

	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"emails"},
		[]string{"id", "account_id", "domain_id", "batch_id", "from_addr", "subject", "message_id", "raw", "tags", "scheduled_at", "status", "template_id", "created_at"},
		pgx.CopyFromRows(emailRows)); err != nil {
		return nil, err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"deliveries"},
		[]string{"id", "email_id", "account_id", "domain_id", "recipient", "status", "priority", "last_error", "next_attempt_at", "created_at", "updated_at"},
		pgx.CopyFromRows(deliveryRows)); err != nil {
		return nil, err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"events"},
		[]string{"account_id", "domain_id", "email_id", "delivery_id", "type", "detail", "created_at"},
		pgx.CopyFromRows(eventRows)); err != nil {
		return nil, err
	}
	if err := incrRollups(ctx, tx, deltas); err != nil {
		return nil, err
	}
	if err := enqueueWebhookEvents(ctx, tx, hooks); err != nil {
		return nil, err
	}
	return queuedMsgs, nil
}

type RollupKey struct{ Account, Domain, Type string }

// IncrRollups adds analytics counters inside the caller's transaction.
func IncrRollups(ctx context.Context, tx pgx.Tx, deltas map[RollupKey]int64) error {
	return incrRollups(ctx, tx, deltas)
}

type webhookEvent struct{ account, typ, emailID, deliveryID, recipient, detail string }

// enqueueWebhookEvents writes email.* events to the webhook outbox inside the caller's transaction;
// the API role's webhook dispatcher delivers them.
func enqueueWebhookEvents(ctx context.Context, tx pgx.Tx, evs []webhookEvent) error {
	if len(evs) == 0 {
		return nil
	}
	n := len(evs)
	accts, types, emails, dlvs, rcpts, details := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, e := range evs {
		accts[i], types[i], emails[i], dlvs[i], rcpts[i], details[i] = e.account, e.typ, e.emailID, e.deliveryID, e.recipient, e.detail
	}
	_, err := tx.Exec(ctx, `
INSERT INTO webhook_deliveries (webhook_id, event_type, payload)
SELECT w.id, x.t, jsonb_build_object(
    'type', x.t,
    'created_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'data', jsonb_strip_nulls(jsonb_build_object('email_id', x.e, 'delivery_id', x.d, 'recipient', x.r, 'detail', NULLIF(x.det, ''))))
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) AS x(a, t, e, d, r, det)
JOIN webhooks w ON w.account_id = x.a::uuid AND w.status = 'active' AND x.t = ANY(w.events)`,
		accts, types, emails, dlvs, rcpts, details)
	return err
}

// incrRollups upserts hourly counters in sorted key order so concurrent writers cannot deadlock.
func incrRollups(ctx context.Context, tx pgx.Tx, deltas map[RollupKey]int64) error {
	if len(deltas) == 0 {
		return nil
	}
	keys := make([]RollupKey, 0, len(deltas))
	for k := range deltas {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b RollupKey) int {
		return strings.Compare(a.Account+a.Domain+a.Type, b.Account+b.Domain+b.Type)
	})
	accts, doms, types := make([]string, len(keys)), make([]string, len(keys)), make([]string, len(keys))
	counts := make([]int64, len(keys))
	for i, k := range keys {
		accts[i], doms[i], types[i], counts[i] = k.Account, k.Domain, k.Type, deltas[k]
	}
	_, err := tx.Exec(ctx, `
INSERT INTO event_rollups (account_id, domain_id, bucket, type, shard, count)
SELECT a::uuid, d::uuid, date_trunc('hour', now()), t, $5, c
FROM unnest($1::text[], $2::text[], $3::text[], $4::bigint[]) AS x(a, d, t, c)
ON CONFLICT (account_id, bucket, domain_id, type, shard)
DO UPDATE SET count = event_rollups.count + EXCLUDED.count`,
		accts, doms, types, counts, int16(rand.IntN(rollupShards)))
	return err
}

// Completion is the outcome of one delivery attempt; Status "deferred" means retry at Next.
type Completion struct {
	DeliveryID string
	Status     string
	Detail     string
	Next       *time.Time
}

// CompleteBatch applies many delivery outcomes in one transaction (update, events, suppressions, rollups).
func CompleteBatch(ctx context.Context, db *pgxpool.Pool, cs []Completion) error {
	n := len(cs)
	if n == 0 {
		return nil
	}
	ids, statuses, details := make([]string, n), make([]string, n), make([]string, n)
	nexts := make([]pgtype.Timestamptz, n)
	for i, c := range cs {
		ids[i], statuses[i], details[i] = c.DeliveryID, c.Status, c.Detail
		if c.Next != nil {
			nexts[i] = pgtype.Timestamptz{Time: *c.Next, Valid: true}
		}
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
UPDATE deliveries d
SET status = u.status, last_error = NULLIF(u.detail, ''), next_attempt_at = COALESCE(u.next, d.next_attempt_at),
    locked_until = NULL, updated_at = now()
FROM unnest($1::text[], $2::text[], $3::text[], $4::timestamptz[]) AS u(id, status, detail, next)
WHERE d.id = u.id::uuid AND d.status = 'sending'
RETURNING d.id, d.account_id, d.domain_id, d.email_id, d.recipient, u.status, u.detail`,
		ids, statuses, details, nexts)
	if err != nil {
		return err
	}
	type sup struct{ account, address, reason string }
	var events [][]any
	var sups []sup
	var hooks []webhookEvent
	deltas := map[RollupKey]int64{}
	emailIDs := make(map[string]struct{})
	now := time.Now()
	for rows.Next() {
		var id, acct, dom, email pgtype.UUID
		var rcpt, status, detail string
		if err := rows.Scan(&id, &acct, &dom, &email, &rcpt, &status, &detail); err != nil {
			rows.Close()
			return err
		}
		emailIDs[uuid.UUID(email.Bytes).String()] = struct{}{}
		if status == "deferred" {
			continue
		}
		var d *string
		if detail != "" {
			d = &detail
		}
		events = append(events, []any{acct, dom, email, id, status, d, now})
		account := uuid.UUID(acct.Bytes).String()
		deltas[RollupKey{account, uuid.UUID(dom.Bytes).String(), status}]++
		if status == "delivered" || status == "bounced" {
			hooks = append(hooks, webhookEvent{account, "email." + status, uuid.UUID(email.Bytes).String(), uuid.UUID(id.Bytes).String(), rcpt, detail})
		}
		if status == "bounced" {
			sups = append(sups, sup{account, strings.ToLower(rcpt), detail})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(emailIDs) > 0 {
		ids := make([]string, 0, len(emailIDs))
		for id := range emailIDs {
			ids = append(ids, id)
		}
		if err := refreshEmailStatuses(ctx, tx, ids); err != nil {
			return err
		}
	}

	if len(events) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"events"},
			[]string{"account_id", "domain_id", "email_id", "delivery_id", "type", "detail", "created_at"},
			pgx.CopyFromRows(events)); err != nil {
			return err
		}
	}
	if len(sups) > 0 {
		slices.SortFunc(sups, func(a, b sup) int { return strings.Compare(a.account+a.address, b.account+b.address) })
		sups = slices.CompactFunc(sups, func(a, b sup) bool { return a.account == b.account && a.address == b.address })
		accts, addrs, reasons := make([]string, len(sups)), make([]string, len(sups)), make([]string, len(sups))
		for i, s := range sups {
			accts[i], addrs[i], reasons[i] = s.account, s.address, s.reason
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO suppressions (account_id, address, reason)
SELECT a::uuid, addr, r FROM unnest($1::text[], $2::text[], $3::text[]) AS x(a, addr, r)
ON CONFLICT DO NOTHING`, accts, addrs, reasons); err != nil {
			return err
		}
	}
	if err := incrRollups(ctx, tx, deltas); err != nil {
		return err
	}
	if err := enqueueWebhookEvents(ctx, tx, hooks); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func refreshEmailStatuses(ctx context.Context, tx pgx.Tx, emailIDs []string) error {
	_, err := tx.Exec(ctx, `
UPDATE emails e
SET status = CASE
	WHEN EXISTS (SELECT 1 FROM deliveries d WHERE d.email_id = e.id AND d.status IN ('queued', 'deferred', 'sending')) THEN 'queued'
	WHEN EXISTS (SELECT 1 FROM deliveries d WHERE d.email_id = e.id AND d.status = 'bounced') THEN 'bounced'
	WHEN EXISTS (SELECT 1 FROM deliveries d WHERE d.email_id = e.id AND d.status = 'failed') THEN 'failed'
	ELSE 'delivered'
END
WHERE e.id = ANY($1::uuid[]) AND e.status <> 'cancelled'`, emailIDs)
	return err
}

// MarkBounced handles asynchronous bounces (DSNs) received after a delivery was accepted.
func MarkBounced(ctx context.Context, db *pgxpool.Pool, accountID, deliveryID, detail string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var dom, email string
	var rcpt string
	err = tx.QueryRow(ctx, `
UPDATE deliveries SET status = 'bounced', last_error = $3, updated_at = now()
WHERE id = $1 AND account_id = $2 AND status IN ('delivered', 'sending', 'deferred')
RETURNING domain_id, email_id, recipient`, deliveryID, accountID, detail).Scan(&dom, &email, &rcpt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO events (account_id, domain_id, email_id, delivery_id, type, detail) VALUES ($1, $2, $3, $4, 'bounced', $5)`,
		accountID, dom, email, deliveryID, detail); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO suppressions (account_id, address, reason) VALUES ($1, lower($2), $3) ON CONFLICT DO NOTHING`,
		accountID, rcpt, detail); err != nil {
		return err
	}
	if err := incrRollups(ctx, tx, map[RollupKey]int64{{accountID, dom, "bounced"}: 1}); err != nil {
		return err
	}
	if err := refreshEmailStatuses(ctx, tx, []string{email}); err != nil {
		return err
	}
	if err := enqueueWebhookEvents(ctx, tx, []webhookEvent{{accountID, "email.bounced", email, deliveryID, rcpt, detail}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
