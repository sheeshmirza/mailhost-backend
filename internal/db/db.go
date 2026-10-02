// Package db manages PostgreSQL connections, schema migrations, and event partitions.
package db

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	migrationLockID = 727274
	partitionLockID = 727275
)

//go:embed schema.sql
var schema string

// Connect creates and health-checks a PostgreSQL connection pool.
func Connect(ctx context.Context, url string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = maxConns
	if maxConns > 4 {
		cfg.MinConns = maxConns / 4
	} else {
		cfg.MinConns = 1
	}
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// Migrate applies the idempotent schema; an advisory lock serialises concurrent instances.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockID)
	_, err = conn.Exec(ctx, schema)
	return err
}

// MaintainPartitions pre-creates upcoming monthly event partitions and drops expired ones.
// Only one instance does the work at a time.
func MaintainPartitions(ctx context.Context, pool *pgxpool.Pool, retentionMonths int) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", partitionLockID).Scan(&got); err != nil || !got {
		return err
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", partitionLockID)

	now := time.Now().UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for i := range 3 {
		from := month.AddDate(0, i, 0)
		// Identifiers and bounds are derived from dates only, never from user input.
		sql := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS events_%s PARTITION OF events FOR VALUES FROM ('%s') TO ('%s')`,
			from.Format("200601"), from.Format(time.RFC3339), from.AddDate(0, 1, 0).Format(time.RFC3339))
		if _, err := conn.Exec(ctx, sql); err != nil {
			return err
		}
	}
	if retentionMonths > 0 {
		for i := retentionMonths + 1; i <= retentionMonths+24; i++ {
			if _, err := conn.Exec(ctx, "DROP TABLE IF EXISTS events_"+month.AddDate(0, -i, 0).Format("200601")); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExpireIdempotencyKeys removes a bounded batch of expired keys. Keeping this
// incremental prevents a large delete from causing long locks or vacuum debt.
func ExpireIdempotencyKeys(ctx context.Context, pool *pgxpool.Pool, limit int) error {
	if limit < 1 {
		return nil
	}
	_, err := pool.Exec(ctx, `
WITH expired AS (
    SELECT ctid FROM idempotency_keys
    WHERE expires_at < now()
    LIMIT $1
)
DELETE FROM idempotency_keys i
USING expired e
WHERE i.ctid = e.ctid`, limit)
	return err
}
