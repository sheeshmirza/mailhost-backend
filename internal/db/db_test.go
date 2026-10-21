package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestEmbeddedSchema(t *testing.T) {
	if len(schema) == 0 {
		t.Fatal("expected embedded schema to be non-empty")
	}

	requiredTables := []string{
		"CREATE TABLE IF NOT EXISTS accounts",
		"CREATE TABLE IF NOT EXISTS domains",
		"CREATE TABLE IF NOT EXISTS emails",
		"CREATE TABLE IF NOT EXISTS deliveries",
		"CREATE TABLE IF NOT EXISTS events",
		"CREATE TABLE IF NOT EXISTS event_rollups",
		"CREATE TABLE IF NOT EXISTS suppressions",
		"CREATE TABLE IF NOT EXISTS api_keys",
		"CREATE TABLE IF NOT EXISTS webhooks",
	}

	for _, tbl := range requiredTables {
		if !strings.Contains(schema, tbl) {
			t.Errorf("schema missing expected table definition: %q", tbl)
		}
	}
}

func TestExpireIdempotencyKeysValidation(t *testing.T) {
	ctx := context.Background()

	// limit < 1 should return nil without making DB calls
	if err := ExpireIdempotencyKeys(ctx, nil, 0); err != nil {
		t.Errorf("expected nil error for limit=0, got %v", err)
	}
	if err := ExpireIdempotencyKeys(ctx, nil, -5); err != nil {
		t.Errorf("expected nil error for limit=-5, got %v", err)
	}
}

func TestConnectInvalidURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if _, err := Connect(ctx, "invalid-postgres-url", 5); err == nil {
		t.Error("expected error for invalid postgres URL")
	}
}

func TestLivePostgresConnectAndPing(t *testing.T) {
	// Connect to local container PostgreSQL on port 5433
	connURL := "postgres://mailhost:mailhost_secret@localhost:5433/mailhost?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := Connect(ctx, connURL, 5)
	if err != nil {
		t.Skipf("skipping live postgres test (port 5433 not accessible from host): %v", err)
		return
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	// Test Migrate
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// Test MaintainPartitions with retention
	if err := MaintainPartitions(ctx, pool, 3); err != nil {
		t.Fatalf("MaintainPartitions failed: %v", err)
	}

	// Verify idempotency cleanup on live pool
	if err := ExpireIdempotencyKeys(ctx, pool, 10); err != nil {
		t.Errorf("ExpireIdempotencyKeys failed: %v", err)
	}

	// Test Connect with small maxConns (<= 4)
	smallPool, err := Connect(ctx, connURL, 2)
	if err != nil {
		t.Fatalf("Connect with small maxConns failed: %v", err)
	}
	smallPool.Close()
}


