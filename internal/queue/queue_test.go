package queue

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"

	"mailhost/internal/db"
)

func TestBrokerRegistration(t *testing.T) {
	orig := getBroker()
	defer SetBroker(orig)

	if getBroker() != orig {
		t.Error("expected broker to match orig")
	}

	SetBroker(nil)
	if getBroker() != nil {
		t.Error("expected nil broker after SetBroker(nil)")
	}
}

func TestPgUUID(t *testing.T) {
	nilID := uuid.Nil
	pgNil := pgUUID(nilID)
	if pgNil.Valid {
		t.Error("expected pgUUID(uuid.Nil) to have Valid=false")
	}

	validID := uuid.New()
	pgValid := pgUUID(validID)
	if !pgValid.Valid || pgValid.Bytes != validID {
		t.Error("expected pgUUID to preserve valid UUID bytes and Valid=true")
	}
}

func TestEmptyBatchHandling(t *testing.T) {
	ctx := context.Background()

	// Enqueue with empty slice should return nil without database calls
	if err := Enqueue(ctx, nil, uuid.New(), nil); err != nil {
		t.Errorf("expected nil error for empty emails, got %v", err)
	}

	// CompleteBatch with empty slice should return nil
	if err := CompleteBatch(ctx, nil, nil); err != nil {
		t.Errorf("expected nil error for empty completions, got %v", err)
	}

	// IncrRollups with empty map should return nil
	if err := IncrRollups(ctx, nil, nil); err != nil {
		t.Errorf("expected nil error for empty deltas, got %v", err)
	}

	// EnqueueIdempotent with empty emails should return error
	if _, _, err := EnqueueIdempotent(ctx, nil, uuid.New(), nil, nil, nil, nil, time.Hour); err == nil {
		t.Error("expected error for empty emails in EnqueueIdempotent")
	}
}

func TestQueueLiveLifecycle(t *testing.T) {
	connURL := "postgres://mailhost:mailhost_secret@localhost:5433/mailhost?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, connURL, 5)
	if err != nil {
		t.Skipf("skipping live queue test (port 5433 unavailable): %v", err)
		return
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	accountID := uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO accounts (id, name) VALUES ($1, 'Queue Account')`, accountID)
	if err != nil {
		t.Fatalf("failed to insert test account: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM accounts WHERE id = $1`, accountID)

	domainID := uuid.New()
	domainName := "testqueue-" + domainID.String()[:8] + ".local"
	_, err = pool.Exec(ctx, `
INSERT INTO domains (id, account_id, name, status, verification_token, dkim_selector, dkim_private_key, dkim_public_key, webhook_secret)
VALUES ($1, $2, $3, 'verified', 'tok_123', 'k1', 'sec_key', 'pub_key', 'sec')`, domainID, accountID, domainName)
	if err != nil {
		t.Fatalf("failed to insert test domain: %v", err)
	}


	// 1. Enqueue
	emailID := uuid.New()
	email := Email{
		ID:         emailID,
		DomainID:   domainID,
		DomainName: "testqueue.local",
		Priority:   PriorityTransactional,
		From:       "sender@testqueue.local",
		Subject:    "Queue Test Subject",
		MessageID:  "msg-001@testqueue.local",
		Raw:        []byte("Subject: Queue Test\r\n\r\nHello"),
		Recipients: []string{"user1@remote.com"},
	}

	if err := Enqueue(ctx, pool, accountID, []Email{email}); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// 2. EnqueueIdempotent
	email2 := email
	email2.ID = uuid.New()
	email2.MessageID = "msg-002@testqueue.local"

	idempKey := sha256.Sum256([]byte("idemp-key-1"))
	reqHash1 := sha256.Sum256([]byte("request-payload-1"))
	respJSON := []byte(`{"id":"` + email2.ID.String() + `"}`)

	// First idempotent enqueue
	resp, replayed, err := EnqueueIdempotent(ctx, pool, accountID, []Email{email2}, idempKey[:], reqHash1[:], respJSON, 24*time.Hour)
	if err != nil || replayed || len(resp) == 0 {
		t.Fatalf("first EnqueueIdempotent failed: resp=%s, replayed=%v, err=%v", string(resp), replayed, err)
	}

	// Replay idempotent enqueue (same key and request hash)
	resp2, replayed2, err := EnqueueIdempotent(ctx, pool, accountID, []Email{email2}, idempKey[:], reqHash1[:], respJSON, 24*time.Hour)
	if err != nil || !replayed2 || string(resp2) != string(resp) {
		t.Fatalf("replay EnqueueIdempotent failed: resp2=%s, replayed=%v, err=%v", string(resp2), replayed2, err)
	}


	// Conflicting idempotent enqueue (same key, different request hash)
	reqHash2 := sha256.Sum256([]byte("different-payload"))
	_, _, err = EnqueueIdempotent(ctx, pool, accountID, []Email{email2}, idempKey[:], reqHash2[:], respJSON, 24*time.Hour)
	if err != ErrIdempotencyConflict {
		t.Errorf("expected ErrIdempotencyConflict, got: %v", err)
	}

	// 3. CompleteBatch: mark delivery as sending, then complete it
	_, err = pool.Exec(ctx, `UPDATE deliveries SET status = 'sending' WHERE email_id = $1`, emailID)
	if err != nil {
		t.Fatalf("failed to update delivery to sending: %v", err)
	}

	completions := []Completion{
		{DeliveryID: emailID.String(), Status: "delivered"},
	}
	if err := CompleteBatch(ctx, pool, completions); err != nil {
		t.Fatalf("CompleteBatch failed: %v", err)
	}

	// 4. MarkBounced
	if err := MarkBounced(ctx, pool, accountID.String(), emailID.String(), "SMTP 550 User Unknown"); err != nil {
		t.Fatalf("MarkBounced failed: %v", err)
	}
}


