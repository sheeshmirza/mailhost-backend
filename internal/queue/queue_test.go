package queue

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

type mockBroker struct {
	published int
}

func (m *mockBroker) Publish(ctx context.Context, msg brokerDeliveryMsg) error {
	m.published++
	return nil
}

func (m *mockBroker) PublishBatch(ctx context.Context, msgs []brokerDeliveryMsg) error {
	m.published += len(msgs)
	return nil
}

type brokerDeliveryMsg = interface{}

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
}
