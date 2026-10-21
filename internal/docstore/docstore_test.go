package docstore

import (
	"context"
	"testing"
	"time"
)

func TestDocstoreNilSafety(t *testing.T) {
	var c *Client
	ctx := context.Background()

	if err := c.Ping(ctx); err == nil {
		t.Error("expected error for nil client Ping")
	}
	if err := c.SaveEmail(ctx, EmailDocument{ID: "test"}); err == nil {
		t.Error("expected error for nil client SaveEmail")
	}
	if doc, err := c.GetEmail(ctx, "test"); doc != nil || err == nil {
		t.Error("expected error for nil client GetEmail")
	}
	if err := c.SaveInbound(ctx, InboundDocument{ID: "test"}); err == nil {
		t.Error("expected error for nil client SaveInbound")
	}
	if doc, err := c.GetInbound(ctx, "test"); doc != nil || err == nil {
		t.Error("expected error for nil client GetInbound")
	}
	if err := c.Close(ctx); err != nil {
		t.Errorf("expected nil error for Close, got %v", err)
	}
}

func TestLiveDocstoreClient(t *testing.T) {
	client, err := New("mongodb://localhost:27018", "mailhost_test")
	if err != nil {
		t.Skipf("skipping live mongodb test: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer client.Close(ctx)

	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	emailDoc := EmailDocument{
		ID:         "email_unit_test_123",
		AccountID:  "acct_unit_test",
		DomainID:   "dom_unit_test",
		From:       "test@example.com",
		Recipients: []string{"user@example.com"},
		Subject:    "Unit Test Subject",
		HTML:       "<p>Hello world</p>",
		Size:       18,
		CreatedAt:  time.Now().UTC().Truncate(time.Millisecond),
	}

	if err := client.SaveEmail(ctx, emailDoc); err != nil {
		t.Fatalf("SaveEmail failed: %v", err)
	}

	retrieved, err := client.GetEmail(ctx, emailDoc.ID)
	if err != nil || retrieved == nil {
		t.Fatalf("GetEmail failed: %v", err)
	}
	if retrieved.Subject != emailDoc.Subject || retrieved.From != emailDoc.From {
		t.Errorf("expected subject %q and from %q, got subject %q and from %q",
			emailDoc.Subject, emailDoc.From, retrieved.Subject, retrieved.From)
	}

	// Test non-existent doc returns (nil, nil)
	missing, err := client.GetEmail(ctx, "non_existent_id")
	if err != nil {
		t.Errorf("expected nil error for missing email, got %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil for missing email, got %+v", missing)
	}

	inboundDoc := InboundDocument{
		ID:        "inbound_unit_test_123",
		AccountID: "acct_unit_test",
		DomainID:  "dom_unit_test",
		MailFrom:  "sender@remote.com",
		RcptTo:    []string{"inbox@example.com"},
		Subject:   "Inbound Test",
		Size:      12,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}

	if err := client.SaveInbound(ctx, inboundDoc); err != nil {
		t.Fatalf("SaveInbound failed: %v", err)
	}

	inRetrieved, err := client.GetInbound(ctx, inboundDoc.ID)
	if err != nil || inRetrieved == nil {
		t.Fatalf("GetInbound failed: %v", err)
	}
	if inRetrieved.Subject != inboundDoc.Subject {
		t.Errorf("expected inbound subject %q, got %q", inboundDoc.Subject, inRetrieved.Subject)
	}
}

