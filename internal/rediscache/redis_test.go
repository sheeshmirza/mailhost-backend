package rediscache

import (
	"context"
	"testing"
	"time"
)

func TestClientNilSafety(t *testing.T) {
	var c *Client
	ctx := context.Background()

	if err := c.Ping(ctx); err == nil {
		t.Error("expected error for nil client Ping")
	}
	if _, ok, err := c.Get(ctx, "k"); ok || err == nil {
		t.Error("expected error for nil client Get")
	}
	if err := c.Set(ctx, "k", []byte("v"), time.Second); err == nil {
		t.Error("expected error for nil client Set")
	}
	if err := c.Delete(ctx, "k"); err != nil {
		t.Errorf("expected no error for nil client Delete, got %v", err)
	}
	if allowed, err := c.AllowRate(ctx, "k", 10, time.Second); !allowed || err != nil {
		t.Errorf("expected allowed=true and err=nil for nil client AllowRate, got %v, %v", allowed, err)
	}
	if err := c.AddSuppression(ctx, "acct", "test@example.com"); err != nil {
		t.Errorf("expected nil error for AddSuppression, got %v", err)
	}
	if err := c.RemoveSuppression(ctx, "acct", "test@example.com"); err != nil {
		t.Errorf("expected nil error for RemoveSuppression, got %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("expected nil error for Close, got %v", err)
	}
}

func TestLiveRedisClient(t *testing.T) {
	client, err := New("redis://localhost:6380/0")
	if err != nil {
		t.Skipf("skipping live redis test: %v", err)
		return
	}
	defer client.Close()

	ctx := context.Background()
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	key := "test:rediscache:unit_test"
	val := []byte("hello-mailhost-cache")

	if err := client.Set(ctx, key, val, 10*time.Second); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	got, ok, err := client.Get(ctx, key)
	if err != nil || !ok {
		t.Fatalf("Get failed: ok=%v, err=%v", ok, err)
	}
	if string(got) != string(val) {
		t.Fatalf("expected %q, got %q", string(val), string(got))
	}

	// Test rate limiting
	rateKey := "test:rediscache:rate"
	for i := 0; i < 3; i++ {
		allowed, err := client.AllowRate(ctx, rateKey, 3, 2*time.Second)
		if err != nil || !allowed {
			t.Fatalf("request %d should be allowed, got allowed=%v, err=%v", i+1, allowed, err)
		}
	}
	// 4th request should exceed limit of 3
	allowed, err := client.AllowRate(ctx, rateKey, 3, 2*time.Second)
	if err != nil {
		t.Fatalf("AllowRate error: %v", err)
	}
	if allowed {
		t.Fatal("expected request 4 to be rate limited (allowed=false)")
	}

	// Test suppressions
	acctID := "test_acct_123"
	supEmail := "bounce@example.com"
	if err := client.AddSuppression(ctx, acctID, supEmail); err != nil {
		t.Fatalf("AddSuppression failed: %v", err)
	}
	if err := client.RemoveSuppression(ctx, acctID, supEmail); err != nil {
		t.Fatalf("RemoveSuppression failed: %v", err)
	}

	// Cleanup
	_ = client.Delete(ctx, key, rateKey, "sups:"+acctID)
}

