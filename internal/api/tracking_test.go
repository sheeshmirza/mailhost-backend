package api

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"mailhost/internal/queue"
)

func TestTrackingBaseURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "http://localhost"},
		{"localhost", "http://localhost"},
		{"localhost:8080", "http://localhost:8080"},
		{"127.0.0.1:3000", "http://127.0.0.1:3000"},
		{"http://localhost:8080", "http://localhost:8080"},
		{"https://mail.example.com", "https://mail.example.com"},
		{"mail.example.com", "https://mail.example.com"},
		{"https://mail.example.com/", "https://mail.example.com"},
	}

	for _, tt := range tests {
		got := trackingBaseURL(tt.input)
		if got != tt.expected {
			t.Errorf("trackingBaseURL(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestInjectTracking(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	delID := uuid.New().String()
	htmlInput := `<html><body><p>Hello</p><a href="https://example.com/dest?name=foo&amp;id=123">Link</a></body></html>`

	res := InjectTracking(htmlInput, "localhost:8080", delID, secret, true, true)

	if !strings.Contains(res, "http://localhost:8080/v1/track/open/"+delID) {
		t.Errorf("expected open tracking pixel with http://localhost:8080, got %s", res)
	}
	if !strings.Contains(res, "http://localhost:8080/v1/track/click/"+delID) {
		t.Errorf("expected click tracking link with http://localhost:8080, got %s", res)
	}

	// Verify the URL query parameter in click tracking
	idx := strings.Index(res, `href="`)
	if idx < 0 {
		t.Fatalf("no href found in result")
	}
	hrefEnd := strings.Index(res[idx+6:], `"`)
	trackedURL := res[idx+6 : idx+6+hrefEnd]

	parsed, err := url.Parse(trackedURL)
	if err != nil {
		t.Fatalf("failed to parse tracked URL: %v", err)
	}
	targetURL := parsed.Query().Get("url")
	sig := parsed.Query().Get("sig")

	// Target URL should have unescaped &amp; to &
	if targetURL != "https://example.com/dest?name=foo&id=123" {
		t.Errorf("expected target URL to be unescaped, got %q", targetURL)
	}

	// Signature verification
	if !verifyTrackingSignature(secret, delID, targetURL, sig) {
		t.Errorf("signature verification failed for %q", targetURL)
	}
}

func TestRecordTrackingEvent(t *testing.T) {
	ctx := context.Background()
	db, err := pgxpool.New(ctx, "postgres://mailhost:mailhost_secret@localhost:5433/mailhost?sslmode=disable")
	if err != nil {
		t.Skip("Postgres not available:", err)
	}
	defer db.Close()

	token := uuid.MustParse("e8a168ed-35b4-4cce-a09b-bca7b2ed2fd2")
	eventType := "opened"
	detail := ""

	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	column := "open_count"
	firstAt := "first_opened_at"
	lastAt := "last_opened_at"
	query := `UPDATE deliveries d SET ` + column + ` = d.` + column + ` + 1, ` +
		firstAt + ` = COALESCE(d.` + firstAt + `, now()), ` + lastAt + ` = now() ` +
		`FROM (` + trackingTargetSQL + `) target WHERE d.id = target.id ` +
		`RETURNING d.account_id, d.domain_id, d.id, d.email_id, d.recipient, ` +
		`(SELECT count(*) FROM deliveries x WHERE x.email_id = d.email_id)`

	rows, err := tx.Query(ctx, query, token)
	if err != nil {
		t.Fatalf("tx.Query failed: %v", err)
	}
	var recipients []trackedRecipient
	for rows.Next() {
		var tracked trackedRecipient
		if err := rows.Scan(&tracked.accountID, &tracked.domainID, &tracked.deliveryID, &tracked.emailID, &tracked.recipient, &tracked.recipientCount); err != nil {
			rows.Close()
			t.Fatalf("scan failed: %v", err)
		}
		recipients = append(recipients, tracked)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	t.Logf("Recipients found: %d", len(recipients))

	events := make([][]any, 0, len(recipients))
	deltas := map[queue.RollupKey]int64{}
	now := time.Now()
	for _, tracked := range recipients {
		var eventDetail *string
		if detail != "" {
			eventDetail = &detail
		}
		events = append(events, []any{tracked.accountID, tracked.domainID, tracked.emailID, tracked.deliveryID, eventType, eventDetail, now})
		deltas[queue.RollupKey{Account: tracked.accountID.String(), Domain: tracked.domainID.String(), Type: eventType}]++
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"events"},
		[]string{"account_id", "domain_id", "email_id", "delivery_id", "type", "detail", "created_at"},
		pgx.CopyFromRows(events)); err != nil {
		t.Fatalf("CopyFrom failed: %v", err)
	}
	t.Log("CopyFrom succeeded!")

	if err := queue.IncrRollups(ctx, tx, deltas); err != nil {
		t.Fatalf("IncrRollups failed: %v", err)
	}
	t.Log("IncrRollups succeeded!")
}

