package delivery

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"mailhost/internal/config"
	"mailhost/internal/queue"
)

func TestIsPermanent(t *testing.T) {
	if !isPermanent(permanentError{"recipient domain does not exist"}) {
		t.Error("expected permanentError to be permanent")
	}

	smtp550 := &textproto.Error{Code: 550, Msg: "User unknown"}
	if !isPermanent(smtp550) {
		t.Error("expected 550 SMTP error to be permanent")
	}

	smtp451 := &textproto.Error{Code: 451, Msg: "Try again later"}
	if isPermanent(smtp451) {
		t.Error("expected 451 SMTP error to be temporary")
	}

	genericErr := errors.New("network timeout")
	if isPermanent(genericErr) {
		t.Error("expected generic network error to be temporary")
	}
}

func TestIsClosing(t *testing.T) {
	smtp421 := &textproto.Error{Code: 421, Msg: "Service closing transmission channel"}
	if !isClosing(smtp421) {
		t.Error("expected 421 to be closing")
	}

	smtp500 := &textproto.Error{Code: 500, Msg: "Syntax error"}
	if isClosing(smtp500) {
		t.Error("expected 500 to not be closing")
	}
}

func TestIsSMTPReply(t *testing.T) {
	smtpError := &textproto.Error{Code: 250, Msg: "OK"}
	if !isSMTPReply(smtpError) {
		t.Error("expected textproto.Error to be SMTP reply")
	}

	if isSMTPReply(errors.New("other error")) {
		t.Error("expected standard error to not be SMTP reply")
	}
}

func TestHashStr(t *testing.T) {
	h1 := hashStr("mx1.example.com")
	h2 := hashStr("mx1.example.com")
	h3 := hashStr("mx2.example.com")

	if h1 != h2 {
		t.Errorf("hashStr is not deterministic: %d vs %d", h1, h2)
	}
	if h1 == h3 {
		t.Errorf("expected distinct hashes for distinct hosts")
	}
}

func TestConnPool(t *testing.T) {
	pool := newConnPool(2)
	ctx := context.Background()

	// Acquire two connections for host A
	rel1, err := pool.acquire(ctx, "mx.example.com:25")
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	rel2, err := pool.acquire(ctx, "mx.example.com:25")
	if err != nil {
		t.Fatalf("second acquire failed: %v", err)
	}

	// Third acquire should block until release
	ctxTimeout, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	_, err = pool.acquire(ctxTimeout, "mx.example.com:25")
	if err == nil {
		t.Error("expected acquire to block and time out when maxPerHost is reached")
	}

	// Release one and re-acquire
	rel1()
	rel3, err := pool.acquire(ctx, "mx.example.com:25")
	if err != nil {
		t.Fatalf("acquire after release failed: %v", err)
	}
	rel2()
	rel3()

	pool.closeAll()
}

func TestMakeResolver(t *testing.T) {
	r1 := makeResolver("")
	if r1 == nil {
		t.Error("expected non-nil default resolver")
	}

	r2 := makeResolver("1.1.1.1:53")
	if r2 == nil {
		t.Error("expected non-nil custom resolver")
	}

	r3 := makeResolver("8.8.8.8")
	if r3 == nil {
		t.Error("expected non-nil custom resolver without explicit port")
	}
}

func TestBackoffAndErrText(t *testing.T) {
	// Backoff
	b0 := backoff(0)
	if b0 < 30*time.Second || b0 > 2*time.Minute {
		t.Errorf("unexpected backoff(0): %v", b0)
	}
	b5 := backoff(5)
	if b5 <= b0 {
		t.Errorf("expected backoff(5) > backoff(0), got %v <= %v", b5, b0)
	}

	// ErrText
	shortErr := errors.New("short error")
	if errText(shortErr) != "short error" {
		t.Errorf("unexpected errText: %s", errText(shortErr))
	}
	longErr := errors.New(strings.Repeat("X", 2000))
	if len(errText(longErr)) != 1000 {
		t.Errorf("expected errText to be truncated to 1000, got %d", len(errText(longErr)))
	}
}

func TestConnPoolEdgeCases(t *testing.T) {
	// acquire when maxPerHost <= 0
	poolUnbounded := newConnPool(0)
	rel, err := poolUnbounded.acquire(context.Background(), "host:25")
	if err != nil {
		t.Fatalf("unexpected error for unbounded pool: %v", err)
	}
	rel()

	// get from empty pool
	if pc := poolUnbounded.get("nonexistent:25"); pc != nil {
		t.Error("expected nil for empty pool get")
	}

	// prune on empty pool
	poolUnbounded.prune()
	poolUnbounded.closeAll()
}

func TestDeliverToLiveMailpit(t *testing.T) {
	// Mailpit runs on localhost:1025
	conn, err := net.DialTimeout("tcp", "localhost:1025", 1*time.Second)
	if err != nil {
		t.Skipf("skipping live mailpit delivery test (port 1025 unavailable): %v", err)
		return
	}
	conn.Close()

	cfg := &config.Config{
		AllowPrivateDelivery: true,
		OutboundSMTPPort:     "1025",
		MaxConnsPerHost:      4,
		DestRateLimitRPS:     100,
		DestRateLimitBurst:   10,
	}
	w := New(nil, cfg, slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	from := "sender@test.local"
	rcpt := "recipient@test.local"
	raw := []byte("From: sender@test.local\r\nTo: recipient@test.local\r\nSubject: Test Delivery\r\n\r\nHello Mailpit!")

	// 1st delivery (establishes new connection and pools it)
	if err := w.deliverTo(ctx, "localhost", "1025", from, rcpt, raw); err != nil {
		t.Fatalf("first deliverTo failed: %v", err)
	}

	// 2nd delivery (reuses connection from pool!)
	if err := w.deliverTo(ctx, "localhost", "1025", from, rcpt, raw); err != nil {
		t.Fatalf("second deliverTo (reusing pooled connection) failed: %v", err)
	}

	// Send to invalid recipient without '@'
	if err := w.send(ctx, from, "invalidrecipient", raw); err == nil {
		t.Error("expected error for recipient address without @")
	}

	w.conns.closeAll()
}

func TestWorkerProcessAndFlush(t *testing.T) {
	cfg := &config.Config{
		MaxAttempts: 3,
	}
	w := New(nil, cfg, slog.Default())
	w.SetBroker(nil)
	w.results = make(chan queue.Completion, 10)

	// Process job with permanent bounce (invalid recipient)
	j1 := job{
		ID:         "deliv-001",
		Recipient:  "bad-address-no-at",
		DomainName: "example.com",
		Attempts:   1,
	}
	w.process(j1)

	select {
	case res := <-w.results:
		if res.Status != "bounced" {
			t.Errorf("expected status 'bounced', got %s", res.Status)
		}
	default:
		t.Fatal("expected result in w.results")
	}

	// flush with empty slice should be a no-op
	w.flush(nil)

	// hostLimiter caching
	l1 := w.hostLimiter("mx.test.com")
	l2 := w.hostLimiter("mx.test.com")
	if l1 != l2 {
		t.Error("expected cached limiter instance")
	}
}



