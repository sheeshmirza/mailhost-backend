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

	"github.com/google/uuid"

	"mailhost/internal/broker"
	"mailhost/internal/config"
	"mailhost/internal/db"
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

	// put with max uses or expired age
	pipeClient, pipeServer := net.Pipe()
	defer pipeServer.Close()
	pcUsed := &pooledConn{
		conn:    pipeClient,
		uses:    connMaxUses,
		created: time.Now(),
	}
	poolUnbounded.put("host:25", pcUsed)

	pipeClient2, pipeServer2 := net.Pipe()
	defer pipeServer2.Close()
	pcOld := &pooledConn{
		conn:    pipeClient2,
		uses:    1,
		created: time.Now().Add(-connMaxAge - time.Hour),
	}
	poolUnbounded.put("host:25", pcOld)

	// put valid connection
	pipeClient3, pipeServer3 := net.Pipe()
	defer pipeServer3.Close()
	pcValid := &pooledConn{
		conn:    pipeClient3,
		uses:    1,
		created: time.Now(),
	}
	poolUnbounded.put("host:25", pcValid)
	if got := poolUnbounded.get("host:25"); got == nil {
		t.Error("expected to retrieve valid pooled conn")
	}

	// dial edge cases
	wDial := New(nil, &config.Config{AllowPrivateDelivery: true}, slog.Default())
	ctxDial, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	if _, err := wDial.dial(ctxDial, "localhost", "1025"); err != nil {
		t.Logf("dial 1025: %v", err)
	}
	if _, err := wDial.dial(ctxDial, "localhost", "99999"); err == nil {
		t.Error("expected error dialing invalid port")
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

	// Seed MX cache with localhost and send via w.send
	_, _ = w.mx.GetOrLoad("mailpit.local", func() ([]string, error) {
		return []string{"localhost"}, nil
	})
	if err := w.send(ctx, from, "recipient@mailpit.local", raw); err != nil {
		t.Fatalf("send to mailpit.local failed: %v", err)
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

	// Process job exceeding max attempts
	jMax := job{
		ID:         "deliv-002",
		Recipient:  "good@mailpit.local",
		DomainName: "mailpit.local",
		Attempts:   5,
	}
	w.process(jMax)

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

func TestWorkerMXHosts(t *testing.T) {
	w := New(nil, &config.Config{}, slog.Default())
	ctx := context.Background()
	hosts, err := w.mxHosts(ctx, "gmail.com")
	if err != nil || len(hosts) == 0 {
		t.Errorf("expected MX hosts for gmail.com, got %v, err=%v", hosts, err)
	}
	// Cached lookup
	hostsCached, err := w.mxHosts(ctx, "gmail.com")
	if err != nil || len(hostsCached) != len(hosts) {
		t.Errorf("expected cached MX hosts, got %v", hostsCached)
	}
	// Invalid domain
	_, err = w.mxHosts(ctx, "nonexistent-domain-xyz-12345.test")
	if err == nil {
		t.Error("expected error for non-existent domain")
	}
}

func TestWorkerRunAndClaim(t *testing.T) {
	connURL := "postgres://mailhost:mailhost_secret@localhost:5433/mailhost?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, connURL, 5)
	if err != nil {
		t.Skipf("skipping live delivery postgres test: %v", err)
		return
	}
	defer pool.Close()

	accountID := uuid.New().String()
	_, err = pool.Exec(ctx, `INSERT INTO accounts (id, name) VALUES ($1, 'Delivery Acct')`, accountID)
	if err != nil {
		t.Fatalf("failed to insert account: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM accounts WHERE id = $1`, accountID)

	domainID := uuid.New().String()
	_, err = pool.Exec(ctx, `INSERT INTO domains (id, account_id, name, status, verification_token, dkim_selector, dkim_private_key, dkim_public_key, webhook_secret, region) VALUES ($1, $2, 'delivery.local', 'verified', 'tok', 'k1', 'priv', 'pub', 'sec', 'us-east-1')`, domainID, accountID)
	if err != nil {
		t.Fatalf("failed to insert domain: %v", err)
	}

	emailID := uuid.New().String()
	_, err = pool.Exec(ctx, `INSERT INTO emails (id, account_id, domain_id, from_addr, subject, message_id, raw) VALUES ($1, $2, $3, 'sender@delivery.local', 'Subj', 'msg-001', 'raw')`, emailID, accountID, domainID)
	if err != nil {
		t.Fatalf("failed to insert email: %v", err)
	}

	delivID := uuid.New().String()
	_, err = pool.Exec(ctx, `INSERT INTO deliveries (id, account_id, domain_id, email_id, recipient, status, priority, attempts) VALUES ($1, $2, $3, $4, 'rcpt@remote.com', 'queued', 0, 0)`, delivID, accountID, domainID, emailID)
	if err != nil {
		t.Fatalf("failed to insert delivery: %v", err)
	}

	cfg := &config.Config{
		Workers:              2,
		PollInterval:         20 * time.Millisecond,
		AllowPrivateDelivery: true,
		MaxAttempts:          3,
	}
	w := New(pool, cfg, slog.Default())
	bClient, bErr := broker.New("amqp://guest:guest@localhost:5673/")
	if bErr == nil {
		w.SetBroker(bClient)
		defer bClient.Close()
	}

	// Test claim
	jobs, err := w.claim(ctx, 10)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if len(jobs) == 0 {
		t.Errorf("expected at least 1 claimed job")
	}

	// Run worker for 100ms then cancel
	runCtx, runCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer runCancel()
	w.Run(runCtx)
}

func TestWorkerFlushLoop(t *testing.T) {
	connURL := "postgres://mailhost:mailhost_secret@localhost:5433/mailhost?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, connURL, 5)
	if err != nil {
		t.Skipf("skipping live delivery flush test: %v", err)
		return
	}
	defer pool.Close()

	w := New(pool, &config.Config{}, slog.Default())
	w.results = make(chan queue.Completion, 5)

	done := make(chan struct{})
	go func() {
		w.flushLoop()
		close(done)
	}()

	// Push a completion
	w.results <- queue.Completion{
		DeliveryID: uuid.New().String(),
		Status:     "delivered",
		Detail:     "test",
	}

	// Close results channel to terminate flushLoop
	close(w.results)
	select {
	case <-done:
		// Clean exit
	case <-time.After(2 * time.Second):
		t.Fatal("flushLoop did not terminate after closing results channel")
	}
}



