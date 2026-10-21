package delivery

import (
	"context"
	"errors"
	"net/textproto"
	"testing"
	"time"
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

