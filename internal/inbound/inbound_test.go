package inbound

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"

	"mailhost/internal/config"
	"mailhost/internal/mailer"
)

func TestCleanAddress(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"<hello@example.com>", "hello@example.com"},
		{"hello@example.com", "hello@example.com"},
		{"\"John Doe\" <john.doe@example.com>", "john.doe@example.com"},
		{"  <spaced@example.com>  ", "spaced@example.com"},
		{"plain-text", "plain-text"},
	}

	for _, tt := range tests {
		got := cleanAddress(tt.input)
		if got != tt.want {
			t.Errorf("cleanAddress(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsDelayNotice(t *testing.T) {
	delayRaw := []byte("Content-Type: multipart/report\r\n\r\nAction: delayed\r\nStatus: 4.4.1")
	if !isDelayNotice(delayRaw) {
		t.Error("expected delay notice to be recognized")
	}

	failedRaw := []byte("Content-Type: multipart/report\r\n\r\nAction: delayed\r\nAction: failed\r\nStatus: 5.1.1")
	if isDelayNotice(failedRaw) {
		t.Error("notice with action: failed should not be treated as delay only")
	}

	normalRaw := []byte("Subject: Normal email\r\n\r\nHello")
	if isDelayNotice(normalRaw) {
		t.Error("normal email should not be recognized as delay notice")
	}
}

func TestBounceDetail(t *testing.T) {
	rawWithDiag := []byte("Subject: Undelivered Mail\r\n\r\nDiagnostic-Code: smtp; 550 5.1.1 <user@example.com>: Recipient address rejected\r\nOther-Line: value")
	p := mailer.Parsed{Subject: "Undelivered Mail"}

	diag := bounceDetail(rawWithDiag, p)
	if diag != "Diagnostic-Code: smtp; 550 5.1.1 <user@example.com>: Recipient address rejected" {
		t.Errorf("unexpected bounce detail: %q", diag)
	}

	rawWithoutDiag := []byte("Subject: Undelivered Mail\r\n\r\nNo diagnostic code here")
	fallback := bounceDetail(rawWithoutDiag, p)
	if fallback != "async bounce: Undelivered Mail" {
		t.Errorf("expected fallback to subject, got: %q", fallback)
	}
}

func TestSASLLoginServer(t *testing.T) {
	authenticated := false
	server := newLoginServer(func(user, pass string) error {
		if user == "valid_user" && pass == "valid_pass" {
			authenticated = true
			return nil
		}
		return errors.New("invalid auth")
	})

	// Step 1: Initial call requests username
	chal, done, err := server.Next(nil)
	if err != nil || done || string(chal) != "Username:" {
		t.Fatalf("expected Username: challenge, got chal=%q, done=%v, err=%v", chal, done, err)
	}

	// Step 2: Send username, requests password
	chal, done, err = server.Next([]byte("valid_user"))
	if err != nil || done || string(chal) != "Password:" {
		t.Fatalf("expected Password: challenge, got chal=%q, done=%v, err=%v", chal, done, err)
	}

	// Step 3: Send password, completes auth
	chal, done, err = server.Next([]byte("valid_pass"))
	if err != nil || !done || !authenticated {
		t.Fatalf("expected done=true and authenticated=true, got done=%v, auth=%v, err=%v", done, authenticated, err)
	}

	// Step 4: Subsequent call errors
	_, _, err = server.Next([]byte("extra"))
	if err == nil {
		t.Error("expected error on subsequent Next call")
	}
}

func TestNewServerConfig(t *testing.T) {
	cfg := &config.Config{
		SMTPAddr:        ":2525",
		Hostname:        "mx.mailhost.local",
		MaxMessageBytes: 10 << 20,
	}
	s, err := NewServer(nil, nil, cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if s.Addr != ":2525" || s.Domain != "mx.mailhost.local" {
		t.Errorf("unexpected server config: addr=%s, domain=%s", s.Addr, s.Domain)
	}
}

func TestInboundSession(t *testing.T) {
	be := &Backend{
		cfg: &config.Config{MaxMessageBytes: 100},
	}
	sess := &session{b: be}

	// AuthMechanisms
	mechs := sess.AuthMechanisms()
	if len(mechs) != 2 {
		t.Errorf("expected 2 auth mechs, got %v", mechs)
	}
	if _, err := sess.Auth("UNSUPPORTED"); err != smtp.ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed for unsupported mech, got: %v", err)
	}
	if _, err := sess.Auth("PLAIN"); err != nil {
		t.Errorf("expected PLAIN server: %v", err)
	}
	if _, err := sess.Auth("LOGIN"); err != nil {
		t.Errorf("expected LOGIN server: %v", err)
	}

	// Logout and Reset
	sess.from = "someone@example.com"
	sess.Reset()
	if sess.from != "" {
		t.Error("expected from to be reset")
	}
	if err := sess.Logout(); err != nil {
		t.Errorf("unexpected error on Logout: %v", err)
	}

	// Submission without auth
	beSub := &Backend{cfg: &config.Config{}, submission: true}
	sessSub := &session{b: beSub}
	if err := sessSub.Mail("from@example.com", nil); err == nil {
		t.Error("expected error on submission server without auth")
	}

	// Authenticated session with sender restriction
	sessAuth := &session{
		b:             be,
		authAccountID: "acct-1",
		authEmail:     "authorized@example.com",
	}
	if err := sessAuth.Mail("bad-email", nil); err != errBadAddress {
		t.Errorf("expected errBadAddress, got: %v", err)
	}
	if err := sessAuth.Mail("spoofed@example.com", nil); err == nil {
		t.Error("expected error for spoofed sender")
	}
	if err := sessAuth.Mail("authorized@example.com", nil); err != nil {
		t.Errorf("expected success for authorized sender: %v", err)
	}

	// Rcpt for authenticated session
	if err := sessAuth.Rcpt("invalid-rcpt", nil); err != errBadAddress {
		t.Errorf("expected errBadAddress for invalid rcpt, got: %v", err)
	}
	if err := sessAuth.Rcpt("valid@example.com", nil); err != nil {
		t.Errorf("expected success for valid rcpt: %v", err)
	}
	if len(sessAuth.authRcpts) != 1 || sessAuth.authRcpts[0] != "valid@example.com" {
		t.Errorf("unexpected authRcpts: %v", sessAuth.authRcpts)
	}

	// Data too large
	largeData := strings.NewReader(strings.Repeat("A", 150))
	if err := sess.Data(largeData); err != smtp.ErrDataTooLarge {
		t.Errorf("expected ErrDataTooLarge, got: %v", err)
	}

	// NewSubmissionServer
	subSrv, err := NewSubmissionServer(nil, nil, &config.Config{SMTPAddr: ":587"}, slog.Default())
	if err != nil {
		t.Fatalf("NewSubmissionServer failed: %v", err)
	}
	subSrv.SetDocstore(nil)
}

func TestBackendResolveAndOutbound(t *testing.T) {
	be := &Backend{cfg: &config.Config{}}
	ctx := context.Background()

	// resolve invalid addresses
	if _, err := be.resolve(ctx, "no-at-sign"); err != errBadAddress {
		t.Errorf("expected errBadAddress, got: %v", err)
	}
	if _, err := be.resolve(ctx, "@missinglocal.com"); err != errBadAddress {
		t.Errorf("expected errBadAddress for missing local part, got: %v", err)
	}
	if _, err := be.resolve(ctx, "user@"); err != errBadAddress {
		t.Errorf("expected errBadAddress for missing domain, got: %v", err)
	}

	// resolve without DB returns errRelayDenied
	if _, err := be.resolve(ctx, "user@example.com"); err != errRelayDenied {
		t.Errorf("expected errRelayDenied when DB is nil, got: %v", err)
	}

	// NewSession
	sess, err := be.NewSession(nil)
	if err != nil || sess == nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Authenticated session without recipients in Data()
	s := &session{
		b:             be,
		authAccountID: "acct-1",
		authRcpts:     nil,
	}
	if err := s.Data(strings.NewReader("hello")); err == nil {
		t.Error("expected 503 error for Data() without recipients in authenticated session")
	}
}



