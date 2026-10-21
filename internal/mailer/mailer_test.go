package mailer

import (
	"strings"
	"testing"
	"time"
)

func TestDKIMGenerationAndSigning(t *testing.T) {
	privPEM, dnsValue, err := GenerateDKIMKey()
	if err != nil {
		t.Fatalf("GenerateDKIMKey failed: %v", err)
	}

	if !strings.HasPrefix(string(privPEM), "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("unexpected private PEM header: %s", string(privPEM))
	}

	if !strings.HasPrefix(dnsValue, "v=DKIM1; k=rsa; p=") {
		t.Fatalf("unexpected dns value format: %s", dnsValue)
	}

	signer, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}

	rawEmail := []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test Email\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMessage-ID: <test@example.com>\r\n\r\nHello World!")

	signed, err := Sign(rawEmail, "example.com", "mh2026", signer)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !strings.Contains(string(signed), "DKIM-Signature:") {
		t.Fatalf("signed message missing DKIM-Signature header: %s", string(signed))
	}
}

func TestBuildMessage(t *testing.T) {
	msg, err := Build(&Message{
		From:      "\"Sender\" <hello@example.com>",
		To:        []string{"\"Recipient\" <world@example.com>"},
		Subject:   "Greetings",
		Text:      "Plain text greeting",
		HTML:      "<p>HTML greeting</p>",
		MessageID: "msg-123@example.com",
		Date:      time.Now(),
	})
	if err != nil {
		t.Fatalf("Build message failed: %v", err)
	}

	body := string(msg)
	if !strings.Contains(body, "From: \"Sender\" <hello@example.com>") {
		t.Errorf("missing From header, got:\n%s", body)
	}
	if !strings.Contains(body, "To: \"Recipient\" <world@example.com>") {
		t.Errorf("missing To header, got:\n%s", body)
	}
	if !strings.Contains(body, "Subject: Greetings") {
		t.Error("missing Subject header")
	}
	if !strings.Contains(body, "multipart/alternative") {
		t.Error("expected multipart/alternative MIME type")
	}
}
