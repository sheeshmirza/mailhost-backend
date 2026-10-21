package mailer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/smtp"
	"net/textproto"
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

func TestBuildMessageVariantsAndValidation(t *testing.T) {
	// Text only message
	msgText, err := Build(&Message{
		From:      "user@example.com",
		To:        []string{"to@example.com"},
		Subject:   "Text Only",
		Text:      "Just plain text",
		MessageID: "msg-text@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(msgText), "text/plain") || strings.Contains(string(msgText), "multipart/alternative") {
		t.Error("expected single text/plain body")
	}

	// HTML only message
	msgHTML, err := Build(&Message{
		From:      "user@example.com",
		To:        []string{"to@example.com"},
		Subject:   "HTML Only",
		HTML:      "<b>HTML text</b>",
		MessageID: "msg-html@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(msgHTML), "text/html") {
		t.Error("expected text/html body")
	}

	// Cc, ReplyTo, Custom Headers, and Attachments
	longContent := []byte(strings.Repeat("0123456789ABCDEF", 20)) // > 76 bytes for base64 line wrapping
	msgWithAtt, err := Build(&Message{
		From:      "user@example.com",
		To:        []string{"to@example.com"},
		Cc:        []string{"cc@example.com"},
		ReplyTo:   []string{"replyto@example.com"},
		Subject:   "With Attachment",
		Text:      "Attachment is attached",
		MessageID: "msg-att@example.com",
		Headers: map[string]string{
			"X-Custom-Header": "CustomValue",
		},
		Attachments: []Attachment{
			{Filename: "document.pdf", Content: longContent},
			{Filename: "data.bin", ContentType: "application/octet-stream", Content: []byte("raw")},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bodyWithAtt := string(msgWithAtt)
	if !strings.Contains(bodyWithAtt, "multipart/mixed") {
		t.Error("expected multipart/mixed for email with attachments")
	}
	if !strings.Contains(bodyWithAtt, "X-Custom-Header: CustomValue") {
		t.Error("expected custom header in output")
	}
	if !strings.Contains(bodyWithAtt, "Cc: <cc@example.com>") {
		t.Error("expected Cc header")
	}
	if !strings.Contains(bodyWithAtt, "Reply-To: <replyto@example.com>") {
		t.Error("expected Reply-To header")
	}

	// Validation Errors
	// Invalid From
	if _, err := Build(&Message{From: "invalid\nfrom@example.com"}); err == nil {
		t.Error("expected error for dangerous characters in From")
	}

	// Invalid To
	if _, err := Build(&Message{From: "valid@example.com", To: []string{"bad\r\nto@example.com"}}); err == nil {
		t.Error("expected error for invalid To address")
	}

	// Subject too long (>900 bytes)
	if _, err := Build(&Message{
		From:    "valid@example.com",
		To:      []string{"to@example.com"},
		Subject: strings.Repeat("A", 901),
	}); err == nil {
		t.Error("expected error for subject > 900 bytes")
	}

	// Reserved header error
	if _, err := Build(&Message{
		From:    "valid@example.com",
		To:      []string{"to@example.com"},
		Subject: "Test",
		Headers: map[string]string{"From": "spoof@example.com"},
	}); err == nil {
		t.Error("expected error for reserved header name")
	}

	// Invalid header name
	if _, err := Build(&Message{
		From:    "valid@example.com",
		To:      []string{"to@example.com"},
		Subject: "Test",
		Headers: map[string]string{"Invalid Header!": "value"},
	}); err == nil {
		t.Error("expected error for invalid header name format")
	}

	// Dangerous header value
	if _, err := Build(&Message{
		From:    "valid@example.com",
		To:      []string{"to@example.com"},
		Subject: "Test",
		Headers: map[string]string{"X-Test": "bad\r\nvalue"},
	}); err == nil {
		t.Error("expected error for dangerous header value")
	}

	// Invalid attachment filename
	if _, err := Build(&Message{
		From:        "valid@example.com",
		To:          []string{"to@example.com"},
		Subject:     "Test",
		Attachments: []Attachment{{Filename: ""}},
	}); err == nil {
		t.Error("expected error for empty attachment filename")
	}

	// Invalid attachment content-type
	if _, err := Build(&Message{
		From:        "valid@example.com",
		To:          []string{"to@example.com"},
		Subject:     "Test",
		Attachments: []Attachment{{Filename: "file.txt", ContentType: "invalid; ; ;"}},
	}); err == nil {
		t.Error("expected error for malformed attachment ContentType")
	}
}

func TestDangerousHeaderString(t *testing.T) {
	if !isDangerousHeaderString("foo\rbar") {
		t.Error("expected CR to be dangerous")
	}
	if !isDangerousHeaderString("foo\nbar") {
		t.Error("expected LF to be dangerous")
	}
	if !isDangerousHeaderString("foo\x00bar") {
		t.Error("expected null byte to be dangerous")
	}
	// Bidirectional override rune \u202A
	if !isDangerousHeaderString("foo\u202Abar") {
		t.Error("expected bidirectional override character to be dangerous")
	}
	if isDangerousHeaderString("hello world! normal string with ütf-8") {
		t.Error("expected regular utf-8 string not to be dangerous")
	}
}

func TestParseMessage(t *testing.T) {
	// Parse empty
	empty := Parse([]byte{})
	if empty.From != "" || empty.Subject != "" {
		t.Errorf("expected empty parsed struct, got %+v", empty)
	}

	// Parse full email with multipart/alternative and attachment
	raw := "From: Sender Name <sender@example.com>\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Hello There\r\n" +
		"Message-Id: <msg-999@example.com>\r\n" +
		"Content-Type: multipart/mixed; boundary=\"boundary42\"\r\n" +
		"\r\n" +
		"--boundary42\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		"Hello plain text\r\n" +
		"--boundary42\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<p>Hello html</p>\r\n" +
		"--boundary42\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Disposition: attachment; filename=\"note.txt\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		"SGVsbG8gQXR0YWNobWVudA==\r\n" +
		"--boundary42--\r\n"

	p := Parse([]byte(raw))
	if p.Subject != "Hello There" {
		t.Errorf("expected 'Hello There', got %q", p.Subject)
	}
	if p.MessageID != "msg-999@example.com" {
		t.Errorf("expected 'msg-999@example.com', got %q", p.MessageID)
	}
	if !strings.Contains(p.Text, "Hello plain text") {
		t.Errorf("expected plain text content, got %q", p.Text)
	}
	if !strings.Contains(p.HTML, "<p>Hello html</p>") {
		t.Errorf("expected html content, got %q", p.HTML)
	}
	if len(p.Attachments) != 1 || p.Attachments[0].Filename != "note.txt" {
		t.Errorf("expected 1 attachment 'note.txt', got %+v", p.Attachments)
	}
}

func TestLoginAuth(t *testing.T) {
	auth := LoginAuth("testuser", "secretpass")
	proto, initial, err := auth.Start(nil)
	if err != nil || proto != "LOGIN" || string(initial) != "testuser" {
		t.Fatalf("unexpected Start output: proto=%s, initial=%s, err=%v", proto, string(initial), err)
	}

	// Challenge for Username
	resp, err := auth.Next([]byte("Username:"), true)
	if err != nil || string(resp) != "testuser" {
		t.Errorf("unexpected Next response for user: %s, %v", string(resp), err)
	}

	// Challenge for Password
	resp, err = auth.Next([]byte("Password:"), true)
	if err != nil || string(resp) != "secretpass" {
		t.Errorf("unexpected Next response for pass: %s, %v", string(resp), err)
	}

	// Generic challenge
	resp, err = auth.Next([]byte("Challenge:"), true)
	if err != nil || string(resp) != "secretpass" {
		t.Errorf("unexpected Next response for generic challenge: %s, %v", string(resp), err)
	}

	// More = false
	resp, err = auth.Next(nil, false)
	if err != nil || resp != nil {
		t.Errorf("expected nil for more=false, got %v, %v", resp, err)
	}
}

func TestDKIMParseInvalidKey(t *testing.T) {
	// Non PEM data
	if _, err := ParsePrivateKey([]byte("not-pem-data")); err == nil {
		t.Error("expected error for invalid PEM data")
	}

	// PEM block with invalid DER bytes
	invalidPEM := "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----"
	if _, err := ParsePrivateKey([]byte(invalidPEM)); err == nil {
		t.Error("expected error for invalid private key DER")
	}
}

func TestParsePrivateKeyPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	signer, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed for PKCS1 key: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer for PKCS1 key")
	}
}

func TestAuthenticateClient(t *testing.T) {
	// Empty username should return nil without touching client
	if err := AuthenticateClient(nil, "localhost", "", ""); err != nil {
		t.Errorf("expected nil for empty username, got: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		tp := textproto.NewConn(conn)
		_ = tp.PrintfLine("220 smtp.local ESMTP")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			parts := strings.Split(line, " ")
			cmd := strings.ToUpper(parts[0])
			switch cmd {
			case "EHLO":
				_ = tp.PrintfLine("250-smtp.local")
				_ = tp.PrintfLine("250 AUTH PLAIN LOGIN")
			case "AUTH":
				_ = tp.PrintfLine("235 2.7.0 Authentication succeeded")
			case "QUIT":
				_ = tp.PrintfLine("221 2.0.0 Bye")
				return
			default:
				_ = tp.PrintfLine("502 Command not implemented")
			}
		}
	}()

	client, err := smtp.Dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial mock smtp: %v", err)
	}
	defer client.Close()

	if err := AuthenticateClient(client, "127.0.0.1", "testuser", "testpass"); err != nil {
		t.Fatalf("AuthenticateClient failed: %v", err)
	}
}



