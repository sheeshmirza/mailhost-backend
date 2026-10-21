package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip     string
		public bool
	}{
		// Public IPv4 addresses
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"104.26.10.12", true},

		// Private IPv4 ranges (RFC 1918)
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},
		{"192.168.0.254", false},

		// Loopback (127.0.0.0/8)
		{"127.0.0.1", false},
		{"127.255.255.254", false},

		// Cloud Metadata & Link-Local (169.254.0.0/16)
		{"169.254.169.254", false},
		{"169.254.1.1", false},

		// Broadcast & Zero Network
		{"0.0.0.0", false},
		{"255.255.255.255", false},

		// Carrier-Grade NAT (CGNAT RFC 6598: 100.64.0.0/10)
		{"100.64.0.1", false},
		{"100.127.255.255", false},

		// Documentation & Benchmark ranges
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"198.18.0.1", false},

		// Public IPv6
		{"2606:4700:4700::1111", true},
		{"2001:4860:4860::8888", true},

		// Private / Loopback IPv6
		{"::1", false},
		{"::", false},
		{"fc00::1", false},
		{"fd12:3456:789a:1::1", false},
		{"fe80::1", false},

		// IPv4-mapped IPv6 (SSRF bypass attempts)
		{"::ffff:127.0.0.1", false},
		{"::ffff:10.0.0.1", false},
		{"::ffff:169.254.169.254", false},
		{"::ffff:192.168.1.1", false},
		{"::ffff:8.8.8.8", true},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %q", tt.ip)
		}
		if got := IsPublicIP(ip); got != tt.public {
			t.Errorf("IsPublicIP(%s) = %v, want %v", tt.ip, got, tt.public)
		}
	}
	if IsPublicIP(nil) {
		t.Error("expected IsPublicIP(nil) to be false")
	}
}

func TestDenyInternal(t *testing.T) {
	// Loopback address should be denied
	if err := DenyInternal("tcp", "127.0.0.1:8080", nil); err == nil {
		t.Error("expected error for loopback 127.0.0.1")
	}
	// Public IP should pass
	if err := DenyInternal("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("expected public IP to pass, got: %v", err)
	}
	// Invalid host:port
	if err := DenyInternal("tcp", "invalid-no-port", nil); err == nil {
		t.Error("expected error for missing port")
	}
}

func TestValidateURLWithPrivate(t *testing.T) {
	// Standard HTTPS URL
	if err := ValidateURLWithPrivate("https://api.example.com/webhook", false); err != nil {
		t.Errorf("expected valid HTTPS URL, got: %v", err)
	}

	// HTTP URL with allowPrivate=false
	if err := ValidateURLWithPrivate("http://api.example.com/webhook", false); err == nil {
		t.Error("expected error for HTTP when allowPrivate=false")
	}

	// HTTP URL with allowPrivate=true
	if err := ValidateURLWithPrivate("http://localhost:8080/webhook", true); err != nil {
		t.Errorf("expected valid HTTP when allowPrivate=true, got: %v", err)
	}

	// Credentials in URL should be rejected
	if err := ValidateURLWithPrivate("https://user:pass@api.example.com/webhook", false); err == nil {
		t.Error("expected error for URL with credentials")
	}

	// Missing host
	if err := ValidateURLWithPrivate("https:///webhook", false); err == nil {
		t.Error("expected error for URL without host")
	}

	// URL too long (> 2048 chars)
	tooLong := "https://example.com/" + string(make([]byte, 2050))
	if err := ValidateURLWithPrivate(tooLong, false); err == nil {
		t.Error("expected error for URL exceeding 2048 chars")
	}
}

func TestDeliverAndDeliverOnce(t *testing.T) {
	secret := []byte("test-webhook-secret-key-32b-long!")
	var receivedTimestamp, receivedSignature, receivedUA string
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTimestamp = r.Header.Get("X-Mailhost-Timestamp")
		receivedSignature = r.Header.Get("X-Mailhost-Signature")
		receivedUA = r.Header.Get("User-Agent")
		receivedBody, _ = io.ReadAll(r.Body)

		switch r.URL.Path {
		case "/success":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		case "/client-error":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"bad_request"}`))
		case "/server-error":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"server_error"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewWithSecurity(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload := map[string]string{"event": "email.delivered", "id": "msg-123"}

	// Test Deliver success
	err := client.Deliver(ctx, srv.URL+"/success", secret, payload)
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}
	if receivedTimestamp == "" || !strings.HasPrefix(receivedSignature, "v1=") {
		t.Errorf("missing signature headers: ts=%s, sig=%s", receivedTimestamp, receivedSignature)
	}
	if receivedUA != "mailhost-webhook/1" {
		t.Errorf("unexpected User-Agent: %s", receivedUA)
	}

	// Verify HMAC signature
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(receivedTimestamp + "."))
	mac.Write(receivedBody)
	expectedSig := "v1=" + hex.EncodeToString(mac.Sum(nil))
	if receivedSignature != expectedSig {
		t.Errorf("signature mismatch: got %s, want %s", receivedSignature, expectedSig)
	}

	// Test Deliver client-error (400 - should fail fast without retry)
	err = client.Deliver(ctx, srv.URL+"/client-error", secret, payload)
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("expected 400 error, got: %v", err)
	}

	// Test DeliverOnce
	code, latency, snippet, err := client.DeliverOnce(ctx, srv.URL+"/success", secret, payload)
	if err != nil || code != 200 || !strings.Contains(snippet, "ok") || latency < 0 {
		t.Errorf("DeliverOnce failed: code=%d, latency=%d, snippet=%s, err=%v", code, latency, snippet, err)
	}

	// Test unmarshalable event in Deliver & DeliverOnce
	unmarshalable := make(chan int)
	if err := client.Deliver(ctx, srv.URL, secret, unmarshalable); err == nil {
		t.Error("expected marshal error in Deliver")
	}
	if _, _, _, err := client.DeliverOnce(ctx, srv.URL, secret, unmarshalable); err == nil {
		t.Error("expected marshal error in DeliverOnce")
	}

	// Test client creation with security enabled (allowPrivate=false)
	secureClient := NewWithSecurity(false)
	if secureClient == nil || secureClient.http == nil {
		t.Fatal("expected non-nil secureClient")
	}

	// Test Deliver with cancelled context
	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if err := client.Deliver(canceledCtx, srv.URL+"/success", secret, payload); err == nil {
		t.Error("expected error for canceled context in Deliver")
	}
}



