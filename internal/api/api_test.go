package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"mailhost/internal/config"
	"mailhost/internal/db"
	"mailhost/internal/mailer"
	"mailhost/internal/secretbox"
)

func TestPublicEndpoints(t *testing.T) {
	cfg := &config.Config{
		Hostname: "mail.example.com",
	}
	srv := New(nil, nil, nil, cfg, slog.Default())
	handler := srv.Handler()

	// 1. /.well-known/ai-plugin.json
	req := httptest.NewRequest(http.MethodGet, "/.well-known/ai-plugin.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/.well-known/ai-plugin.json code = %d, want 200", rec.Code)
	}


	// 4. /openapi.json
	req = httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/openapi.json code = %d, want 200", rec.Code)
	}

	// 5. /openapi.yaml
	req = httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/openapi.yaml code = %d, want 200", rec.Code)
	}

	// 6. Security headers check
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options: nosniff header")
	}

	// 7. CORS preflight
	req = httptest.NewRequest(http.MethodOptions, "/v1/emails", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("CORS preflight code = %d, want 204", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("CORS allow origin = %s, want *", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestUnauthenticatedRejection(t *testing.T) {
	srv := New(nil, nil, nil, &config.Config{}, slog.Default())
	handler := srv.Handler()

	// Missing auth header
	req := httptest.NewRequest(http.MethodGet, "/v1/domains", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing auth, got %d", rec.Code)
	}

	// Invalid Bearer token
	req = httptest.NewRequest(http.MethodGet, "/v1/domains", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-123")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for invalid token, got %d", rec.Code)
	}
}

func TestLiveAPIEndpoints(t *testing.T) {
	connURL := "postgres://mailhost:mailhost_secret@localhost:5433/mailhost?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, connURL, 5)
	if err != nil {
		t.Skipf("skipping live api tests (port 5433 unavailable): %v", err)
		return
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	accountID := uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO accounts (id, name) VALUES ($1, 'API Test Account')`, accountID)
	if err != nil {
		t.Fatalf("failed to insert test account: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM accounts WHERE id = $1`, accountID)

	apiToken := "mh_live_" + uuid.New().String()
	tokenHash := sha256.Sum256([]byte(apiToken))
	_, err = pool.Exec(ctx, `INSERT INTO api_keys (account_id, key_hash, name, permission) VALUES ($1, $2, 'Test Key', 'full_access')`, accountID, tokenHash[:])
	if err != nil {
		t.Fatalf("failed to insert api key: %v", err)
	}

	boxKey := make([]byte, 32)
	box, _ := secretbox.New(boxKey)

	cfg := &config.Config{
		Hostname:             "localhost",
		AllowPrivateDelivery: true,
	}

	server := New(pool, pool, box, cfg, slog.Default())
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	doReq := func(method, path string, body any) (*http.Response, []byte) {
		var rdr io.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			rdr = bytes.NewReader(data)
		}
		req, _ := http.NewRequestWithContext(ctx, method, ts.URL+path, rdr)
		req.Header.Set("Authorization", "Bearer "+apiToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, respBody
	}

	// 1. Domains: List and Create
	resp, body := doReq(http.MethodGet, "/v1/domains", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/domains code=%d, body=%s", resp.StatusCode, string(body))
	}

	// Test /healthz and /readyz on live server
	respHealth, _ := http.Get(ts.URL + "/healthz")
	if respHealth.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz code=%d", respHealth.StatusCode)
	}
	respHealth.Body.Close()

	respReady, _ := http.Get(ts.URL + "/readyz")
	if respReady.StatusCode != http.StatusOK {
		t.Errorf("GET /readyz code=%d", respReady.StatusCode)
	}
	respReady.Body.Close()

	domainName := "api-test-" + accountID.String()[:8] + ".local"
	resp, body = doReq(http.MethodPost, "/v1/domains", map[string]string{
		"name":   domainName,
		"region": "us-east-1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST /v1/domains code=%d, body=%s", resp.StatusCode, string(body))
	}

	var createdDomain struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &createdDomain)

	if createdDomain.ID != "" {
		resp, _ = doReq(http.MethodGet, "/v1/domains/"+createdDomain.ID, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /v1/domains/%s code=%d", createdDomain.ID, resp.StatusCode)
		}
	}

	// 2. Templates: Create, List, Get, Delete
	resp, body = doReq(http.MethodPost, "/v1/templates", map[string]string{
		"name": "Welcome Email",
		"html": "<p>Hello {{name}}</p>",
		"text": "Hello {{name}}",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST /v1/templates code=%d, body=%s", resp.StatusCode, string(body))
	}
	var createdTpl struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &createdTpl)

	resp, _ = doReq(http.MethodGet, "/v1/templates", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/templates code=%d", resp.StatusCode)
	}

	if createdTpl.ID != "" {
		resp, _ = doReq(http.MethodGet, "/v1/templates/"+createdTpl.ID, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /v1/templates/%s code=%d", createdTpl.ID, resp.StatusCode)
		}
		resp, _ = doReq(http.MethodDelete, "/v1/templates/"+createdTpl.ID, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("DELETE /v1/templates/%s code=%d", createdTpl.ID, resp.StatusCode)
		}
	}

	// 3. API Keys: List and Create
	resp, _ = doReq(http.MethodGet, "/v1/api-keys", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/api-keys code=%d", resp.StatusCode)
	}
	resp, _ = doReq(http.MethodPost, "/v1/api-keys", map[string]string{
		"name":       "Secondary Key",
		"permission": "full_access",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST /v1/api-keys code=%d", resp.StatusCode)
	}

	// 4. Suppressions: Create, List, Delete
	suppEmail := "bounce-" + accountID.String()[:8] + "@suppressed.com"
	resp, _ = doReq(http.MethodPost, "/v1/suppressions", map[string]string{
		"address": suppEmail,
		"reason":  "hard_bounce",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST /v1/suppressions code=%d", resp.StatusCode)
	}
	resp, _ = doReq(http.MethodGet, "/v1/suppressions", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/suppressions code=%d", resp.StatusCode)
	}
	resp, _ = doReq(http.MethodDelete, "/v1/suppressions/"+suppEmail, nil)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE /v1/suppressions/%s code=%d", suppEmail, resp.StatusCode)
	}


	// 5. Analytics, IPs, Audiences, Broadcasts, Automations, Emails
	resp, _ = doReq(http.MethodGet, "/v1/analytics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/analytics code=%d", resp.StatusCode)
	}

	resp, _ = doReq(http.MethodGet, "/v1/ips", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/ips code=%d", resp.StatusCode)
	}

	resp, _ = doReq(http.MethodGet, "/v1/audiences", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/audiences code=%d", resp.StatusCode)
	}

	resp, _ = doReq(http.MethodGet, "/v1/broadcasts", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/broadcasts code=%d", resp.StatusCode)
	}

	resp, _ = doReq(http.MethodGet, "/v1/automations", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/automations code=%d", resp.StatusCode)
	}

	// 6. Insert verified domain with DKIM key for email sending
	verifiedDomID := uuid.New()
	verifiedDomName := "verified-" + verifiedDomID.String()[:8] + ".local"
	dkimPrivPEM, dkimDNS, err := mailer.GenerateDKIMKey()
	if err != nil {
		t.Fatalf("GenerateDKIMKey failed: %v", err)
	}
	encDKIM, err := box.Seal(dkimPrivPEM)
	if err != nil {
		t.Fatalf("box.Seal failed: %v", err)
	}

	_, err = pool.Exec(ctx, `
INSERT INTO domains (id, account_id, name, status, verification_token, dkim_selector, dkim_private_key, dkim_public_key, webhook_secret)
VALUES ($1, $2, $3, 'verified', 'tok_ver', 'k1', $4, $5, 'sec')`, verifiedDomID, accountID, verifiedDomName, encDKIM, dkimDNS)
	if err != nil {
		t.Fatalf("failed to insert verified test domain: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, verifiedDomID)

	// 7. Emails: Send and Retrieve
	resp, body = doReq(http.MethodPost, "/v1/emails", map[string]any{
		"from":    "hello@" + verifiedDomName,
		"to":      []string{"recipient@remote.com"},
		"subject": "Live API Email Test",
		"html":    "<p>Hello from API Test</p>",
		"text":    "Hello from API Test",
	})
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		t.Errorf("POST /v1/emails code=%d, body=%s", resp.StatusCode, string(body))
	}
	var sentEmail struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &sentEmail)

	if sentEmail.ID != "" {
		resp, _ = doReq(http.MethodGet, "/v1/emails/"+sentEmail.ID, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /v1/emails/%s code=%d", sentEmail.ID, resp.StatusCode)
		}
	}

	// 8. Contacts: Create and List
	resp, _ = doReq(http.MethodPost, "/v1/contacts", map[string]string{
		"email":      "bob-" + accountID.String()[:8] + "@example.com",
		"first_name": "Bob",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST /v1/contacts code=%d", resp.StatusCode)
	}
	resp, _ = doReq(http.MethodGet, "/v1/contacts", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/contacts code=%d", resp.StatusCode)
	}

	// 9. Broadcasts: Create and List
	resp, _ = doReq(http.MethodPost, "/v1/broadcasts", map[string]string{
		"name":    "Spring Newsletter",
		"from":    "news@" + verifiedDomName,
		"subject": "Spring Announcements",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST /v1/broadcasts code=%d", resp.StatusCode)
	}
	resp, _ = doReq(http.MethodGet, "/v1/broadcasts", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/broadcasts code=%d", resp.StatusCode)
	}

	// 10. Automations: Create and List
	resp, _ = doReq(http.MethodPost, "/v1/automations", map[string]string{
		"name": "User Onboarding Flow",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST /v1/automations code=%d", resp.StatusCode)
	}
	resp, _ = doReq(http.MethodGet, "/v1/automations", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/automations code=%d", resp.StatusCode)
	}

	// 11. Members: List
	resp, _ = doReq(http.MethodGet, "/v1/members", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/members code=%d", resp.StatusCode)
	}

	// 12. MCP endpoint (JSON-RPC tools/list)
	resp, body = doReq(http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1,
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /mcp code=%d, body=%s", resp.StatusCode, string(body))
	}

	// Clean up created domain
	if createdDomain.ID != "" {
		_, _ = doReq(http.MethodDelete, "/v1/domains/"+createdDomain.ID, nil)
	}
}

