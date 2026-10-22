package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"mailhost/internal/config"
	"mailhost/internal/qdrant"
	"mailhost/internal/secretbox"
)

func TestSemanticSearchEndpoints(t *testing.T) {
	// 1. Mock Qdrant Server
	qdrantSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stringsContains := r.URL.Path; stringsContains != "" {
			res := map[string]any{
				"result": []map[string]any{
					{
						"id":    "00000000-0000-0000-0000-000000000001",
						"score": 0.95,
						"payload": map[string]any{
							"account_id": "test-acct",
							"subject":    "Invoice #1234",
							"snippet":    "Payment receipt for your plan",
							"name":       "Invoice Template",
						},
					},
				},
				"status": "ok",
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(res)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer qdrantSrv.Close()

	key := make([]byte, 32)
	box, _ := secretbox.New(key)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := &config.Config{
		Roles: map[string]bool{"api": true},
	}
	s := New(nil, nil, box, cfg, logger)

	qc, err := qdrant.New(qdrantSrv.URL, "", "test", logger)
	if err != nil {
		t.Fatalf("failed to init test qdrant client: %v", err)
	}
	s.SetQdrant(qc)

	// Test 1: Empty query validation for emails
	t.Run("EmptyQueryEmails", func(t *testing.T) {
		body := bytes.NewReader([]byte(`{"query": "   "}`))
		req := httptest.NewRequest(http.MethodPost, "/v1/emails/semantic-search", body)
		w := httptest.NewRecorder()
		s.semanticSearchEmails(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for empty query, got %d", w.Code)
		}
	})

	// Test 2: Valid semantic search emails with Qdrant
	t.Run("ValidQueryEmails", func(t *testing.T) {
		body := bytes.NewReader([]byte(`{"query": "invoice payment receipt", "limit": 5}`))
		req := httptest.NewRequest(http.MethodPost, "/v1/emails/semantic-search", body)
		req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, "test-acct"))
		w := httptest.NewRecorder()
		s.semanticSearchEmails(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
		}
		var parsed struct {
			Data   []qdrant.EmailSearchResult `json:"data"`
			Source string                     `json:"source"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		if parsed.Source != "qdrant" {
			t.Fatalf("expected source qdrant, got %s", parsed.Source)
		}
		if len(parsed.Data) != 1 || parsed.Data[0].Subject != "Invoice #1234" {
			t.Fatalf("unexpected data: %+v", parsed.Data)
		}
	})

	// Test 3: Empty query validation for templates
	t.Run("EmptyQueryTemplates", func(t *testing.T) {
		body := bytes.NewReader([]byte(`{"query": ""}`))
		req := httptest.NewRequest(http.MethodPost, "/v1/templates/semantic-search", body)
		w := httptest.NewRecorder()
		s.semanticSearchTemplates(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for empty query, got %d", w.Code)
		}
	})

	// Test 4: Valid semantic search templates with Qdrant
	t.Run("ValidQueryTemplates", func(t *testing.T) {
		body := bytes.NewReader([]byte(`{"query": "billing invoice", "limit": 10}`))
		req := httptest.NewRequest(http.MethodPost, "/v1/templates/semantic-search", body)
		req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, "test-acct"))
		w := httptest.NewRecorder()
		s.semanticSearchTemplates(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
		}
		var parsed struct {
			Data   []qdrant.TemplateSearchResult `json:"data"`
			Source string                        `json:"source"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		if parsed.Source != "qdrant" {
			t.Fatalf("expected source qdrant, got %s", parsed.Source)
		}
		if len(parsed.Data) != 1 || parsed.Data[0].Name != "Invoice Template" {
			t.Fatalf("unexpected data: %+v", parsed.Data)
		}
	})
}
