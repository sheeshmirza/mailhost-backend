package qdrant

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVectorize(t *testing.T) {
	v1 := Vectorize("Welcome to Mailhost! Your invoice is ready for payment.")
	if len(v1) != VectorDimension {
		t.Fatalf("expected vector dimension %d, got %d", VectorDimension, len(v1))
	}

	// Verify L2 norm is ~1.0
	var sumSquares float64
	for _, val := range v1 {
		sumSquares += float64(val * val)
	}
	if math.Abs(sumSquares-1.0) > 1e-4 {
		t.Fatalf("expected L2 norm to be ~1.0, got %f", sumSquares)
	}

	// Identical text produces identical vectors
	v2 := Vectorize("Welcome to Mailhost! Your invoice is ready for payment.")
	for i := range v1 {
		if v1[i] != v2[i] {
			t.Fatalf("expected identical vectors at index %d", i)
		}
	}

	// Similar text should have high cosine similarity (dot product since normalized)
	vSimilar := Vectorize("Invoice payment confirmation for Mailhost account.")
	var dotSimilar float64
	for i := range v1 {
		dotSimilar += float64(v1[i] * vSimilar[i])
	}

	// Completely unrelated text
	vUnrelated := Vectorize("Chocolate cake recipe baking temperature and ingredients.")
	var dotUnrelated float64
	for i := range v1 {
		dotUnrelated += float64(v1[i] * vUnrelated[i])
	}

	if dotSimilar <= dotUnrelated {
		t.Fatalf("expected dot product for similar text (%f) to be higher than unrelated (%f)", dotSimilar, dotUnrelated)
	}
}

func TestClient_Lifecycle(t *testing.T) {
	collectionsCreated := make(map[string]bool)
	pointsUpserted := make(map[string][]map[string]any)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Ping
		if path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// EnsureCollection GET
		if r.Method == http.MethodGet && strings.HasPrefix(path, "/collections/") {
			col := strings.TrimPrefix(path, "/collections/")
			if collectionsCreated[col] {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// EnsureCollection PUT
		if r.Method == http.MethodPut && strings.HasPrefix(path, "/collections/") && !strings.Contains(path, "/points") {
			col := strings.TrimPrefix(path, "/collections/")
			collectionsCreated[col] = true
			w.WriteHeader(http.StatusOK)
			return
		}

		// Points Upsert
		if r.Method == http.MethodPut && strings.Contains(path, "/points") {
			parts := strings.Split(path, "/")
			col := parts[2]
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if pts, ok := body["points"].([]any); ok {
				for _, p := range pts {
					if pm, ok := p.(map[string]any); ok {
						pointsUpserted[col] = append(pointsUpserted[col], pm)
					}
				}
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
			return
		}

		// Points Search
		if r.Method == http.MethodPost && strings.Contains(path, "/points/search") {
			parts := strings.Split(path, "/")
			col := parts[2]
			pts := pointsUpserted[col]
			results := make([]rawSearchHit, 0, len(pts))
			for _, p := range pts {
				id, _ := p["id"].(string)
				payload, _ := p["payload"].(map[string]any)
				results = append(results, rawSearchHit{
					ID:      id,
					Score:   0.92,
					Payload: payload,
				})
			}
			_ = json.NewEncoder(w).Encode(qdrantSearchResponse{
				Result: results,
				Status: "ok",
			})
			return
		}

		// Points Delete
		if r.Method == http.MethodPost && strings.Contains(path, "/points/delete") {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx := context.Background()
	client, err := New(srv.URL, "test-api-key", "test_app", slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("failed to init qdrant client: %v", err)
	}

	// 1. Ping
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("ping failed: %v", err)
	}

	// 2. EnsureCollections
	if err := client.EnsureCollections(ctx); err != nil {
		t.Fatalf("ensure collections failed: %v", err)
	}
	if !collectionsCreated[client.EmailsCollection()] || !collectionsCreated[client.TemplatesCollection()] {
		t.Fatalf("expected collections to be marked as created")
	}

	// 3. UpsertEmail
	emailPt := EmailPoint{
		ID:        "00000000-0000-0000-0000-000000000001",
		AccountID: "acct-123",
		Subject:   "Order Confirmation #48291",
		Snippet:   "Thank you for your purchase. Your receipt is attached.",
		From:      "orders@example.com",
		To:        []string{"alice@example.com"},
		CreatedAt: "2026-10-22T10:00:00Z",
		Tags:      map[string]string{"category": "transactional"},
	}
	if err := client.UpsertEmail(ctx, emailPt); err != nil {
		t.Fatalf("upsert email failed: %v", err)
	}

	// 4. SearchEmails
	emailHits, err := client.SearchEmails(ctx, "acct-123", "order receipt", 10)
	if err != nil {
		t.Fatalf("search emails failed: %v", err)
	}
	if len(emailHits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(emailHits))
	}
	if emailHits[0].ID != emailPt.ID || emailHits[0].Subject != emailPt.Subject {
		t.Fatalf("unexpected search hit data: %+v", emailHits[0])
	}

	// 5. UpsertTemplate & SearchTemplates
	tmplPt := TemplatePoint{
		ID:        "00000000-0000-0000-0000-000000000002",
		AccountID: "acct-123",
		Name:      "Welcome Email",
		Subject:   "Welcome to our service!",
		Snippet:   "Here is your getting started guide.",
	}
	if err := client.UpsertTemplate(ctx, tmplPt); err != nil {
		t.Fatalf("upsert template failed: %v", err)
	}

	tmplHits, err := client.SearchTemplates(ctx, "acct-123", "getting started", 5)
	if err != nil {
		t.Fatalf("search templates failed: %v", err)
	}
	if len(tmplHits) != 1 {
		t.Fatalf("expected 1 template hit, got %d", len(tmplHits))
	}
	if tmplHits[0].ID != tmplPt.ID || tmplHits[0].Name != tmplPt.Name {
		t.Fatalf("unexpected template hit: %+v", tmplHits[0])
	}

	// 6. DeletePoint
	if err := client.DeletePoint(ctx, client.EmailsCollection(), emailPt.ID); err != nil {
		t.Fatalf("delete point failed: %v", err)
	}
}

func TestClient_ValidationErrors(t *testing.T) {
	client, err := New("http://localhost:6333", "", "", nil)
	if err != nil {
		t.Fatalf("expected valid init: %v", err)
	}

	ctx := context.Background()

	// Empty query
	if _, err := client.SearchEmails(ctx, "acct", "   ", 10); err != ErrEmptyQuery {
		t.Fatalf("expected ErrEmptyQuery, got %v", err)
	}

	// Missing account ID
	if _, err := client.SearchEmails(ctx, "", "query", 10); err == nil {
		t.Fatalf("expected error for empty account ID")
	}

	// Invalid URL
	if _, err := New("ftp://invalid-scheme", "", "", nil); err == nil {
		t.Fatalf("expected error on invalid scheme")
	}
}

