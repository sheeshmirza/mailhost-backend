package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"mailhost/internal/webhook"
)

type webhookReq struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Status string   `json:"status"` // "active" or "disabled"
}

var validWebhookEvents = map[string]bool{
	"email.sent": true, "email.delivered": true, "email.bounced": true,
	"email.opened": true, "email.clicked": true,
	"contact.created": true, "contact.updated": true,
}

const encryptedWebhookSecretPrefix = "enc:v1:"

func validateWebhookEvents(events []string) error {
	if len(events) == 0 || len(events) > 20 {
		return errors.New("events must contain between 1 and 20 items")
	}
	seen := make(map[string]bool, len(events))
	for _, event := range events {
		event = strings.ToLower(strings.TrimSpace(event))
		if !validWebhookEvents[event] || seen[event] {
			return errors.New("events contains an invalid or duplicate event type")
		}
		seen[event] = true
	}
	return nil
}

func generateSigningSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Server) sealSigningSecret(secret string) (string, error) {
	if s.box == nil {
		return "", errors.New("secretbox is not initialized")
	}
	ciphertext, err := s.box.Seal([]byte(secret))
	if err != nil {
		return "", err
	}
	return encryptedWebhookSecretPrefix + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (s *Server) openSigningSecret(stored string) ([]byte, bool, error) {
	encoded, encrypted := strings.CutPrefix(stored, encryptedWebhookSecretPrefix)
	if !encrypted {
		return []byte(stored), false, nil
	}
	if s.box == nil {
		return nil, true, errors.New("secretbox is not initialized")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, true, err
	}
	secret, err := s.box.Open(ciphertext)
	return secret, true, err
}

func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req webhookReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	targetURL := strings.TrimSpace(req.URL)
	if err := webhook.ValidateURLWithPrivate(targetURL, s.cfg.AllowPrivateDelivery); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid webhook url: "+err.Error())
		return
	}

	if err := validateWebhookEvents(req.Events); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = "active"
	} else if status != "active" && status != "disabled" {
		writeError(w, http.StatusUnprocessableEntity, "status must be active or disabled")
		return
	}

	secret, err := generateSigningSecret()
	if err != nil {
		s.internal(w, err)
		return
	}
	storedSecret, err := s.sealSigningSecret(secret)
	if err != nil {
		s.internal(w, err)
		return
	}
	acct := accountID(r)

	var id uuid.UUID
	var createdAt, updatedAt time.Time

	err = s.db.QueryRow(r.Context(), `
INSERT INTO webhooks (account_id, url, events, status, signing_secret, updated_at)
VALUES ($1, $2, $3, $4, $5, now())
RETURNING id, created_at, updated_at`,
		acct, targetURL, req.Events, status, storedSecret).
		Scan(&id, &createdAt, &updatedAt)
	if err != nil {
		s.log.Error("create webhook failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create webhook")
		return
	}

	s.audit(r.Context(), acct, "create", "webhook", id.String(), r)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             id.String(),
		"object":         "webhook",
		"url":            targetURL,
		"events":         req.Events,
		"status":         status,
		"signing_secret": secret,
		"created_at":     createdAt.Format(time.RFC3339),
		"updated_at":     updatedAt.Format(time.RFC3339),
	})
}

func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, url, events, status, created_at, updated_at
FROM webhooks
WHERE account_id = $1 AND created_at < $2
ORDER BY created_at DESC LIMIT $3`,
		acct, before, limit)
	if err != nil {
		s.log.Error("list webhooks failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list webhooks")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var targetURL, status string
		var events []string
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &targetURL, &events, &status, &createdAt, &updatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}

		data = append(data, map[string]any{
			"id":         id.String(),
			"object":     "webhook",
			"url":        targetURL,
			"events":     events,
			"status":     status,
			"created_at": createdAt.Format(time.RFC3339Nano),
			"updated_at": updatedAt.Format(time.RFC3339),
		})
	}

	resp := map[string]any{
		"object": "list",
		"data":   data,
	}
	if len(data) == limit {
		resp["next_before"] = data[len(data)-1]["created_at"]
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getWebhook(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook id")
		return
	}

	acct := accountID(r)
	var targetURL, status string
	var events []string
	var createdAt, updatedAt time.Time

	err = s.rdb.QueryRow(r.Context(), `
SELECT url, events, status, created_at, updated_at
FROM webhooks
WHERE id = $1 AND account_id = $2`,
		id, acct).Scan(&targetURL, &events, &status, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":         id.String(),
		"object":     "webhook",
		"url":        targetURL,
		"events":     events,
		"status":     status,
		"created_at": createdAt.Format(time.RFC3339),
		"updated_at": updatedAt.Format(time.RFC3339),
	})
}

func (s *Server) updateWebhook(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook id")
		return
	}

	var req webhookReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	targetURL := strings.TrimSpace(req.URL)
	if targetURL != "" {
		if err := webhook.ValidateURLWithPrivate(targetURL, s.cfg.AllowPrivateDelivery); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid webhook url: "+err.Error())
			return
		}
	}
	if len(req.Events) > 0 {
		if err := validateWebhookEvents(req.Events); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status != "" && status != "active" && status != "disabled" {
		writeError(w, http.StatusUnprocessableEntity, "status must be active or disabled")
		return
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(), `
UPDATE webhooks
SET url = COALESCE(NULLIF($3, ''), url),
    events = CASE WHEN $4::text[] IS NOT NULL AND array_length($4::text[], 1) > 0 THEN $4::text[] ELSE events END,
    status = CASE WHEN $5 = 'active' OR $5 = 'disabled' THEN $5 ELSE status END,
    updated_at = now()
WHERE id = $1 AND account_id = $2`,
		id, acct, targetURL, req.Events, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}

	s.audit(r.Context(), acct, "update", "webhook", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "webhook",
		"updated": true,
	})
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook id")
		return
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(),
		`DELETE FROM webhooks WHERE id = $1 AND account_id = $2`,
		id, acct)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}

	s.audit(r.Context(), acct, "delete", "webhook", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "webhook",
		"deleted": true,
	})
}

// dispatchWebhookEvent sends the event to all registered, active webhooks for this account.
func (s *Server) dispatchWebhookEvent(ctx context.Context, accountID, eventType string, data any) {
	eventPayload := map[string]any{
		"type":       eventType,
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"data":       data,
	}
	payload, err := json.Marshal(eventPayload)
	if err != nil {
		s.log.Error("marshal webhook event", "event_type", eventType, "error", err)
		return
	}
	_, err = s.db.Exec(ctx, `
INSERT INTO webhook_deliveries (webhook_id, event_type, payload)
SELECT id, $2, $3::jsonb
FROM webhooks
WHERE account_id = $1 AND status = 'active' AND $2 = ANY(events)`, accountID, eventType, string(payload))
	if err != nil {
		s.log.Error("enqueue webhook event", "event_type", eventType, "error", err)
	}
}

func webhookRetryDelay(attempt int) time.Duration {
	power := min(max(attempt-1, 0), 10)
	return min(5*time.Second*time.Duration(1<<power), time.Hour)
}

// ProcessWebhookDeliveries claims a bounded batch with leases so other API replicas
// can recover work after a worker exits or loses its database connection.
func (s *Server) ProcessWebhookDeliveries(ctx context.Context) {
	type delivery struct {
		id         uuid.UUID
		webhookID  uuid.UUID
		url        string
		secretText string
		payload    []byte
		attempts   int
	}
	rows, err := s.db.Query(ctx, `
WITH due AS (
    SELECT id
    FROM webhook_deliveries
    WHERE (status = 'queued' AND next_attempt_at <= now())
       OR (status = 'sending' AND locked_until < now())
    ORDER BY next_attempt_at, created_at
    LIMIT 100
    FOR UPDATE SKIP LOCKED
)
UPDATE webhook_deliveries d
SET status = 'sending', attempts = d.attempts + 1,
	locked_until = now() + interval '10 minutes', updated_at = now()
FROM due, webhooks w
WHERE d.id = due.id AND w.id = d.webhook_id
RETURNING d.id, w.id, w.url, w.signing_secret, d.payload, d.attempts`)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Error("claim webhook deliveries", "error", err)
		}
		return
	}
	defer rows.Close()
	var deliveries []delivery
	for rows.Next() {
		var d delivery
		if err := rows.Scan(&d.id, &d.webhookID, &d.url, &d.secretText, &d.payload, &d.attempts); err != nil {
			s.log.Error("scan webhook delivery", "error", err)
			continue
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("read webhook deliveries", "error", err)
		return
	}
	rows.Close()

	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, d := range deliveries {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(d delivery) {
			defer wg.Done()
			defer func() { <-sem }()
			secret, encrypted, err := s.openSigningSecret(d.secretText)
			if err == nil && !encrypted {
				var upgraded string
				upgraded, err = s.sealSigningSecret(d.secretText)
				if err == nil {
					_, err = s.db.Exec(ctx, `UPDATE webhooks SET signing_secret = $2 WHERE id = $1 AND signing_secret = $3`, d.webhookID, upgraded, d.secretText)
				}
			}
			if err == nil {
				dCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				err = s.webhookClient.Deliver(dCtx, d.url, secret, json.RawMessage(d.payload))
				cancel()
			}
			if err == nil {
				_, err = s.db.Exec(ctx, `UPDATE webhook_deliveries SET status = 'delivered', locked_until = NULL, last_error = NULL, updated_at = now() WHERE id = $1 AND status = 'sending'`, d.id)
				if err != nil {
					s.log.Error("mark webhook delivery complete", "delivery_id", d.id, "error", err)
				}
				return
			}
			status := "queued"
			if d.attempts >= 12 {
				status = "failed"
			}
			if _, updateErr := s.db.Exec(ctx, `
UPDATE webhook_deliveries
SET status = $2, next_attempt_at = now() + $3::interval, locked_until = NULL,
    last_error = left($4, 1000), updated_at = now()
WHERE id = $1 AND status = 'sending'`, d.id, status, webhookRetryDelay(d.attempts).String(), err.Error()); updateErr != nil {
				s.log.Error("reschedule webhook delivery", "delivery_id", d.id, "error", updateErr)
			}
		}(d)
	}
	wg.Wait()
}
