package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"mailhost/internal/validator"
)

type customEventReq struct {
	Name         string         `json:"name"`
	Email        string         `json:"email"`
	ContactEmail string         `json:"contact_email,omitempty"`
	Data         map[string]any `json:"data"`
}

func (s *Server) triggerEvent(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req customEventReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be between 1 and 100 characters")
		return
	}
	emailInput := req.Email
	if emailInput == "" {
		emailInput = req.ContactEmail
	}
	email := strings.ToLower(strings.TrimSpace(emailInput))
	if !validator.IsValidEmail(email) {
		writeError(w, http.StatusUnprocessableEntity, "valid contact email address is required")
		return
	}

	dataJSON, _ := json.Marshal(req.Data)
	if len(dataJSON) > 1<<20 {
		writeError(w, http.StatusUnprocessableEntity, "data cannot exceed 1 MiB")
		return
	}
	if req.Data == nil {
		dataJSON = []byte("{}")
	}

	acct := accountID(r)

	// Ensure contact exists or create if missing
	var contactID uuid.UUID
	err := s.db.QueryRow(r.Context(), `
INSERT INTO contacts (account_id, email, traits, updated_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (account_id, email)
DO UPDATE SET traits = contacts.traits || EXCLUDED.traits, updated_at = now()
RETURNING id`,
		acct, email, dataJSON).Scan(&contactID)
	if err != nil {
		s.log.Error("ensure contact for event failed", "account_id", acct, "email", email, "event_name", name, "err", err)
		writeError(w, http.StatusInternalServerError, "failed to prepare event contact")
		return
	}

	// Insert into custom_events
	var eventID uuid.UUID
	var createdAt time.Time
	err = s.db.QueryRow(r.Context(), `
INSERT INTO custom_events (account_id, name, contact_email, data)
VALUES ($1, $2, $3, $4)
RETURNING id, created_at`,
		acct, name, email, dataJSON).Scan(&eventID, &createdAt)
	if err != nil {
		s.log.Error("record custom event failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to record event")
		return
	}

	// Trigger matching active automations asynchronously
	go s.triggerAutomations(context.Background(), acct, "event", name, contactID.String(), email, req.Data)

	s.audit(r.Context(), acct, "trigger", "event", eventID.String(), r)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":            eventID.String(),
		"object":        "event",
		"name":          name,
		"contact_email": email,
		"data":          req.Data,
		"created_at":    createdAt.Format(time.RFC3339),
	})
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, name, contact_email, data, created_at
FROM custom_events
WHERE account_id = $1 AND created_at < $2
ORDER BY created_at DESC LIMIT $3`,
		acct, before, limit)
	if err != nil {
		s.log.Error("list events failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list events")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var name, email string
		var dataBytes []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &email, &dataBytes, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		var payload map[string]any
		_ = json.Unmarshal(dataBytes, &payload)

		data = append(data, map[string]any{
			"id":            id.String(),
			"object":        "event",
			"name":          name,
			"contact_email": email,
			"data":          payload,
			"created_at":    createdAt.Format(time.RFC3339Nano),
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

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid event id")
		return
	}

	acct := accountID(r)
	var name, email string
	var dataBytes []byte
	var createdAt time.Time

	err = s.rdb.QueryRow(r.Context(), `
SELECT name, contact_email, data, created_at
FROM custom_events
WHERE id = $1 AND account_id = $2`,
		id, acct).Scan(&name, &email, &dataBytes, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	var payload map[string]any
	_ = json.Unmarshal(dataBytes, &payload)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":            id.String(),
		"object":        "event",
		"name":          name,
		"contact_email": email,
		"data":          payload,
		"created_at":    createdAt.Format(time.RFC3339),
	})
}
