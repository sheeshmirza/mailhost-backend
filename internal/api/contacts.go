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
	"github.com/jackc/pgx/v5/pgconn"

	"mailhost/internal/validator"
)

// --- Audiences ---

type createAudienceReq struct {
	Name string `json:"name"`
}

func (s *Server) createAudience(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req createAudienceReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be between 1 and 100 characters")
		return
	}

	acct := accountID(r)
	var id uuid.UUID
	var createdAt time.Time
	err := s.db.QueryRow(r.Context(),
		`INSERT INTO audiences (account_id, name) VALUES ($1, $2) RETURNING id, created_at`,
		acct, name).Scan(&id, &createdAt)
	if err != nil {
		s.log.Error("create audience failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create audience")
		return
	}

	s.audit(r.Context(), acct, "create", "audience", id.String(), r)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id.String(),
		"object":     "audience",
		"name":       name,
		"created_at": createdAt.Format(time.RFC3339),
	})
}

func (s *Server) listAudiences(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(),
		`SELECT id, name, created_at FROM audiences WHERE account_id = $1 AND created_at < $2 ORDER BY created_at DESC LIMIT $3`,
		acct, before, limit)
	if err != nil {
		s.log.Error("list audiences failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list audiences")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var name string
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		data = append(data, map[string]any{
			"id":         id.String(),
			"object":     "audience",
			"name":       name,
			"created_at": createdAt.Format(time.RFC3339Nano),
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

func (s *Server) getAudience(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid audience id")
		return
	}

	var name string
	var createdAt time.Time
	err = s.rdb.QueryRow(r.Context(),
		`SELECT name, created_at FROM audiences WHERE id = $1 AND account_id = $2`,
		id, accountID(r)).Scan(&name, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "audience not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":         id.String(),
		"object":     "audience",
		"name":       name,
		"created_at": createdAt.Format(time.RFC3339),
	})
}

func (s *Server) deleteAudience(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid audience id")
		return
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(),
		`DELETE FROM audiences WHERE id = $1 AND account_id = $2`,
		id, acct)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "audience not found")
		return
	}

	s.audit(r.Context(), acct, "delete", "audience", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "audience",
		"deleted": true,
	})
}

// --- Contacts ---

type contactReq struct {
	Email        string         `json:"email"`
	FirstName    string         `json:"first_name"`
	LastName     string         `json:"last_name"`
	Unsubscribed *bool          `json:"unsubscribed"`
	AudienceID   *string        `json:"audience_id"`
	Traits       map[string]any `json:"traits"`
}

func (s *Server) createContact(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req contactReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !validator.IsValidEmail(email) {
		writeError(w, http.StatusUnprocessableEntity, "valid email address is required")
		return
	}

	var audienceID *uuid.UUID
	// Path param or body
	aidStr := r.PathValue("audience_id")
	if aidStr == "" && req.AudienceID != nil {
		aidStr = *req.AudienceID
	}
	if aidStr != "" {
		parsed, err := uuid.Parse(aidStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid audience_id")
			return
		}
		var belongs bool
		if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM audiences WHERE id = $1 AND account_id = $2)`, parsed, accountID(r)).Scan(&belongs); err != nil {
			s.internal(w, err)
			return
		}
		if !belongs {
			writeError(w, http.StatusUnprocessableEntity, "audience_id does not belong to this account")
			return
		}
		audienceID = &parsed
	}

	if len(req.FirstName) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "first_name must be at most 100 characters")
		return
	}
	if len(req.LastName) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "last_name must be at most 100 characters")
		return
	}

	unsub := req.Unsubscribed != nil && *req.Unsubscribed
	traitsJSON, _ := json.Marshal(req.Traits)
	if len(traitsJSON) > 1<<20 {
		writeError(w, http.StatusUnprocessableEntity, "traits cannot exceed 1 MiB")
		return
	}
	if req.Traits == nil {
		traitsJSON = []byte("{}")
	}

	acct := accountID(r)
	var contactID uuid.UUID
	var createdAt, updatedAt time.Time

	err := s.db.QueryRow(r.Context(), `
INSERT INTO contacts (account_id, audience_id, email, first_name, last_name, unsubscribed, traits, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $8, now())
ON CONFLICT (account_id, email)
DO UPDATE SET
    audience_id = COALESCE(EXCLUDED.audience_id, contacts.audience_id),
    first_name = CASE WHEN EXCLUDED.first_name <> '' THEN EXCLUDED.first_name ELSE contacts.first_name END,
    last_name = CASE WHEN EXCLUDED.last_name <> '' THEN EXCLUDED.last_name ELSE contacts.last_name END,
    unsubscribed = CASE WHEN $7 THEN EXCLUDED.unsubscribed ELSE contacts.unsubscribed END,
    traits = contacts.traits || EXCLUDED.traits,
    updated_at = now()
RETURNING id, created_at, updated_at, unsubscribed`,
		acct, audienceID, email, strings.TrimSpace(req.FirstName), strings.TrimSpace(req.LastName), unsub, req.Unsubscribed != nil, traitsJSON).
		Scan(&contactID, &createdAt, &updatedAt, &unsub)
	if err != nil {
		s.log.Error("upsert contact failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to save contact")
		return
	}

	// Trigger automation for contact creation/upsert
	go s.triggerAutomations(context.Background(), acct, "contact.created", "contact.created", contactID.String(), email, req.Traits)

	s.audit(r.Context(), acct, "create", "contact", contactID.String(), r)
	s.dispatchWebhookEvent(r.Context(), acct, "contact.created", map[string]any{"id": contactID.String(), "email": email, "unsubscribed": unsub})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":           contactID.String(),
		"object":       "contact",
		"email":        email,
		"first_name":   req.FirstName,
		"last_name":    req.LastName,
		"unsubscribed": unsub,
		"created_at":   createdAt.Format(time.RFC3339),
		"updated_at":   updatedAt.Format(time.RFC3339),
	})
}

func (s *Server) listContacts(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	aidStr := r.PathValue("audience_id")

	var rows pgx.Rows
	var err error
	if aidStr != "" {
		aid, pErr := uuid.Parse(aidStr)
		if pErr != nil {
			writeError(w, http.StatusBadRequest, "invalid audience_id")
			return
		}
		rows, err = s.rdb.Query(r.Context(),
			`SELECT id, email, first_name, last_name, unsubscribed, traits, created_at, updated_at
FROM contacts WHERE account_id = $1 AND audience_id = $2 AND created_at < $3 ORDER BY created_at DESC LIMIT $4`,
			acct, aid, before, limit)
	} else {
		rows, err = s.rdb.Query(r.Context(),
			`SELECT id, email, first_name, last_name, unsubscribed, traits, created_at, updated_at
FROM contacts WHERE account_id = $1 AND created_at < $2 ORDER BY created_at DESC LIMIT $3`,
			acct, before, limit)
	}
	if err != nil {
		s.log.Error("list contacts failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list contacts")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var email, fn, ln string
		var unsub bool
		var traitsBytes []byte
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &email, &fn, &ln, &unsub, &traitsBytes, &createdAt, &updatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		var traits map[string]any
		_ = json.Unmarshal(traitsBytes, &traits)

		data = append(data, map[string]any{
			"id":           id.String(),
			"object":       "contact",
			"email":        email,
			"first_name":   fn,
			"last_name":    ln,
			"unsubscribed": unsub,
			"traits":       traits,
			"created_at":   createdAt.Format(time.RFC3339Nano),
			"updated_at":   updatedAt.Format(time.RFC3339),
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

func (s *Server) getContact(w http.ResponseWriter, r *http.Request) {
	idOrEmail := r.PathValue("id")
	acct := accountID(r)

	var id uuid.UUID
	var email, fn, ln string
	var unsub bool
	var traitsBytes []byte
	var createdAt, updatedAt time.Time

	var err error
	if parsedUUID, pErr := uuid.Parse(idOrEmail); pErr == nil {
		err = s.rdb.QueryRow(r.Context(),
			`SELECT id, email, first_name, last_name, unsubscribed, traits, created_at, updated_at FROM contacts WHERE id = $1 AND account_id = $2`,
			parsedUUID, acct).Scan(&id, &email, &fn, &ln, &unsub, &traitsBytes, &createdAt, &updatedAt)
	} else {
		err = s.rdb.QueryRow(r.Context(),
			`SELECT id, email, first_name, last_name, unsubscribed, traits, created_at, updated_at FROM contacts WHERE lower(email) = lower($1) AND account_id = $2`,
			idOrEmail, acct).Scan(&id, &email, &fn, &ln, &unsub, &traitsBytes, &createdAt, &updatedAt)
	}

	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "contact not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	var traits map[string]any
	_ = json.Unmarshal(traitsBytes, &traits)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":           id.String(),
		"object":       "contact",
		"email":        email,
		"first_name":   fn,
		"last_name":    ln,
		"unsubscribed": unsub,
		"traits":       traits,
		"created_at":   createdAt.Format(time.RFC3339),
		"updated_at":   updatedAt.Format(time.RFC3339),
	})
}

func (s *Server) updateContact(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idOrEmail := r.PathValue("id")
	acct := accountID(r)

	var req contactReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.FirstName != "" && len(req.FirstName) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "first_name must be at most 100 characters")
		return
	}
	if req.LastName != "" && len(req.LastName) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "last_name must be at most 100 characters")
		return
	}

	var traitsJSON []byte
	if req.Traits != nil {
		traitsJSON, _ = json.Marshal(req.Traits)
		if len(traitsJSON) > 1<<20 {
			writeError(w, http.StatusUnprocessableEntity, "traits cannot exceed 1 MiB")
			return
		}
	}

	var contactID uuid.UUID
	if parsedUUID, err := uuid.Parse(idOrEmail); err == nil {
		contactID = parsedUUID
	} else {
		err := s.db.QueryRow(r.Context(),
			`SELECT id FROM contacts WHERE lower(email) = lower($1) AND account_id = $2`,
			idOrEmail, acct).Scan(&contactID)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "contact not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "lookup failed")
			return
		}
	}

	var email, fn, ln string
	var unsub bool
	var traitsBytes []byte
	var createdAt, updatedAt time.Time

	err := s.db.QueryRow(r.Context(), `
UPDATE contacts
SET
    first_name = COALESCE(NULLIF($3, ''), first_name),
    last_name = COALESCE(NULLIF($4, ''), last_name),
    unsubscribed = COALESCE($5, unsubscribed),
    traits = CASE WHEN $6::jsonb IS NOT NULL AND $6::jsonb <> '{}'::jsonb AND $6::jsonb <> 'null'::jsonb THEN traits || $6::jsonb ELSE traits END,
    updated_at = now()
WHERE id = $1 AND account_id = $2
RETURNING id, email, first_name, last_name, unsubscribed, traits, created_at, updated_at`,
		contactID, acct, req.FirstName, req.LastName, req.Unsubscribed, traitsJSON).
		Scan(&contactID, &email, &fn, &ln, &unsub, &traitsBytes, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "contact not found")
		return
	}
	if err != nil {
		s.log.Error("update contact failed", "err", err)
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	var traits map[string]any
	_ = json.Unmarshal(traitsBytes, &traits)

	s.audit(r.Context(), acct, "update", "contact", contactID.String(), r)
	s.dispatchWebhookEvent(r.Context(), acct, "contact.updated", map[string]any{"id": contactID.String(), "email": email, "unsubscribed": unsub})
	writeJSON(w, http.StatusOK, map[string]any{
		"id":           contactID.String(),
		"object":       "contact",
		"email":        email,
		"first_name":   fn,
		"last_name":    ln,
		"unsubscribed": unsub,
		"traits":       traits,
		"created_at":   createdAt.Format(time.RFC3339),
		"updated_at":   updatedAt.Format(time.RFC3339),
	})
}

func (s *Server) deleteContact(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idOrEmail := r.PathValue("id")
	acct := accountID(r)

	var tag pgconn.CommandTag
	var err error
	var deletedID string

	if parsedUUID, pErr := uuid.Parse(idOrEmail); pErr == nil {
		deletedID = parsedUUID.String()
		tag, err = s.db.Exec(r.Context(),
			`DELETE FROM contacts WHERE id = $1 AND account_id = $2`,
			parsedUUID, acct)
	} else {
		err = s.db.QueryRow(r.Context(),
			`DELETE FROM contacts WHERE lower(email) = lower($1) AND account_id = $2 RETURNING id`,
			idOrEmail, acct).Scan(&deletedID)
		if err == nil {
			tag = pgconn.NewCommandTag("DELETE 1")
		}
	}

	if errors.Is(err, pgx.ErrNoRows) || (tag.RowsAffected() == 0 && err == nil) {
		writeError(w, http.StatusNotFound, "contact not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}

	s.audit(r.Context(), acct, "delete", "contact", deletedID, r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      deletedID,
		"object":  "contact",
		"deleted": true,
	})
}

// --- Segments ---

type segmentReq struct {
	Name   string         `json:"name"`
	Filter map[string]any `json:"filter"`
}

func (s *Server) createSegment(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req segmentReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be between 1 and 100 characters")
		return
	}

	filterJSON, _ := json.Marshal(req.Filter)
	if len(filterJSON) > 1<<20 {
		writeError(w, http.StatusUnprocessableEntity, "filter cannot exceed 1 MiB")
		return
	}
	if req.Filter == nil {
		filterJSON = []byte("{}")
	}

	acct := accountID(r)
	var id uuid.UUID
	var createdAt time.Time
	err := s.db.QueryRow(r.Context(),
		`INSERT INTO segments (account_id, name, filter) VALUES ($1, $2, $3) RETURNING id, created_at`,
		acct, name, filterJSON).Scan(&id, &createdAt)
	if err != nil {
		s.log.Error("create segment failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create segment")
		return
	}

	s.audit(r.Context(), acct, "create", "segment", id.String(), r)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id.String(),
		"object":     "segment",
		"name":       name,
		"filter":     req.Filter,
		"created_at": createdAt.Format(time.RFC3339),
	})
}

func (s *Server) listSegments(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(),
		`SELECT id, name, filter, created_at FROM segments WHERE account_id = $1 AND created_at < $2 ORDER BY created_at DESC LIMIT $3`,
		acct, before, limit)
	if err != nil {
		s.log.Error("list segments failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list segments")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var name string
		var filterBytes []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &filterBytes, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		var filter map[string]any
		_ = json.Unmarshal(filterBytes, &filter)
		data = append(data, map[string]any{
			"id":         id.String(),
			"object":     "segment",
			"name":       name,
			"filter":     filter,
			"created_at": createdAt.Format(time.RFC3339Nano),
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

func (s *Server) getSegment(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid segment id")
		return
	}

	var name string
	var filterBytes []byte
	var createdAt time.Time
	err = s.rdb.QueryRow(r.Context(),
		`SELECT name, filter, created_at FROM segments WHERE id = $1 AND account_id = $2`,
		id, accountID(r)).Scan(&name, &filterBytes, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "segment not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	var filter map[string]any
	_ = json.Unmarshal(filterBytes, &filter)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         id.String(),
		"object":     "segment",
		"name":       name,
		"filter":     filter,
		"created_at": createdAt.Format(time.RFC3339),
	})
}

func (s *Server) updateSegment(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid segment id")
		return
	}

	var req segmentReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name != "" && len(strings.TrimSpace(req.Name)) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be at most 100 characters")
		return
	}

	acct := accountID(r)
	var filterJSON []byte
	if req.Filter != nil {
		filterJSON, _ = json.Marshal(req.Filter)
		if len(filterJSON) > 1<<20 {
			writeError(w, http.StatusUnprocessableEntity, "filter cannot exceed 1 MiB")
			return
		}
	}

	var name string
	var filterBytes []byte
	var createdAt time.Time
	err = s.db.QueryRow(r.Context(), `
UPDATE segments
SET name = COALESCE(NULLIF($3, ''), name),
    filter = CASE WHEN $4::jsonb IS NOT NULL AND $4::jsonb <> '{}'::jsonb AND $4::jsonb <> 'null'::jsonb THEN $4::jsonb ELSE filter END
WHERE id = $1 AND account_id = $2
RETURNING name, filter, created_at`,
		id, acct, strings.TrimSpace(req.Name), filterJSON).Scan(&name, &filterBytes, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "segment not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	var filter map[string]any
	_ = json.Unmarshal(filterBytes, &filter)
	s.audit(r.Context(), acct, "update", "segment", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         id.String(),
		"object":     "segment",
		"name":       name,
		"filter":     filter,
		"created_at": createdAt.Format(time.RFC3339),
	})
}

func (s *Server) deleteSegment(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid segment id")
		return
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(),
		`DELETE FROM segments WHERE id = $1 AND account_id = $2`,
		id, acct)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "segment not found")
		return
	}

	s.audit(r.Context(), acct, "delete", "segment", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "segment",
		"deleted": true,
	})
}

func (s *Server) listSegmentContacts(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	sidStr := r.PathValue("id")
	sid, err := uuid.Parse(sidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid segment id")
		return
	}

	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT c.id, c.email, c.first_name, c.last_name, c.unsubscribed, c.traits, c.created_at, c.updated_at
FROM contacts c
JOIN contact_segments cs ON cs.contact_id = c.id
WHERE cs.segment_id = $1 AND c.account_id = $2 AND c.created_at < $3
ORDER BY c.created_at DESC LIMIT $4`,
		sid, acct, before, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var email, fn, ln string
		var unsub bool
		var traitsBytes []byte
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &email, &fn, &ln, &unsub, &traitsBytes, &createdAt, &updatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		var traits map[string]any
		_ = json.Unmarshal(traitsBytes, &traits)

		data = append(data, map[string]any{
			"id":           id.String(),
			"object":       "contact",
			"email":        email,
			"first_name":   fn,
			"last_name":    ln,
			"unsubscribed": unsub,
			"traits":       traits,
			"created_at":   createdAt.Format(time.RFC3339Nano),
			"updated_at":   updatedAt.Format(time.RFC3339),
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

func (s *Server) addContactToSegment(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	cidStr := r.PathValue("id")
	sidStr := r.PathValue("segment_id")

	cid, err := uuid.Parse(cidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid contact id")
		return
	}
	sid, err := uuid.Parse(sidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid segment id")
		return
	}

	acct := accountID(r)
	var exists bool
	err = s.db.QueryRow(r.Context(),
		`SELECT EXISTS(
					SELECT 1 FROM contacts c
					JOIN segments s ON s.account_id = c.account_id
					WHERE c.id = $1 AND s.id = $2 AND c.account_id = $3
				)`, cid, sid, acct).Scan(&exists)
	if err != nil || !exists {
		writeError(w, http.StatusNotFound, "contact not found")
		return
	}

	_, err = s.db.Exec(r.Context(),
		`INSERT INTO contact_segments (contact_id, segment_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		cid, sid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to add contact to segment")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"contact_id": cid.String(),
		"segment_id": sid.String(),
		"success":    true,
	})
}

func (s *Server) removeContactFromSegment(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	cidStr := r.PathValue("id")
	sidStr := r.PathValue("segment_id")

	cid, err := uuid.Parse(cidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid contact id")
		return
	}
	sid, err := uuid.Parse(sidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid segment id")
		return
	}

	_, err = s.db.Exec(r.Context(),
		`DELETE FROM contact_segments cs
				 WHERE cs.contact_id = $1 AND cs.segment_id = $2
				 AND EXISTS (SELECT 1 FROM contacts c WHERE c.id = cs.contact_id AND c.account_id = $3)
				 AND EXISTS (SELECT 1 FROM segments s WHERE s.id = cs.segment_id AND s.account_id = $3)`,
		cid, sid, accountID(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"contact_id": cid.String(),
		"segment_id": sid.String(),
		"deleted":    true,
	})
}

func (s *Server) listContactSegments(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	cidStr := r.PathValue("id")
	cid, err := uuid.Parse(cidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid contact id")
		return
	}

	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT s.id, s.name, s.filter, s.created_at
FROM segments s
JOIN contact_segments cs ON cs.segment_id = s.id
WHERE cs.contact_id = $1 AND s.account_id = $2 AND s.created_at < $3
ORDER BY s.created_at DESC LIMIT $4`,
		cid, acct, before, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var name string
		var filterBytes []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &filterBytes, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		var filter map[string]any
		_ = json.Unmarshal(filterBytes, &filter)
		data = append(data, map[string]any{
			"id":         id.String(),
			"object":     "segment",
			"name":       name,
			"filter":     filter,
			"created_at": createdAt.Format(time.RFC3339Nano),
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

// --- Topics ---

type topicReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Visibility  string `json:"visibility"` // "public" or "private"
}

func (s *Server) createTopic(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req topicReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be between 1 and 100 characters")
		return
	}
	vis := strings.ToLower(strings.TrimSpace(req.Visibility))
	if vis != "private" {
		vis = "public"
	}

	acct := accountID(r)
	var id uuid.UUID
	var createdAt time.Time
	err := s.db.QueryRow(r.Context(),
		`INSERT INTO topics (account_id, name, description, visibility) VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
		acct, name, strings.TrimSpace(req.Description), vis).Scan(&id, &createdAt)
	if err != nil {
		s.log.Error("create topic failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create topic")
		return
	}

	s.audit(r.Context(), acct, "create", "topic", id.String(), r)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          id.String(),
		"object":      "topic",
		"name":        name,
		"description": req.Description,
		"visibility":  vis,
		"created_at":  createdAt.Format(time.RFC3339),
	})
}

func (s *Server) listTopics(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(),
		`SELECT id, name, description, visibility, created_at FROM topics WHERE account_id = $1 AND created_at < $2 ORDER BY created_at DESC LIMIT $3`,
		acct, before, limit)
	if err != nil {
		s.log.Error("list topics failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list topics")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var name, desc, vis string
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &desc, &vis, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		data = append(data, map[string]any{
			"id":          id.String(),
			"object":      "topic",
			"name":        name,
			"description": desc,
			"visibility":  vis,
			"created_at":  createdAt.Format(time.RFC3339Nano),
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

func (s *Server) getTopic(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid topic id")
		return
	}

	var name, desc, vis string
	var createdAt time.Time
	err = s.rdb.QueryRow(r.Context(),
		`SELECT name, description, visibility, created_at FROM topics WHERE id = $1 AND account_id = $2`,
		id, accountID(r)).Scan(&name, &desc, &vis, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "topic not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          id.String(),
		"object":      "topic",
		"name":        name,
		"description": desc,
		"visibility":  vis,
		"created_at":  createdAt.Format(time.RFC3339),
	})
}

func (s *Server) updateTopic(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid topic id")
		return
	}

	var req topicReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	acct := accountID(r)
	var name, desc, vis string
	var createdAt time.Time
	err = s.db.QueryRow(r.Context(), `
UPDATE topics
SET name = COALESCE(NULLIF($3, ''), name),
    description = COALESCE(NULLIF($4, ''), description),
    visibility = CASE WHEN $5 = 'public' OR $5 = 'private' THEN $5 ELSE visibility END
WHERE id = $1 AND account_id = $2
RETURNING name, description, visibility, created_at`,
		id, acct, req.Name, req.Description, strings.ToLower(req.Visibility)).
		Scan(&name, &desc, &vis, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "topic not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	s.audit(r.Context(), acct, "update", "topic", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          id.String(),
		"object":      "topic",
		"name":        name,
		"description": desc,
		"visibility":  vis,
		"created_at":  createdAt.Format(time.RFC3339),
	})
}

func (s *Server) deleteTopic(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid topic id")
		return
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(),
		`DELETE FROM topics WHERE id = $1 AND account_id = $2`,
		id, acct)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "topic not found")
		return
	}

	s.audit(r.Context(), acct, "delete", "topic", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "topic",
		"deleted": true,
	})
}

type contactTopicReq struct {
	Status string `json:"status"` // "subscribed" or "unsubscribed"
}

func (s *Server) updateContactTopic(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	cidStr := r.PathValue("id")
	tidStr := r.PathValue("topic_id")

	cid, err := uuid.Parse(cidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid contact id")
		return
	}
	tid, err := uuid.Parse(tidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid topic id")
		return
	}

	var req contactTopicReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status != "unsubscribed" {
		status = "subscribed"
	}

	acct := accountID(r)
	var exists bool
	err = s.db.QueryRow(r.Context(),
		`SELECT EXISTS(
					SELECT 1 FROM contacts c
					JOIN topics t ON t.account_id = c.account_id
					WHERE c.id = $1 AND t.id = $2 AND c.account_id = $3
				)`, cid, tid, acct).Scan(&exists)
	if err != nil || !exists {
		writeError(w, http.StatusNotFound, "contact not found")
		return
	}

	_, err = s.db.Exec(r.Context(), `
INSERT INTO contact_topics (contact_id, topic_id, status)
VALUES ($1, $2, $3)
ON CONFLICT (contact_id, topic_id)
DO UPDATE SET status = EXCLUDED.status`,
		cid, tid, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update topic subscription")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"contact_id": cid.String(),
		"topic_id":   tid.String(),
		"status":     status,
	})
}

func (s *Server) removeContactTopic(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	cidStr := r.PathValue("id")
	tidStr := r.PathValue("topic_id")

	cid, err := uuid.Parse(cidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid contact id")
		return
	}
	tid, err := uuid.Parse(tidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid topic id")
		return
	}

	_, err = s.db.Exec(r.Context(),
		`DELETE FROM contact_topics ct
				 WHERE ct.contact_id = $1 AND ct.topic_id = $2
				 AND EXISTS (SELECT 1 FROM contacts c WHERE c.id = ct.contact_id AND c.account_id = $3)
				 AND EXISTS (SELECT 1 FROM topics t WHERE t.id = ct.topic_id AND t.account_id = $3)`,
		cid, tid, accountID(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"contact_id": cid.String(),
		"topic_id":   tid.String(),
		"deleted":    true,
	})
}

func (s *Server) listContactTopics(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	cidStr := r.PathValue("id")
	cid, err := uuid.Parse(cidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid contact id")
		return
	}

	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT t.id, t.name, t.description, t.visibility, COALESCE(ct.status, 'subscribed') as status, t.created_at
FROM topics t
LEFT JOIN contact_topics ct ON ct.topic_id = t.id AND ct.contact_id = $1
WHERE t.account_id = $2 AND t.created_at < $3
ORDER BY t.created_at DESC LIMIT $4`,
		cid, acct, before, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var name, desc, vis, status string
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &desc, &vis, &status, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		data = append(data, map[string]any{
			"id":          id.String(),
			"name":        name,
			"description": desc,
			"visibility":  vis,
			"status":      status,
			"created_at":  createdAt.Format(time.RFC3339Nano),
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
