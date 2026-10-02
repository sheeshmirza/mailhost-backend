package api

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type apiKeyView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Permission string     `json:"permission"`
	DomainID   *string    `json:"domain_id,omitempty"`
	LastFour   string     `json:"last_four"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req struct {
		Name       string  `json:"name"`
		Permission string  `json:"permission"`
		DomainID   *string `json:"domain_id"`
	}
	if r.Body != nil && r.ContentLength != 0 && !decode(w, r, 0, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = "Default Key"
	}
	if len(req.Name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be at most 100 characters")
		return
	}
	req.Permission = strings.TrimSpace(strings.ToLower(req.Permission))
	if req.Permission == "" {
		req.Permission = "full_access"
	}
	if req.Permission != "full_access" && req.Permission != "sending_access" {
		writeError(w, http.StatusUnprocessableEntity, "permission must be 'full_access' or 'sending_access'")
		return
	}

	acct := accountID(r)
	var domUUID *string
	if req.DomainID != nil && *req.DomainID != "" {
		if !validUUID(*req.DomainID) {
			writeError(w, http.StatusUnprocessableEntity, "domain_id must be a UUID")
			return
		}
		var exists bool
		err := s.db.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM domains WHERE id = $1::uuid AND account_id = $2)`,
			*req.DomainID, acct).Scan(&exists)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to validate domain_id")
			return
		}
		if !exists {
			writeError(w, http.StatusUnprocessableEntity, "domain_id does not exist or does not belong to this account")
			return
		}
		domUUID = req.DomainID
	}

	key := newToken("re_live_", 28)
	lastFour := key[len(key)-4:]
	var id string
	var created time.Time
	if err := s.db.QueryRow(r.Context(), `
INSERT INTO api_keys (account_id, name, permission, domain_id, last_four, key_hash)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
		acct, req.Name, req.Permission, domUUID, lastFour, hashKey(key)).Scan(&id, &created); err != nil {
		s.internal(w, err)
		return
	}
	s.auditLog(r.Context(), acct, acct, "create", "api_key", id, clientIP(r), r.UserAgent())
	resp := map[string]any{
		"id":         id,
		"name":       req.Name,
		"permission": req.Permission,
		"api_key":    key,
		"last_four":  lastFour,
		"created_at": created,
	}
	if domUUID != nil {
		resp["domain_id"] = *domUUID
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, name, permission, domain_id::text, last_four, created_at, last_used_at
FROM api_keys WHERE account_id = $1 AND created_at < $2 ORDER BY created_at DESC LIMIT $3`, accountID(r), before, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	keys, err := pgx.CollectRows(rows, pgx.RowToStructByPos[apiKeyView])
	if err != nil {
		s.internal(w, err)
		return
	}
	resp := map[string]any{"data": keys}
	if len(keys) == limit {
		resp["next_before"] = keys[len(keys)-1].CreatedAt
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var hash []byte
	err := s.db.QueryRow(r.Context(), `
DELETE FROM api_keys WHERE id = $1 AND account_id = $2 RETURNING key_hash`, id, accountID(r)).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.keys.Delete(string(hash))
	if s.redis != nil {
		_ = s.redis.Delete(r.Context(), "apikey:"+hex.EncodeToString(hash))
	}
	s.auditLog(r.Context(), accountID(r), accountID(r), "delete", "api_key", id, clientIP(r), r.UserAgent())
	w.WriteHeader(http.StatusNoContent)
}
