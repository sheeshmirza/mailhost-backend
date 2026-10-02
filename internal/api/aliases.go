package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"mailhost/internal/mailer"
	"mailhost/internal/validator"
)

type aliasView struct {
	ID           string    `json:"id"`
	DomainID     string    `json:"domain_id"`
	Name         string    `json:"name"`
	Address      string    `json:"address"`
	Destinations []string  `json:"destinations"`
	StoreCopy    bool      `json:"store_copy"`
	CreatedAt    time.Time `json:"created_at"`
}

const aliasSelect = `SELECT a.id, a.domain_id, a.local_part, d.name, a.destinations, a.store_copy, a.created_at
FROM aliases a JOIN domains d ON d.id = a.domain_id`

func scanAlias(row pgx.Row) (aliasView, error) {
	var a aliasView
	var domain string
	err := row.Scan(&a.ID, &a.DomainID, &a.Name, &domain, &a.Destinations, &a.StoreCopy, &a.CreatedAt)
	a.Address = a.Name + "@" + domain
	return a, err
}

func validateDestinations(in []string, storeCopy bool) ([]string, string) {
	if len(in) == 0 && !storeCopy {
		return nil, "an alias needs destinations or store_copy=true"
	}
	out := make([]string, 0, len(in))
	for _, d := range in {
		a, err := mailer.ParseAddress(d)
		if err != nil {
			return nil, "invalid destination " + d
		}
		out = append(out, strings.ToLower(a.Address))
	}
	return out, ""
}

func (s *Server) createAlias(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req struct {
		DomainID     string   `json:"domain_id"`
		Name         string   `json:"name"`
		Destinations []string `json:"destinations"`
		StoreCopy    *bool    `json:"store_copy"`
	}
	if !decode(w, r, 0, &req) {
		return
	}
	if !validUUID(req.DomainID) {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	if !validator.IsValidLocalPart(name) {
		writeError(w, http.StatusUnprocessableEntity, "name must be a valid local part (a-z, 0-9, . _ -) or *")
		return
	}
	storeCopy := len(req.Destinations) == 0
	if req.StoreCopy != nil {
		storeCopy = *req.StoreCopy
	}
	dests, msg := validateDestinations(req.Destinations, storeCopy)
	if msg != "" {
		writeError(w, http.StatusUnprocessableEntity, msg)
		return
	}
	var id string
	err := s.db.QueryRow(r.Context(), `
INSERT INTO aliases (account_id, domain_id, local_part, destinations, store_copy)
SELECT $1, d.id, $3, $4, $5 FROM domains d WHERE d.id = $2::uuid AND d.account_id = $1
RETURNING id`, accountID(r), req.DomainID, name, dests, storeCopy).Scan(&id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		writeError(w, http.StatusNotFound, "domain not found")
		return
	case isUniqueViolation(err):
		writeError(w, http.StatusConflict, "alias already exists")
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	a, err := scanAlias(s.db.QueryRow(r.Context(), aliasSelect+` WHERE a.id = $1`, id))
	if err != nil {
		s.internal(w, err)
		return
	}
	s.auditLog(r.Context(), accountID(r), accountID(r), "create", "alias", id, clientIP(r), r.UserAgent())
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) listAliases(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	domainID, ok := optionalUUID(w, r, "domain_id")
	if !ok {
		return
	}
	rows, err := s.rdb.Query(r.Context(),
		aliasSelect+` WHERE a.account_id = $1 AND ($2::uuid IS NULL OR a.domain_id = $2::uuid) AND a.created_at < $3 ORDER BY a.created_at DESC LIMIT $4`,
		accountID(r), domainID, before, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	out := []aliasView{}
	for rows.Next() {
		a, err := scanAlias(rows)
		if err != nil {
			s.internal(w, err)
			return
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}
	resp := map[string]any{"data": out}
	if len(out) == limit {
		resp["next_before"] = out[len(out)-1].CreatedAt
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getAlias(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	a, err := scanAlias(s.db.QueryRow(r.Context(), aliasSelect+` WHERE a.id = $1 AND a.account_id = $2`, id, accountID(r)))
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "alias not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) updateAlias(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Destinations []string `json:"destinations"`
		StoreCopy    bool     `json:"store_copy"`
	}
	if !decode(w, r, 0, &req) {
		return
	}
	dests, msg := validateDestinations(req.Destinations, req.StoreCopy)
	if msg != "" {
		writeError(w, http.StatusUnprocessableEntity, msg)
		return
	}
	tag, err := s.db.Exec(r.Context(), `UPDATE aliases SET destinations = $3, store_copy = $4 WHERE id = $1 AND account_id = $2`,
		id, accountID(r), dests, req.StoreCopy)
	if err != nil {
		s.internal(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "alias not found")
		return
	}
	s.auditLog(r.Context(), accountID(r), accountID(r), "update", "alias", id, clientIP(r), r.UserAgent())
	s.getAlias(w, r)
}

func (s *Server) deleteAlias(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	tag, err := s.db.Exec(r.Context(), `DELETE FROM aliases WHERE id = $1 AND account_id = $2`, id, accountID(r))
	if err != nil {
		s.internal(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "alias not found")
		return
	}
	s.auditLog(r.Context(), accountID(r), accountID(r), "delete", "alias", id, clientIP(r), r.UserAgent())
	w.WriteHeader(http.StatusNoContent)
}
