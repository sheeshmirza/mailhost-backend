package api

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type smtpCredView struct {
	ID         string     `json:"id"`
	DomainID   string     `json:"domain_id"`
	Email      string     `json:"email"`
	Name       string     `json:"name"`
	Username   string     `json:"username"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type createSMTPCredReq struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (s *Server) createSMTPCredential(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req createSMTPCredReq
	if !decode(w, r, 0, &req) {
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" {
		writeError(w, http.StatusUnprocessableEntity, "email is required")
		return
	}
	addr, err := mail.ParseAddress(req.Email)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid email address")
		return
	}
	dom := domainOf(addr.Address)

	// Verify sender domain belongs to account and is verified
	var domainID string
	err = s.db.QueryRow(r.Context(), `
SELECT id FROM domains WHERE account_id = $1 AND name = $2 AND status = 'verified'`,
		accountID(r), dom).Scan(&domainID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusUnprocessableEntity, "domain "+dom+" is not verified on this account")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = "SMTP Password for " + addr.Address
	}
	if len(req.Name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be at most 100 characters")
		return
	}

	password := newToken("smtp_live_", 28)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		s.internal(w, err)
		return
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	hash := h.Sum(nil)
	storedHash := make([]byte, 0, 16+len(hash))
	storedHash = append(storedHash, salt...)
	storedHash = append(storedHash, hash...)

	var id string
	var created time.Time
	err = s.db.QueryRow(r.Context(), `
INSERT INTO smtp_credentials (account_id, domain_id, email, name, password_hash)
VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		accountID(r), domainID, addr.Address, req.Name, storedHash).Scan(&id, &created)
	if err != nil {
		s.internal(w, err)
		return
	}

	s.auditLog(r.Context(), accountID(r), accountID(r), "create", "smtp_credential", id, clientIP(r), r.UserAgent())

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id,
		"domain_id":  domainID,
		"email":      addr.Address,
		"name":       req.Name,
		"username":   addr.Address,
		"password":   password,
		"smtp_host":  s.cfg.Hostname,
		"smtp_port":  587,
		"tls":        "STARTTLS",
		"created_at": created,
	})
}

func (s *Server) listSMTPCredentials(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	emailFilter := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("email")))

	var rows pgx.Rows
	var err error
	if emailFilter != "" {
		rows, err = s.rdb.Query(r.Context(), `
SELECT id, domain_id, email, name, email as username, last_used_at, created_at
FROM smtp_credentials WHERE account_id = $1 AND lower(email) = $2 AND created_at < $3 ORDER BY created_at DESC LIMIT $4`, accountID(r), emailFilter, before, limit)
	} else {
		rows, err = s.rdb.Query(r.Context(), `
SELECT id, domain_id, email, name, email as username, last_used_at, created_at
FROM smtp_credentials WHERE account_id = $1 AND created_at < $2 ORDER BY created_at DESC LIMIT $3`, accountID(r), before, limit)
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()

	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[smtpCredView])
	if err != nil {
		s.internal(w, err)
		return
	}
	resp := map[string]any{"data": list}
	if len(list) == limit {
		resp["next_before"] = list[len(list)-1].CreatedAt
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) deleteSMTPCredential(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	tag, err := s.db.Exec(r.Context(), `DELETE FROM smtp_credentials WHERE id = $1 AND account_id = $2`, id, accountID(r))
	if err != nil {
		s.internal(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "smtp credential not found")
		return
	}
	s.auditLog(r.Context(), accountID(r), accountID(r), "delete", "smtp_credential", id, clientIP(r), r.UserAgent())
	w.WriteHeader(http.StatusNoContent)
}
