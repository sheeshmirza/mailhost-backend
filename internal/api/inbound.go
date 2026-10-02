package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

type inboundSummary struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	MailFrom  string    `json:"mail_from"`
	RcptTo    []string  `json:"rcpt_to"`
	From      string    `json:"from"`
	Subject   string    `json:"subject"`
	Size      int       `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) listInbound(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	domainID, ok := optionalUUID(w, r, "domain_id")
	if !ok {
		return
	}
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, domain_id, mail_from, rcpt_to, from_header, subject, size, created_at FROM inbound_emails
WHERE account_id = $1 AND created_at < $2 AND ($4::uuid IS NULL OR domain_id = $4::uuid)
ORDER BY created_at DESC LIMIT $3`, accountID(r), before, limit, domainID)
	if err != nil {
		s.internal(w, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[inboundSummary])
	if err != nil {
		s.internal(w, err)
		return
	}
	resp := map[string]any{"data": out}
	if len(out) == limit {
		resp["next_before"] = out[len(out)-1].CreatedAt
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getInbound(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var m struct {
		inboundSummary
		MessageID   string          `json:"message_id"`
		Text        string          `json:"text"`
		HTML        string          `json:"html"`
		Attachments json.RawMessage `json:"attachments"`
	}
	err := s.db.QueryRow(r.Context(), `
SELECT id, domain_id, mail_from, rcpt_to, from_header, subject, size, created_at, message_id, text_body, html_body, attachments
FROM inbound_emails WHERE id = $1 AND account_id = $2`, id, accountID(r)).Scan(
		&m.ID, &m.DomainID, &m.MailFrom, &m.RcptTo, &m.From, &m.Subject, &m.Size, &m.CreatedAt,
		&m.MessageID, &m.Text, &m.HTML, &m.Attachments)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "inbound email not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) getInboundRaw(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var raw []byte
	err := s.db.QueryRow(r.Context(), `SELECT raw FROM inbound_emails WHERE id = $1 AND account_id = $2`, id, accountID(r)).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "inbound email not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.eml"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(raw)
}

// --- Mailhost Receiving API ---

func (s *Server) listReceivedEmails(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, domain_id, mail_from, rcpt_to, from_header, subject, size, attachments, created_at
FROM inbound_emails
WHERE account_id = $1 AND created_at < $2
ORDER BY created_at DESC LIMIT $3`, accountID(r), before, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id, domainID, mailFrom, fromHeader, subject string
		var rcptTo []string
		var size int
		var attsBytes []byte
		var createdAt time.Time

		if err := rows.Scan(&id, &domainID, &mailFrom, &rcptTo, &fromHeader, &subject, &size, &attsBytes, &createdAt); err != nil {
			s.internal(w, err)
			return
		}
		var atts []any
		_ = json.Unmarshal(attsBytes, &atts)
		if atts == nil {
			atts = []any{}
		}

		data = append(data, map[string]any{
			"id":          id,
			"object":      "email",
			"from":        fromHeader,
			"to":          rcptTo,
			"subject":     subject,
			"size":        size,
			"attachments": atts,
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

func (s *Server) getReceivedEmail(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	var m struct {
		ID          string          `json:"id"`
		From        string          `json:"from"`
		To          []string        `json:"to"`
		Subject     string          `json:"subject"`
		MessageID   string          `json:"message_id"`
		Text        string          `json:"text"`
		HTML        string          `json:"html"`
		Attachments json.RawMessage `json:"attachments"`
		CreatedAt   time.Time       `json:"created_at"`
	}

	err := s.rdb.QueryRow(r.Context(), `
SELECT id, from_header, rcpt_to, subject, message_id, text_body, html_body, attachments, created_at
FROM inbound_emails WHERE id = $1 AND account_id = $2`, id, accountID(r)).Scan(
		&m.ID, &m.From, &m.To, &m.Subject, &m.MessageID, &m.Text, &m.HTML, &m.Attachments, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "received email not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	var atts []any
	_ = json.Unmarshal(m.Attachments, &atts)
	if atts == nil {
		atts = []any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          m.ID,
		"object":      "email",
		"from":        m.From,
		"to":          m.To,
		"subject":     m.Subject,
		"message_id":  m.MessageID,
		"text":        m.Text,
		"html":        m.HTML,
		"attachments": atts,
		"created_at":  m.CreatedAt.Format(time.RFC3339),
	})
}

func (s *Server) listReceivedAttachments(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	var attsBytes []byte
	err := s.rdb.QueryRow(r.Context(), `
SELECT attachments FROM inbound_emails WHERE id = $1 AND account_id = $2`, id, accountID(r)).Scan(&attsBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "received email not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	var atts []any
	_ = json.Unmarshal(attsBytes, &atts)
	if atts == nil {
		atts = []any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   atts,
	})
}
