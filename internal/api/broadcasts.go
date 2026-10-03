package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"mailhost/internal/mailer"
	"mailhost/internal/queue"
	"mailhost/internal/validator"
)

type broadcastReq struct {
	Name        string  `json:"name"`
	From        string  `json:"from"`
	Subject     string  `json:"subject"`
	ReplyTo     any     `json:"reply_to"` // string or []string
	PreviewText string  `json:"preview_text"`
	HTML        string  `json:"html"`
	Text        string  `json:"text"`
	SegmentID   *string `json:"segment_id"`
	AudienceID  *string `json:"audience_id"`
	TopicID     *string `json:"topic_id"`
	ScheduledAt *string `json:"scheduled_at"`
}

type sendBroadcastReq struct {
	ScheduledAt *string `json:"scheduled_at"`
}

type recipientInfo struct {
	email, firstName, lastName string
}

func parseBroadcastSchedule(value *string) (*time.Time, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(*value))
	if err != nil {
		return nil, errors.New("scheduled_at must be an RFC 3339 timestamp")
	}
	return &t, nil
}

func parseReplyTo(v any) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		if strings.TrimSpace(val) != "" {
			return []string{strings.TrimSpace(val)}
		}
	case []any:
		var res []string
		for _, item := range val {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				res = append(res, strings.TrimSpace(s))
			}
		}
		return res
	case []string:
		return val
	}
	return nil
}

func (s *Server) createBroadcast(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req broadcastReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be between 1 and 100 characters")
		return
	}
	from := strings.TrimSpace(req.From)
	fromAddr, err := mailer.ParseAddress(from)
	if err != nil || !validator.IsValidEmail(fromAddr.Address) {
		writeError(w, http.StatusUnprocessableEntity, "valid 'from' email address is required")
		return
	}
	fromDom := domainOf(fromAddr.Address)
	var domStatus string
	err = s.db.QueryRow(r.Context(), `SELECT status FROM domains WHERE account_id = $1 AND lower(name) = $2`, accountID(r), strings.ToLower(fromDom)).Scan(&domStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusUnprocessableEntity, "from domain \""+fromDom+"\" is not a registered domain on this account")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if domStatus != "verified" {
		writeError(w, http.StatusUnprocessableEntity, "from domain \""+fromDom+"\" is registered but not verified on this account")
		return
	}
	if strings.TrimSpace(req.Subject) == "" || len(req.Subject) > 998 || strings.ContainsAny(req.Subject, "\r\n") {
		writeError(w, http.StatusUnprocessableEntity, "subject must be non-empty, under 998 characters, and contain no newlines")
		return
	}

	replyTo := parseReplyTo(req.ReplyTo)
	if replyTo == nil {
		replyTo = []string{}
	}
	for _, rt := range replyTo {
		if !validator.IsValidEmail(rt) {
			writeError(w, http.StatusUnprocessableEntity, "invalid reply_to address: "+rt)
			return
		}
	}
	var segID, audID, topID *uuid.UUID
	if req.SegmentID != nil && *req.SegmentID != "" {
		id, err := uuid.Parse(*req.SegmentID)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "segment_id must be a UUID")
			return
		}
		segID = &id
	}
	if req.AudienceID != nil && *req.AudienceID != "" {
		id, err := uuid.Parse(*req.AudienceID)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "audience_id must be a UUID")
			return
		}
		audID = &id
	}
	if req.TopicID != nil && *req.TopicID != "" {
		id, err := uuid.Parse(*req.TopicID)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "topic_id must be a UUID")
			return
		}
		topID = &id
	}
	acct := accountID(r)
	refs := []struct {
		name, table string
		id          *uuid.UUID
	}{
		{name: "segment_id", table: "segments", id: segID},
		{name: "audience_id", table: "audiences", id: audID},
		{name: "topic_id", table: "topics", id: topID},
	}
	for _, ref := range refs {
		name, table, id := ref.name, ref.table, ref.id
		if id == nil {
			continue
		}
		var belongs bool
		if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id = $1 AND account_id = $2)`, *id, acct).Scan(&belongs); err != nil {
			s.internal(w, err)
			return
		}
		if !belongs {
			writeError(w, http.StatusUnprocessableEntity, name+" does not belong to this account")
			return
		}
	}

	scheduledAt, scheduleErr := parseBroadcastSchedule(req.ScheduledAt)
	if scheduleErr != nil {
		writeError(w, http.StatusUnprocessableEntity, scheduleErr.Error())
		return
	}

	var id uuid.UUID
	var createdAt, updatedAt time.Time

	err = s.db.QueryRow(r.Context(), `
INSERT INTO broadcasts (account_id, segment_id, audience_id, topic_id, name, from_addr, subject, reply_to, preview_text, html, text, status, scheduled_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'draft', $12, now())
RETURNING id, created_at, updated_at`,
		acct, segID, audID, topID, name, from, req.Subject, replyTo, req.PreviewText, req.HTML, req.Text, scheduledAt).
		Scan(&id, &createdAt, &updatedAt)
	if err != nil {
		s.log.Error("create broadcast failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create broadcast")
		return
	}

	s.audit(r.Context(), acct, "create", "broadcast", id.String(), r)
	resp := map[string]any{
		"id":           id.String(),
		"object":       "broadcast",
		"name":         name,
		"from":         from,
		"subject":      req.Subject,
		"reply_to":     replyTo,
		"preview_text": req.PreviewText,
		"status":       "draft",
		"segment_id":   req.SegmentID,
		"audience_id":  req.AudienceID,
		"topic_id":     req.TopicID,
		"created_at":   createdAt.Format(time.RFC3339),
		"updated_at":   updatedAt.Format(time.RFC3339),
	}
	if scheduledAt != nil {
		resp["scheduled_at"] = scheduledAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) listBroadcasts(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, segment_id, audience_id, topic_id, name, from_addr, subject, reply_to, preview_text, status,
       scheduled_at, sent_at, recipients_count, sent_count, created_at, updated_at
FROM broadcasts
WHERE account_id = $1 AND created_at < $2
ORDER BY created_at DESC LIMIT $3`,
		acct, before, limit)
	if err != nil {
		s.log.Error("list broadcasts failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list broadcasts")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var segID, audID, topID *uuid.UUID
		var name, from, subject, preview, status string
		var replyTo []string
		var schedAt, sentAt *time.Time
		var rcptCount, sentCount int
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &segID, &audID, &topID, &name, &from, &subject, &replyTo, &preview, &status,
			&schedAt, &sentAt, &rcptCount, &sentCount, &createdAt, &updatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}

		item := map[string]any{
			"id":               id.String(),
			"object":           "broadcast",
			"name":             name,
			"from":             from,
			"subject":          subject,
			"reply_to":         replyTo,
			"preview_text":     preview,
			"status":           status,
			"recipients_count": rcptCount,
			"sent_count":       sentCount,
			"created_at":       createdAt.Format(time.RFC3339Nano),
			"updated_at":       updatedAt.Format(time.RFC3339),
		}
		if segID != nil {
			item["segment_id"] = segID.String()
		}
		if audID != nil {
			item["audience_id"] = audID.String()
		}
		if topID != nil {
			item["topic_id"] = topID.String()
		}
		if schedAt != nil {
			item["scheduled_at"] = schedAt.Format(time.RFC3339)
		}
		if sentAt != nil {
			item["sent_at"] = sentAt.Format(time.RFC3339)
		}
		data = append(data, item)
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

func (s *Server) getBroadcast(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid broadcast id")
		return
	}

	acct := accountID(r)
	var segID, audID, topID *uuid.UUID
	var name, from, subject, preview, htmlStr, textStr, status string
	var replyTo []string
	var schedAt, sentAt *time.Time
	var rcptCount, sentCount int
	var createdAt, updatedAt time.Time

	err = s.rdb.QueryRow(r.Context(), `
SELECT id, segment_id, audience_id, topic_id, name, from_addr, subject, reply_to, preview_text,
       html, text, status, scheduled_at, sent_at, recipients_count, sent_count, created_at, updated_at
FROM broadcasts
WHERE id = $1 AND account_id = $2`,
		id, acct).Scan(&id, &segID, &audID, &topID, &name, &from, &subject, &replyTo, &preview,
		&htmlStr, &textStr, &status, &schedAt, &sentAt, &rcptCount, &sentCount, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "broadcast not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	resp := map[string]any{
		"id":               id.String(),
		"object":           "broadcast",
		"name":             name,
		"from":             from,
		"subject":          subject,
		"reply_to":         replyTo,
		"preview_text":     preview,
		"html":             htmlStr,
		"text":             textStr,
		"status":           status,
		"recipients_count": rcptCount,
		"sent_count":       sentCount,
		"created_at":       createdAt.Format(time.RFC3339),
		"updated_at":       updatedAt.Format(time.RFC3339),
	}
	if segID != nil {
		resp["segment_id"] = segID.String()
	}
	if audID != nil {
		resp["audience_id"] = audID.String()
	}
	if topID != nil {
		resp["topic_id"] = topID.String()
	}
	if schedAt != nil {
		resp["scheduled_at"] = schedAt.Format(time.RFC3339)
	}
	if sentAt != nil {
		resp["sent_at"] = sentAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) updateBroadcast(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid broadcast id")
		return
	}

	var req broadcastReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name != "" && len(strings.TrimSpace(req.Name)) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be at most 100 characters")
		return
	}
	acct := accountID(r)
	if req.From != "" {
		from := strings.TrimSpace(req.From)
		fromAddr, err := mailer.ParseAddress(from)
		if err != nil || !validator.IsValidEmail(fromAddr.Address) {
			writeError(w, http.StatusUnprocessableEntity, "valid 'from' email address is required")
			return
		}
		fromDom := domainOf(fromAddr.Address)
		var domStatus string
		err = s.db.QueryRow(r.Context(), `SELECT status FROM domains WHERE account_id = $1 AND lower(name) = $2`, acct, strings.ToLower(fromDom)).Scan(&domStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusUnprocessableEntity, "from domain \""+fromDom+"\" is not a registered domain on this account")
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		if domStatus != "verified" {
			writeError(w, http.StatusUnprocessableEntity, "from domain \""+fromDom+"\" is registered but not verified on this account")
			return
		}
	}
	if req.Subject != "" && (len(req.Subject) > 998 || strings.ContainsAny(req.Subject, "\r\n")) {
		writeError(w, http.StatusUnprocessableEntity, "subject must be under 998 characters and contain no newlines")
		return
	}

	replyTo := parseReplyTo(req.ReplyTo)
	for _, rt := range replyTo {
		if !validator.IsValidEmail(rt) {
			writeError(w, http.StatusUnprocessableEntity, "invalid reply_to address: "+rt)
			return
		}
	}

	tag, err := s.db.Exec(r.Context(), `
UPDATE broadcasts
SET name = COALESCE(NULLIF($3, ''), name),
    from_addr = COALESCE(NULLIF($4, ''), from_addr),
    subject = COALESCE(NULLIF($5, ''), subject),
    reply_to = CASE WHEN $6::text[] IS NOT NULL AND array_length($6::text[], 1) > 0 THEN $6::text[] ELSE reply_to END,
    preview_text = COALESCE(NULLIF($7, ''), preview_text),
    html = COALESCE(NULLIF($8, ''), html),
    text = COALESCE(NULLIF($9, ''), text),
    updated_at = now()
WHERE id = $1 AND account_id = $2 AND status = 'draft'`,
		id, acct, req.Name, req.From, req.Subject, replyTo, req.PreviewText, req.HTML, req.Text)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "broadcast not found or already sent")
		return
	}

	s.audit(r.Context(), acct, "update", "broadcast", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "broadcast",
		"updated": true,
	})
}

func (s *Server) deleteBroadcast(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid broadcast id")
		return
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(),
		`DELETE FROM broadcasts WHERE id = $1 AND account_id = $2`,
		id, acct)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "broadcast not found")
		return
	}

	s.audit(r.Context(), acct, "delete", "broadcast", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "broadcast",
		"deleted": true,
	})
}

func (s *Server) duplicateBroadcast(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid broadcast id")
		return
	}

	acct := accountID(r)
	var newID uuid.UUID
	var name string
	var createdAt time.Time

	err = s.db.QueryRow(r.Context(), `
INSERT INTO broadcasts (account_id, segment_id, audience_id, topic_id, name, from_addr, subject, reply_to, preview_text, html, text, status)
SELECT account_id, segment_id, audience_id, topic_id, name || ' (Copy)', from_addr, subject, reply_to, preview_text, html, text, 'draft'
FROM broadcasts
WHERE id = $1 AND account_id = $2
RETURNING id, name, created_at`,
		id, acct).Scan(&newID, &name, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "broadcast not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "duplicate failed")
		return
	}

	s.audit(r.Context(), acct, "duplicate", "broadcast", newID.String(), r)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         newID.String(),
		"object":     "broadcast",
		"name":       name,
		"status":     "draft",
		"created_at": createdAt.Format(time.RFC3339),
	})
}

func (s *Server) executeSendBroadcast(ctx context.Context, acct string, id uuid.UUID, scheduledAtStr *string) (map[string]any, int, error) {
	// Fetch broadcast details
	var b struct {
		from, subject, html, text string
		replyTo                   []string
		segID, audID, topID       *uuid.UUID
	}

	err := s.db.QueryRow(ctx, `
SELECT from_addr, subject, html, text, reply_to, segment_id, audience_id, topic_id
FROM broadcasts
WHERE id = $1 AND account_id = $2`,
		id, acct).Scan(&b.from, &b.subject, &b.html, &b.text, &b.replyTo, &b.segID, &b.audID, &b.topID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, http.StatusNotFound, errors.New("broadcast not found")
	}
	if err != nil {
		return nil, http.StatusInternalServerError, errors.New("lookup failed")
	}

	if _, err := s.signingKeys(ctx, acct, []string{b.from}); err != nil {
		var ve validationError
		if errors.As(err, &ve) {
			return nil, http.StatusUnprocessableEntity, errors.New(ve.msg)
		}
		return nil, http.StatusInternalServerError, err
	}

	// Schedule check
	if t, err := parseBroadcastSchedule(scheduledAtStr); err != nil {
		return nil, http.StatusUnprocessableEntity, err
	} else if t != nil {
		if t.After(time.Now()) {
			tag, updateErr := s.db.Exec(ctx,
				`UPDATE broadcasts SET status = 'queued', scheduled_at = $3, updated_at = now()
					 WHERE id = $1 AND account_id = $2 AND status IN ('draft', 'queued')`,
				id, acct, *t)
			if updateErr != nil {
				return nil, http.StatusInternalServerError, errors.New("failed to schedule broadcast")
			}
			if tag.RowsAffected() == 0 {
				return nil, http.StatusConflict, errors.New("broadcast has already been sent or is being sent")
			}
			return map[string]any{
				"id":           id.String(),
				"object":       "broadcast",
				"status":       "queued",
				"scheduled_at": t.Format(time.RFC3339),
			}, http.StatusOK, nil
		}
	}

	var claimedID uuid.UUID
	err = s.db.QueryRow(ctx, `
			UPDATE broadcasts
			SET status = 'sending', updated_at = now()
			WHERE id = $1 AND account_id = $2 AND status IN ('draft', 'queued')
			RETURNING id`, id, acct).Scan(&claimedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, http.StatusConflict, errors.New("broadcast has already been sent or is being sent")
	}
	if err != nil {
		return nil, http.StatusInternalServerError, errors.New("failed to claim broadcast")
	}

	// Immediate send: query contacts
	var query string
	var args []any
	args = append(args, acct)

	if b.segID != nil {
		query = `
SELECT c.email, c.first_name, c.last_name
FROM contacts c
JOIN contact_segments cs ON cs.contact_id = c.id
WHERE c.account_id = $1 AND cs.segment_id = $2 AND c.unsubscribed = false`
		args = append(args, *b.segID)
	} else if b.audID != nil {
		query = `
SELECT c.email, c.first_name, c.last_name
FROM contacts c
WHERE c.account_id = $1 AND c.audience_id = $2 AND c.unsubscribed = false`
		args = append(args, *b.audID)
	} else {
		query = `
SELECT c.email, c.first_name, c.last_name
FROM contacts c
WHERE c.account_id = $1 AND c.unsubscribed = false`
	}

	// Exclude contacts opted out of the topic
	if b.topID != nil {
		args = append(args, *b.topID)
		query += ` AND c.id NOT IN (SELECT contact_id FROM contact_topics WHERE topic_id = $` + strconv.Itoa(len(args)) + ` AND status = 'unsubscribed')`
	}

	rows, err := s.rdb.Query(ctx, query, args...)
	if err != nil {
		s.log.Error("gather broadcast contacts failed", "err", err)
		return nil, http.StatusInternalServerError, errors.New("failed to gather recipients")
	}
	defer rows.Close()

	var recipients []recipientInfo
	for rows.Next() {
		var r recipientInfo
		if err := rows.Scan(&r.email, &r.firstName, &r.lastName); err == nil {
			recipients = append(recipients, r)
		}
	}

	if len(recipients) == 0 {
		_, _ = s.db.Exec(ctx, `UPDATE broadcasts SET status = 'draft', updated_at = now() WHERE id = $1 AND account_id = $2`, id, acct)
		return nil, http.StatusUnprocessableEntity, errors.New("no eligible recipients found for broadcast")
	}

	_, _ = s.db.Exec(ctx,
		`UPDATE broadcasts SET recipients_count = $3, updated_at = now() WHERE id = $1 AND account_id = $2`,
		id, acct, len(recipients))

	// Asynchronously dispatch personalized messages in parallel batches
	go s.dispatchBroadcast(context.Background(), id, acct, b.from, b.subject, b.html, b.text, b.replyTo, recipients)

	return map[string]any{
		"id":               id.String(),
		"object":           "broadcast",
		"status":           "sending",
		"recipients_count": len(recipients),
	}, http.StatusOK, nil
}

func (s *Server) sendBroadcast(w http.ResponseWriter, r *http.Request) {
	if !requireSender(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid broadcast id")
		return
	}

	var req sendBroadcastReq
	if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	res, status, err := s.executeSendBroadcast(r.Context(), accountID(r), id, req.ScheduledAt)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}

	s.audit(r.Context(), accountID(r), "send", "broadcast", id.String(), r)
	writeJSON(w, status, res)
}

func (s *Server) dispatchBroadcast(ctx context.Context, broadcastID uuid.UUID, acct, from, subject, html, text string, replyTo []string, recipients []recipientInfo) {
	const batchSize = 100
	totalSent := 0

	keys, err := s.signingKeys(ctx, acct, []string{from})
	if err != nil {
		s.log.Error("broadcast signing keys lookup failed", "broadcast_id", broadcastID, "err", err)
		_, _ = s.db.Exec(ctx, `UPDATE broadcasts SET status = 'failed', updated_at = now() WHERE id = $1 AND account_id = $2`, broadcastID, acct)
		return
	}

	failed := false
	for i := 0; i < len(recipients); i += batchSize {
		end := i + batchSize
		if end > len(recipients) {
			end = len(recipients)
		}
		chunk := recipients[i:end]

		emails := make([]queue.Email, 0, len(chunk))
		for _, rcpt := range chunk {
			vars := map[string]any{
				"contact.first_name": rcpt.firstName,
				"contact.last_name":  rcpt.lastName,
				"contact.email":      rcpt.email,
				"first_name":         rcpt.firstName,
				"last_name":          rcpt.lastName,
				"email":              rcpt.email,
			}
			rSub, rHTML, rText := RenderTemplate(subject, html, text, vars)
			req := sendReq{
				From:            from,
				To:              []string{rcpt.email},
				ReplyTo:         replyTo,
				Subject:         rSub,
				HTML:            rHTML,
				Text:            rText,
				listUnsubscribe: true,
			}
			e, err := s.prepare(&req, nil, keys, uuid.Nil)
			if err != nil {
				s.log.Error("broadcast prepare failed", "broadcast_id", broadcastID, "recipient", rcpt.email, "err", err)
				failed = true
				continue
			}
			emails = append(emails, e)
		}

		// Enqueue the batch
		err := s.enqueueDirect(ctx, acct, emails)
		if err == nil {
			totalSent += len(emails)
		} else {
			s.log.Error("broadcast chunk enqueue failed", "broadcast_id", broadcastID, "err", err)
			failed = true
		}
	}

	status := "sent"
	if totalSent == 0 && len(recipients) > 0 {
		status = "failed"
	} else if failed && totalSent < len(recipients) {
		status = "partial"
	}
	_, _ = s.db.Exec(ctx, `
UPDATE broadcasts
SET status = $3, sent_at = CASE WHEN $3 IN ('sent', 'partial') THEN COALESCE(sent_at, now()) ELSE sent_at END, sent_count = $4, updated_at = now()
WHERE id = $1 AND account_id = $2`,
		broadcastID, acct, status, totalSent)
}

// ProcessScheduledBroadcasts finds queued broadcasts whose scheduled_at is due and triggers sending.
func (s *Server) ProcessScheduledBroadcasts(ctx context.Context) {
	rows, err := s.db.Query(ctx, `
SELECT id, account_id, from_addr, subject, html, text, reply_to, segment_id, audience_id, topic_id
FROM broadcasts
WHERE status = 'queued' AND scheduled_at IS NOT NULL AND scheduled_at <= now()
FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return
	}
	defer rows.Close()

	type dueBroadcast struct {
		id                  uuid.UUID
		acct, from, subject string
		html, text          string
		replyTo             []string
		segID, audID, topID *uuid.UUID
	}
	var due []dueBroadcast
	for rows.Next() {
		var b dueBroadcast
		if err := rows.Scan(&b.id, &b.acct, &b.from, &b.subject, &b.html, &b.text, &b.replyTo, &b.segID, &b.audID, &b.topID); err == nil {
			due = append(due, b)
		}
	}

	for _, b := range due {
		var claimed uuid.UUID
		if err := s.db.QueryRow(ctx, `
				UPDATE broadcasts
				SET status = 'sending', updated_at = now()
				WHERE id = $1 AND account_id = $2 AND status = 'queued'
				RETURNING id`, b.id, b.acct).Scan(&claimed); err != nil {
			continue
		}
		var query string
		var args []any
		args = append(args, b.acct)

		if b.segID != nil {
			query = `
SELECT c.email, c.first_name, c.last_name
FROM contacts c
JOIN contact_segments cs ON cs.contact_id = c.id
WHERE c.account_id = $1 AND cs.segment_id = $2 AND c.unsubscribed = false`
			args = append(args, *b.segID)
		} else if b.audID != nil {
			query = `
SELECT c.email, c.first_name, c.last_name
FROM contacts c
WHERE c.account_id = $1 AND c.audience_id = $2 AND c.unsubscribed = false`
			args = append(args, *b.audID)
		} else {
			query = `
SELECT c.email, c.first_name, c.last_name
FROM contacts c
WHERE c.account_id = $1 AND c.unsubscribed = false`
		}

		if b.topID != nil {
			args = append(args, *b.topID)
			query += ` AND c.id NOT IN (SELECT contact_id FROM contact_topics WHERE topic_id = $` + strconv.Itoa(len(args)) + ` AND status = 'unsubscribed')`
		}

		cRows, err := s.rdb.Query(ctx, query, args...)
		if err != nil {
			continue
		}
		var recipients []recipientInfo
		for cRows.Next() {
			var r recipientInfo
			if err := cRows.Scan(&r.email, &r.firstName, &r.lastName); err == nil {
				recipients = append(recipients, r)
			}
		}
		cRows.Close()

		if len(recipients) == 0 {
			_, _ = s.db.Exec(ctx, `UPDATE broadcasts SET status = 'sent', sent_at = now(), sent_count = 0, updated_at = now() WHERE id = $1`, b.id)
			continue
		}

		_, _ = s.db.Exec(ctx, `UPDATE broadcasts SET recipients_count = $2, updated_at = now() WHERE id = $1 AND account_id = $3`, b.id, len(recipients), b.acct)
		go s.dispatchBroadcast(context.Background(), b.id, b.acct, b.from, b.subject, b.html, b.text, b.replyTo, recipients)
	}
}
