package api

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/mail"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"mailhost/internal/docstore"
	"mailhost/internal/mailer"
	"mailhost/internal/queue"
	"mailhost/internal/validator"
)

type validationError struct{ msg string }

func (e validationError) Error() string { return e.msg }

func invalid(format string, a ...any) error { return validationError{fmt.Sprintf(format, a...)} }

type attachmentReq struct {
	Filename    string `json:"filename"`
	Content     string `json:"content"` // base64
	ContentType string `json:"content_type"`
}

type emailTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type sendReq struct {
	From        string            `json:"from"`
	To          []string          `json:"to"`
	Cc          []string          `json:"cc"`
	Bcc         []string          `json:"bcc"`
	ReplyTo     []string          `json:"reply_to"`
	Subject     string            `json:"subject"`
	HTML        string            `json:"html"`
	Text        string            `json:"text"`
	Headers     map[string]string `json:"headers"`
	Attachments []attachmentReq   `json:"attachments"`
	Tags        []emailTag        `json:"tags"`
	ScheduledAt *string           `json:"scheduled_at"`
	TemplateID  string            `json:"template_id"`
	Template    string            `json:"template"`
	Variables   map[string]any    `json:"variables"`

	// listUnsubscribe adds RFC 8058 one-click unsubscribe headers (marketing mail).
	listUnsubscribe bool
}

type signingKey struct {
	domainID       uuid.UUID
	name, selector string
	signer         crypto.Signer
	openTracking   bool
	clickTracking  bool
}

// signingKeys loads DKIM signers for the verified sender domains referenced by froms.
func (s *Server) signingKeys(ctx context.Context, account string, froms []string) (map[string]*signingKey, error) {
	seen := map[string]bool{}
	var names []string
	for _, f := range froms {
		a, err := mail.ParseAddress(f)
		if err != nil {
			return nil, invalid("invalid sender address %q: %v", f, err)
		}
		if d := domainOf(a.Address); !seen[d] {
			seen[d] = true
			names = append(names, d)
		}
	}
	keys := make(map[string]*signingKey, len(names))
	if len(names) == 0 {
		return keys, nil
	}

	var missing []string
	for _, name := range names {
		if k, ok := s.domains.Get(account + ":" + name); ok && k != nil {
			keys[name] = k
		} else {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		rows, err := s.db.Query(ctx,
			`SELECT id, name, status, dkim_selector, dkim_private_key, open_tracking, click_tracking FROM domains WHERE account_id = $1 AND name = ANY($2)`,
			account, missing)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		foundStatus := map[string]string{}
		for rows.Next() {
			var id, status string
			var enc []byte
			k := &signingKey{}
			if err := rows.Scan(&id, &k.name, &status, &k.selector, &enc, &k.openTracking, &k.clickTracking); err != nil {
				return nil, err
			}
			foundStatus[k.name] = status
			if status != "verified" {
				continue
			}
			k.domainID = uuid.MustParse(id)
			if k.signer, err = s.signer(id, enc); err != nil {
				return nil, err
			}
			keys[k.name] = k
			s.domains.Set(account+":"+k.name, k)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, name := range missing {
			st, found := foundStatus[name]
			if !found {
				return nil, invalid("from domain %q is not a registered domain on this account", name)
			}
			if st != "verified" {
				return nil, invalid("from domain %q is registered but not verified on this account", name)
			}
		}
	}
	for _, name := range names {
		if keys[name] == nil {
			return nil, invalid("from domain %q is not a verified domain on this account", name)
		}
	}
	if restrictedDom, ok := ctx.Value(domainKey{}).(string); ok && restrictedDom != "" {
		for domName, k := range keys {
			if k.domainID.String() != restrictedDom {
				return nil, invalid("API key is restricted to domain %s; cannot send from %s", restrictedDom, domName)
			}
		}
	}
	return keys, nil
}

func (s *Server) signer(id string, enc []byte) (crypto.Signer, error) {
	if v, ok := s.signers.Get(id); ok {
		return v, nil
	}
	pemBytes, err := s.box.Open(enc)
	if err != nil {
		return nil, err
	}
	sg, err := mailer.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	s.signers.Set(id, sg)
	return sg, nil
}

func idempotencyKey(r *http.Request) ([]byte, bool, error) {
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		return nil, false, nil
	}
	if len(key) > 255 {
		return nil, false, invalid("Idempotency-Key must be at most 255 bytes")
	}
	for _, c := range key {
		if c <= 0x1f || c == 0x7f {
			return nil, false, invalid("Idempotency-Key contains an invalid character")
		}
	}
	h := sha256.Sum256([]byte(key))
	return h[:], true, nil
}

// enqueueRequest returns a previously stored response for an idempotent retry,
// or writes the queue and stores this response in the same transaction.
func (s *Server) enqueueRequest(r *http.Request, emails []queue.Email, request, response any) ([]byte, error) {
	responseJSON, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	keyHash, hasKey, err := idempotencyKey(r)
	if err != nil {
		return nil, err
	}
	if !hasKey {
		if err := queue.Enqueue(r.Context(), s.db, accountUUID(r), emails); err != nil {
			return nil, err
		}
		s.saveEmailsToDocstore(accountID(r), emails)
		return responseJSON, nil
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	requestHash := sha256.Sum256(requestJSON)
	acctID := accountID(r)
	redisKey := "idemp:" + acctID + ":" + hex.EncodeToString(keyHash)

	if s.redis != nil {
		if cached, ok, _ := s.redis.Get(r.Context(), redisKey); ok && len(cached) > 32 {
			cachedHash := cached[:32]
			cachedResp := cached[32:]
			if subtle.ConstantTimeCompare(cachedHash, requestHash[:]) == 1 {
				return cachedResp, nil
			}
			return nil, queue.ErrIdempotencyConflict
		}
	}

	stored, _, err := queue.EnqueueIdempotent(r.Context(), s.db, accountUUID(r), emails, keyHash, requestHash[:], responseJSON, s.cfg.IdempotencyTTL)
	if err != nil {
		return nil, err
	}
	s.saveEmailsToDocstore(acctID, emails)

	if s.redis != nil {
		val := make([]byte, 0, 32+len(stored))
		val = append(val, requestHash[:]...)
		val = append(val, stored...)
		_ = s.redis.Set(r.Context(), redisKey, val, s.cfg.IdempotencyTTL)
	}

	return stored, nil
}

func (s *Server) enqueueDirect(ctx context.Context, acct string, emails []queue.Email) error {
	acctUUID, err := uuid.Parse(acct)
	if err != nil {
		return err
	}
	if err := queue.Enqueue(ctx, s.db, acctUUID, emails); err != nil {
		return err
	}
	s.saveEmailsToDocstore(acct, emails)
	return nil
}

func (s *Server) saveEmailsToDocstore(acctID string, emails []queue.Email) {
	if s.docstore == nil || len(emails) == 0 {
		return
	}
	for _, e := range emails {
		doc := docstore.EmailDocument{
			ID:         e.ID.String(),
			AccountID:  acctID,
			DomainID:   e.DomainID.String(),
			From:       e.From,
			Recipients: e.Recipients,
			Subject:    e.Subject,
			Raw:        e.Raw,
			Size:       len(e.Raw),
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
		}
		if e.BatchID != uuid.Nil {
			doc.BatchID = e.BatchID.String()
		}
		go func(d docstore.EmailDocument) {
			bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.docstore.SaveEmail(bgCtx, d)
		}(doc)
	}
}

func (s *Server) enqueueError(w http.ResponseWriter, err error) {
	var ve validationError
	switch {
	case errors.As(err, &ve):
		s.sendError(w, "", err)
	case errors.Is(err, queue.ErrIdempotencyConflict):
		writeError(w, http.StatusConflict, "Idempotency-Key was already used for a different request")
	default:
		s.internal(w, err)
	}
}

func decodeAttachments(in []attachmentReq) ([]mailer.Attachment, error) {
	const (
		maxAttachmentCount = 20
		maxAttachmentBytes = 25 << 20
	)
	if len(in) > maxAttachmentCount {
		return nil, invalid("attachments cannot contain more than %d items", maxAttachmentCount)
	}
	out := make([]mailer.Attachment, 0, len(in))
	var totalBytes int64
	for i, a := range in {
		if a.Filename == "" || len(a.Filename) > 255 {
			return nil, invalid("attachments[%d].filename is required", i)
		}
		data, err := base64.StdEncoding.DecodeString(a.Content)
		if err != nil {
			return nil, invalid("attachments[%d].content must be base64", i)
		}
		totalBytes += int64(len(data))
		if totalBytes > maxAttachmentBytes {
			return nil, invalid("total attachments size exceeds %d bytes", maxAttachmentBytes)
		}
		out = append(out, mailer.Attachment{Filename: a.Filename, ContentType: a.ContentType, Content: data})
	}
	return out, nil
}

// prepare validates, renders and DKIM-signs one message. It is safe for concurrent use.
func (s *Server) prepare(req *sendReq, atts []mailer.Attachment, keys map[string]*signingKey, batchID uuid.UUID) (queue.Email, error) {
	from, err := mailer.ParseAddress(req.From)
	if err != nil {
		return queue.Email{}, invalid("from: %v", err)
	}
	dom := domainOf(from.Address)
	key := keys[dom]
	if key == nil {
		return queue.Email{}, invalid("from domain %q is not a verified domain on this account", dom)
	}
	seen := map[string]bool{}
	var rcpts []string
	for _, list := range [][]string{req.To, req.Cc, req.Bcc} {
		for _, r := range list {
			a, err := mailer.ParseAddress(r)
			if err != nil {
				return queue.Email{}, invalid("invalid recipient %q", r)
			}
			if lc := strings.ToLower(a.Address); !seen[lc] {
				seen[lc] = true
				rcpts = append(rcpts, a.Address)
			}
		}
	}
	if len(rcpts) == 0 {
		return queue.Email{}, invalid("at least one recipient is required")
	}
	if len(rcpts) > 1000 {
		return queue.Email{}, invalid("at most 1000 recipients are allowed")
	}
	if req.HTML == "" && req.Text == "" {
		return queue.Email{}, invalid("html or text is required")
	}
	if len(req.Tags) > 100 {
		return queue.Email{}, invalid("at most 100 tags are allowed")
	}
	for i, tag := range req.Tags {
		if len(tag.Name) == 0 || len(tag.Name) > 100 || len(tag.Value) > 1000 {
			return queue.Email{}, invalid("tags[%d] is invalid", i)
		}
	}

	id := uuid.New()
	msgID := id.String() + "@" + dom
	bodyHTML := req.HTML
	if bodyHTML != "" && (key.openTracking || key.clickTracking) {
		host := s.cfg.Hostname
		if host == "" {
			host = "localhost"
		}
		bodyHTML = InjectTracking(bodyHTML, host, id.String(), s.cfg.MasterKey, key.openTracking, key.clickTracking)
	}
	headers := req.Headers
	if req.listUnsubscribe {
		headers = make(map[string]string, len(req.Headers)+2)
		for k, v := range req.Headers {
			headers[k] = v
		}
		headers["List-Unsubscribe"] = "<https://" + s.cfg.Hostname + "/v1/unsubscribe/" + id.String() + ">"
		headers["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
	}
	raw, err := mailer.Build(&mailer.Message{
		From: req.From, To: req.To, Cc: req.Cc, ReplyTo: req.ReplyTo,
		Subject: req.Subject, Text: req.Text, HTML: bodyHTML,
		Headers: headers, Attachments: atts, MessageID: msgID, Date: time.Now(),
	})
	if err != nil {
		return queue.Email{}, invalid("%v", err)
	}
	signed, err := mailer.Sign(raw, key.name, key.selector, key.signer)
	if err != nil {
		return queue.Email{}, err
	}
	if s.cfg.MaxMessageBytes > 0 && int64(len(signed)) > s.cfg.MaxMessageBytes {
		return queue.Email{}, invalid("message exceeds %d bytes", s.cfg.MaxMessageBytes)
	}
	tagsBytes, _ := json.Marshal(req.Tags)
	if req.Tags == nil {
		tagsBytes = []byte("[]")
	}
	var schedAt *time.Time
	if req.ScheduledAt != nil && *req.ScheduledAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ScheduledAt)
		if err != nil {
			return queue.Email{}, invalid("scheduled_at must be an RFC 3339 timestamp")
		}
		if t.Before(time.Now()) {
			return queue.Email{}, invalid("scheduled_at must not be in the past")
		}
		schedAt = &t
	}
	var tmplID *uuid.UUID
	if req.TemplateID != "" {
		id, err := uuid.Parse(req.TemplateID)
		if err != nil {
			return queue.Email{}, invalid("template_id must be a UUID")
		}
		tmplID = &id
	}

	return queue.Email{
		ID: id, DomainID: key.domainID, DomainName: dom, BatchID: batchID, From: from.Address,
		Subject: req.Subject, MessageID: msgID, Raw: signed, Recipients: rcpts,
		Tags: tagsBytes, ScheduledAt: schedAt, TemplateID: tmplID,
	}, nil
}

func (s *Server) resolveTemplates(ctx context.Context, acct string, reqs []sendReq) {
	for i := range reqs {
		if reqs[i].TemplateID != "" || reqs[i].Template != "" {
			ref := reqs[i].TemplateID
			if ref == "" {
				ref = reqs[i].Template
			}
			var pSub, pHTML, pText string
			err := s.rdb.QueryRow(ctx, `
SELECT published_subject, published_html, published_text
FROM templates
WHERE (id::text = $1 OR alias = $1) AND account_id = $2 AND status = 'published'`,
				ref, acct).Scan(&pSub, &pHTML, &pText)
			if err == nil {
				sub, h, t := RenderTemplate(pSub, pHTML, pText, reqs[i].Variables)
				if reqs[i].Subject == "" {
					reqs[i].Subject = sub
				}
				if reqs[i].HTML == "" {
					reqs[i].HTML = h
				}
				if reqs[i].Text == "" {
					reqs[i].Text = t
				}
			}
		}
	}
}

func (s *Server) sendError(w http.ResponseWriter, prefix string, err error) {
	var ve validationError
	if errors.As(err, &ve) {
		writeError(w, http.StatusUnprocessableEntity, prefix+ve.msg)
		return
	}
	s.internal(w, err)
}

func (s *Server) sendEmail(w http.ResponseWriter, r *http.Request) {
	if !requireSender(w, r) {
		return
	}
	var req sendReq
	var limit int64
	if s.cfg != nil && s.cfg.MaxMessageBytes > 0 {
		limit = s.cfg.MaxMessageBytes * 2
	}
	if !decode(w, r, limit, &req) {
		return
	}
	reqs := []sendReq{req}
	s.resolveTemplates(r.Context(), accountID(r), reqs)
	req = reqs[0]
	atts, err := decodeAttachments(req.Attachments)
	if err != nil {
		s.sendError(w, "", err)
		return
	}
	keys, err := s.signingKeys(r.Context(), accountID(r), []string{req.From})
	if err != nil {
		s.sendError(w, "", err)
		return
	}
	e, err := s.prepare(&req, atts, keys, uuid.Nil)
	if err != nil {
		s.sendError(w, "", err)
		return
	}
	response := map[string]any{"id": e.ID, "status": "queued"}
	body, err := s.enqueueRequest(r, []queue.Email{e}, req, response)
	if err != nil {
		s.enqueueError(w, err)
		return
	}
	writeJSONBytes(w, http.StatusAccepted, body)
}

// sendBatch accepts independent emails without batch size limit and enqueues them atomically.
func (s *Server) sendBatch(w http.ResponseWriter, r *http.Request) {
	if !requireSender(w, r) {
		return
	}
	var reqs []sendReq
	var limit int64
	if s.cfg != nil && s.cfg.MaxMessageBytes > 0 {
		limit = s.cfg.MaxMessageBytes * 4
	}
	if !decode(w, r, limit, &reqs) {
		return
	}
	if len(reqs) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "batch must contain at least 1 email")
		return
	}
	if len(reqs) > 5000 {
		writeError(w, http.StatusUnprocessableEntity, "batch cannot contain more than 5000 emails")
		return
	}
	s.resolveTemplates(r.Context(), accountID(r), reqs)
	froms := make([]string, len(reqs))
	for i := range reqs {
		froms[i] = reqs[i].From
	}
	keys, err := s.signingKeys(r.Context(), accountID(r), froms)
	if err != nil {
		s.sendError(w, "", err)
		return
	}
	batchID := uuid.New()
	emails := make([]queue.Email, len(reqs))
	ids := make([]map[string]any, len(reqs))

	if len(reqs) == 1 {
		atts, err := decodeAttachments(reqs[0].Attachments)
		if err == nil {
			emails[0], err = s.prepare(&reqs[0], atts, keys, batchID)
		}
		if err != nil {
			s.sendError(w, "emails[0]: ", err)
			return
		}
		ids[0] = map[string]any{"id": emails[0].ID}
	} else {
		errs := make([]error, len(reqs))
		var wg sync.WaitGroup
		sem := make(chan struct{}, runtime.GOMAXPROCS(0)*2)
		for i := range reqs {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int) {
				defer func() { <-sem; wg.Done() }()
				atts, err := decodeAttachments(reqs[idx].Attachments)
				if err != nil {
					errs[idx] = err
					return
				}
				emails[idx], errs[idx] = s.prepare(&reqs[idx], atts, keys, batchID)
			}(i)
		}
		wg.Wait()

		for i := range reqs {
			if errs[i] != nil {
				s.sendError(w, fmt.Sprintf("emails[%d]: ", i), errs[i])
				return
			}
			ids[i] = map[string]any{"id": emails[i].ID}
		}
	}

	response := map[string]any{"batch_id": batchID, "data": ids}
	body, err := s.enqueueRequest(r, emails, reqs, response)
	if err != nil {
		s.enqueueError(w, err)
		return
	}
	writeJSONBytes(w, http.StatusAccepted, body)
}

type bulkRecipient struct {
	To        string            `json:"to"`
	Variables map[string]string `json:"variables"`
}

type bulkReq struct {
	From        string            `json:"from"`
	ReplyTo     []string          `json:"reply_to"`
	Subject     string            `json:"subject"`
	HTML        string            `json:"html"`
	Text        string            `json:"text"`
	Headers     map[string]string `json:"headers"`
	Attachments []attachmentReq   `json:"attachments"`
	Recipients  []bulkRecipient   `json:"recipients"`
}

func validateVars(vars map[string]string) error {
	for k := range vars {
		if !validator.IsValidVariableName(k) {
			return invalid("invalid variable name %q", k)
		}
	}
	return nil
}

// render substitutes {{name}} placeholders; values are HTML-escaped for HTML bodies.
func render(tpl string, vars map[string]string, escape bool) string {
	if len(vars) == 0 || !strings.Contains(tpl, "{{") {
		return tpl
	}
	pairs := make([]string, 0, len(vars)*2)
	for k, v := range vars {
		if escape {
			v = html.EscapeString(v)
		}
		pairs = append(pairs, "{{"+k+"}}", v)
	}
	return strings.NewReplacer(pairs...).Replace(tpl)
}

func renderWithinLimit(tpl string, vars map[string]string, escape bool, limit int64) (string, error) {
	if limit < 0 || int64(len(tpl)) > limit {
		return "", invalid("rendered message exceeds %d bytes", limit)
	}
	estimated := int64(len(tpl))
	for key, value := range vars {
		tokenLength := int64(len("{{" + key + "}}"))
		if escape {
			value = html.EscapeString(value)
		}
		delta := int64(len(value)) - tokenLength
		if delta <= 0 {
			continue
		}
		occurrences := int64(strings.Count(tpl, "{{"+key+"}}"))
		if occurrences > 0 && delta > (limit-estimated)/occurrences {
			return "", invalid("rendered message exceeds %d bytes", limit)
		}
		estimated += occurrences * delta
	}
	result := render(tpl, vars, escape)
	if int64(len(result)) > limit {
		return "", invalid("rendered message exceeds %d bytes", limit)
	}
	return result, nil
}

// sendBulk sends one templated message without recipient count limit, each receiving an individual email.
func (s *Server) sendBulk(w http.ResponseWriter, r *http.Request) {
	if !requireSender(w, r) {
		return
	}
	const maxBulkRawBytes int64 = 256 << 20
	var req bulkReq
	var limit int64
	if s.cfg != nil && s.cfg.MaxMessageBytes > 0 {
		limit = s.cfg.MaxMessageBytes*2 + 64<<20
	}
	if !decode(w, r, limit, &req) {
		return
	}
	n := len(req.Recipients)
	if n == 0 {
		writeError(w, http.StatusUnprocessableEntity, "recipients must contain at least 1 entry")
		return
	}
	if n > 10000 {
		writeError(w, http.StatusUnprocessableEntity, "recipients cannot contain more than 10000 entries")
		return
	}
	for i, rc := range req.Recipients {
		if err := validateVars(rc.Variables); err != nil {
			s.sendError(w, fmt.Sprintf("recipients[%d]: ", i), err)
			return
		}
	}
	atts, err := decodeAttachments(req.Attachments)
	if err != nil {
		s.sendError(w, "", err)
		return
	}
	keys, err := s.signingKeys(r.Context(), accountID(r), []string{req.From})
	if err != nil {
		s.sendError(w, "", err)
		return
	}

	batchID := uuid.New()
	emails := make([]queue.Email, n)
	maxMessageBytes := int64(25 << 20)
	if s.cfg != nil && s.cfg.MaxMessageBytes > 0 {
		maxMessageBytes = s.cfg.MaxMessageBytes
	}
	var totalRawBytes int64
	for i := range req.Recipients {
		rc := req.Recipients[i]
		subject, err := renderWithinLimit(req.Subject, rc.Variables, false, maxMessageBytes)
		if err != nil {
			s.sendError(w, fmt.Sprintf("recipients[%d].subject: ", i), err)
			return
		}
		htmlBody, err := renderWithinLimit(req.HTML, rc.Variables, true, maxMessageBytes)
		if err != nil {
			s.sendError(w, fmt.Sprintf("recipients[%d].html: ", i), err)
			return
		}
		textBody, err := renderWithinLimit(req.Text, rc.Variables, false, maxMessageBytes)
		if err != nil {
			s.sendError(w, fmt.Sprintf("recipients[%d].text: ", i), err)
			return
		}
		one := sendReq{
			From: req.From, To: []string{rc.To}, ReplyTo: req.ReplyTo, Headers: req.Headers,
			Subject: subject, HTML: htmlBody, Text: textBody,
		}
		e, err := s.prepare(&one, atts, keys, batchID)
		if err != nil {
			s.sendError(w, fmt.Sprintf("recipients[%d]: ", i), err)
			return
		}
		if int64(len(e.Raw)) > maxBulkRawBytes-totalRawBytes {
			s.sendError(w, "", invalid("bulk request exceeds %d bytes of prepared messages", maxBulkRawBytes))
			return
		}
		totalRawBytes += int64(len(e.Raw))
		emails[i] = e
	}
	response := map[string]any{"batch_id": batchID, "count": n, "status": "queued"}
	body, err := s.enqueueRequest(r, emails, req, response)
	if err != nil {
		s.enqueueError(w, err)
		return
	}
	writeJSONBytes(w, http.StatusAccepted, body)
}

type deliveryView struct {
	ID        string    `json:"id"`
	Recipient string    `json:"recipient"`
	Status    string    `json:"status"`
	Attempts  int       `json:"attempts"`
	LastError *string   `json:"last_error"`
	UpdatedAt time.Time `json:"updated_at"`
}

type eventView struct {
	DeliveryID string    `json:"delivery_id"`
	Type       string    `json:"type"`
	Detail     *string   `json:"detail"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Server) getEmail(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var e struct {
		ID         string         `json:"id"`
		BatchID    *string        `json:"batch_id"`
		From       string         `json:"from"`
		Subject    string         `json:"subject"`
		MessageID  string         `json:"message_id"`
		CreatedAt  time.Time      `json:"created_at"`
		Deliveries []deliveryView `json:"deliveries"`
		Events     []eventView    `json:"events"`
	}
	err := s.db.QueryRow(r.Context(),
		`SELECT id, batch_id, from_addr, subject, message_id, created_at FROM emails WHERE id = $1 AND account_id = $2`,
		id, accountID(r)).Scan(&e.ID, &e.BatchID, &e.From, &e.Subject, &e.MessageID, &e.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "email not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	rows, err := s.db.Query(r.Context(),
		`SELECT id, recipient, status, attempts, last_error, updated_at FROM deliveries WHERE email_id = $1 ORDER BY recipient`, id)
	if err == nil {
		e.Deliveries, err = pgx.CollectRows(rows, pgx.RowToStructByPos[deliveryView])
	}
	if err == nil {
		rows, err = s.db.Query(r.Context(),
			`SELECT delivery_id, type, detail, created_at FROM events WHERE email_id = $1 ORDER BY id`, id)
		if err == nil {
			e.Events, err = pgx.CollectRows(rows, pgx.RowToStructByPos[eventView])
		}
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if e.Deliveries == nil {
		e.Deliveries = []deliveryView{}
	}
	if e.Events == nil {
		e.Events = []eventView{}
	}
	writeJSON(w, http.StatusOK, e)
}

type emailSummary struct {
	ID        string    `json:"id"`
	BatchID   *string   `json:"batch_id"`
	From      string    `json:"from"`
	Subject   string    `json:"subject"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) listEmails(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	statusFilter := r.URL.Query().Get("status")
	validStatuses := map[string]bool{
		"queued": true, "scheduled": true, "sending": true, "delivered": true,
		"bounced": true, "deferred": true, "failed": true, "cancelled": true,
	}
	if statusFilter != "" && statusFilter != "all" && !validStatuses[statusFilter] {
		writeError(w, http.StatusUnprocessableEntity, "invalid email status")
		return
	}
	beforeID, ok := optionalUUID(w, r, "before_id")
	if !ok {
		return
	}
	var status *string
	if statusFilter != "" && statusFilter != "all" {
		status = &statusFilter
	}
	// Emails from one batch share created_at, so the cursor needs the id as a tie-breaker.
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, batch_id, from_addr, subject, status, created_at FROM emails
WHERE account_id = $1 AND ($2::text IS NULL OR status = $2)
  AND (created_at < $3 OR ($5::uuid IS NOT NULL AND created_at = $3 AND id < $5::uuid))
ORDER BY created_at DESC, id DESC LIMIT $4`, accountID(r), status, before, limit, beforeID)
	if err != nil {
		s.internal(w, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[emailSummary])
	if err != nil {
		s.internal(w, err)
		return
	}
	resp := map[string]any{"data": out}
	if len(out) == limit {
		resp["next_before"] = out[len(out)-1].CreatedAt
		resp["next_before_id"] = out[len(out)-1].ID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getBatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rows, err := s.rdb.Query(r.Context(), `
SELECT d.status, count(*) FROM deliveries d JOIN emails e ON e.id = d.email_id
WHERE e.batch_id = $1 AND e.account_id = $2 GROUP BY d.status`, id, accountID(r))
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	counts := map[string]int64{}
	var total int64
	for rows.Next() {
		var st string
		var c int64
		if err := rows.Scan(&st, &c); err != nil {
			s.internal(w, err)
			return
		}
		counts[st] = c
		total += c
	}
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}
	if total == 0 {
		writeError(w, http.StatusNotFound, "batch not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"batch_id": id, "total": total, "statuses": counts})
}

func (s *Server) cancelEmail(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid email id")
		return
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(), `
UPDATE deliveries
SET status = 'cancelled', updated_at = now()
WHERE email_id = $1 AND account_id = $2 AND status IN ('scheduled', 'queued', 'deferred')`,
		id, acct)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cancel failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "email not found or already delivered")
		return
	}
	if err := s.refreshCancelledEmail(r.Context(), acct, id); err != nil {
		s.internal(w, err)
		return
	}

	s.audit(r.Context(), acct, "cancel", "email", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":     id.String(),
		"object": "email",
		"status": "cancelled",
	})
}

// refreshCancelledEmail marks the email cancelled only when none of its deliveries are still pending or sent.
func (s *Server) refreshCancelledEmail(ctx context.Context, acct string, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `
UPDATE emails e SET status = 'cancelled'
WHERE e.id = $1 AND e.account_id = $2
  AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.email_id = e.id AND d.status <> 'cancelled')`, id, acct)
	return err
}
