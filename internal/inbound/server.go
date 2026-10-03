// Package inbound is the receiving MTA (MX) for user domains: it stores mail, forwards aliases,
// fires webhooks and processes asynchronous bounces addressed to VERP return paths.
package inbound

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"mailhost/internal/cache"
	"mailhost/internal/config"
	"mailhost/internal/docstore"
	"mailhost/internal/mailbox"
	"mailhost/internal/mailer"
	"mailhost/internal/metrics"
	"mailhost/internal/queue"
	"mailhost/internal/secretbox"
	"mailhost/internal/webhook"
)

type smtpAuthInfo struct {
	AccountID string
	DomainID  string
	Email     string
}

type Backend struct {
	db        *pgxpool.Pool
	box       *secretbox.Box
	cfg       *config.Config
	log       *slog.Logger
	hooks     *webhook.Client
	hookSem   chan struct{}
	authCache *cache.Cache[*smtpAuthInfo]
	docstore  *docstore.Client
	// submission marks a port-587 listener, which only accepts authenticated clients.
	submission bool
}

type Server struct {
	*smtp.Server
	be *Backend
}

func (s *Server) SetDocstore(d *docstore.Client) {
	if s != nil && s.be != nil {
		s.be.docstore = d
	}
}

func NewServer(db *pgxpool.Pool, box *secretbox.Box, cfg *config.Config, log *slog.Logger) (*Server, error) {
	return newServer(db, box, cfg, log, false)
}

// NewSubmissionServer builds a listener for authenticated client submission (RFC 6409).
func NewSubmissionServer(db *pgxpool.Pool, box *secretbox.Box, cfg *config.Config, log *slog.Logger) (*Server, error) {
	return newServer(db, box, cfg, log, true)
}

func newServer(db *pgxpool.Pool, box *secretbox.Box, cfg *config.Config, log *slog.Logger, submission bool) (*Server, error) {
	be := &Backend{
		db: db, box: box, cfg: cfg, log: log,
		hooks:      webhook.NewWithSecurity(cfg.AllowPrivateDelivery),
		hookSem:    make(chan struct{}, 256),
		authCache:  cache.New[*smtpAuthInfo](5*time.Minute, 100_000),
		submission: submission,
	}
	s := smtp.NewServer(be)
	s.Addr = cfg.SMTPAddr
	s.Domain = cfg.Hostname
	s.ReadTimeout = 2 * time.Minute
	s.WriteTimeout = 2 * time.Minute
	s.MaxMessageBytes = cfg.MaxMessageBytes
	s.MaxRecipients = 100
	if cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	return &Server{Server: s, be: be}, nil
}

func (b *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) { return &session{b: b}, nil }

type kind int

const (
	kindMailbox kind = iota
	kindBounce
)

type inDomain struct {
	id, accountID, name string
	webhookURL          *string
	secretEnc           []byte
}

type target struct {
	kind         kind
	address      string
	deliveryID   string
	domain       *inDomain
	destinations []string
	storeCopy    bool
}

var (
	errRelayDenied = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "relay access denied"}
	errBadAddress  = &smtp.SMTPError{Code: 501, EnhancedCode: smtp.EnhancedCode{5, 1, 3}, Message: "bad recipient address"}
	errTemporary   = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "temporary failure, try again later"}
)

type session struct {
	b       *Backend
	from    string
	targets []target

	authAccountID string
	authDomainID  string
	authEmail     string
	authRcpts     []string
}

func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain, "LOGIN"}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return s.authenticate(username, password)
		}), nil
	case "LOGIN":
		return newLoginServer(func(username, password string) error {
			return s.authenticate(username, password)
		}), nil
	default:
		return nil, smtp.ErrAuthFailed
	}
}

type loginServer struct {
	auth func(username, password string) error
	step int
	user string
}

func newLoginServer(auth func(username, password string) error) sasl.Server {
	return &loginServer{auth: auth}
}

func (l *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch l.step {
	case 0:
		l.step++
		return []byte("Username:"), false, nil
	case 1:
		l.user = string(response)
		l.step++
		return []byte("Password:"), false, nil
	case 2:
		l.step++
		if err := l.auth(l.user, string(response)); err != nil {
			return nil, true, err
		}
		return nil, true, nil
	default:
		return nil, true, errors.New("sasl: unexpected call to Next")
	}
}

func cleanAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if parsed, err := mail.ParseAddress(addr); err == nil {
		return strings.TrimSpace(parsed.Address)
	}
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	return strings.TrimSpace(addr)
}

func (s *session) authenticate(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return smtp.ErrAuthFailed
	}
	hash := sha256.Sum256([]byte(password))
	cacheKey := strings.ToLower(username) + ":" + string(hash[:])
	if info, ok := s.b.authCache.Get(cacheKey); ok && info != nil {
		s.authAccountID = info.AccountID
		s.authDomainID = info.DomainID
		s.authEmail = info.Email
		return nil
	}

	if s.b.db == nil {
		return smtp.ErrAuthFailed
	}

	user, err := mailbox.Authenticate(context.Background(), s.b.db, username, password)
	if err != nil {
		// Tarpit delay on failed authentication to thwart brute-force password spraying
		time.Sleep(1 * time.Second)
		return smtp.ErrAuthFailed
	}

	s.authAccountID = user.AccountID
	s.authDomainID = user.DomainID
	s.authEmail = user.Email
	if strings.HasPrefix(user.Email, "api@") {
		s.authEmail = "*"
	}
	s.b.authCache.Set(cacheKey, &smtpAuthInfo{
		AccountID: s.authAccountID,
		DomainID:  s.authDomainID,
		Email:     s.authEmail,
	})
	return nil
}

func (s *session) Reset() {
	s.from = ""
	s.targets = nil
	s.authRcpts = nil
}

func (s *session) Logout() error { return nil }

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	from = cleanAddress(from)
	if s.authAccountID != "" {
		addr, err := mail.ParseAddress(from)
		if err != nil {
			return errBadAddress
		}
		if s.authEmail != "*" && !strings.EqualFold(addr.Address, s.authEmail) {
			return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "sender address not permitted for this SMTP credential"}
		}
		s.from = addr.Address
		s.authRcpts = nil
		return nil
	}
	if s.b.submission {
		return &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "authentication required"}
	}
	s.from = from
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	to = cleanAddress(to)
	if s.authAccountID != "" {
		addr, err := mail.ParseAddress(to)
		if err != nil {
			return errBadAddress
		}
		s.authRcpts = append(s.authRcpts, addr.Address)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t, err := s.b.resolve(ctx, strings.ToLower(to))
	if err != nil {
		return err
	}
	s.targets = append(s.targets, t)
	return nil
}

func (s *session) Data(r io.Reader) error {
	var raw []byte
	var err error
	if s.b.cfg.MaxMessageBytes > 0 {
		raw, err = io.ReadAll(io.LimitReader(r, s.b.cfg.MaxMessageBytes+1))
		if err != nil {
			return err
		}
		if int64(len(raw)) > s.b.cfg.MaxMessageBytes {
			return smtp.ErrDataTooLarge
		}
	} else {
		raw, err = io.ReadAll(r)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if s.authAccountID != "" {
		if len(s.authRcpts) == 0 {
			return &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "no recipients"}
		}
		if err := s.b.handleOutbound(ctx, s.authAccountID, s.authDomainID, s.from, s.authRcpts, raw); err != nil {
			var smtpErr *smtp.SMTPError
			if errors.As(err, &smtpErr) {
				return smtpErr
			}
			s.b.log.Error("outbound smtp handle failed", "err", err)
			return errTemporary
		}
		return nil
	}

	if err := s.b.handle(ctx, s.from, s.targets, raw); err != nil {
		s.b.log.Error("inbound handle", "err", err)
		return errTemporary
	}
	return nil
}

func (b *Backend) resolve(ctx context.Context, addr string) (target, error) {
	addr = cleanAddress(addr)
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return target{}, errBadAddress
	}
	local, domain := addr[:at], addr[at+1:]

	if b.db == nil {
		return target{}, errRelayDenied
	}

	d := &inDomain{}
	err := b.db.QueryRow(ctx,
		`SELECT id, account_id, name, inbound_webhook_url, webhook_secret FROM domains WHERE name = $1 AND status = 'verified'`,
		domain).Scan(&d.id, &d.accountID, &d.name, &d.webhookURL, &d.secretEnc)
	if errors.Is(err, pgx.ErrNoRows) {
		return target{}, errRelayDenied
	}
	if err != nil {
		b.log.Error("inbound domain lookup", "err", err)
		return target{}, errTemporary
	}

	if id, ok := strings.CutPrefix(local, "bounce+"); ok {
		if _, err := uuid.Parse(id); err != nil {
			return target{}, errBadAddress
		}
		return target{kind: kindBounce, address: addr, deliveryID: id, domain: d}, nil
	}

	base := local
	if i := strings.IndexByte(local, '+'); i > 0 {
		base = local[:i]
	}
	t := target{kind: kindMailbox, address: addr, domain: d, storeCopy: true}
	err = b.db.QueryRow(ctx, `
SELECT destinations, store_copy FROM aliases
WHERE domain_id = $1 AND local_part IN ($2, $3, '*')
ORDER BY CASE local_part WHEN $2 THEN 0 WHEN $3 THEN 1 ELSE 2 END
LIMIT 1`, d.id, local, base).Scan(&t.destinations, &t.storeCopy)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		b.log.Error("inbound alias lookup", "err", err)
		return target{}, errTemporary
	}
	return t, nil
}

func (b *Backend) handle(ctx context.Context, mailFrom string, targets []target, raw []byte) error {
	parsed := mailer.Parse(raw)
	type group struct {
		d     *inDomain
		rcpts []string
	}
	groups := map[string]*group{}
	var order []string

	for _, t := range targets {
		if t.kind == kindBounce {
			if isDelayNotice(raw) {
				continue
			}
			if err := queue.MarkBounced(ctx, b.db, t.domain.accountID, t.deliveryID, bounceDetail(raw, parsed)); err != nil {
				return err
			}
			continue
		}
		if len(t.destinations) > 0 {
			if err := b.forward(ctx, mailFrom, t, parsed, raw); err != nil {
				return err
			}
		}
		if t.storeCopy {
			g := groups[t.domain.id]
			if g == nil {
				g = &group{d: t.domain}
				groups[t.domain.id] = g
				order = append(order, t.domain.id)
			}
			g.rcpts = append(g.rcpts, t.address)
		}
	}
	for _, id := range order {
		if err := b.store(ctx, mailFrom, groups[id].d, groups[id].rcpts, parsed, raw); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backend) store(ctx context.Context, mailFrom string, d *inDomain, rcpts []string, p mailer.Parsed, raw []byte) error {
	var id string
	var received time.Time
	attsJSON, err := json.Marshal(p.Attachments)
	if err != nil || len(attsJSON) == 0 {
		attsJSON = []byte("[]")
	}
	err = b.db.QueryRow(ctx, `
INSERT INTO inbound_emails (account_id, domain_id, mail_from, rcpt_to, from_header, subject, message_id, text_body, html_body, attachments, size, raw)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING id, created_at`,
		d.accountID, d.id, mailFrom, rcpts, p.From, p.Subject, p.MessageID, p.Text, p.HTML, attsJSON, len(raw), raw,
	).Scan(&id, &received)
	if err != nil {
		return err
	}
	metrics.Default.RecordInbound()
	for _, rcpt := range rcpts {
		_, _ = mailbox.DeliverMessage(ctx, b.db, d.accountID, rcpt, "INBOX", raw, nil, received)
	}
	if b.docstore != nil {
		doc := docstore.InboundDocument{
			ID:         id,
			AccountID:  d.accountID,
			DomainID:   d.id,
			MailFrom:   mailFrom,
			RcptTo:     rcpts,
			FromHeader: p.From,
			Subject:    p.Subject,
			MessageID:  p.MessageID,
			TextBody:   p.Text,
			HTMLBody:   p.HTML,
			Size:       len(raw),
			Raw:        raw,
			CreatedAt:  received,
		}
		go func(d docstore.InboundDocument) {
			bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = b.docstore.SaveInbound(bgCtx, d)
		}(doc)
	}
	if d.webhookURL == nil || *d.webhookURL == "" {
		return nil
	}
	secret, err := b.box.Open(d.secretEnc)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"type":       "email.received",
		"created_at": received,
		"data": map[string]any{
			"id": id, "domain": d.name, "mail_from": mailFrom, "rcpt_to": rcpts,
			"from": p.From, "to": p.To, "subject": p.Subject, "message_id": p.MessageID,
			"text": p.Text, "html": p.HTML, "attachments": p.Attachments, "size": len(raw),
		},
	}
	url := *d.webhookURL
	b.hookSem <- struct{}{}
	go func() {
		defer func() { <-b.hookSem }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := b.hooks.Deliver(ctx, url, secret, payload); err != nil {
			b.log.Warn("inbound webhook failed", "inbound_id", id, "err", err)
		}
	}()
	return nil
}

func (b *Backend) forward(ctx context.Context, mailFrom string, t target, p mailer.Parsed, raw []byte) error {
	loopHeader := "X-Mailhost-Loop: " + t.domain.name
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = len(raw)
	}
	if bytes.Contains(bytes.ToLower(raw[:headerEnd]), []byte(strings.ToLower(loopHeader))) {
		b.log.Warn("forwarding loop detected", "alias", t.address)
		return nil
	}
	// Prepending an unsigned header keeps the original DKIM signature valid.
	fwd := make([]byte, 0, len(loopHeader)+2+len(raw))
	fwd = append(fwd, loopHeader+"\r\n"...)
	fwd = append(fwd, raw...)

	id := uuid.New()
	return queue.Enqueue(ctx, b.db, uuid.MustParse(t.domain.accountID), []queue.Email{{
		ID:         id,
		DomainID:   uuid.MustParse(t.domain.id),
		DomainName: t.domain.name,
		From:       mailFrom,
		Subject:    p.Subject,
		MessageID:  p.MessageID,
		Raw:        fwd,
		Recipients: t.destinations,
	}})
}

func isDelayNotice(raw []byte) bool {
	lower := bytes.ToLower(raw[:min(len(raw), 64<<10)])
	return bytes.Contains(lower, []byte("action: delayed")) && !bytes.Contains(lower, []byte("action: failed"))
}

func bounceDetail(raw []byte, p mailer.Parsed) string {
	lower := bytes.ToLower(raw[:min(len(raw), 64<<10)])
	if i := bytes.Index(lower, []byte("diagnostic-code:")); i >= 0 {
		line := raw[i:]
		if j := bytes.IndexByte(line, '\n'); j >= 0 {
			line = line[:j]
		}
		s := strings.ToValidUTF8(strings.TrimSpace(string(line)), "?")
		return s[:min(len(s), 500)]
	}
	return "async bounce: " + p.Subject
}

func (b *Backend) handleOutbound(ctx context.Context, accountID, domainID, from string, rcpts []string, raw []byte) error {
	p := mailer.Parse(raw)
	emailID := uuid.New()
	at := strings.LastIndexByte(from, '@')
	domainName := ""
	if at >= 0 {
		domainName = from[at+1:]
	}
	msgID := p.MessageID
	if msgID == "" {
		msgID = emailID.String() + "@" + domainName
	}

	var scope any
	if domainID != "" {
		scope = domainID
	}
	var dID uuid.UUID
	err := b.db.QueryRow(ctx, `
SELECT id FROM domains
WHERE account_id = $1 AND lower(name) = $2 AND status = 'verified'
  AND ($3::uuid IS NULL OR id = $3::uuid)`, accountID, strings.ToLower(domainName), scope).Scan(&dID)
	if err != nil {
		return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "sender domain is not verified or is outside the credential scope"}
	}

	// Sign with DKIM if not already signed
	signedRaw := raw
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = len(raw)
	}
	if !bytes.Contains(bytes.ToLower(raw[:headerEnd]), []byte("dkim-signature:")) && b.db != nil {
		var selector string
		var encKey []byte
		if err := b.db.QueryRow(ctx, `SELECT dkim_selector, dkim_private_key FROM domains WHERE id = $1`, dID).Scan(&selector, &encKey); err == nil {
			if pemBytes, err := b.box.Open(encKey); err == nil {
				if signer, err := mailer.ParsePrivateKey(pemBytes); err == nil {
					if signed, err := mailer.Sign(raw, domainName, selector, signer); err == nil {
						signedRaw = signed
					}
				}
			}
		}
	}

	subject := p.Subject
	if subject == "" {
		subject = "(no subject)"
	}

	if b.db != nil {
		err := queue.Enqueue(ctx, b.db, uuid.MustParse(accountID), []queue.Email{{
			ID:         emailID,
			DomainID:   dID,
			DomainName: domainName,
			Priority:   queue.PriorityTransactional,
			From:       from,
			Subject:    subject,
			MessageID:  msgID,
			Raw:        signedRaw,
			Recipients: rcpts,
		}})
		if err != nil {
			b.log.Error("smtp submission enqueue failed", "err", err)
			return errTemporary
		}
		_, _ = mailbox.DeliverMessage(ctx, b.db, accountID, from, "Sent", signedRaw, []string{"\\Seen"}, time.Now())
	}
	return nil
}
