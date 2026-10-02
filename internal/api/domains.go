package api

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"mailhost/internal/mailer"
	"mailhost/internal/validator"
	"mailhost/internal/webhook"
)

type dnsRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Priority int    `json:"priority,omitempty"`
	Purpose  string `json:"purpose"`
	Required bool   `json:"required"`
	Status   string `json:"status,omitempty"`
}

type domainView struct {
	ID                string      `json:"id"`
	Name              string      `json:"name"`
	Status            string      `json:"status"`
	Region            string      `json:"region"`
	OpenTracking      bool        `json:"open_tracking"`
	ClickTracking     bool        `json:"click_tracking"`
	TLS               string      `json:"tls"`
	InboundWebhookURL *string     `json:"inbound_webhook_url"`
	WebhookSecret     string      `json:"webhook_secret,omitempty"`
	CreatedAt         time.Time   `json:"created_at"`
	VerifiedAt        *time.Time  `json:"verified_at"`
	Records           []dnsRecord `json:"records"`
}

const domainCols = `id, name, status, verification_token, dkim_selector, dkim_public_key, inbound_webhook_url, open_tracking, click_tracking, tls, region, created_at, verified_at`

func (s *Server) records(name, token, selector, dkimValue string) []dnsRecord {
	return []dnsRecord{
		{Type: "TXT", Name: "_mailhost." + name, Value: "mailhost-verification=" + token, Purpose: "ownership", Required: true},
		{Type: "TXT", Name: selector + "._domainkey." + name, Value: dkimValue, Purpose: "dkim", Required: true},
		{Type: "TXT", Name: name, Value: "v=spf1 a:" + s.cfg.Hostname + " ~all", Purpose: "spf"},
		{Type: "MX", Name: name, Value: s.cfg.Hostname, Priority: 10, Purpose: "inbound"},
		{Type: "TXT", Name: "_dmarc." + name, Value: "v=DMARC1; p=none;", Purpose: "dmarc"},
		{Type: "TXT", Name: "default._bimi." + name, Value: "v=BIMI1; l=https://" + name + "/logo.svg;", Purpose: "bimi"},
	}
}

func (s *Server) scanDomain(row pgx.Row) (domainView, error) {
	var d domainView
	var token, selector, pub string
	err := row.Scan(&d.ID, &d.Name, &d.Status, &token, &selector, &pub, &d.InboundWebhookURL,
		&d.OpenTracking, &d.ClickTracking, &d.TLS, &d.Region, &d.CreatedAt, &d.VerifiedAt)
	d.Records = s.records(d.Name, token, selector, pub)
	return d, err
}

func (s *Server) createDomain(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req struct {
		Name              string  `json:"name"`
		Region            string  `json:"region"`
		InboundWebhookURL *string `json:"inbound_webhook_url"`
	}
	if !decode(w, r, 0, &req) {
		return
	}
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Name)), ".")
	if !validator.IsValidDomain(name) {
		writeError(w, http.StatusUnprocessableEntity, "name must be a valid domain name")
		return
	}
	region := strings.TrimSpace(strings.ToLower(req.Region))
	if region == "" {
		writeError(w, http.StatusUnprocessableEntity, "region is required")
		return
	}
	if req.InboundWebhookURL != nil {
		if err := webhook.ValidateURLWithPrivate(*req.InboundWebhookURL, s.cfg.AllowPrivateDelivery); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	privPEM, pub, err := mailer.GenerateDKIMKey()
	if err != nil {
		s.internal(w, err)
		return
	}
	secret := newToken("whsec_", 32)
	selector := "mh" + time.Now().UTC().Format("200601")
	encPrivateKey, err := s.box.Seal(privPEM)
	if err != nil {
		s.internal(w, err)
		return
	}
	encWebhookSecret, err := s.box.Seal([]byte(secret))
	if err != nil {
		s.internal(w, err)
		return
	}

	d, err := s.scanDomain(s.db.QueryRow(r.Context(), `
INSERT INTO domains (account_id, name, verification_token, dkim_selector, dkim_private_key, dkim_public_key, inbound_webhook_url, webhook_secret, region)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING `+domainCols,
		accountID(r), name, newToken("", 16), selector, encPrivateKey, pub, req.InboundWebhookURL, encWebhookSecret, region))
	if isUniqueViolation(err) {
		writeError(w, http.StatusConflict, "domain already added to this account")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	d.WebhookSecret = secret // returned once only
	s.auditLog(r.Context(), accountID(r), accountID(r), "create", "domain", d.ID, clientIP(r), r.UserAgent())
	writeJSON(w, http.StatusCreated, d)
}

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	rows, err := s.rdb.Query(r.Context(), `SELECT `+domainCols+` FROM domains WHERE account_id = $1 AND created_at < $2 ORDER BY created_at DESC LIMIT $3`, accountID(r), before, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	out := []domainView{}
	for rows.Next() {
		d, err := s.scanDomain(rows)
		if err != nil {
			s.internal(w, err)
			return
		}
		out = append(out, d)
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

func (s *Server) loadDomain(w http.ResponseWriter, r *http.Request) (domainView, bool) {
	id, ok := pathID(w, r)
	if !ok {
		return domainView{}, false
	}
	d, err := s.scanDomain(s.db.QueryRow(r.Context(), `SELECT `+domainCols+` FROM domains WHERE id = $1 AND account_id = $2`, id, accountID(r)))
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "domain not found")
		return d, false
	}
	if err != nil {
		s.internal(w, err)
		return d, false
	}
	return d, true
}

func (s *Server) getDomain(w http.ResponseWriter, r *http.Request) {
	if d, ok := s.loadDomain(w, r); ok {
		writeJSON(w, http.StatusOK, d)
	}
}

func (s *Server) updateDomain(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		InboundWebhookURL *string `json:"inbound_webhook_url"`
		OpenTracking      *bool   `json:"open_tracking"`
		ClickTracking     *bool   `json:"click_tracking"`
		TLS               *string `json:"tls"`
	}
	if !decode(w, r, 8<<10, &req) {
		return
	}
	if req.InboundWebhookURL != nil && *req.InboundWebhookURL != "" {
		if err := webhook.ValidateURLWithPrivate(*req.InboundWebhookURL, s.cfg.AllowPrivateDelivery); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	d, err := s.scanDomain(s.db.QueryRow(r.Context(), `
UPDATE domains
SET inbound_webhook_url = CASE WHEN $3::text IS NOT NULL THEN NULLIF($3::text, '') ELSE inbound_webhook_url END,
    open_tracking = COALESCE($4, open_tracking),
    click_tracking = COALESCE($5, click_tracking),
    tls = CASE WHEN $6 = 'enforced' OR $6 = 'opportunistic' THEN $6 ELSE tls END
WHERE id = $1 AND account_id = $2 RETURNING `+domainCols,
		id, accountID(r), req.InboundWebhookURL, req.OpenTracking, req.ClickTracking, req.TLS))
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) verifyDomainRecord(ctx context.Context, acct string, id string) (domainView, error) {
	d, err := s.scanDomain(s.db.QueryRow(ctx, `SELECT `+domainCols+` FROM domains WHERE id = $1 AND account_id = $2`, id, acct))
	if err != nil {
		return domainView{}, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	allRequired := true
	for i := range d.Records {
		rec := &d.Records[i]
		if s.cfg.SkipDNSVerification || s.checkRecord(checkCtx, rec) {
			rec.Status = "verified"
		} else {
			rec.Status = "not_found"
			if rec.Required {
				allRequired = false
			}
		}
	}
	if allRequired && d.Status != "verified" {
		err := s.db.QueryRow(ctx,
			`UPDATE domains SET status = 'verified', verified_at = now() WHERE id = $1 AND account_id = $2 RETURNING status, verified_at`,
			d.ID, acct).Scan(&d.Status, &d.VerifiedAt)
		if isUniqueViolation(err) {
			return domainView{}, fmt.Errorf("domain is already verified by another account")
		}
		if err != nil {
			return domainView{}, err
		}
		s.domains.Delete(acct + ":" + d.Name)
	}
	return d, nil
}

func (s *Server) verifyDomain(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	d, err := s.verifyDomainRecord(r.Context(), accountID(r), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		if strings.Contains(err.Error(), "already verified") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		s.internal(w, err)
		return
	}
	s.auditLog(r.Context(), accountID(r), accountID(r), "verify", "domain", d.ID, clientIP(r), r.UserAgent())
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) checkRecord(ctx context.Context, rec *dnsRecord) bool {
	if rec.Type == "MX" {
		mxs, err := s.resolver.LookupMX(ctx, rec.Name)
		if err != nil {
			return false
		}
		for _, mx := range mxs {
			if strings.EqualFold(strings.TrimSuffix(mx.Host, "."), rec.Value) {
				return true
			}
		}
		return false
	}
	txts, err := s.resolver.LookupTXT(ctx, rec.Name)
	if err != nil {
		return false
	}
	norm := func(v string) string { return strings.NewReplacer(" ", "", `"`, "").Replace(v) }
	for _, t := range txts {
		switch rec.Purpose {
		case "spf":
			if strings.HasPrefix(t, "v=spf1") && strings.Contains(t, s.cfg.Hostname) {
				return true
			}
		case "dmarc":
			if strings.HasPrefix(t, "v=DMARC1") {
				return true
			}
		case "bimi":
			if strings.HasPrefix(t, "v=BIMI1") {
				return true
			}
		case "ownership":
			if norm(t) == norm(rec.Value) {
				return true
			}
		case "dkim":
			if norm(t) == norm(rec.Value) {
				return true
			}
		default:
			if norm(t) == norm(rec.Value) {
				return true
			}
		}
	}
	return false
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	// Domain-scoped API keys are removed by ON DELETE CASCADE, so their cached auth entries must be evicted too.
	var scopedKeyHashes [][]byte
	if rows, err := s.db.Query(r.Context(), `SELECT key_hash FROM api_keys WHERE domain_id = $1 AND account_id = $2`, id, accountID(r)); err == nil {
		scopedKeyHashes, _ = pgx.CollectRows(rows, pgx.RowTo[[]byte])
	}
	var name string
	err := s.db.QueryRow(r.Context(), `DELETE FROM domains WHERE id = $1 AND account_id = $2 RETURNING name`, id, accountID(r)).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	for _, h := range scopedKeyHashes {
		s.keys.Delete(string(h))
		if s.redis != nil {
			_ = s.redis.Delete(r.Context(), "apikey:"+hex.EncodeToString(h))
		}
	}
	s.signers.Delete(id)
	s.domains.Delete(accountID(r) + ":" + name)
	s.auditLog(r.Context(), accountID(r), accountID(r), "delete", "domain", id, clientIP(r), r.UserAgent())
	w.WriteHeader(http.StatusNoContent)
}
