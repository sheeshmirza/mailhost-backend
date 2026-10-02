package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"mailhost/internal/queue"
)

// 1x1 transparent GIF bytes
var transparentGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21,
	0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x44,
	0x00, 0x3b,
}

// computeTrackingSignature computes an HMAC-SHA256 signature for a tracking URL to prevent open redirect vulnerabilities.
func computeTrackingSignature(secret []byte, deliveryID, targetURL string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(deliveryID))
	mac.Write([]byte(":"))
	mac.Write([]byte(targetURL))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyTrackingSignature checks if the provided signature matches the expected HMAC for deliveryID and targetURL.
func verifyTrackingSignature(secret []byte, deliveryID, targetURL, sig string) bool {
	expected := computeTrackingSignature(secret, deliveryID, targetURL)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) == 1
}

type trackedRecipient struct {
	accountID  uuid.UUID
	domainID   uuid.UUID
	deliveryID uuid.UUID
	emailID    uuid.UUID
	recipient  string
	// recipientCount > 1 means the token is an email ID shared by several recipients
	// (one MIME body for To/Cc), so the individual recipient is unknown.
	recipientCount int
}

// trackingTargetSQL resolves a delivery ID, or for multi-recipient messages the email ID, to one delivery row.
const trackingTargetSQL = `
SELECT id FROM deliveries WHERE id = $1
UNION ALL
SELECT id FROM (SELECT id FROM deliveries WHERE email_id = $1 ORDER BY id LIMIT 1) first_delivery
WHERE NOT EXISTS (SELECT 1 FROM deliveries WHERE id = $1)`

func (t trackedRecipient) payload() map[string]any {
	p := map[string]any{"email_id": t.emailID.String()}
	if t.recipientCount > 1 {
		p["recipient_count"] = t.recipientCount
	} else {
		p["delivery_id"] = t.deliveryID.String()
		p["recipient"] = t.recipient
	}
	return p
}

func (s *Server) recordTrackingEvent(ctx context.Context, token uuid.UUID, eventType, detail string) ([]trackedRecipient, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	column := "open_count"
	firstAt := "first_opened_at"
	lastAt := "last_opened_at"
	if eventType == "clicked" {
		column, firstAt, lastAt = "click_count", "first_clicked_at", "last_clicked_at"
	}
	query := `UPDATE deliveries d SET ` + column + ` = d.` + column + ` + 1, ` +
		firstAt + ` = COALESCE(d.` + firstAt + `, now()), ` + lastAt + ` = now() ` +
		`FROM (` + trackingTargetSQL + `) target WHERE d.id = target.id ` +
		`RETURNING d.account_id, d.domain_id, d.id, d.email_id, d.recipient, ` +
		`(SELECT count(*) FROM deliveries x WHERE x.email_id = d.email_id)`
	rows, err := tx.Query(ctx, query, token)
	if err != nil {
		return nil, err
	}
	var recipients []trackedRecipient
	for rows.Next() {
		var tracked trackedRecipient
		if err := rows.Scan(&tracked.accountID, &tracked.domainID, &tracked.deliveryID, &tracked.emailID, &tracked.recipient, &tracked.recipientCount); err != nil {
			rows.Close()
			return nil, err
		}
		recipients = append(recipients, tracked)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, tx.Commit(ctx)
	}

	events := make([][]any, 0, len(recipients))
	deltas := map[queue.RollupKey]int64{}
	now := time.Now()
	for _, tracked := range recipients {
		var eventDetail *string
		if detail != "" {
			eventDetail = &detail
		}
		events = append(events, []any{tracked.accountID, tracked.domainID, tracked.emailID, tracked.deliveryID, eventType, eventDetail, now})
		deltas[queue.RollupKey{Account: tracked.accountID.String(), Domain: tracked.domainID.String(), Type: eventType}]++
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"events"},
		[]string{"account_id", "domain_id", "email_id", "delivery_id", "type", "detail", "created_at"},
		pgx.CopyFromRows(events)); err != nil {
		return nil, err
	}
	if err := queue.IncrRollups(ctx, tx, deltas); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return recipients, nil
}

func (s *Server) trackOpen(w http.ResponseWriter, r *http.Request) {
	dlvIDStr := r.PathValue("delivery_id")
	dlvID, err := uuid.Parse(dlvIDStr)
	if err == nil {
		go func(id uuid.UUID) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			recipients, err := s.recordTrackingEvent(ctx, id, "opened", "")
			if err != nil {
				s.log.Warn("record open tracking event failed", "token", id, "error", err)
				return
			}
			for _, tracked := range recipients {
				payload := tracked.payload()
				acct := tracked.accountID.String()
				s.dispatchWebhookEvent(ctx, acct, "email.opened", payload)
				if tracked.recipientCount == 1 {
					s.triggerAutomations(ctx, acct, "email.opened", "email.opened", "", tracked.recipient, payload)
				}
			}
		}(dlvID)
	}

	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(transparentGIF)
}

func (s *Server) trackClick(w http.ResponseWriter, r *http.Request) {
	dlvIDStr := r.PathValue("delivery_id")
	targetURL := r.URL.Query().Get("url")
	sig := r.URL.Query().Get("sig")

	if targetURL == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	parsed, err := url.Parse(targetURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		writeError(w, http.StatusBadRequest, "invalid target URL")
		return
	}

	// Verify HMAC signature to protect against open redirects; fail closed without a key.
	if len(s.cfg.MasterKey) == 0 || sig == "" || !verifyTrackingSignature(s.cfg.MasterKey, dlvIDStr, targetURL, sig) {
		writeError(w, http.StatusBadRequest, "invalid or missing tracking signature")
		return
	}

	dlvID, err := uuid.Parse(dlvIDStr)
	if err == nil {
		go func(id uuid.UUID, clickedURL string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			recipients, err := s.recordTrackingEvent(ctx, id, "clicked", clickedURL)
			if err != nil {
				s.log.Warn("record click tracking event failed", "token", id, "error", err)
				return
			}
			for _, tracked := range recipients {
				payload := tracked.payload()
				payload["click"] = map[string]any{"link": clickedURL}
				acct := tracked.accountID.String()
				s.dispatchWebhookEvent(ctx, acct, "email.clicked", payload)
				if tracked.recipientCount == 1 {
					s.triggerAutomations(ctx, acct, "email.clicked", "email.clicked", "", tracked.recipient, payload)
				}
			}
		}(dlvID, targetURL)
	}

	http.Redirect(w, r, targetURL, http.StatusFound)
}

func (s *Server) unsubscribeContact(w http.ResponseWriter, r *http.Request) {
	deliveryID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "unsubscribe link not found")
		return
	}

	var acctID uuid.UUID
	var email string
	var exact bool
	err = s.db.QueryRow(r.Context(), `
SELECT d.account_id, d.recipient, d.id = $1
FROM deliveries d JOIN (`+trackingTargetSQL+`) target ON target.id = d.id`, deliveryID).Scan(&acctID, &email, &exact)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "unsubscribe link not found")
		return
	}
	if err == nil && !exact {
		writeError(w, http.StatusUnprocessableEntity, "this link is shared by several recipients and cannot identify who to unsubscribe")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query delivery")
		return
	}

	// GET must be safe: mail scanners and link prefetchers follow links automatically.
	if r.Method == http.MethodGet {
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			writeJSON(w, http.StatusOK, map[string]any{
				"email":   email,
				"message": "send a POST request to this URL to confirm unsubscribe",
			})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Unsubscribe</title></head>
<body style="font-family:system-ui,sans-serif;max-width:500px;margin:80px auto;text-align:center">
<h1>Unsubscribe</h1>
<p>Stop receiving emails from this sender at <strong>` + html.EscapeString(email) + `</strong>?</p>
<form method="post"><input type="hidden" name="List-Unsubscribe" value="One-Click"><button type="submit">Unsubscribe</button></form>
</body>
</html>`))
		return
	}

	var contactID *uuid.UUID
	var cID uuid.UUID
	err = s.db.QueryRow(r.Context(), `
UPDATE contacts
SET unsubscribed = true, updated_at = now()
WHERE account_id = $1 AND lower(email) = lower($2)
RETURNING id`, acctID, email).Scan(&cID)
	if err == nil {
		contactID = &cID
	}

	acct := acctID.String()
	// Add to account suppressions
	_, _ = s.db.Exec(r.Context(), `
INSERT INTO suppressions (account_id, address, reason)
VALUES ($1, lower($2), 'Unsubscribed by recipient')
ON CONFLICT (account_id, address) DO NOTHING`, acctID, email)
	if s.redis != nil {
		_ = s.redis.AddSuppression(r.Context(), acct, strings.ToLower(email))
	}

	// Dispatch webhook
	whPayload := map[string]any{
		"email":        email,
		"unsubscribed": true,
	}
	if contactID != nil {
		whPayload["id"] = contactID.String()
	}
	s.dispatchWebhookEvent(r.Context(), acct, "contact.updated", whPayload)

	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		resp := map[string]any{
			"email":        email,
			"unsubscribed": true,
			"message":      "Successfully unsubscribed",
		}
		if contactID != nil {
			resp["id"] = contactID.String()
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Clean HTML response for browser clicks
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Unsubscribed</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:500px;margin:80px auto;padding:24px;text-align:center;line-height:1.6}h1{font-size:24px;color:#111}p{color:#666}</style>
</head>
<body>
<h1>You have been unsubscribed</h1>
<p>You will no longer receive emails from this sender at <strong>` + html.EscapeString(email) + `</strong>.</p>
</body>
</html>`))
}

var hrefRegex = regexp.MustCompile(`(?i)<a\s+([^>]*?)href=["'](https?://[^"']+)["']([^>]*)>`)

// InjectTracking modifies HTML content to inject open tracking pixels and rewrite links for click tracking.
func InjectTracking(htmlContent, host, deliveryID string, secret []byte, openTrack, clickTrack bool) string {
	if htmlContent == "" || deliveryID == "" || host == "" {
		return htmlContent
	}

	result := htmlContent

	// Rewrite links for click tracking
	if clickTrack {
		result = hrefRegex.ReplaceAllStringFunc(result, func(m string) string {
			sub := hrefRegex.FindStringSubmatch(m)
			if len(sub) < 4 {
				return m
			}
			origURL := sub[2]
			if strings.Contains(origURL, "/v1/track/") || strings.Contains(origURL, "/v1/unsubscribe/") {
				return m
			}
			var trackedURL string
			if len(secret) > 0 {
				sig := computeTrackingSignature(secret, deliveryID, origURL)
				trackedURL = fmt.Sprintf("https://%s/v1/track/click/%s?url=%s&sig=%s", host, deliveryID, url.QueryEscape(origURL), sig)
			} else {
				trackedURL = fmt.Sprintf("https://%s/v1/track/click/%s?url=%s", host, deliveryID, url.QueryEscape(origURL))
			}
			return fmt.Sprintf(`<a %shref="%s"%s>`, sub[1], trackedURL, sub[3])
		})
	}

	// Inject 1x1 open tracking pixel
	if openTrack {
		pixel := fmt.Sprintf(`<img src="https://%s/v1/track/open/%s" width="1" height="1" alt="" style="display:none;width:1px;height:1px;border:0;" />`, host, deliveryID)
		if idx := strings.LastIndex(strings.ToLower(result), "</body>"); idx >= 0 {
			result = result[:idx] + pixel + result[idx:]
		} else {
			result += pixel
		}
	}

	return result
}
