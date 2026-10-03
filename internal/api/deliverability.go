package api

import (
	"context"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"mailhost/internal/validator"
)

type deliverabilityInspectReq struct {
	Domain  string            `json:"domain"`
	From    string            `json:"from"`
	Subject string            `json:"subject"`
	HTML    string            `json:"html"`
	Text    string            `json:"text"`
	Headers map[string]string `json:"headers"`
}

type dnsCheckResult struct {
	Status      string   `json:"status"` // "pass", "warn", "fail"
	RecordType  string   `json:"record_type"`
	QueryName   string   `json:"query_name"`
	FoundValues []string `json:"found_values"`
	Details     string   `json:"details"`
}

type spamAuditFinding struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"` // "high", "medium", "low"
	Penalty     int    `json:"penalty"`
	Description string `json:"description"`
}

type deliverabilityInspectResp struct {
	Score             int                       `json:"score"`   // 0 to 100
	Verdict           string                    `json:"verdict"` // "Optimal", "Good", "Needs Improvement", "Critical Risk"
	Domain            string                    `json:"domain"`
	DNSAuthentication map[string]dnsCheckResult `json:"dns_authentication"` // spf, dkim, dmarc, mx
	SpamAudit         []spamAuditFinding        `json:"spam_audit"`
	PlacementForecast map[string]string         `json:"placement_forecast"` // gmail, outlook, apple_mail, yahoo
	RFC8058Compliant  bool                      `json:"rfc8058_compliant"`
	Recommendations   []string                  `json:"recommendations"`
}

var spamTriggerWords = []string{
	"100% free", "act now", "apply now", "buy direct", "call now",
	"casino", "claim now", "crypto jackpot", "double your income",
	"earn money fast", "exclusive deal", "extra cash", "free gift",
	"free membership", "get paid", "guaranteed", "make money",
	"million dollars", "no catch", "no cost", "no fees", "no strings attached",
	"one time offer", "pure profit", "risk free", "urgent", "viagra", "winner",
}

var httpLinkRegex = regexp.MustCompile(`(?i)href\s*=\s*["']http://`)

func (s *Server) inspectDeliverability(w http.ResponseWriter, r *http.Request) {
	var req deliverabilityInspectReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	targetDomain := strings.TrimSpace(strings.ToLower(req.Domain))
	if targetDomain == "" && req.From != "" {
		if addr, err := mail.ParseAddress(req.From); err == nil {
			targetDomain = domainOf(addr.Address)
		} else {
			targetDomain = domainOf(req.From)
		}
	}

	if targetDomain != "" && !validator.IsValidDomain(targetDomain) {
		writeError(w, http.StatusUnprocessableEntity, "invalid domain format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()

	dnsResults := make(map[string]dnsCheckResult)
	score := 100
	var findings []spamAuditFinding
	var recommendations []string

	// 1. DNS Authentication Checks
	if targetDomain != "" {
		// --- SPF Check ---
		spfResult := dnsCheckResult{
			RecordType: "TXT",
			QueryName:  targetDomain,
			Status:     "fail",
			Details:    "No SPF record detected. Inbound MTAs may reject or mark outbound emails as spam.",
		}
		if txts, err := s.resolver.LookupTXT(ctx, targetDomain); err == nil {
			for _, txt := range txts {
				if strings.HasPrefix(strings.TrimSpace(txt), "v=spf1") {
					spfResult.FoundValues = append(spfResult.FoundValues, txt)
					if strings.Contains(txt, "+all") {
						spfResult.Status = "fail"
						spfResult.Details = "SPF record contains '+all', permitting any unauthorized server to spoof your domain."
						score -= 15
						findings = append(findings, spamAuditFinding{
							Rule:        "spf_permissive_all",
							Severity:    "high",
							Penalty:     15,
							Description: "SPF record uses permissive '+all' mechanism.",
						})
						recommendations = append(recommendations, "Update SPF record to end with '~all' (softfail) or '-all' (hardfail).")
					} else if strings.Contains(txt, "~all") || strings.Contains(txt, "-all") {
						spfResult.Status = "pass"
						spfResult.Details = "Valid SPF record configured with strict authorization policy."
					} else {
						spfResult.Status = "warn"
						spfResult.Details = "SPF record found, but missing an explicit '~all' or '-all' enforcement tag."
						score -= 5
						recommendations = append(recommendations, "Add '~all' or '-all' to your domain SPF record.")
					}
					break
				}
			}
		}
		if spfResult.Status == "fail" && len(spfResult.FoundValues) == 0 {
			score -= 20
			findings = append(findings, spamAuditFinding{
				Rule:        "spf_missing",
				Severity:    "high",
				Penalty:     20,
				Description: "Domain lacks an SPF DNS record.",
			})
			recommendations = append(recommendations, "Add a TXT record for '"+targetDomain+"' with value: 'v=spf1 include:mailhost.local ~all'.")
		}
		dnsResults["spf"] = spfResult

		// --- DKIM Check ---
		acct := accountID(r)
		selector := "resend"
		var storedSelector string
		_ = s.rdb.QueryRow(ctx, "SELECT dkim_selector FROM domains WHERE account_id = $1 AND name = $2", acct, targetDomain).Scan(&storedSelector)
		if storedSelector != "" {
			selector = storedSelector
		}
		dkimQuery := selector + "._domainkey." + targetDomain
		dkimResult := dnsCheckResult{
			RecordType: "TXT",
			QueryName:  dkimQuery,
			Status:     "fail",
			Details:    "DKIM public key TXT record not found at " + dkimQuery + ".",
		}
		if txts, err := s.resolver.LookupTXT(ctx, dkimQuery); err == nil && len(txts) > 0 {
			for _, txt := range txts {
				if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "p=") {
					dkimResult.FoundValues = append(dkimResult.FoundValues, txt)
					dkimResult.Status = "pass"
					dkimResult.Details = "DKIM public key is correctly published in DNS."
					break
				}
			}
		}
		if dkimResult.Status == "fail" {
			score -= 20
			findings = append(findings, spamAuditFinding{
				Rule:        "dkim_missing",
				Severity:    "high",
				Penalty:     20,
				Description: "DKIM selector TXT record not found.",
			})
			recommendations = append(recommendations, "Publish the DKIM public key TXT record at '"+dkimQuery+"'.")
		}
		dnsResults["dkim"] = dkimResult

		// --- DMARC Check ---
		dmarcQuery := "_dmarc." + targetDomain
		dmarcResult := dnsCheckResult{
			RecordType: "TXT",
			QueryName:  dmarcQuery,
			Status:     "fail",
			Details:    "No DMARC policy found. Gmail, Yahoo, and Outlook mandate DMARC for bulk deliverability.",
		}
		if txts, err := s.resolver.LookupTXT(ctx, dmarcQuery); err == nil {
			for _, txt := range txts {
				if strings.HasPrefix(strings.TrimSpace(txt), "v=DMARC1") {
					dmarcResult.FoundValues = append(dmarcResult.FoundValues, txt)
					if strings.Contains(txt, "p=reject") || strings.Contains(txt, "p=quarantine") {
						dmarcResult.Status = "pass"
						dmarcResult.Details = "DMARC policy actively protects domain against unauthorized spoofing."
					} else {
						dmarcResult.Status = "warn"
						dmarcResult.Details = "DMARC policy is set to 'p=none'. Upgrade to 'p=quarantine' or 'p=reject' for maximum inbox placement."
						score -= 5
						recommendations = append(recommendations, "Elevate DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'.")
					}
					break
				}
			}
		}
		if dmarcResult.Status == "fail" {
			score -= 15
			findings = append(findings, spamAuditFinding{
				Rule:        "dmarc_missing",
				Severity:    "high",
				Penalty:     15,
				Description: "DMARC TXT record not configured.",
			})
			recommendations = append(recommendations, "Publish a DMARC TXT record at '"+dmarcQuery+"' with 'v=DMARC1; p=quarantine; sp=quarantine;'.")
		}
		dnsResults["dmarc"] = dmarcResult

		// --- MX Check ---
		mxResult := dnsCheckResult{
			RecordType: "MX",
			QueryName:  targetDomain,
			Status:     "pass",
			Details:    "Valid mail exchanger (MX) records found.",
		}
		if mxs, err := s.resolver.LookupMX(ctx, targetDomain); err != nil || len(mxs) == 0 {
			mxResult.Status = "warn"
			mxResult.Details = "No MX records found for domain. Receiving return-path bounces and replies may fail."
			score -= 5
			recommendations = append(recommendations, "Configure MX records for your sender domain to handle return-path bounces.")
		} else {
			for _, mx := range mxs {
				mxResult.FoundValues = append(mxResult.FoundValues, mx.Host)
			}
		}
		dnsResults["mx"] = mxResult
	}

	// 2. Content & Spam Diagnostics
	subject := strings.TrimSpace(req.Subject)
	html := strings.TrimSpace(req.HTML)
	text := strings.TrimSpace(req.Text)

	// Check Subject ALL CAPS
	if len(subject) > 8 {
		upperCount := 0
		letterCount := 0
		for _, r := range subject {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				letterCount++
				if r >= 'A' && r <= 'Z' {
					upperCount++
				}
			}
		}
		if letterCount > 0 && float64(upperCount)/float64(letterCount) > 0.7 {
			score -= 10
			findings = append(findings, spamAuditFinding{
				Rule:        "subject_all_caps",
				Severity:    "medium",
				Penalty:     10,
				Description: "Subject line contains excessive uppercase characters.",
			})
			recommendations = append(recommendations, "Use natural title casing in your subject line instead of all caps.")
		}
	}

	// Check Spam Keywords
	haystack := strings.ToLower(subject + " " + html)
	triggerWordHits := 0
	for _, word := range spamTriggerWords {
		if strings.Contains(haystack, word) {
			triggerWordHits++
			if triggerWordHits <= 3 {
				score -= 5
				findings = append(findings, spamAuditFinding{
					Rule:        "spam_keyword_detected",
					Severity:    "low",
					Penalty:     5,
					Description: "Detected high-risk spam keyword: '" + word + "'.",
				})
			}
		}
	}
	if triggerWordHits > 0 {
		recommendations = append(recommendations, "Replace promotional spam keywords with direct, customer-centric value language.")
	}

	// Check Insecure HTTP Links
	if httpLinkRegex.MatchString(html) {
		score -= 10
		findings = append(findings, spamAuditFinding{
			Rule:        "insecure_http_links",
			Severity:    "medium",
			Penalty:     10,
			Description: "Email body contains unencrypted HTTP links (http:// instead of https://).",
		})
		recommendations = append(recommendations, "Upgrade all links in the email body to secure HTTPS protocols.")
	}

	// Check Plaintext Alternative
	if len(html) > 200 && len(text) == 0 {
		score -= 5
		findings = append(findings, spamAuditFinding{
			Rule:        "missing_plaintext_part",
			Severity:    "low",
			Penalty:     5,
			Description: "Email HTML provided without a matching plaintext alternative body.",
		})
		recommendations = append(recommendations, "Include a plaintext alternative body for accessibility and spam filter compliance.")
	}

	// Check RFC 8058 One-Click Unsubscribe
	hasListUnsubHeader := false
	if req.Headers != nil {
		for k := range req.Headers {
			if strings.EqualFold(k, "List-Unsubscribe") {
				hasListUnsubHeader = true
				break
			}
		}
	}
	hasUnsubLink := strings.Contains(strings.ToLower(html), "unsubscribe")
	rfc8058Compliant := hasListUnsubHeader || hasUnsubLink

	if !rfc8058Compliant {
		score -= 10
		findings = append(findings, spamAuditFinding{
			Rule:        "rfc8058_unsubscribe_missing",
			Severity:    "medium",
			Penalty:     10,
			Description: "Missing RFC-8058 List-Unsubscribe header or unsubscribe link in body.",
		})
		recommendations = append(recommendations, "Ensure marketing broadcasts provide an unsubscribe link and List-Unsubscribe header.")
	}

	// Check Role-Based Sender
	if req.From != "" && validator.IsRoleBasedEmail(req.From) {
		score -= 5
		findings = append(findings, spamAuditFinding{
			Rule:        "role_based_sender",
			Severity:    "low",
			Penalty:     5,
			Description: "Sender address uses a shared department role prefix (e.g. admin@, info@, sales@).",
		})
		recommendations = append(recommendations, "Consider sending marketing and engagement campaigns from a personalized sender address.")
	}

	if score < 0 {
		score = 0
	}

	// Verdict Determination
	verdict := "Optimal"
	if score < 50 {
		verdict = "Critical Risk"
	} else if score < 75 {
		verdict = "Needs Improvement"
	} else if score < 90 {
		verdict = "Good"
	}

	// Placement Forecast
	placement := map[string]string{
		"gmail":      "Inbox",
		"outlook":    "Focused",
		"apple_mail": "Inbox",
		"yahoo":      "Inbox",
	}
	if score < 50 {
		placement["gmail"] = "Spam"
		placement["outlook"] = "Junk"
		placement["apple_mail"] = "Junk"
		placement["yahoo"] = "Spam"
	} else if score < 75 {
		placement["gmail"] = "Promotions / Spam"
		placement["outlook"] = "Other / Junk"
		placement["apple_mail"] = "Inbox"
		placement["yahoo"] = "Spam"
	} else if score < 90 {
		placement["gmail"] = "Promotions"
		placement["outlook"] = "Other"
		placement["apple_mail"] = "Inbox"
		placement["yahoo"] = "Inbox"
	}

	writeJSON(w, http.StatusOK, deliverabilityInspectResp{
		Score:             score,
		Verdict:           verdict,
		Domain:            targetDomain,
		DNSAuthentication: dnsResults,
		SpamAudit:         findings,
		PlacementForecast: placement,
		RFC8058Compliant:  rfc8058Compliant,
		Recommendations:   recommendations,
	})
}
