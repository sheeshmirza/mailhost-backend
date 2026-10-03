package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"mailhost/internal/queue"
	"mailhost/internal/validator"
)

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *mcpError `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema inputSchema `json:"inputSchema"`
}

type inputSchema struct {
	Type       string                `json:"type"`
	Properties map[string]schemaProp `json:"properties"`
	Required   []string              `json:"required,omitempty"`
}

type schemaProp struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

var mailhostMCPTools = []mcpTool{
	{
		Name:        "send_email",
		Description: "Send an email to one or more recipients with transactional delivery, DKIM signing, and optional open/click tracking.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]schemaProp{
				"from":         {Type: "string", Description: "Verified sender email address (e.g. 'onboarding@example.com' or 'Acme <onboarding@example.com>')."},
				"to":           {Type: "string", Description: "Comma-separated recipient email address(es)."},
				"subject":      {Type: "string", Description: "Email subject line."},
				"html":         {Type: "string", Description: "HTML body content."},
				"text":         {Type: "string", Description: "Plain text body content."},
				"reply_to":     {Type: "string", Description: "Optional Reply-To email address."},
				"scheduled_at": {Type: "string", Description: "Optional ISO 8601 delivery schedule timestamp."},
			},
			Required: []string{"from", "to", "subject"},
		},
	},
	{
		Name:        "get_email",
		Description: "Retrieve detailed delivery status, bounce error details, and event timeline for a sent email by ID.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]schemaProp{
				"id": {Type: "string", Description: "The UUID of the email."},
			},
			Required: []string{"id"},
		},
	},
	{
		Name:        "cancel_email",
		Description: "Cancel a scheduled email before its delivery time arrives.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]schemaProp{
				"id": {Type: "string", Description: "The UUID of the scheduled email to cancel."},
			},
			Required: []string{"id"},
		},
	},
	{
		Name:        "list_domains",
		Description: "List all sender domains configured in the account along with their verification and DNS status.",
		InputSchema: inputSchema{
			Type:       "object",
			Properties: map[string]schemaProp{},
		},
	},
	{
		Name:        "verify_domain",
		Description: "Trigger DNS verification for a domain to check DKIM, SPF, DMARC, and MX records.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]schemaProp{
				"id": {Type: "string", Description: "The UUID of the domain to verify."},
			},
			Required: []string{"id"},
		},
	},
	{
		Name:        "create_contact",
		Description: "Add a new subscriber contact to the audience directory.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]schemaProp{
				"email":      {Type: "string", Description: "Contact email address."},
				"first_name": {Type: "string", Description: "Contact first name."},
				"last_name":  {Type: "string", Description: "Contact last name."},
			},
			Required: []string{"email"},
		},
	},
	{
		Name:        "list_contacts",
		Description: "List contacts in the audience directory.",
		InputSchema: inputSchema{
			Type:       "object",
			Properties: map[string]schemaProp{},
		},
	},
	{
		Name:        "create_broadcast",
		Description: "Create a marketing broadcast campaign draft.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]schemaProp{
				"name":    {Type: "string", Description: "Name of the broadcast."},
				"from":    {Type: "string", Description: "Verified sender email address."},
				"subject": {Type: "string", Description: "Subject line."},
				"html":    {Type: "string", Description: "HTML content."},
			},
			Required: []string{"name", "from", "subject"},
		},
	},
	{
		Name:        "send_broadcast",
		Description: "Trigger sending of a broadcast campaign to all eligible audience contacts.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]schemaProp{
				"id": {Type: "string", Description: "The UUID of the broadcast campaign to send."},
			},
			Required: []string{"id"},
		},
	},
	{
		Name:        "list_templates",
		Description: "List all email templates including their published status and version.",
		InputSchema: inputSchema{
			Type:       "object",
			Properties: map[string]schemaProp{},
		},
	},
	{
		Name:        "get_analytics",
		Description: "Retrieve sending performance counters (sent, delivered, opened, clicked, bounced) for the account.",
		InputSchema: inputSchema{
			Type:       "object",
			Properties: map[string]schemaProp{},
		},
	},
}

// handleMCP processes JSON-RPC 2.0 requests conforming to the Model Context Protocol (MCP).
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"service": "mailhost-mcp",
			"version": "1.0.0",
			"tools":   len(mailhostMCPTools),
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	var req mcpRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, mcpResponse{
			JSONRPC: "2.0",
			Error:   &mcpError{Code: -32700, Message: "Parse error"},
		})
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcpError{Code: -32600, Message: "Invalid Request"},
		})
		return
	}

	switch req.Method {
	case "initialize":
		writeJSON(w, http.StatusOK, mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    "mailhost-mcp",
					"version": "1.0.0",
				},
			},
		})

	case "notifications/initialized":
		w.WriteHeader(http.StatusNoContent)

	case "tools/list":
		writeJSON(w, http.StatusOK, mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": mailhostMCPTools,
			},
		})

	case "tools/call":
		var callParams struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			writeJSON(w, http.StatusOK, mcpResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &mcpError{Code: -32602, Message: "Invalid params"},
			})
			return
		}

		resStr, callErr := "", error(nil)
		if !mcpToolAllowed(r, callParams.Name) {
			callErr = fmt.Errorf("forbidden: insufficient permissions for tool %s", callParams.Name)
		} else {
			resStr, callErr = s.executeMCPTool(r.Context(), accountID(r), callParams.Name, callParams.Arguments)
		}
		if callErr != nil {
			writeJSON(w, http.StatusOK, mcpResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]any{
					"isError": true,
					"content": []map[string]any{
						{"type": "text", "text": "Error: " + callErr.Error()},
					},
				},
			})
			return
		}

		writeJSON(w, http.StatusOK, mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": resStr},
				},
			},
		})

	default:
		writeJSON(w, http.StatusOK, mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcpError{Code: -32601, Message: fmt.Sprintf("Method %q not found", req.Method)},
		})
	}
}

func mcpJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// mcpToolAllowed applies the same role rules as the equivalent REST endpoints.
func mcpToolAllowed(r *http.Request, toolName string) bool {
	switch toolName {
	case "send_email", "send_broadcast":
		return isDeveloperOrAdmin(r) || keyPermission(r) == "sending_access"
	case "cancel_email", "verify_domain", "create_contact", "create_broadcast":
		return isDeveloperOrAdmin(r)
	default:
		return true
	}
}

func (s *Server) executeMCPTool(ctx context.Context, acct, toolName string, args map[string]any) (string, error) {
	switch toolName {
	case "send_email":
		from, _ := args["from"].(string)
		toStr, _ := args["to"].(string)
		subject, _ := args["subject"].(string)
		htmlBody, _ := args["html"].(string)
		textBody, _ := args["text"].(string)
		replyTo, _ := args["reply_to"].(string)

		if from == "" || toStr == "" || subject == "" {
			return "", fmt.Errorf("from, to, and subject are required")
		}

		toParts := strings.Split(toStr, ",")
		var rcpts []string
		for _, p := range toParts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				rcpts = append(rcpts, trimmed)
			}
		}

		req := sendReq{
			From:    from,
			To:      rcpts,
			Subject: subject,
			HTML:    htmlBody,
			Text:    textBody,
		}
		if replyTo != "" {
			req.ReplyTo = []string{replyTo}
		}
		if sched, ok := args["scheduled_at"].(string); ok && sched != "" {
			req.ScheduledAt = &sched
		}

		keys, err := s.signingKeys(ctx, acct, []string{req.From})
		if err != nil {
			return "", err
		}
		e, err := s.prepare(&req, nil, keys, uuid.Nil)
		if err != nil {
			return "", err
		}

		if err := s.enqueueDirect(ctx, acct, []queue.Email{e}); err != nil {
			return "", err
		}
		return mcpJSON(map[string]any{"id": e.ID.String(), "status": "queued", "message": "Email successfully enqueued"})

	case "get_email":
		idStr, _ := args["id"].(string)
		id, err := uuid.Parse(idStr)
		if err != nil {
			return "", fmt.Errorf("invalid email id")
		}

		var from, subject, msgID string
		var createdAt time.Time
		err = s.rdb.QueryRow(ctx, `SELECT from_addr, subject, message_id, created_at FROM emails WHERE id = $1 AND account_id = $2`, id, acct).
			Scan(&from, &subject, &msgID, &createdAt)
		if err != nil {
			return "", fmt.Errorf("email not found")
		}
		return mcpJSON(map[string]any{"id": id.String(), "from": from, "subject": subject, "message_id": msgID, "created_at": createdAt.Format(time.RFC3339)})

	case "cancel_email":
		idStr, _ := args["id"].(string)
		id, err := uuid.Parse(idStr)
		if err != nil {
			return "", fmt.Errorf("invalid email id")
		}
		tag, err := s.db.Exec(ctx, `UPDATE deliveries SET status = 'cancelled', updated_at = now() WHERE email_id = $1 AND account_id = $2 AND status IN ('scheduled', 'queued', 'deferred')`, id, acct)
		if err != nil || tag.RowsAffected() == 0 {
			return "", fmt.Errorf("email not found or already sent")
		}
		if err := s.refreshCancelledEmail(ctx, acct, id); err != nil {
			return "", err
		}
		return mcpJSON(map[string]any{"id": id.String(), "status": "cancelled"})

	case "list_domains":
		rows, err := s.rdb.Query(ctx, `SELECT id, name, status, region, created_at FROM domains WHERE account_id = $1`, acct)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		doms := make([]map[string]any, 0)
		for rows.Next() {
			var id uuid.UUID
			var name, status, region string
			var createdAt time.Time
			if err := rows.Scan(&id, &name, &status, &region, &createdAt); err == nil {
				doms = append(doms, map[string]any{
					"id":         id.String(),
					"name":       name,
					"status":     status,
					"region":     region,
					"created_at": createdAt.Format(time.RFC3339),
				})
			}
		}
		b, _ := json.Marshal(doms)
		return string(b), nil

	case "verify_domain":
		idStr, _ := args["id"].(string)
		if !validUUID(idStr) {
			return "", fmt.Errorf("domain id must be a UUID")
		}
		d, err := s.verifyDomainRecord(ctx, acct, idStr)
		if err != nil {
			return "", err
		}
		b, err := json.Marshal(d)
		if err != nil {
			return "", err
		}
		return string(b), nil

	case "create_contact":
		email, _ := args["email"].(string)
		first, _ := args["first_name"].(string)
		last, _ := args["last_name"].(string)
		email = strings.ToLower(strings.TrimSpace(email))
		if !validator.IsValidEmail(email) {
			return "", fmt.Errorf("a valid email is required")
		}
		if len(first) > 100 || len(last) > 100 {
			return "", fmt.Errorf("first_name and last_name must be at most 100 characters")
		}
		var id uuid.UUID
		err := s.db.QueryRow(ctx, `
INSERT INTO contacts (account_id, email, first_name, last_name, updated_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (account_id, email) DO UPDATE SET first_name = $3, last_name = $4, updated_at = now()
RETURNING id`, acct, email, first, last).Scan(&id)
		if err != nil {
			return "", err
		}
		return mcpJSON(map[string]any{"id": id.String(), "email": email, "status": "created"})

	case "list_contacts":
		rows, err := s.rdb.Query(ctx, `SELECT id, email, first_name, last_name, unsubscribed FROM contacts WHERE account_id = $1 LIMIT 50`, acct)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		contacts := make([]map[string]any, 0)
		for rows.Next() {
			var id uuid.UUID
			var em, fn, ln string
			var un bool
			if err := rows.Scan(&id, &em, &fn, &ln, &un); err == nil {
				contacts = append(contacts, map[string]any{
					"id":           id.String(),
					"email":        em,
					"first_name":   fn,
					"last_name":    ln,
					"unsubscribed": un,
				})
			}
		}
		b, _ := json.Marshal(contacts)
		return string(b), nil

	case "create_broadcast":
		name, _ := args["name"].(string)
		from, _ := args["from"].(string)
		sub, _ := args["subject"].(string)
		htmlBody, _ := args["html"].(string)
		name, from = strings.TrimSpace(name), strings.TrimSpace(from)
		if name == "" || len(name) > 100 {
			return "", fmt.Errorf("name must be between 1 and 100 characters")
		}
		if !validator.IsValidEmail(from) {
			return "", fmt.Errorf("a valid from address is required")
		}
		if strings.TrimSpace(sub) == "" || len(sub) > 998 || strings.ContainsAny(sub, "\r\n") {
			return "", fmt.Errorf("subject must be non-empty, under 998 characters, and contain no newlines")
		}
		if err := s.ValidateFromAddress(ctx, acct, from); err != nil {
			return "", err
		}
		var id uuid.UUID
		err := s.db.QueryRow(ctx, `
INSERT INTO broadcasts (account_id, name, from_addr, subject, html, status, updated_at)
VALUES ($1, $2, $3, $4, $5, 'draft', now()) RETURNING id`, acct, name, from, sub, htmlBody).Scan(&id)
		if err != nil {
			return "", err
		}
		return mcpJSON(map[string]any{"id": id.String(), "name": name, "status": "draft"})

	case "send_broadcast":
		idStr, _ := args["id"].(string)
		id, err := uuid.Parse(idStr)
		if err != nil {
			return "", fmt.Errorf("invalid broadcast id: %w", err)
		}
		var schedPtr *string
		if sched, ok := args["scheduled_at"].(string); ok && sched != "" {
			schedPtr = &sched
		}
		res, _, err := s.executeSendBroadcast(ctx, acct, id, schedPtr)
		if err != nil {
			return "", err
		}
		b, err := json.Marshal(res)
		if err != nil {
			return "", err
		}
		return string(b), nil

	case "list_templates":
		rows, err := s.rdb.Query(ctx, `SELECT id, name, alias, status, created_at FROM templates WHERE account_id = $1`, acct)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		tmpls := make([]map[string]any, 0)
		for rows.Next() {
			var id uuid.UUID
			var name, status string
			var alias *string
			var createdAt time.Time
			if err := rows.Scan(&id, &name, &alias, &status, &createdAt); err == nil {
				tmpls = append(tmpls, map[string]any{
					"id":         id.String(),
					"name":       name,
					"alias":      alias,
					"status":     status,
					"created_at": createdAt.Format(time.RFC3339),
				})
			}
		}
		b, _ := json.Marshal(tmpls)
		return string(b), nil

	case "get_analytics":
		rows, err := s.rdb.Query(ctx, `SELECT type, sum(count) FROM event_rollups WHERE account_id = $1 GROUP BY type`, acct)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		counters := map[string]int64{}
		for rows.Next() {
			var t string
			var c int64
			if err := rows.Scan(&t, &c); err == nil {
				counters[t] = c
			}
		}
		b, _ := json.Marshal(counters)
		return string(b), nil

	default:
		return "", fmt.Errorf("unsupported tool: %s", toolName)
	}
}
