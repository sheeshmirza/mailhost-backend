package api

import (
	"context"
	"net/http"
	"time"
)

type auditLogView struct {
	ID           string    `json:"id"`
	AccountID    string    `json:"account_id"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

func (s *Server) auditLog(ctx context.Context, acctID, actor, action, resourceType, resourceID, ip, userAgent string) {
	if s.db == nil || acctID == "" {
		return
	}
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := s.db.Exec(bgCtx, `
			INSERT INTO audit_logs (account_id, actor, action, resource_type, resource_id, ip_address, user_agent)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, acctID, actor, action, resourceType, resourceID, ip, userAgent)
		if err != nil {
			s.log.Error("failed to record audit log", "error", err, "account_id", acctID, "action", action)
		}
	}()
}

func (s *Server) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
		SELECT id, account_id, actor, action, resource_type, resource_id, coalesce(ip_address, ''), coalesce(user_agent, ''), created_at
		FROM audit_logs
		WHERE account_id = $1 AND created_at < $2
		ORDER BY created_at DESC
		LIMIT $3
	`, acct, before, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()

	list := make([]auditLogView, 0)
	for rows.Next() {
		var l auditLogView
		if err := rows.Scan(&l.ID, &l.AccountID, &l.Actor, &l.Action, &l.ResourceType, &l.ResourceID, &l.IPAddress, &l.UserAgent, &l.CreatedAt); err != nil {
			s.internal(w, err)
			return
		}
		list = append(list, l)
	}
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": list})
}
