package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type dedicatedIPView struct {
	ID         string    `json:"id"`
	IPAddress  string    `json:"ip_address"`
	Status     string    `json:"status"` // "warming", "active", "paused"
	WarmupDay  int       `json:"warmup_day"`
	DailyQuota int       `json:"daily_quota"`
	SentToday  int       `json:"sent_today"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type warmupScheduleDay struct {
	Day        int `json:"day"`
	DailyLimit int `json:"daily_limit"`
	GmailLimit int `json:"gmail_limit"`
	YahooLimit int `json:"yahoo_limit"`
}

var recommendedWarmupSchedule = []warmupScheduleDay{
	{Day: 1, DailyLimit: 50, GmailLimit: 20, YahooLimit: 20},
	{Day: 2, DailyLimit: 100, GmailLimit: 40, YahooLimit: 40},
	{Day: 3, DailyLimit: 200, GmailLimit: 80, YahooLimit: 80},
	{Day: 4, DailyLimit: 400, GmailLimit: 150, YahooLimit: 150},
	{Day: 5, DailyLimit: 800, GmailLimit: 300, YahooLimit: 300},
	{Day: 6, DailyLimit: 1500, GmailLimit: 600, YahooLimit: 600},
	{Day: 7, DailyLimit: 3000, GmailLimit: 1200, YahooLimit: 1200},
	{Day: 8, DailyLimit: 5000, GmailLimit: 2000, YahooLimit: 2000},
	{Day: 9, DailyLimit: 8000, GmailLimit: 3000, YahooLimit: 3000},
	{Day: 10, DailyLimit: 12000, GmailLimit: 4500, YahooLimit: 4500},
	{Day: 15, DailyLimit: 25000, GmailLimit: 10000, YahooLimit: 10000},
	{Day: 20, DailyLimit: 50000, GmailLimit: 20000, YahooLimit: 20000},
	{Day: 25, DailyLimit: 100000, GmailLimit: 40000, YahooLimit: 40000},
	{Day: 30, DailyLimit: 250000, GmailLimit: 100000, YahooLimit: 100000},
}

func (s *Server) listDedicatedIPs(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, ip_address, status, warmup_day, daily_quota, sent_today, created_at, updated_at
FROM dedicated_ips
WHERE account_id = $1 AND created_at < $2
ORDER BY created_at DESC LIMIT $3`, acct, before, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query dedicated ips")
		return
	}
	defer rows.Close()

	ips := make([]dedicatedIPView, 0)
	for rows.Next() {
		var ip dedicatedIPView
		if err := rows.Scan(&ip.ID, &ip.IPAddress, &ip.Status, &ip.WarmupDay, &ip.DailyQuota, &ip.SentToday, &ip.CreatedAt, &ip.UpdatedAt); err == nil {
			ips = append(ips, ip)
		}
	}

	resp := map[string]any{
		"object": "list",
		"data":   ips,
	}
	if len(ips) == limit {
		resp["next_before"] = ips[len(ips)-1].CreatedAt
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getWarmingSchedule(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"object":   "warming_schedule",
		"provider": "mailhost",
		"schedule": recommendedWarmupSchedule,
	})
}

func (s *Server) updateIPWarmup(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ip id")
		return
	}

	var req struct {
		Status     *string `json:"status"` // "warming", "active", "paused"
		WarmupDay  *int    `json:"warmup_day"`
		DailyQuota *int    `json:"daily_quota"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	if req.Status != nil {
		st := strings.ToLower(strings.TrimSpace(*req.Status))
		if st != "warming" && st != "active" && st != "paused" {
			writeError(w, http.StatusUnprocessableEntity, "invalid status; must be warming, active, or paused")
			return
		}
		req.Status = &st
	}
	if req.WarmupDay != nil && *req.WarmupDay < 1 {
		writeError(w, http.StatusUnprocessableEntity, "warmup_day must be at least 1")
		return
	}
	if req.DailyQuota != nil && *req.DailyQuota < 0 {
		writeError(w, http.StatusUnprocessableEntity, "daily_quota must be non-negative")
		return
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(), `
UPDATE dedicated_ips
SET status = COALESCE($3, status),
    warmup_day = COALESCE($4, warmup_day),
    daily_quota = COALESCE($5, daily_quota),
    updated_at = now()
WHERE id = $1 AND account_id = $2`,
		id, acct, req.Status, req.WarmupDay, req.DailyQuota)
	if err != nil {
		s.internal(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "dedicated ip not found")
		return
	}

	s.audit(r.Context(), acct, "update", "dedicated_ip", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "dedicated_ip",
		"updated": true,
	})
}
