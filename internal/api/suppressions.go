package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type suppressionView struct {
	Address   string    `json:"address"`
	Reason    *string   `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) listSuppressions(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	rows, err := s.rdb.Query(r.Context(), `
SELECT address, reason, created_at FROM suppressions
WHERE account_id = $1 AND created_at < $2 ORDER BY created_at DESC LIMIT $3`, accountID(r), before, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[suppressionView])
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

func (s *Server) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	addr := strings.ToLower(r.PathValue("address"))
	tag, err := s.db.Exec(r.Context(), `DELETE FROM suppressions WHERE account_id = $1 AND address = $2`, accountID(r), addr)
	if err != nil {
		s.internal(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "suppression not found")
		return
	}
	if s.redis != nil {
		_ = s.redis.RemoveSuppression(r.Context(), accountID(r), addr)
	}
	s.auditLog(r.Context(), accountID(r), accountID(r), "delete", "suppression", addr, clientIP(r), r.UserAgent())
	w.WriteHeader(http.StatusNoContent)
}
