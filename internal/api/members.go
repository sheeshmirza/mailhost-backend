package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"mailhost/internal/validator"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type orgMemberView struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, COALESCE(user_id::text, ''), email, role, created_at, updated_at
FROM organization_members
WHERE account_id = $1 AND created_at < $2
ORDER BY created_at DESC LIMIT $3`, acct, before, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query members")
		return
	}
	defer rows.Close()

	members := make([]orgMemberView, 0)
	for rows.Next() {
		var m orgMemberView
		if err := rows.Scan(&m.ID, &m.UserID, &m.Email, &m.Role, &m.CreatedAt, &m.UpdatedAt); err == nil {
			members = append(members, m)
		}
	}

	resp := map[string]any{
		"object": "list",
		"data":   members,
	}
	if len(members) == limit {
		resp["next_before"] = members[len(members)-1].CreatedAt
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !validator.IsValidEmail(email) {
		writeError(w, http.StatusUnprocessableEntity, "valid email address is required")
		return
	}

	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role == "" {
		role = "user"
	} else if !validator.IsValidRole(role) {
		writeError(w, http.StatusUnprocessableEntity, "invalid role: use administrator, developer, or a custom role name")
		return
	}

	acct := accountID(r)

	var matchedUserID *uuid.UUID
	_ = s.db.QueryRow(r.Context(), `SELECT id FROM users WHERE lower(email) = $1 AND email_verified`, email).Scan(&matchedUserID)

	var id uuid.UUID
	var returnedUserID *uuid.UUID
	var createdAt, updatedAt time.Time
	err := s.db.QueryRow(r.Context(), `
INSERT INTO organization_members (account_id, user_id, email, role)
VALUES ($1, $2, $3, $4)
ON CONFLICT (account_id, email) DO UPDATE SET role = $4, user_id = COALESCE($2, organization_members.user_id), updated_at = now()
RETURNING id, user_id, created_at, updated_at`,
		acct, matchedUserID, email, role).Scan(&id, &returnedUserID, &createdAt, &updatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to add member")
		return
	}

	uIDStr := ""
	if returnedUserID != nil {
		uIDStr = returnedUserID.String()
	}

	s.audit(r.Context(), acct, "add_member", "organization_member", id.String(), r)
	writeJSON(w, http.StatusCreated, orgMemberView{
		ID:        id.String(),
		UserID:    uIDStr,
		Email:     email,
		Role:      role,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	})
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid member id")
		return
	}

	acct := accountID(r)

	var targetRole string
	err = s.db.QueryRow(r.Context(), `SELECT role FROM organization_members WHERE id = $1 AND account_id = $2`, id, acct).Scan(&targetRole)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "member not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	normTargetRole := strings.ToLower(strings.TrimSpace(targetRole))
	if normTargetRole == "administrator" || normTargetRole == "owner" || normTargetRole == "admin" {
		var adminCount int
		_ = s.db.QueryRow(r.Context(), `
SELECT COUNT(*) FROM organization_members
WHERE account_id = $1 AND lower(role) IN ('administrator', 'owner', 'admin')`, acct).Scan(&adminCount)
		if adminCount <= 1 {
			writeError(w, http.StatusUnprocessableEntity, "cannot remove the only administrator of the organization")
			return
		}
	}

	tag, err := s.db.Exec(r.Context(), `
DELETE FROM organization_members
WHERE id = $1 AND account_id = $2`, id, acct)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "member not found")
		return
	}

	s.audit(r.Context(), acct, "remove_member", "organization_member", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "organization_member",
		"deleted": true,
	})
}
