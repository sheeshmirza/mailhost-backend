package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"mailhost/internal/validator"
)

type templateVariable struct {
	Key           string `json:"key"`
	Type          string `json:"type"` // "string" or "number"
	FallbackValue string `json:"fallback_value,omitempty"`
}

type templateReq struct {
	Name      string             `json:"name"`
	Alias     string             `json:"alias"`
	Subject   string             `json:"subject"`
	HTML      string             `json:"html"`
	Text      string             `json:"text"`
	Variables []templateVariable `json:"variables"`
}

var templateAliasRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func (s *Server) createTemplate(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req templateReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be between 1 and 100 characters")
		return
	}

	alias := strings.TrimSpace(req.Alias)
	if alias != "" {
		if len(alias) > 50 || !templateAliasRe.MatchString(alias) {
			writeError(w, http.StatusUnprocessableEntity, "alias must contain only alphanumeric characters, dots, underscores, or hyphens and be 50 characters or less")
			return
		}
		alias = strings.ToLower(alias)
	}
	if req.Subject != "" && (len(req.Subject) > 998 || strings.ContainsAny(req.Subject, "\r\n")) {
		writeError(w, http.StatusUnprocessableEntity, "subject must be under 998 characters and contain no newlines")
		return
	}
	if len(req.Variables) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "variables cannot contain more than 100 items")
		return
	}
	for i, variable := range req.Variables {
		if !validator.IsValidVariableName(variable.Key) || (variable.Type != "string" && variable.Type != "number") || len(variable.FallbackValue) > 10000 {
			writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("variables[%d] is invalid", i))
			return
		}
	}

	var aliasVal *string
	if alias != "" {
		aliasVal = &alias
	}

	varsJSON, _ := json.Marshal(req.Variables)
	if len(varsJSON) > 1<<20 {
		writeError(w, http.StatusUnprocessableEntity, "variables cannot exceed 1 MiB")
		return
	}
	if req.Variables == nil {
		varsJSON = []byte("[]")
	}

	acct := accountID(r)
	var id uuid.UUID
	var createdAt, updatedAt time.Time

	err := s.db.QueryRow(r.Context(), `
INSERT INTO templates (account_id, name, alias, subject, html, text, variables, status, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'draft', now())
RETURNING id, created_at, updated_at`,
		acct, name, aliasVal, req.Subject, req.HTML, req.Text, varsJSON).
		Scan(&id, &createdAt, &updatedAt)
	if isUniqueViolation(err) {
		writeError(w, http.StatusConflict, "a template with this name already exists")
		return
	}
	if err != nil {
		s.log.Error("create template failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create template")
		return
	}

	s.audit(r.Context(), acct, "create", "template", id.String(), r)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id.String(),
		"object":     "template",
		"name":       name,
		"alias":      aliasVal,
		"subject":    req.Subject,
		"html":       req.HTML,
		"text":       req.Text,
		"status":     "draft",
		"variables":  req.Variables,
		"created_at": createdAt.Format(time.RFC3339),
		"updated_at": updatedAt.Format(time.RFC3339),
	})
}

func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, name, alias, subject, status, variables, published_at, created_at, updated_at
FROM templates
WHERE account_id = $1 AND created_at < $2
ORDER BY created_at DESC LIMIT $3`,
		acct, before, limit)
	if err != nil {
		s.log.Error("list templates failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list templates")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var name, subject, status string
		var alias *string
		var varsBytes []byte
		var publishedAt *time.Time
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &name, &alias, &subject, &status, &varsBytes, &publishedAt, &createdAt, &updatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}

		var vars []templateVariable
		_ = json.Unmarshal(varsBytes, &vars)

		item := map[string]any{
			"id":         id.String(),
			"object":     "template",
			"name":       name,
			"alias":      alias,
			"subject":    subject,
			"status":     status,
			"variables":  vars,
			"created_at": createdAt.Format(time.RFC3339Nano),
			"updated_at": updatedAt.Format(time.RFC3339),
		}
		if publishedAt != nil {
			item["published_at"] = publishedAt.Format(time.RFC3339)
		}
		data = append(data, item)
	}

	resp := map[string]any{
		"object": "list",
		"data":   data,
	}
	if len(data) == limit {
		resp["next_before"] = data[len(data)-1]["created_at"]
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getTemplate(w http.ResponseWriter, r *http.Request) {
	idOrAlias := r.PathValue("id")
	acct := accountID(r)

	var id uuid.UUID
	var name, subject, htmlStr, textStr, status string
	var pubSubject, pubHTML, pubText string
	var alias *string
	var varsBytes, pubVarsBytes []byte
	var publishedAt *time.Time
	var createdAt, updatedAt time.Time

	var err error
	if parsedUUID, pErr := uuid.Parse(idOrAlias); pErr == nil {
		err = s.rdb.QueryRow(r.Context(), `
SELECT id, name, alias, subject, html, text, variables, status,
       published_subject, published_html, published_text, published_variables, published_at,
       created_at, updated_at
FROM templates WHERE id = $1 AND account_id = $2`,
			parsedUUID, acct).Scan(&id, &name, &alias, &subject, &htmlStr, &textStr, &varsBytes, &status,
			&pubSubject, &pubHTML, &pubText, &pubVarsBytes, &publishedAt, &createdAt, &updatedAt)
	} else {
		err = s.rdb.QueryRow(r.Context(), `
SELECT id, name, alias, subject, html, text, variables, status,
       published_subject, published_html, published_text, published_variables, published_at,
       created_at, updated_at
FROM templates WHERE alias = $1 AND account_id = $2`,
			idOrAlias, acct).Scan(&id, &name, &alias, &subject, &htmlStr, &textStr, &varsBytes, &status,
			&pubSubject, &pubHTML, &pubText, &pubVarsBytes, &publishedAt, &createdAt, &updatedAt)
	}

	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "template not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	var vars, pubVars []templateVariable
	_ = json.Unmarshal(varsBytes, &vars)
	_ = json.Unmarshal(pubVarsBytes, &pubVars)

	resp := map[string]any{
		"id":         id.String(),
		"object":     "template",
		"name":       name,
		"alias":      alias,
		"subject":    subject,
		"html":       htmlStr,
		"text":       textStr,
		"status":     status,
		"variables":  vars,
		"created_at": createdAt.Format(time.RFC3339),
		"updated_at": updatedAt.Format(time.RFC3339),
	}
	if publishedAt != nil {
		resp["published_at"] = publishedAt.Format(time.RFC3339)
		resp["published"] = map[string]any{
			"subject":   pubSubject,
			"html":      pubHTML,
			"text":      pubText,
			"variables": pubVars,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) updateTemplate(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	var req templateReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if len(req.Name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be at most 100 characters")
		return
	}
	req.Alias = strings.ToLower(strings.TrimSpace(req.Alias))
	if req.Alias != "" && (len(req.Alias) > 50 || !templateAliasRe.MatchString(req.Alias)) {
		writeError(w, http.StatusUnprocessableEntity, "alias must contain only alphanumeric characters, dots, underscores, or hyphens and be 50 characters or less")
		return
	}
	if req.Subject != "" && (len(req.Subject) > 998 || strings.ContainsAny(req.Subject, "\r\n")) {
		writeError(w, http.StatusUnprocessableEntity, "subject must be under 998 characters and contain no newlines")
		return
	}
	if len(req.Variables) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "variables cannot contain more than 100 items")
		return
	}
	for i, variable := range req.Variables {
		if !validator.IsValidVariableName(variable.Key) || (variable.Type != "string" && variable.Type != "number") || len(variable.FallbackValue) > 10000 {
			writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("variables[%d] is invalid", i))
			return
		}
	}

	var varsJSON []byte
	if req.Variables != nil {
		varsJSON, _ = json.Marshal(req.Variables)
		if len(varsJSON) > 1<<20 {
			writeError(w, http.StatusUnprocessableEntity, "variables cannot exceed 1 MiB")
			return
		}
	}

	acct := accountID(r)
	var name, subject, htmlStr, textStr, status string
	var alias *string
	var varsBytes []byte
	var createdAt, updatedAt time.Time

	err = s.db.QueryRow(r.Context(), `
UPDATE templates
SET name = COALESCE(NULLIF($3, ''), name),
    alias = CASE WHEN $4 <> '' THEN $4 ELSE alias END,
    subject = COALESCE(NULLIF($5, ''), subject),
    html = COALESCE(NULLIF($6, ''), html),
    text = COALESCE(NULLIF($7, ''), text),
    variables = CASE WHEN $8::jsonb IS NOT NULL AND $8::jsonb <> 'null'::jsonb THEN $8::jsonb ELSE variables END,
    updated_at = now()
WHERE id = $1 AND account_id = $2
RETURNING id, name, alias, subject, html, text, variables, status, created_at, updated_at`,
		id, acct, req.Name, req.Alias, req.Subject, req.HTML, req.Text, varsJSON).
		Scan(&id, &name, &alias, &subject, &htmlStr, &textStr, &varsBytes, &status, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "template not found")
		return
	}
	if isUniqueViolation(err) {
		writeError(w, http.StatusConflict, "a template with this name already exists")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	var vars []templateVariable
	_ = json.Unmarshal(varsBytes, &vars)

	s.audit(r.Context(), acct, "update", "template", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         id.String(),
		"object":     "template",
		"name":       name,
		"alias":      alias,
		"subject":    subject,
		"html":       htmlStr,
		"text":       textStr,
		"status":     status,
		"variables":  vars,
		"created_at": createdAt.Format(time.RFC3339),
		"updated_at": updatedAt.Format(time.RFC3339),
	})
}

func (s *Server) publishTemplate(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	acct := accountID(r)
	var name, pubSubject, pubHTML, pubText string
	var alias *string
	var pubVarsBytes []byte
	var pubAt time.Time

	err = s.db.QueryRow(r.Context(), `
UPDATE templates
SET status = 'published',
    published_subject = subject,
    published_html = html,
    published_text = text,
    published_variables = variables,
    published_at = now(),
    updated_at = now()
WHERE id = $1 AND account_id = $2
RETURNING name, alias, published_subject, published_html, published_text, published_variables, published_at`,
		id, acct).
		Scan(&name, &alias, &pubSubject, &pubHTML, &pubText, &pubVarsBytes, &pubAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "template not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "publish failed")
		return
	}

	var vars []templateVariable
	_ = json.Unmarshal(pubVarsBytes, &vars)

	var versionNumber int
	err = s.db.QueryRow(r.Context(), `
INSERT INTO template_versions (template_id, account_id, version_number, subject, html, text, variables, published_by, created_at)
VALUES ($1, $2, COALESCE((SELECT MAX(version_number) FROM template_versions WHERE template_id = $1), 0) + 1, $3, $4, $5, $6, $7, $8)
RETURNING version_number`,
		id, acct, pubSubject, pubHTML, pubText, pubVarsBytes, acct, pubAt).Scan(&versionNumber)
	if err != nil {
		if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, "template was published concurrently; please retry")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create template version")
		return
	}

	s.audit(r.Context(), acct, "publish", "template", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             id.String(),
		"object":         "template",
		"name":           name,
		"alias":          alias,
		"status":         "published",
		"version_number": versionNumber,
		"published_at":   pubAt.Format(time.RFC3339),
		"variables":      vars,
	})
}

func (s *Server) listTemplateVersions(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, version_number, subject, html, text, variables, published_by, created_at
FROM template_versions
WHERE template_id = $1 AND account_id = $2 AND created_at < $3
ORDER BY version_number DESC LIMIT $4`,
		id, acct, before, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query versions")
		return
	}
	defer rows.Close()

	versions := make([]map[string]any, 0)
	for rows.Next() {
		var vID uuid.UUID
		var vNum int
		var sub, htmlStr, textStr, pubBy string
		var varsBytes []byte
		var createdAt time.Time
		if err := rows.Scan(&vID, &vNum, &sub, &htmlStr, &textStr, &varsBytes, &pubBy, &createdAt); err == nil {
			var vVars []templateVariable
			_ = json.Unmarshal(varsBytes, &vVars)
			versions = append(versions, map[string]any{
				"id":             vID.String(),
				"template_id":    id.String(),
				"version_number": vNum,
				"subject":        sub,
				"html":           htmlStr,
				"text":           textStr,
				"variables":      vVars,
				"published_by":   pubBy,
				"created_at":     createdAt.Format(time.RFC3339Nano),
			})
		}
	}

	resp := map[string]any{
		"object": "list",
		"data":   versions,
	}
	if len(versions) == limit {
		resp["next_before"] = versions[len(versions)-1]["created_at"]
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) rollbackTemplate(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid template id")
		return
	}
	versionStr := r.PathValue("version")

	acct := accountID(r)
	var sub, htmlStr, textStr string
	var varsBytes []byte
	var vNum int

	var queryErr error
	if vParsed, pErr := uuid.Parse(versionStr); pErr == nil {
		queryErr = s.rdb.QueryRow(r.Context(), `
SELECT version_number, subject, html, text, variables
FROM template_versions
WHERE id = $1 AND template_id = $2 AND account_id = $3`,
			vParsed, id, acct).Scan(&vNum, &sub, &htmlStr, &textStr, &varsBytes)
	} else if vInt, iErr := strconv.Atoi(versionStr); iErr == nil && vInt > 0 {
		queryErr = s.rdb.QueryRow(r.Context(), `
SELECT version_number, subject, html, text, variables
FROM template_versions
WHERE version_number = $1 AND template_id = $2 AND account_id = $3`,
			vInt, id, acct).Scan(&vNum, &sub, &htmlStr, &textStr, &varsBytes)
	} else {
		writeError(w, http.StatusBadRequest, "version must be a positive integer or version UUID")
		return
	}

	if errors.Is(queryErr, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "template version not found")
		return
	}
	if queryErr != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	tag, err := s.db.Exec(r.Context(), `
UPDATE templates
SET subject = $3, html = $4, text = $5, variables = $6, updated_at = now()
WHERE id = $1 AND account_id = $2`,
		id, acct, sub, htmlStr, textStr, varsBytes)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusInternalServerError, "rollback update failed")
		return
	}

	s.audit(r.Context(), acct, "rollback", "template", fmt.Sprintf("%s/v%d", id.String(), vNum), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":               id.String(),
		"object":           "template",
		"status":           "draft",
		"restored_version": vNum,
		"message":          "Template draft restored to target version",
	})
}

func (s *Server) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(),
		`DELETE FROM templates WHERE id = $1 AND account_id = $2`,
		id, acct)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "template not found")
		return
	}

	s.audit(r.Context(), acct, "delete", "template", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "template",
		"deleted": true,
	})
}

// Regex for {{key}}, {{{key}}}, {{{contact.first_name|fallback}}}, {{{MAILHOST_UNSUBSCRIBE_URL}}}
var templateVarRegex = regexp.MustCompile(`\{\{\{?([a-zA-Z0-9_.]+)(?:\|([^}]+))?\}?\}\}`)

// RenderTemplate substitutes variables into subject, html, and text.
func RenderTemplate(subject, htmlContent, textContent string, vars map[string]any) (string, string, string) {
	render := func(src string, escape bool) string {
		if src == "" {
			return ""
		}
		return templateVarRegex.ReplaceAllStringFunc(src, func(match string) string {
			submatches := templateVarRegex.FindStringSubmatch(match)
			if len(submatches) < 2 {
				return match
			}
			key := submatches[1]
			fallback := ""
			if len(submatches) >= 3 {
				fallback = submatches[2]
			}

			// Support nested dot lookup (e.g. contact.first_name)
			val, ok := lookupVar(vars, key)
			if ok && val != nil {
				res := fmt.Sprintf("%v", val)
				if escape && !strings.HasPrefix(match, "{{{") {
					res = html.EscapeString(res)
				}
				return res
			}
			if fallback != "" {
				if escape && !strings.HasPrefix(match, "{{{") {
					return html.EscapeString(fallback)
				}
				return fallback
			}
			return ""
		})
	}

	return render(subject, false), render(htmlContent, true), render(textContent, false)
}

func lookupVar(vars map[string]any, key string) (any, bool) {
	if vars == nil {
		return nil, false
	}
	if val, ok := vars[key]; ok {
		return val, true
	}
	// Try nested dot path
	if strings.ContainsRune(key, '.') {
		parts := strings.Split(key, ".")
		var curr any = vars
		for _, part := range parts {
			m, ok := curr.(map[string]any)
			if !ok {
				return nil, false
			}
			curr, ok = m[part]
			if !ok {
				return nil, false
			}
		}
		return curr, true
	}
	return nil, false
}
