package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"mailhost/internal/queue"
)

type stepConfig struct {
	TemplateID   string `json:"template_id,omitempty"`
	Template     string `json:"template,omitempty"`
	From         string `json:"from,omitempty"`
	Subject      string `json:"subject,omitempty"`
	HTML         string `json:"html,omitempty"`
	Text         string `json:"text,omitempty"`
	DelaySeconds int    `json:"delay_seconds,omitempty"`
	Field        string `json:"field,omitempty"`
	Operator     string `json:"operator,omitempty"` // "eq", "neq", "gt", "lt", "contains"
	Value        any    `json:"value,omitempty"`
	SegmentID    string `json:"segment_id,omitempty"`
}

type automationStep struct {
	ID        string           `json:"id"`
	Type      string           `json:"type"` // "send_email", "email", "delay", "condition", "add_to_segment", "remove_from_segment"
	Config    stepConfig       `json:"config"`
	ThenSteps []automationStep `json:"then_steps,omitempty"`
	ElseSteps []automationStep `json:"else_steps,omitempty"`
}

type automationTrigger struct {
	Type      string `json:"type"` // "event", "contact.created", "email.opened", "email.clicked"
	EventName string `json:"event_name,omitempty"`
}

type automationReq struct {
	Name    string            `json:"name"`
	Status  string            `json:"status"` // "active", "draft", "paused"
	Trigger automationTrigger `json:"trigger"`
	Steps   []automationStep  `json:"steps"`
}

func validateAutomationSteps(steps []automationStep, path string, topLevel bool) string {
	for i, step := range steps {
		p := fmt.Sprintf("%s[%d]", path, i)
		switch step.Type {
		case "send_email", "email", "condition", "add_to_segment", "remove_from_segment":
		case "delay":
			if !topLevel {
				return p + ": delay steps are not supported inside condition branches"
			}
			if step.Config.DelaySeconds < 0 || step.Config.DelaySeconds > 31_536_000 {
				return p + ".delay_seconds is invalid"
			}
		default:
			return p + " has an invalid type"
		}
		if msg := validateAutomationSteps(step.ThenSteps, p+".then_steps", false); msg != "" {
			return msg
		}
		if msg := validateAutomationSteps(step.ElseSteps, p+".else_steps", false); msg != "" {
			return msg
		}
	}
	return ""
}

func (s *Server) createAutomation(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	var req automationReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be between 1 and 100 characters")
		return
	}

	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = "draft"
	} else if status != "active" && status != "paused" && status != "draft" {
		writeError(w, http.StatusUnprocessableEntity, "status must be active, draft, or paused")
		return
	}

	trigType := strings.ToLower(strings.TrimSpace(req.Trigger.Type))
	if trigType == "" {
		trigType = "event"
	}
	validTriggers := map[string]bool{
		"event":           true,
		"contact.created": true,
		"email.opened":    true,
		"email.clicked":   true,
	}
	if !validTriggers[trigType] {
		writeError(w, http.StatusUnprocessableEntity, "invalid trigger type; supported: event, contact.created, email.opened, email.clicked")
		return
	}
	if len(req.Steps) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "steps cannot contain more than 100 items")
		return
	}
	if msg := validateAutomationSteps(req.Steps, "steps", true); msg != "" {
		writeError(w, http.StatusUnprocessableEntity, msg)
		return
	}

	trigJSON, _ := json.Marshal(req.Trigger)
	if len(trigJSON) > 1<<20 {
		writeError(w, http.StatusUnprocessableEntity, "trigger cannot exceed 1 MiB")
		return
	}
	stepsJSON, _ := json.Marshal(req.Steps)
	if len(stepsJSON) > 1<<20 {
		writeError(w, http.StatusUnprocessableEntity, "steps cannot exceed 1 MiB")
		return
	}
	if req.Steps == nil {
		stepsJSON = []byte("[]")
	}

	acct := accountID(r)
	var id uuid.UUID
	var createdAt, updatedAt time.Time

	err := s.db.QueryRow(r.Context(), `
INSERT INTO automations (account_id, name, status, trigger_type, trigger_config, steps, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
RETURNING id, created_at, updated_at`,
		acct, name, status, trigType, trigJSON, stepsJSON).
		Scan(&id, &createdAt, &updatedAt)
	if err != nil {
		s.log.Error("create automation failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create automation")
		return
	}

	s.audit(r.Context(), acct, "create", "automation", id.String(), r)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id.String(),
		"object":     "automation",
		"name":       name,
		"status":     status,
		"trigger":    req.Trigger,
		"steps":      req.Steps,
		"created_at": createdAt.Format(time.RFC3339),
		"updated_at": updatedAt.Format(time.RFC3339),
	})
}

func (s *Server) listAutomations(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, name, status, trigger_type, trigger_config, steps, created_at, updated_at
FROM automations
WHERE account_id = $1 AND created_at < $2
ORDER BY created_at DESC LIMIT $3`,
		acct, before, limit)
	if err != nil {
		s.log.Error("list automations failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list automations")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var id uuid.UUID
		var name, status, trigType string
		var trigBytes, stepsBytes []byte
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &name, &status, &trigType, &trigBytes, &stepsBytes, &createdAt, &updatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}

		var trig automationTrigger
		var steps []automationStep
		_ = json.Unmarshal(trigBytes, &trig)
		_ = json.Unmarshal(stepsBytes, &steps)

		data = append(data, map[string]any{
			"id":         id.String(),
			"object":     "automation",
			"name":       name,
			"status":     status,
			"trigger":    trig,
			"steps":      steps,
			"created_at": createdAt.Format(time.RFC3339Nano),
			"updated_at": updatedAt.Format(time.RFC3339),
		})
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

func (s *Server) getAutomation(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid automation id")
		return
	}

	acct := accountID(r)
	var name, status, trigType string
	var trigBytes, stepsBytes []byte
	var createdAt, updatedAt time.Time

	err = s.rdb.QueryRow(r.Context(), `
SELECT name, status, trigger_type, trigger_config, steps, created_at, updated_at
FROM automations
WHERE id = $1 AND account_id = $2`,
		id, acct).Scan(&name, &status, &trigType, &trigBytes, &stepsBytes, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "automation not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	var trig automationTrigger
	var steps []automationStep
	_ = json.Unmarshal(trigBytes, &trig)
	_ = json.Unmarshal(stepsBytes, &steps)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":         id.String(),
		"object":     "automation",
		"name":       name,
		"status":     status,
		"trigger":    trig,
		"steps":      steps,
		"created_at": createdAt.Format(time.RFC3339),
		"updated_at": updatedAt.Format(time.RFC3339),
	})
}

func (s *Server) updateAutomation(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid automation id")
		return
	}

	var req automationReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name != "" && len(strings.TrimSpace(req.Name)) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be at most 100 characters")
		return
	}
	if req.Status != "" {
		st := strings.ToLower(strings.TrimSpace(req.Status))
		if st != "active" && st != "draft" && st != "paused" {
			writeError(w, http.StatusUnprocessableEntity, "status must be active, draft, or paused")
			return
		}
		req.Status = st
	}
	if req.Trigger.Type != "" {
		trigType := strings.ToLower(strings.TrimSpace(req.Trigger.Type))
		validTriggers := map[string]bool{
			"event":           true,
			"contact.created": true,
			"email.opened":    true,
			"email.clicked":   true,
		}
		if !validTriggers[trigType] {
			writeError(w, http.StatusUnprocessableEntity, "invalid trigger type; supported: event, contact.created, email.opened, email.clicked")
			return
		}
		req.Trigger.Type = trigType
	}
	if len(req.Steps) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "steps cannot contain more than 100 items")
		return
	}
	if msg := validateAutomationSteps(req.Steps, "steps", true); msg != "" {
		writeError(w, http.StatusUnprocessableEntity, msg)
		return
	}

	var trigJSON []byte
	if req.Trigger.Type != "" || req.Trigger.EventName != "" {
		trigJSON, _ = json.Marshal(req.Trigger)
		if len(trigJSON) > 1<<20 {
			writeError(w, http.StatusUnprocessableEntity, "trigger cannot exceed 1 MiB")
			return
		}
	}
	var stepsJSON []byte
	if req.Steps != nil {
		stepsJSON, _ = json.Marshal(req.Steps)
		if len(stepsJSON) > 1<<20 {
			writeError(w, http.StatusUnprocessableEntity, "steps cannot exceed 1 MiB")
			return
		}
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(), `
UPDATE automations
SET name = COALESCE(NULLIF($3, ''), name),
    status = CASE WHEN $4 = 'active' OR $4 = 'draft' OR $4 = 'paused' THEN $4 ELSE status END,
    trigger_type = CASE WHEN $5 <> '' THEN $5 ELSE trigger_type END,
    trigger_config = CASE WHEN $6::jsonb IS NOT NULL AND $6::jsonb <> 'null'::jsonb THEN $6::jsonb ELSE trigger_config END,
    steps = CASE WHEN $7::jsonb IS NOT NULL AND $7::jsonb <> 'null'::jsonb THEN $7::jsonb ELSE steps END,
    updated_at = now()
WHERE id = $1 AND account_id = $2`,
		id, acct, req.Name, req.Status, req.Trigger.Type, trigJSON, stepsJSON)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "automation not found")
		return
	}

	s.audit(r.Context(), acct, "update", "automation", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "automation",
		"updated": true,
	})
}

func (s *Server) deleteAutomation(w http.ResponseWriter, r *http.Request) {
	if !requireDeveloperOrAdmin(w, r) {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid automation id")
		return
	}

	acct := accountID(r)
	tag, err := s.db.Exec(r.Context(),
		`DELETE FROM automations WHERE id = $1 AND account_id = $2`,
		id, acct)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "automation not found")
		return
	}

	s.audit(r.Context(), acct, "delete", "automation", id.String(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id.String(),
		"object":  "automation",
		"deleted": true,
	})
}

func (s *Server) listAutomationRuns(w http.ResponseWriter, r *http.Request) {
	limit, before, ok := page(w, r)
	if !ok {
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid automation id")
		return
	}

	acct := accountID(r)
	rows, err := s.rdb.Query(r.Context(), `
SELECT id, contact_email, event_name, status, current_step_index, step_results, created_at, updated_at
FROM automation_runs
WHERE automation_id = $1 AND account_id = $2 AND created_at < $3
ORDER BY created_at DESC LIMIT $4`,
		id, acct, before, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	data := make([]map[string]any, 0)
	for rows.Next() {
		var runID uuid.UUID
		var email, evName, status string
		var stepIdx int
		var resultsBytes []byte
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&runID, &email, &evName, &status, &stepIdx, &resultsBytes, &createdAt, &updatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}

		var results []any
		_ = json.Unmarshal(resultsBytes, &results)

		data = append(data, map[string]any{
			"id":                 runID.String(),
			"object":             "automation_run",
			"automation_id":      id.String(),
			"contact_email":      email,
			"event_name":         evName,
			"status":             status,
			"current_step_index": stepIdx,
			"step_results":       results,
			"created_at":         createdAt.Format(time.RFC3339Nano),
			"updated_at":         updatedAt.Format(time.RFC3339),
		})
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

func (s *Server) getAutomationRun(w http.ResponseWriter, r *http.Request) {
	runIDStr := r.PathValue("run_id")
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	acct := accountID(r)
	var autoID uuid.UUID
	var email, evName, status string
	var stepIdx int
	var dataBytes, resultsBytes []byte
	var createdAt, updatedAt time.Time

	err = s.rdb.QueryRow(r.Context(), `
SELECT automation_id, contact_email, event_name, event_data, status, current_step_index, step_results, created_at, updated_at
FROM automation_runs
WHERE id = $1 AND account_id = $2`,
		runID, acct).Scan(&autoID, &email, &evName, &dataBytes, &status, &stepIdx, &resultsBytes, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "automation run not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	var evData map[string]any
	var results []any
	_ = json.Unmarshal(dataBytes, &evData)
	_ = json.Unmarshal(resultsBytes, &results)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":                 runID.String(),
		"object":             "automation_run",
		"automation_id":      autoID.String(),
		"contact_email":      email,
		"event_name":         evName,
		"event_data":         evData,
		"status":             status,
		"current_step_index": stepIdx,
		"step_results":       results,
		"created_at":         createdAt.Format(time.RFC3339),
		"updated_at":         updatedAt.Format(time.RFC3339),
	})
}

// --- Automation Execution Engine ---

func (s *Server) triggerAutomations(ctx context.Context, acct, triggerType, eventName, contactID, contactEmail string, eventData map[string]any) {
	rows, err := s.db.Query(ctx, `
SELECT id, steps
FROM automations
WHERE account_id = $1 AND status = 'active'
  AND ((trigger_type = $2 AND $2 <> 'event')
    OR (trigger_type = 'event' AND $2 = 'event' AND coalesce(trigger_config->>'event_name', '') IN ('', $3)))`,
		acct, triggerType, eventName)
	if err != nil {
		s.log.Error("query matching automations failed", "err", err)
		return
	}
	defer rows.Close()

	type autoMatch struct {
		id    uuid.UUID
		steps []automationStep
	}
	var matches []autoMatch

	for rows.Next() {
		var aID uuid.UUID
		var stepsBytes []byte
		if err := rows.Scan(&aID, &stepsBytes); err == nil {
			var steps []automationStep
			_ = json.Unmarshal(stepsBytes, &steps)
			matches = append(matches, autoMatch{id: aID, steps: steps})
		}
	}

	for _, m := range matches {
		s.startAutomationRun(ctx, acct, m.id, m.steps, contactID, contactEmail, eventName, eventData)
	}
}

func (s *Server) startAutomationRun(ctx context.Context, acct string, autoID uuid.UUID, steps []automationStep, contactID, email, eventName string, eventData map[string]any) {
	var cUUID *uuid.UUID
	if parsed, err := uuid.Parse(contactID); err == nil {
		cUUID = &parsed
	}

	evDataJSON, _ := json.Marshal(eventData)
	if eventData == nil {
		evDataJSON = []byte("{}")
	}

	var runID uuid.UUID
	err := s.db.QueryRow(ctx, `
INSERT INTO automation_runs (account_id, automation_id, contact_id, contact_email, event_name, event_data, status, current_step_index, step_results, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, 'running', 0, '[]', now())
RETURNING id`,
		acct, autoID, cUUID, email, eventName, evDataJSON).Scan(&runID)
	if err != nil {
		s.log.Error("start automation run failed", "auto_id", autoID, "err", err)
		return
	}

	s.executeSteps(ctx, runID, acct, steps, 0, contactID, email, eventData)
}

func (s *Server) executeSteps(ctx context.Context, runID uuid.UUID, acct string, steps []automationStep, startIndex int, contactID, email string, eventData map[string]any) {
	var results []map[string]any
	if startIndex > 0 {
		var prevJSON []byte
		if err := s.db.QueryRow(ctx, `SELECT step_results FROM automation_runs WHERE id = $1`, runID).Scan(&prevJSON); err == nil && len(prevJSON) > 0 {
			_ = json.Unmarshal(prevJSON, &results)
		}
	}

	results, paused := s.runSteps(ctx, runID, acct, steps, startIndex, contactID, email, eventData, results, true)
	if paused {
		return
	}

	resJSON, _ := json.Marshal(results)
	_, _ = s.db.Exec(ctx, `
UPDATE automation_runs
SET status = 'completed', current_step_index = $2, step_results = $3, updated_at = now()
WHERE id = $1`,
		runID, len(steps), resJSON)
}

// runSteps executes steps in order and reports whether the run paused on a top-level delay.
func (s *Server) runSteps(ctx context.Context, runID uuid.UUID, acct string, steps []automationStep, startIndex int, contactID, email string, eventData map[string]any, results []map[string]any, topLevel bool) ([]map[string]any, bool) {
	for i := startIndex; i < len(steps); i++ {
		step := steps[i]
		switch step.Type {
		case "send_email", "email":
			// Render and send
			vars := make(map[string]any)
			for k, v := range eventData {
				vars["data."+k] = v
				vars[k] = v
			}
			vars["email"] = email
			vars["contact.email"] = email

			from := step.Config.From
			sub := step.Config.Subject
			htmlContent := step.Config.HTML
			textContent := step.Config.Text

			if step.Config.TemplateID != "" || step.Config.Template != "" {
				tmplRef := step.Config.TemplateID
				if tmplRef == "" {
					tmplRef = step.Config.Template
				}
				// Load published template
				var pSub, pHTML, pText string
				templateErr := s.db.QueryRow(ctx, `
SELECT published_subject, published_html, published_text
FROM templates WHERE (id::text = $1 OR alias = $1) AND account_id = $2 AND status = 'published'`,
					tmplRef, acct).Scan(&pSub, &pHTML, &pText)
				if templateErr != nil {
					results = append(results, map[string]any{
						"step_id":     step.ID,
						"type":        step.Type,
						"status":      "error",
						"error":       "published template not found",
						"executed_at": time.Now().Format(time.RFC3339),
					})
					continue
				}
				if pSub != "" {
					sub = pSub
					htmlContent = pHTML
					textContent = pText
				}
			}

			rSub, rHTML, rText := RenderTemplate(sub, htmlContent, textContent, vars)
			sReq := sendReq{
				From:    from,
				To:      []string{email},
				Subject: rSub,
				HTML:    rHTML,
				Text:    rText,
			}
			keys, keyErr := s.signingKeys(ctx, acct, []string{sReq.From})
			var sendErr error
			if keyErr != nil {
				sendErr = keyErr
			} else {
				e, prepErr := s.prepare(&sReq, nil, keys, uuid.Nil)
				if prepErr != nil {
					sendErr = prepErr
				} else {
					sendErr = s.enqueueDirect(ctx, acct, []queue.Email{e})
				}
			}
			res := map[string]any{"step_id": step.ID, "type": step.Type, "executed_at": time.Now().Format(time.RFC3339)}
			if sendErr != nil {
				res["status"] = "error"
				res["error"] = sendErr.Error()
			} else {
				res["status"] = "success"
			}
			results = append(results, res)

		case "delay":
			if !topLevel {
				results = append(results, map[string]any{
					"step_id":     step.ID,
					"type":        "delay",
					"status":      "error",
					"error":       "delay steps are not supported inside condition branches",
					"executed_at": time.Now().Format(time.RFC3339),
				})
				continue
			}
			// Pause execution until delay_seconds elapsed
			delaySec := step.Config.DelaySeconds
			if delaySec <= 0 {
				delaySec = 60
			}
			resumeAt := time.Now().Add(time.Duration(delaySec) * time.Second)
			results = append(results, map[string]any{
				"step_id":     step.ID,
				"type":        "delay",
				"duration":    delaySec,
				"resumes_at":  resumeAt.Format(time.RFC3339),
				"executed_at": time.Now().Format(time.RFC3339),
			})

			resJSON, _ := json.Marshal(results)
			_, _ = s.db.Exec(ctx, `
UPDATE automation_runs
SET status = 'waiting', current_step_index = $2, next_execution_at = $3, step_results = $4, updated_at = now()
WHERE id = $1`,
				runID, i+1, resumeAt, resJSON)
			return results, true

		case "add_to_segment":
			if step.Config.SegmentID != "" && contactID != "" {
				_, _ = s.db.Exec(ctx,
					`INSERT INTO contact_segments (contact_id, segment_id)
							 SELECT $1, $2
							 WHERE EXISTS (SELECT 1 FROM contacts WHERE id = $1 AND account_id = $3)
							 AND EXISTS (SELECT 1 FROM segments WHERE id = $2 AND account_id = $3)
							 ON CONFLICT DO NOTHING`,
					contactID, step.Config.SegmentID, acct)
			}
			results = append(results, map[string]any{
				"step_id":     step.ID,
				"type":        "add_to_segment",
				"status":      "success",
				"executed_at": time.Now().Format(time.RFC3339),
			})

		case "remove_from_segment":
			if step.Config.SegmentID != "" && contactID != "" {
				_, _ = s.db.Exec(ctx,
					`DELETE FROM contact_segments cs
							 WHERE cs.contact_id = $1 AND cs.segment_id = $2
							 AND EXISTS (SELECT 1 FROM contacts WHERE id = cs.contact_id AND account_id = $3)
							 AND EXISTS (SELECT 1 FROM segments WHERE id = cs.segment_id AND account_id = $3)`,
					contactID, step.Config.SegmentID, acct)
			}
			results = append(results, map[string]any{
				"step_id":     step.ID,
				"type":        "remove_from_segment",
				"status":      "success",
				"executed_at": time.Now().Format(time.RFC3339),
			})

		case "condition":
			matched := evaluateCondition(step.Config, eventData)
			results = append(results, map[string]any{
				"step_id":     step.ID,
				"type":        "condition",
				"matched":     matched,
				"executed_at": time.Now().Format(time.RFC3339),
			})
			if matched && len(step.ThenSteps) > 0 {
				results, _ = s.runSteps(ctx, runID, acct, step.ThenSteps, 0, contactID, email, eventData, results, false)
			} else if !matched && len(step.ElseSteps) > 0 {
				results, _ = s.runSteps(ctx, runID, acct, step.ElseSteps, 0, contactID, email, eventData, results, false)
			}
		}
	}
	return results, false
}

func evaluateCondition(cfg stepConfig, eventData map[string]any) bool {
	val, ok := lookupVar(eventData, cfg.Field)
	if !ok {
		return false
	}
	valStr := fmt.Sprintf("%v", val)
	targetStr := fmt.Sprintf("%v", cfg.Value)

	switch cfg.Operator {
	case "eq", "=":
		return strings.EqualFold(valStr, targetStr)
	case "neq", "!=":
		return !strings.EqualFold(valStr, targetStr)
	case "contains":
		return strings.Contains(strings.ToLower(valStr), strings.ToLower(targetStr))
	case "gt", "lt":
		value, valueErr := strconv.ParseFloat(valStr, 64)
		target, targetErr := strconv.ParseFloat(targetStr, 64)
		if valueErr != nil || targetErr != nil {
			return false
		}
		if cfg.Operator == "gt" {
			return value > target
		}
		return value < target
	default:
		return false
	}
}

// ProcessWaitingAutomations resumes automation runs whose time delay has expired.
func (s *Server) ProcessWaitingAutomations(ctx context.Context) {
	rows, err := s.db.Query(ctx, `
WITH due AS (
	SELECT id
	FROM automation_runs
	WHERE status = 'waiting' AND next_execution_at IS NOT NULL AND next_execution_at <= now()
	ORDER BY next_execution_at
	LIMIT 50
	FOR UPDATE SKIP LOCKED
)
UPDATE automation_runs r
SET status = 'running', updated_at = now()
FROM due, automations a
WHERE r.id = due.id AND a.id = r.automation_id
RETURNING r.id, r.account_id, r.current_step_index, r.contact_id, r.contact_email, r.event_data, a.steps`)
	if err != nil {
		return
	}
	defer rows.Close()

	type waitingRun struct {
		id             uuid.UUID
		acct           string
		stepIdx        int
		contactID      *uuid.UUID
		email          string
		eventDataBytes []byte
		stepsBytes     []byte
	}
	var runs []waitingRun
	for rows.Next() {
		var w waitingRun
		if err := rows.Scan(&w.id, &w.acct, &w.stepIdx, &w.contactID, &w.email, &w.eventDataBytes, &w.stepsBytes); err == nil {
			runs = append(runs, w)
		}
	}

	for _, r := range runs {
		var steps []automationStep
		_ = json.Unmarshal(r.stepsBytes, &steps)
		var evData map[string]any
		_ = json.Unmarshal(r.eventDataBytes, &evData)

		cID := ""
		if r.contactID != nil {
			cID = r.contactID.String()
		}

		go s.executeSteps(context.Background(), r.id, r.acct, steps, r.stepIdx, cID, r.email, evData)
	}
}
