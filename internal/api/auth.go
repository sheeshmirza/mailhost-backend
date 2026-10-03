package api

import (
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"mailhost/internal/mailer"
	"mailhost/internal/validator"
)

type userView struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	AvatarURL     string    `json:"avatar_url,omitempty"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

type userAccountView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type userSessionView struct {
	ID         string     `json:"id"`
	AccountID  string     `json:"account_id"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	IsCurrent  bool       `json:"is_current"`
}

// sendAuthEmail delivers account verification and password reset messages via AUTH_EMAIL_SMTP_ADDR.
func (s *Server) sendAuthEmail(toEmail, subject, htmlBody, textBody string) {
	if s.cfg == nil || s.cfg.AuthEmailSMTPAddr == "" || s.cfg.AuthEmailFrom == "" {
		return
	}
	if validator.ContainsCRLF(toEmail) || validator.ContainsCRLF(subject) || !validator.IsValidEmail(toEmail) {
		return
	}
	go func() {
		if err := s.deliverAuthEmail(toEmail, subject, htmlBody, textBody); err != nil {
			s.log.Warn("account email delivery failed", "smtp_addr", s.cfg.AuthEmailSMTPAddr, "err", err)
		}
	}()
}

func (s *Server) deliverAuthEmail(toEmail, subject, htmlBody, textBody string) error {
	host, port, err := net.SplitHostPort(s.cfg.AuthEmailSMTPAddr)
	if err != nil {
		host = strings.TrimSpace(s.cfg.AuthEmailSMTPAddr)
		port = "587"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Minute))

	var client *smtp.Client
	if port == "465" {
		tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return fmt.Errorf("tls handshake %s:465: %w", host, err)
		}
		client, err = smtp.NewClient(tlsConn, host)
		if err != nil {
			_ = tlsConn.Close()
			return err
		}
	} else {
		client, err = smtp.NewClient(conn, host)
		if err != nil {
			_ = conn.Close()
			return err
		}
	}
	defer client.Close()
	if err := client.Hello(s.cfg.Hostname); err != nil {
		return err
	}
	if port != "465" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return err
			}
		}
	}
	if s.cfg.AuthEmailSMTPUsername != "" {
		if err := mailer.AuthenticateClient(client, host, s.cfg.AuthEmailSMTPUsername, s.cfg.AuthEmailSMTPPassword); err != nil {
			return err
		}
	}
	from, err := mail.ParseAddress(s.cfg.AuthEmailFrom)
	if err != nil {
		return err
	}
	if err := client.Mail(from.Address); err != nil {
		return err
	}
	if err := client.Rcpt(toEmail); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	body := htmlBody
	contentType := "text/html"
	if body == "" {
		body = textBody
		contentType = "text/plain"
	}
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: %s; charset=UTF-8\r\n\r\n%s",
		from.String(), toEmail, subject, time.Now().Format(time.RFC1123Z), uuid.NewString(), s.cfg.Hostname, contentType, body)
	if _, err := writer.Write([]byte(message)); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// registerUser allows self-service user signup, creating a user with email verification,
// their primary organization, default full-access API key, and active session token.
func (s *Server) registerUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		Name             string `json:"name"`
		OrganizationName string `json:"organization_name"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !validator.IsValidEmail(email) {
		writeError(w, http.StatusUnprocessableEntity, "valid email address is required")
		return
	}

	if len(req.Password) < 8 || len(req.Password) > 72 {
		writeError(w, http.StatusUnprocessableEntity, "password must be between 8 and 72 characters")
		return
	}

	name := strings.TrimSpace(req.Name)
	if len(name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "name must be at most 100 characters")
		return
	}

	orgName := strings.TrimSpace(req.OrganizationName)
	if orgName == "" {
		if name != "" {
			orgName = name + "'s Team"
		} else {
			orgName = "Default Team"
		}
	}
	if len(orgName) > 200 {
		writeError(w, http.StatusUnprocessableEntity, "organization_name must be at most 200 characters")
		return
	}

	// Check if user already exists
	var exists bool
	err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE lower(email) = $1)`, email).Scan(&exists)
	if err != nil {
		s.internal(w, err)
		return
	}
	if exists {
		writeError(w, http.StatusConflict, "user with this email already exists")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.internal(w, err)
		return
	}

	verToken := newToken("re_ver_", 32)
	verExpiresAt := time.Now().Add(24 * time.Hour)

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	defer tx.Rollback(r.Context())

	var userID string
	var userCreated time.Time
	err = tx.QueryRow(r.Context(), `
INSERT INTO users (email, password_hash, name, email_verified, verification_token, verification_token_expires_at)
VALUES ($1, $2, $3, false, $4, $5)
RETURNING id, created_at`, email, string(hash), name, verToken, verExpiresAt).Scan(&userID, &userCreated)
	if err != nil {
		if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, "user with this email already exists")
			return
		}
		s.internal(w, err)
		return
	}

	var acctID string
	var acctCreated time.Time
	err = tx.QueryRow(r.Context(), `
INSERT INTO accounts (name)
VALUES ($1)
RETURNING id, created_at`, orgName).Scan(&acctID, &acctCreated)
	if err != nil {
		s.internal(w, err)
		return
	}

	_, err = tx.Exec(r.Context(), `
INSERT INTO organization_members (account_id, user_id, email, role)
VALUES ($1, $2, $3, 'administrator')`, acctID, userID, email)
	if err != nil {
		s.internal(w, err)
		return
	}

	apiKey := newToken("re_live_", 28)
	lastFour := apiKey[len(apiKey)-4:]
	_, err = tx.Exec(r.Context(), `
INSERT INTO api_keys (account_id, name, permission, last_four, key_hash)
VALUES ($1, 'Default Key', 'full_access', $2, $3)`, acctID, lastFour, hashKey(apiKey))
	if err != nil {
		s.internal(w, err)
		return
	}

	sessionToken := newToken("re_usr_", 32)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	_, err = tx.Exec(r.Context(), `
INSERT INTO user_sessions (user_id, account_id, token_hash, expires_at)
VALUES ($1, $2, $3, $4)`, userID, acctID, hashKey(sessionToken), expiresAt)
	if err != nil {
		s.internal(w, err)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		s.internal(w, err)
		return
	}

	// Send verification email via SMTP
	verifyURL := fmt.Sprintf("/v1/users/verify-email?token=%s", verToken)
	verifyHTML := fmt.Sprintf(`<h1>Verify your email</h1><p>Welcome, %s! Please verify your email address by visiting: <a href="%s">%s</a></p><p>Verification code: <code>%s</code></p>`, html.EscapeString(name), html.EscapeString(verifyURL), html.EscapeString(verifyURL), html.EscapeString(verToken))
	s.sendAuthEmail(email, "Verify your email address - Mailhost", verifyHTML, "Verification token: "+verToken)

	s.audit(r.Context(), acctID, "register", "user", userID, r)
	writeJSON(w, http.StatusCreated, map[string]any{
		"object": "user_registration",
		"token":  sessionToken,
		"user": userView{
			ID:            userID,
			Email:         email,
			Name:          name,
			EmailVerified: false,
			CreatedAt:     userCreated,
		},
		"account": userAccountView{
			ID:        acctID,
			Name:      orgName,
			Role:      "administrator",
			CreatedAt: acctCreated,
		},
		"api_key": apiKey,
	})
}

// verifyEmail marks a user's email address as verified using a verification token.
func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var token string
	if r.Method == http.MethodGet {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	} else {
		var req struct {
			Token string `json:"token"`
		}
		if !decode(w, r, 0, &req) {
			return
		}
		token = strings.TrimSpace(req.Token)
	}

	if token == "" {
		writeError(w, http.StatusUnprocessableEntity, "verification token is required")
		return
	}

	var userID, email string
	var verified bool
	var expiresAt *time.Time
	err := s.db.QueryRow(r.Context(), `
SELECT id, email, email_verified, verification_token_expires_at
FROM users WHERE verification_token = $1`, token).Scan(&userID, &email, &verified, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusBadRequest, "invalid or expired verification token")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	if verified {
		writeJSON(w, http.StatusOK, map[string]any{
			"object":   "email_verification",
			"verified": true,
			"email":    email,
			"message":  "email already verified",
		})
		return
	}

	if expiresAt == nil || expiresAt.Before(time.Now()) {
		writeError(w, http.StatusBadRequest, "verification token has expired")
		return
	}

	_, err = s.db.Exec(r.Context(), `
UPDATE users SET email_verified = true, verification_token_expires_at = NULL, updated_at = now()
WHERE id = $1`, userID)
	if err != nil {
		s.internal(w, err)
		return
	}
	// Pending invitations are claimed only once the address is proven to belong to this user.
	_, _ = s.db.Exec(r.Context(), `
UPDATE organization_members SET user_id = $1, updated_at = now() WHERE lower(email) = lower($2) AND user_id IS NULL`, userID, email)

	writeJSON(w, http.StatusOK, map[string]any{
		"object":   "email_verification",
		"verified": true,
		"email":    email,
		"message":  "email verified successfully",
	})
}

// resendVerification sends a new verification email to the user.
func (s *Server) resendVerification(w http.ResponseWriter, r *http.Request) {
	var email string
	var req struct {
		Email string `json:"email"`
	}
	if r.Body != nil && r.ContentLength > 0 {
		if !decode(w, r, 0, &req) {
			return
		}
		email = strings.ToLower(strings.TrimSpace(req.Email))
	}

	if email == "" {
		uid := resolveUserID(s, r)
		if uid != "" {
			_ = s.db.QueryRow(r.Context(), `SELECT email FROM users WHERE id = $1`, uid).Scan(&email)
		}
	}

	if email == "" || !validator.IsValidEmail(email) {
		writeError(w, http.StatusUnprocessableEntity, "valid email address is required")
		return
	}

	var userID string
	var verified bool
	err := s.db.QueryRow(r.Context(), `
SELECT id, email_verified FROM users WHERE lower(email) = $1`, email).Scan(&userID, &verified)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "if the email is registered and unverified, a verification link has been sent",
		})
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	if verified {
		writeJSON(w, http.StatusOK, map[string]any{
			"message":  "email is already verified",
			"verified": true,
		})
		return
	}

	verToken := newToken("re_ver_", 32)
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = s.db.Exec(r.Context(), `
UPDATE users SET verification_token = $1, verification_token_expires_at = $2, updated_at = now() WHERE id = $3`,
		verToken, expiresAt, userID)
	if err != nil {
		s.internal(w, err)
		return
	}

	verifyURL := fmt.Sprintf("/v1/users/verify-email?token=%s", verToken)
	verifyHTML := fmt.Sprintf(`<h1>Verify your email</h1><p>Please verify your email address: <a href="%s">%s</a></p><p>Verification code: <code>%s</code></p>`, html.EscapeString(verifyURL), html.EscapeString(verifyURL), html.EscapeString(verToken))
	s.sendAuthEmail(email, "Verify your email address - Mailhost", verifyHTML, "Verification token: "+verToken)

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "if the email is registered and unverified, a verification link has been sent",
	})
}

// forgotPassword initiates a password reset request and sends a reset token via email.
func (s *Server) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !validator.IsValidEmail(email) {
		writeError(w, http.StatusUnprocessableEntity, "valid email address is required")
		return
	}

	var userID string
	err := s.db.QueryRow(r.Context(), `SELECT id FROM users WHERE lower(email) = $1`, email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Do not reveal whether email exists
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "if an account with that email exists, a password reset link has been sent",
		})
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	resetToken := newToken("re_rst_", 32)
	expiresAt := time.Now().Add(1 * time.Hour)
	_, err = s.db.Exec(r.Context(), `
INSERT INTO password_resets (user_id, email, token_hash, expires_at)
VALUES ($1, $2, $3, $4)`, userID, email, hashKey(resetToken), expiresAt)
	if err != nil {
		s.internal(w, err)
		return
	}

	resetURL := fmt.Sprintf("/v1/users/reset-password?token=%s", resetToken)
	resetHTML := fmt.Sprintf(`<h1>Reset your password</h1><p>You requested a password reset. Click the link below to set a new password:</p><p><a href="%s">%s</a></p><p>Reset token: <code>%s</code></p><p>This link expires in 1 hour.</p>`, html.EscapeString(resetURL), html.EscapeString(resetURL), html.EscapeString(resetToken))
	s.sendAuthEmail(email, "Reset your password - Mailhost", resetHTML, "Password reset token: "+resetToken)

	writeJSON(w, http.StatusOK, map[string]any{
		"object":  "forgot_password",
		"message": "if an account with that email exists, a password reset link has been sent",
	})
}

// resetPassword completes the password reset using a valid reset token.
func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if token == "" {
		writeError(w, http.StatusUnprocessableEntity, "reset token is required")
		return
	}

	if len(req.NewPassword) < 8 || len(req.NewPassword) > 72 {
		writeError(w, http.StatusUnprocessableEntity, "new_password must be between 8 and 72 characters")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.internal(w, err)
		return
	}

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	defer tx.Rollback(r.Context())

	var userID string
	err = tx.QueryRow(r.Context(), `
UPDATE password_resets
SET used_at = now()
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
RETURNING user_id`, hashKey(token)).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusBadRequest, "invalid or expired password reset token")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	// Update user password
	_, err = tx.Exec(r.Context(), `
UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`, string(newHash), userID)
	if err != nil {
		s.internal(w, err)
		return
	}

	// Revoke all existing sessions for security
	_, err = tx.Exec(r.Context(), `DELETE FROM user_sessions WHERE user_id = $1`, userID)
	if err != nil {
		s.internal(w, err)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		s.internal(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"object":  "password_reset",
		"success": true,
		"message": "password reset successfully. You can now log in with your new password.",
	})
}

// changeEmail allows an authenticated user to update their email address.
func (s *Server) changeEmail(w http.ResponseWriter, r *http.Request) {
	uid := resolveUserID(s, r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "no associated user profile found for this key")
		return
	}

	var req struct {
		NewEmail string `json:"new_email"`
		Password string `json:"password"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	newEmail := strings.ToLower(strings.TrimSpace(req.NewEmail))
	if !validator.IsValidEmail(newEmail) {
		writeError(w, http.StatusUnprocessableEntity, "valid email address is required")
		return
	}

	if req.Password == "" {
		writeError(w, http.StatusUnprocessableEntity, "current password is required")
		return
	}

	var currentHash, oldEmail string
	err := s.db.QueryRow(r.Context(), `SELECT password_hash, email FROM users WHERE id = $1`, uid).Scan(&currentHash, &oldEmail)
	if err != nil {
		s.internal(w, err)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "incorrect password")
		return
	}

	if newEmail == oldEmail {
		writeError(w, http.StatusUnprocessableEntity, "new email must be different from current email")
		return
	}

	var emailTaken bool
	_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE lower(email) = $1 AND id != $2)`, newEmail, uid).Scan(&emailTaken)
	if emailTaken {
		writeError(w, http.StatusConflict, "this email is already in use by another account")
		return
	}

	verToken := newToken("re_ver_", 32)
	verExpiresAt := time.Now().Add(24 * time.Hour)

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	defer tx.Rollback(r.Context())

	_, err = tx.Exec(r.Context(), `
UPDATE users SET email = $1, email_verified = false, verification_token = $2, verification_token_expires_at = $3, updated_at = now()
WHERE id = $4`, newEmail, verToken, verExpiresAt, uid)
	if err != nil {
		s.internal(w, err)
		return
	}

	_, err = tx.Exec(r.Context(), `
UPDATE organization_members SET email = $1, updated_at = now() WHERE user_id = $2`, newEmail, uid)
	if err != nil {
		s.internal(w, err)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		s.internal(w, err)
		return
	}

	verifyURL := fmt.Sprintf("/v1/users/verify-email?token=%s", verToken)
	verifyHTML := fmt.Sprintf(`<h1>Verify your new email</h1><p>Please confirm your new email address: <a href="%s">%s</a></p><p>Verification code: <code>%s</code></p>`, html.EscapeString(verifyURL), html.EscapeString(verifyURL), html.EscapeString(verToken))
	s.sendAuthEmail(newEmail, "Verify your new email address - Mailhost", verifyHTML, "Verification token: "+verToken)

	writeJSON(w, http.StatusOK, map[string]any{
		"object":         "email_change",
		"email":          newEmail,
		"email_verified": false,
		"message":        "email changed successfully. Please verify your new email address.",
	})
}

// loginUser authenticates user credentials and issues a user session token.
func (s *Server) loginUser(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if blocked, _ := s.checkAuthRate(ip); blocked {
		w.Header().Set("Retry-After", "300")
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !validator.IsValidEmail(email) || req.Password == "" {
		writeError(w, http.StatusUnprocessableEntity, "valid email and password are required")
		return
	}

	var userID, pwdHash, name, avatarURL string
	var verified bool
	var userCreated time.Time
	err := s.db.QueryRow(r.Context(), `
SELECT id, password_hash, name, avatar_url, email_verified, created_at
FROM users WHERE lower(email) = $1`, email).Scan(&userID, &pwdHash, &name, &avatarURL, &verified, &userCreated)
	if errors.Is(err, pgx.ErrNoRows) {
		s.recordAuthFailure(ip)
		time.Sleep(200 * time.Millisecond)
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(pwdHash), []byte(req.Password)); err != nil {
		s.recordAuthFailure(ip)
		time.Sleep(200 * time.Millisecond)
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	s.recordAuthSuccess(ip)

	if verified {
		_, _ = s.db.Exec(r.Context(), `
UPDATE organization_members SET user_id = $1, updated_at = now() WHERE lower(email) = $2 AND user_id IS NULL`, userID, email)
	}

	// Fetch user's organizations
	rows, err := s.db.Query(r.Context(), `
SELECT a.id, a.name, m.role, a.created_at
FROM organization_members m
JOIN accounts a ON a.id = m.account_id
WHERE m.user_id = $1
ORDER BY (m.role = 'administrator') DESC, m.created_at ASC`, userID)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()

	var accounts []userAccountView
	for rows.Next() {
		var a userAccountView
		if err := rows.Scan(&a.ID, &a.Name, &a.Role, &a.CreatedAt); err == nil {
			accounts = append(accounts, a)
		}
	}

	var primaryAcct userAccountView
	if len(accounts) > 0 {
		primaryAcct = accounts[0]
	} else {
		// Provision default account if none exists
		var newAcctID string
		var newAcctCreated time.Time
		tx, err := s.db.Begin(r.Context())
		if err != nil {
			s.internal(w, err)
			return
		}
		defer tx.Rollback(r.Context())
		if err := tx.QueryRow(r.Context(), `
INSERT INTO accounts (name) VALUES ('Default Team') RETURNING id, created_at`).Scan(&newAcctID, &newAcctCreated); err != nil {
			s.internal(w, err)
			return
		}
		if _, err := tx.Exec(r.Context(), `
INSERT INTO organization_members (account_id, user_id, email, role) VALUES ($1, $2, $3, 'administrator')`, newAcctID, userID, email); err != nil {
			s.internal(w, err)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			s.internal(w, err)
			return
		}
		primaryAcct = userAccountView{ID: newAcctID, Name: "Default Team", Role: "administrator", CreatedAt: newAcctCreated}
		accounts = append(accounts, primaryAcct)
	}

	// Create session token
	sessionToken := newToken("re_usr_", 32)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	_, err = s.db.Exec(r.Context(), `
INSERT INTO user_sessions (user_id, account_id, token_hash, expires_at)
VALUES ($1, $2, $3, $4)`, userID, primaryAcct.ID, hashKey(sessionToken), expiresAt)
	if err != nil {
		s.internal(w, err)
		return
	}

	s.audit(r.Context(), primaryAcct.ID, "login", "user", userID, r)
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "user_session",
		"token":  sessionToken,
		"user": userView{
			ID:            userID,
			Email:         email,
			Name:          name,
			AvatarURL:     avatarURL,
			EmailVerified: verified,
			CreatedAt:     userCreated,
		},
		"current_account": primaryAcct,
		"accounts":        accounts,
	})
}

// getCurrentUser returns the profile and organizations of the authenticated user.
func (s *Server) getCurrentUser(w http.ResponseWriter, r *http.Request) {
	uid := userID(r)
	acct := accountID(r)

	var u userView
	if uid != "" {
		err := s.db.QueryRow(r.Context(), `
SELECT id, email, name, avatar_url, email_verified, created_at
FROM users WHERE id = $1`, uid).Scan(&u.ID, &u.Email, &u.Name, &u.AvatarURL, &u.EmailVerified, &u.CreatedAt)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.internal(w, err)
			return
		}
	}

	if u.ID == "" {
		// API key without an attached user: return account representation
		var acctName string
		var acctCreated time.Time
		_ = s.db.QueryRow(r.Context(), `SELECT name, created_at FROM accounts WHERE id = $1`, acct).Scan(&acctName, &acctCreated)
		writeJSON(w, http.StatusOK, map[string]any{
			"object": "account_info",
			"account": map[string]any{
				"id":         acct,
				"name":       acctName,
				"created_at": acctCreated,
			},
		})
		return
	}

	// Fetch all accounts for user
	rows, err := s.db.Query(r.Context(), `
SELECT a.id, a.name, m.role, a.created_at
FROM organization_members m
JOIN accounts a ON a.id = m.account_id
WHERE m.user_id = $1
ORDER BY (m.role = 'administrator') DESC, m.created_at ASC`, u.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()

	var accounts []userAccountView
	var currentAcct *userAccountView
	for rows.Next() {
		var a userAccountView
		if err := rows.Scan(&a.ID, &a.Name, &a.Role, &a.CreatedAt); err == nil {
			accounts = append(accounts, a)
			if a.ID == acct {
				currentAcct = &a
			}
		}
	}

	if currentAcct == nil && len(accounts) > 0 {
		currentAcct = &accounts[0]
	}

	resp := map[string]any{
		"object":         "user",
		"id":             u.ID,
		"email":          u.Email,
		"name":           u.Name,
		"email_verified": u.EmailVerified,
		"accounts":       accounts,
	}
	if u.AvatarURL != "" {
		resp["avatar_url"] = u.AvatarURL
	}
	if currentAcct != nil {
		resp["current_account"] = currentAcct
	}

	writeJSON(w, http.StatusOK, resp)
}

// updateCurrentUser updates the user's name or avatar URL.
func (s *Server) updateCurrentUser(w http.ResponseWriter, r *http.Request) {
	uid := resolveUserID(s, r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "no associated user profile found for this key")
		return
	}

	var req struct {
		Name      *string `json:"name"`
		AvatarURL *string `json:"avatar_url"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if len(trimmed) > 100 {
			writeError(w, http.StatusUnprocessableEntity, "name must be at most 100 characters")
			return
		}
		_, err := s.db.Exec(r.Context(), `UPDATE users SET name = $1, updated_at = now() WHERE id = $2`, trimmed, uid)
		if err != nil {
			s.internal(w, err)
			return
		}
	}

	if req.AvatarURL != nil {
		trimmed := strings.TrimSpace(*req.AvatarURL)
		if len(trimmed) > 2048 {
			writeError(w, http.StatusUnprocessableEntity, "avatar_url must be at most 2048 characters")
			return
		}
		if trimmed != "" {
			u, err := url.Parse(trimmed)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
				writeError(w, http.StatusUnprocessableEntity, "avatar_url must be a valid http or https URL")
				return
			}
		}
		_, err := s.db.Exec(r.Context(), `UPDATE users SET avatar_url = $1, updated_at = now() WHERE id = $2`, trimmed, uid)
		if err != nil {
			s.internal(w, err)
			return
		}
	}

	s.getCurrentUser(w, r)
}

// changePassword updates the user's password and revokes all other active sessions.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	uid := resolveUserID(s, r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "no associated user profile found for this key")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	if len(req.NewPassword) < 8 || len(req.NewPassword) > 72 {
		writeError(w, http.StatusUnprocessableEntity, "new_password must be between 8 and 72 characters")
		return
	}

	var currentHash string
	err := s.db.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id = $1`, uid).Scan(&currentHash)
	if err != nil {
		s.internal(w, err)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)); err != nil {
		writeError(w, http.StatusUnauthorized, "incorrect current password")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.internal(w, err)
		return
	}

	_, err = s.db.Exec(r.Context(), `UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`, string(newHash), uid)
	if err != nil {
		s.internal(w, err)
		return
	}

	// Revoke other sessions
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok != "" {
		_, _ = s.db.Exec(r.Context(), `DELETE FROM user_sessions WHERE user_id = $1 AND token_hash != $2`, uid, hashKey(tok))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "password updated successfully",
	})
}

// logoutUser revokes the current user session token.
func (s *Server) logoutUser(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if ok && tok != "" {
		_, _ = s.db.Exec(r.Context(), `DELETE FROM user_sessions WHERE token_hash = $1`, hashKey(tok))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "successfully logged out",
	})
}

// listUserAccounts returns all organizations the user belongs to.
func (s *Server) listUserAccounts(w http.ResponseWriter, r *http.Request) {
	uid := resolveUserID(s, r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "no associated user profile found for this key")
		return
	}

	rows, err := s.db.Query(r.Context(), `
SELECT a.id, a.name, m.role, a.created_at
FROM organization_members m
JOIN accounts a ON a.id = m.account_id
WHERE m.user_id = $1
ORDER BY m.created_at ASC`, uid)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()

	var accounts []userAccountView
	for rows.Next() {
		var a userAccountView
		if err := rows.Scan(&a.ID, &a.Name, &a.Role, &a.CreatedAt); err == nil {
			accounts = append(accounts, a)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   accounts,
	})
}

// createUserAccount allows an authenticated user to create an additional organization/team.
func (s *Server) createUserAccount(w http.ResponseWriter, r *http.Request) {
	uid := resolveUserID(s, r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "no associated user profile found for this key")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 200 {
		writeError(w, http.StatusUnprocessableEntity, "name must be between 1 and 200 characters")
		return
	}

	var email string
	_ = s.db.QueryRow(r.Context(), `SELECT email FROM users WHERE id = $1`, uid).Scan(&email)

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	defer tx.Rollback(r.Context())

	var acctID string
	var acctCreated time.Time
	err = tx.QueryRow(r.Context(), `
INSERT INTO accounts (name) VALUES ($1) RETURNING id, created_at`, name).Scan(&acctID, &acctCreated)
	if err != nil {
		s.internal(w, err)
		return
	}

	_, err = tx.Exec(r.Context(), `
INSERT INTO organization_members (account_id, user_id, email, role)
VALUES ($1, $2, $3, 'administrator')`, acctID, uid, email)
	if err != nil {
		s.internal(w, err)
		return
	}

	apiKey := newToken("re_live_", 28)
	lastFour := apiKey[len(apiKey)-4:]
	_, err = tx.Exec(r.Context(), `
INSERT INTO api_keys (account_id, name, permission, last_four, key_hash)
VALUES ($1, 'Default Key', 'full_access', $2, $3)`, acctID, lastFour, hashKey(apiKey))
	if err != nil {
		s.internal(w, err)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		s.internal(w, err)
		return
	}

	s.audit(r.Context(), acctID, "create_account", "account", acctID, r)
	writeJSON(w, http.StatusCreated, map[string]any{
		"object": "account",
		"account": userAccountView{
			ID:        acctID,
			Name:      name,
			Role:      "administrator",
			CreatedAt: acctCreated,
		},
		"api_key": apiKey,
	})
}

// switchUserAccount switches the active organization context for the current session token.
func (s *Server) switchUserAccount(w http.ResponseWriter, r *http.Request) {
	uid := resolveUserID(s, r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "no associated user profile found for this key")
		return
	}

	var req struct {
		AccountID string `json:"account_id"`
	}
	if !decode(w, r, 0, &req) {
		return
	}

	targetAcctID, err := uuid.Parse(req.AccountID)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "account_id must be a valid UUID")
		return
	}

	var role string
	var acctName string
	var acctCreated time.Time
	err = s.db.QueryRow(r.Context(), `
SELECT m.role, a.name, a.created_at
FROM organization_members m
JOIN accounts a ON a.id = m.account_id
WHERE m.user_id = $1 AND m.account_id = $2`, uid, targetAcctID).Scan(&role, &acctName, &acctCreated)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusForbidden, "user is not a member of the requested account")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok != "" {
		_, _ = s.db.Exec(r.Context(), `
UPDATE user_sessions SET account_id = $1 WHERE token_hash = $2`, targetAcctID, hashKey(tok))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"object": "switch_account",
		"current_account": map[string]any{
			"id":         targetAcctID.String(),
			"name":       acctName,
			"role":       role,
			"created_at": acctCreated,
		},
	})
}

// listUserSessions lists all active sessions for the current user.
func (s *Server) listUserSessions(w http.ResponseWriter, r *http.Request) {
	uid := resolveUserID(s, r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "no associated user profile found for this key")
		return
	}

	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	rows, err := s.db.Query(r.Context(), `
SELECT id, account_id, created_at, last_used_at, expires_at, token_hash = $2
FROM user_sessions
WHERE user_id = $1 AND expires_at > now()
ORDER BY created_at DESC`, uid, hashKey(tok))
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()

	var sessions []userSessionView
	for rows.Next() {
		var sess userSessionView
		if err := rows.Scan(&sess.ID, &sess.AccountID, &sess.CreatedAt, &sess.LastUsedAt, &sess.ExpiresAt, &sess.IsCurrent); err == nil {
			sessions = append(sessions, sess)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   sessions,
	})
}

func (s *Server) revokeOtherUserSessions(w http.ResponseWriter, r *http.Request) {
	uid := resolveUserID(s, r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "no associated user profile found for this key")
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		writeError(w, http.StatusUnauthorized, "missing API key")
		return
	}
	tag, err := s.db.Exec(r.Context(), `
DELETE FROM user_sessions WHERE user_id = $1 AND token_hash != $2`, uid, hashKey(tok))
	if err != nil {
		s.internal(w, err)
		return
	}
	revoked := tag.RowsAffected()
	writeJSON(w, http.StatusOK, map[string]any{
		"object":  "user_session_list",
		"revoked": revoked,
		"message": fmt.Sprintf("revoked %d other sessions", revoked),
	})
}

// revokeUserSession deletes a specific session.
func (s *Server) revokeUserSession(w http.ResponseWriter, r *http.Request) {
	uid := resolveUserID(s, r)
	if uid == "" {
		writeError(w, http.StatusUnauthorized, "no associated user profile found for this key")
		return
	}

	id, ok := pathID(w, r)
	if !ok {
		return
	}

	tag, err := s.db.Exec(r.Context(), `
DELETE FROM user_sessions WHERE id = $1 AND user_id = $2`, id, uid)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id,
		"object":  "user_session",
		"deleted": true,
	})
}

func resolveUserID(s *Server, r *http.Request) string {
	return userID(r)
}
