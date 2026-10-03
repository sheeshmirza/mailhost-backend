// Package api exposes the authenticated HTTP API and public tracking endpoints.
package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"mailhost/internal/cache"
	"mailhost/internal/config"
	"mailhost/internal/docstore"
	"mailhost/internal/metrics"
	"mailhost/internal/rediscache"
	"mailhost/internal/secretbox"
	"mailhost/internal/webhook"
)

// Server owns API dependencies, request middleware, and endpoint handlers.
type Server struct {
	db            *pgxpool.Pool
	rdb           *pgxpool.Pool // read replica (or primary) for list/analytics reads
	box           *secretbox.Box
	cfg           *config.Config
	log           *slog.Logger
	resolver      *net.Resolver
	keys          *cache.Cache[*keyAuth]      // api key hash -> *keyAuth
	limiters      *cache.Cache[*rate.Limiter] // account id -> token bucket
	signers       *cache.Cache[crypto.Signer] // domain id -> DKIM signer
	domains       *cache.Cache[*signingKey]   // account_id:domain_name -> verified signingKey
	redis         *rediscache.Client
	docstore      *docstore.Client
	webhookClient *webhook.Client
	authMu        sync.Mutex
	authFailures  map[string]*authFailureRecord
}

func makeResolver(dnsServer string) *net.Resolver {
	if dnsServer == "" {
		return net.DefaultResolver
	}
	if !strings.Contains(dnsServer, ":") {
		dnsServer = net.JoinHostPort(dnsServer, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
}

// New constructs an API server with default caches and middleware dependencies.
func New(db, rdb *pgxpool.Pool, box *secretbox.Box, cfg *config.Config, log *slog.Logger) *Server {
	if rdb == nil {
		rdb = db
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &Server{
		db: db, rdb: rdb, box: box, cfg: cfg, log: log,
		resolver:      makeResolver(cfg.DNSServer),
		keys:          cache.New[*keyAuth](time.Minute, 1_000_000),
		limiters:      cache.New[*rate.Limiter](10*time.Minute, 1_000_000),
		signers:       cache.New[crypto.Signer](5*time.Minute, 500_000),
		domains:       cache.New[*signingKey](5*time.Minute, 500_000),
		webhookClient: webhook.NewWithSecurity(cfg.AllowPrivateDelivery),
		authFailures:  make(map[string]*authFailureRecord),
	}
}

// SetRedis configures the optional Redis cache and rate-limit backend.
func (s *Server) SetRedis(r *rediscache.Client) {
	s.redis = r
}

// SetDocstore configures the optional document store used for large payloads.
func (s *Server) SetDocstore(d *docstore.Client) {
	s.docstore = d
}

// Handler returns the complete HTTP handler, including authentication,
// security headers, metrics, access logging, CORS, and panic recovery.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.readiness)
	mux.Handle("GET /metrics", s.authed(metrics.Handler().ServeHTTP))
	mux.HandleFunc("GET /.well-known/ai-plugin.json", s.pluginManifest)
	mux.HandleFunc("GET /openapi.json", s.openapiSpec)
	mux.HandleFunc("GET /openapi.yaml", s.openapiSpecYAML)
	mux.HandleFunc("GET /logo.png", s.pluginLogo)
	mux.HandleFunc("GET /legal", s.pluginLegal)

	// Public Tracking, Unsubscribe, and Auth Endpoints
	publicEndpoints := map[string]http.HandlerFunc{
		"GET /v1/track/open/{delivery_id}":   s.trackOpen,
		"GET /v1/track/click/{delivery_id}":  s.trackClick,
		"GET /v1/unsubscribe/{id}":           s.unsubscribeContact,
		"POST /v1/unsubscribe/{id}":          s.unsubscribeContact,
		"POST /v1/users/register":            s.registerUser,
		"POST /v1/users/login":               s.loginUser,
		"GET /v1/users/verify-email":         s.verifyEmail,
		"POST /v1/users/verify-email":        s.verifyEmail,
		"POST /v1/users/resend-verification": s.resendVerification,
		"POST /v1/users/forgot-password":     s.forgotPassword,
		"POST /v1/users/reset-password":      s.resetPassword,
	}
	for pattern, h := range publicEndpoints {
		mux.HandleFunc(pattern, h)
		if strings.Contains(pattern, " /v1/") {
			aliasPattern := strings.Replace(pattern, " /v1/", " /", 1)
			mux.HandleFunc(aliasPattern, h)
		}
	}

	routes := map[string]http.HandlerFunc{
		// User Account & Profile Management
		"GET /v1/users/me":                      s.getCurrentUser,
		"PATCH /v1/users/me":                    s.updateCurrentUser,
		"POST /v1/users/change-email":           s.changeEmail,
		"POST /v1/users/change-password":        s.changePassword,
		"POST /v1/users/logout":                 s.logoutUser,
		"GET /v1/users/accounts":                s.listUserAccounts,
		"POST /v1/users/accounts":               s.createUserAccount,
		"POST /v1/users/switch-account":         s.switchUserAccount,
		"GET /v1/users/sessions":                s.listUserSessions,
		"POST /v1/users/sessions/revoke-others": s.revokeOtherUserSessions,
		"DELETE /v1/users/sessions/{id}":        s.revokeUserSession,

		"POST /v1/api-keys":        s.createAPIKey,
		"GET /v1/api-keys":         s.listAPIKeys,
		"DELETE /v1/api-keys/{id}": s.deleteAPIKey,

		"GET /v1/audit-logs": s.listAuditLogs,

		"POST /v1/smtp-credentials":        s.createSMTPCredential,
		"GET /v1/smtp-credentials":         s.listSMTPCredentials,
		"DELETE /v1/smtp-credentials/{id}": s.deleteSMTPCredential,

		"POST /v1/domains":             s.createDomain,
		"GET /v1/domains":              s.listDomains,
		"GET /v1/domains/{id}":         s.getDomain,
		"PATCH /v1/domains/{id}":       s.updateDomain,
		"POST /v1/domains/{id}/verify": s.verifyDomain,
		"DELETE /v1/domains/{id}":      s.deleteDomain,

		"POST /v1/aliases":        s.createAlias,
		"GET /v1/aliases":         s.listAliases,
		"GET /v1/aliases/{id}":    s.getAlias,
		"PATCH /v1/aliases/{id}":  s.updateAlias,
		"DELETE /v1/aliases/{id}": s.deleteAlias,

		// Emails
		"POST /v1/emails":             s.sendEmail,
		"POST /v1/emails/batch":       s.sendBatch,
		"POST /v1/emails/bulk":        s.sendBulk,
		"GET /v1/emails":              s.listEmails,
		"GET /v1/emails/{id}":         s.getEmail,
		"POST /v1/emails/{id}/cancel": s.cancelEmail,
		"PATCH /v1/emails/{id}":       s.cancelEmail,
		"GET /v1/batches/{id}":        s.getBatch,

		// Inbound & Receiving
		"GET /v1/inbound":                           s.listInbound,
		"GET /v1/inbound/{id}":                      s.getInbound,
		"GET /v1/inbound/{id}/raw":                  s.getInboundRaw,
		"GET /v1/emails/receiving":                  s.listReceivedEmails,
		"GET /v1/emails/receiving/{id}":             s.getReceivedEmail,
		"GET /v1/emails/receiving/{id}/attachments": s.listReceivedAttachments,

		// Audiences
		"POST /v1/audiences":                               s.createAudience,
		"GET /v1/audiences":                                s.listAudiences,
		"GET /v1/audiences/{id}":                           s.getAudience,
		"DELETE /v1/audiences/{id}":                        s.deleteAudience,
		"POST /v1/audiences/{audience_id}/contacts":        s.createContact,
		"GET /v1/audiences/{audience_id}/contacts":         s.listContacts,
		"GET /v1/audiences/{audience_id}/contacts/{id}":    s.getContact,
		"PATCH /v1/audiences/{audience_id}/contacts/{id}":  s.updateContact,
		"DELETE /v1/audiences/{audience_id}/contacts/{id}": s.deleteContact,

		// Contacts (global)
		"POST /v1/contacts":                              s.createContact,
		"GET /v1/contacts":                               s.listContacts,
		"GET /v1/contacts/{id}":                          s.getContact,
		"PATCH /v1/contacts/{id}":                        s.updateContact,
		"DELETE /v1/contacts/{id}":                       s.deleteContact,
		"POST /v1/contacts/{id}/segments/{segment_id}":   s.addContactToSegment,
		"DELETE /v1/contacts/{id}/segments/{segment_id}": s.removeContactFromSegment,
		"GET /v1/contacts/{id}/segments":                 s.listContactSegments,
		"POST /v1/contacts/{id}/topics/{topic_id}":       s.updateContactTopic,
		"DELETE /v1/contacts/{id}/topics/{topic_id}":     s.removeContactTopic,
		"GET /v1/contacts/{id}/topics":                   s.listContactTopics,

		// Segments
		"POST /v1/segments":              s.createSegment,
		"GET /v1/segments":               s.listSegments,
		"GET /v1/segments/{id}":          s.getSegment,
		"PATCH /v1/segments/{id}":        s.updateSegment,
		"DELETE /v1/segments/{id}":       s.deleteSegment,
		"GET /v1/segments/{id}/contacts": s.listSegmentContacts,

		// Topics
		"POST /v1/topics":        s.createTopic,
		"GET /v1/topics":         s.listTopics,
		"GET /v1/topics/{id}":    s.getTopic,
		"PATCH /v1/topics/{id}":  s.updateTopic,
		"DELETE /v1/topics/{id}": s.deleteTopic,

		// Broadcasts
		"POST /v1/broadcasts":                s.createBroadcast,
		"GET /v1/broadcasts":                 s.listBroadcasts,
		"GET /v1/broadcasts/{id}":            s.getBroadcast,
		"PATCH /v1/broadcasts/{id}":          s.updateBroadcast,
		"DELETE /v1/broadcasts/{id}":         s.deleteBroadcast,
		"POST /v1/broadcasts/{id}/send":      s.sendBroadcast,
		"POST /v1/broadcasts/{id}/duplicate": s.duplicateBroadcast,

		// Templates
		"POST /v1/templates":                         s.createTemplate,
		"GET /v1/templates":                          s.listTemplates,
		"GET /v1/templates/{id}":                     s.getTemplate,
		"PATCH /v1/templates/{id}":                   s.updateTemplate,
		"DELETE /v1/templates/{id}":                  s.deleteTemplate,
		"POST /v1/templates/{id}/publish":            s.publishTemplate,
		"GET /v1/templates/{id}/versions":            s.listTemplateVersions,
		"POST /v1/templates/{id}/rollback/{version}": s.rollbackTemplate,

		// Dedicated IPs & Auto-Warming
		"GET /v1/ips":                  s.listDedicatedIPs,
		"GET /v1/ips/warming-schedule": s.getWarmingSchedule,
		"PATCH /v1/ips/{id}":           s.updateIPWarmup,

		// Organization Members & Multi-Tenant RBAC
		"GET /v1/members":         s.listMembers,
		"POST /v1/members":        s.addMember,
		"DELETE /v1/members/{id}": s.removeMember,

		// React Email & HTML Boilerplate Rendering
		"POST /v1/render": s.renderEmail,

		// Remote MCP Server
		"POST /mcp": s.handleMCP,
		"GET /mcp":  s.handleMCP,

		// Automations
		"POST /v1/automations":                   s.createAutomation,
		"GET /v1/automations":                    s.listAutomations,
		"GET /v1/automations/{id}":               s.getAutomation,
		"PATCH /v1/automations/{id}":             s.updateAutomation,
		"DELETE /v1/automations/{id}":            s.deleteAutomation,
		"GET /v1/automations/{id}/runs":          s.listAutomationRuns,
		"GET /v1/automations/{id}/runs/{run_id}": s.getAutomationRun,

		// Events
		"POST /v1/events":     s.triggerEvent,
		"GET /v1/events":      s.listEvents,
		"GET /v1/events/{id}": s.getEvent,

		// Webhooks
		"POST /v1/webhooks":        s.createWebhook,
		"GET /v1/webhooks":         s.listWebhooks,
		"GET /v1/webhooks/{id}":    s.getWebhook,
		"PATCH /v1/webhooks/{id}":  s.updateWebhook,
		"DELETE /v1/webhooks/{id}": s.deleteWebhook,

		"GET /v1/suppressions":              s.listSuppressions,
		"DELETE /v1/suppressions/{address}": s.deleteSuppression,

		"GET /v1/analytics": s.analytics,
	}
	for pattern, h := range routes {
		mux.Handle(pattern, s.authed(h))
		if strings.Contains(pattern, " /v1/") {
			aliasPattern := strings.Replace(pattern, " /v1/", " /", 1)
			mux.Handle(aliasPattern, s.authed(h))
		}
	}
	return s.realIP(s.recoverer(s.cors(s.securityHeaders(s.metricsTracker(s.accessLog(mux))))))
}

// realIP replaces RemoteAddr with the client address from X-Forwarded-For, but only for
// requests arriving from a configured trusted proxy; otherwise the header could be spoofed.
func (s *Server) realIP(next http.Handler) http.Handler {
	if len(s.cfg.TrustedProxies) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			if peer := net.ParseIP(host); peer != nil && s.isTrustedProxy(peer) {
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					parts := strings.Split(xff, ",")
					if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
						r.RemoteAddr = net.JoinHostPort(ip.String(), "0")
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) isTrustedProxy(ip net.IP) bool {
	for _, n := range s.cfg.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// StartBackgroundSchedulers launches background loops for processing scheduled broadcasts and waiting automation runs.
func (s *Server) StartBackgroundSchedulers(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.ProcessScheduledBroadcasts(ctx)
				s.ProcessWaitingAutomations(ctx)
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.ProcessWebhookDeliveries(ctx)
			}
		}
	}()
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.Ping(ctx); err != nil {
		s.log.Error("liveness check failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := map[string]string{}
	if s.db == nil {
		s.log.Error("readiness check failed for database", "reason", "pool unavailable")
		checks["database"] = "unavailable"
	} else if err := s.db.Ping(ctx); err != nil {
		s.log.Error("readiness check failed for database", "error", err)
		checks["database"] = "unavailable"
	} else {
		checks["database"] = "ok"
	}

	if s.rdb != s.db {
		if err := s.rdb.Ping(ctx); err != nil {
			s.log.Error("readiness check failed for read_replica", "error", err)
			checks["read_replica"] = "unavailable"
		} else {
			checks["read_replica"] = "ok"
		}
	}

	sealed, sealErr := s.box.Seal([]byte("ping"))
	if sealErr != nil {
		checks["secretbox"] = "unavailable"
	} else if unsealed, err := s.box.Open(sealed); err != nil || string(unsealed) != "ping" {
		checks["secretbox"] = "unavailable"
	} else {
		checks["secretbox"] = "ok"
	}

	if s.redis != nil {
		if err := s.redis.Ping(ctx); err != nil {
			s.log.Error("readiness check failed for redis", "error", err)
			checks["redis"] = "unavailable"
		} else {
			checks["redis"] = "ok"
		}
	}

	if s.docstore != nil {
		if err := s.docstore.Ping(ctx); err != nil {
			s.log.Error("readiness check failed for mongodb", "error", err)
			checks["mongodb"] = "unavailable"
		} else {
			checks["mongodb"] = "ok"
		}
	}

	for _, v := range checks {
		if v != "ok" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

type ctxKey struct{}
type permKey struct{}
type roleKey struct{}
type domainKey struct{}
type reqIDKey struct{}

func keyDomainID(ctx context.Context) string {
	if v, ok := ctx.Value(domainKey{}).(string); ok {
		return v
	}
	return ""
}

type keyAuth struct {
	AccountID  string  `json:"account_id"`
	Permission string  `json:"permission"`
	DomainID   *string `json:"domain_id,omitempty"`
	UserID     string  `json:"user_id,omitempty"`
	Role       string  `json:"role,omitempty"`
}

func accountID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKey{}).(string); ok {
		return v
	}
	return ""
}
func accountUUID(r *http.Request) uuid.UUID {
	id, _ := uuid.Parse(accountID(r))
	return id
}
func reqID(r *http.Request) string {
	if v, ok := r.Context().Value(reqIDKey{}).(string); ok {
		return v
	}
	return ""
}

type userIDKey struct{}

func userID(r *http.Request) string {
	if v, ok := r.Context().Value(userIDKey{}).(string); ok {
		return v
	}
	return ""
}

func keyPermission(r *http.Request) string {
	if v, ok := r.Context().Value(permKey{}).(string); ok && v != "" {
		return v
	}
	return "full_access"
}

func userRole(r *http.Request) string {
	if v, ok := r.Context().Value(roleKey{}).(string); ok && v != "" {
		return v
	}
	if userID(r) == "" && keyPermission(r) == "full_access" {
		return "administrator"
	}
	return "user"
}

func isAdministrator(r *http.Request) bool {
	role := strings.ToLower(userRole(r))
	return role == "administrator" || role == "owner" || role == "admin"
}

func isDeveloperOrAdmin(r *http.Request) bool {
	role := strings.ToLower(userRole(r))
	return role == "administrator" || role == "owner" || role == "admin" || role == "developer"
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !isAdministrator(r) {
		writeError(w, http.StatusForbidden, "forbidden: only administrators can perform this action")
		return false
	}
	return true
}

func requireDeveloperOrAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !isDeveloperOrAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden: insufficient permissions for this action")
		return false
	}
	return true
}

// requireSender permits developers, administrators and sending_access API keys.
func requireSender(w http.ResponseWriter, r *http.Request) bool {
	if isDeveloperOrAdmin(r) || keyPermission(r) == "sending_access" {
		return true
	}
	writeError(w, http.StatusForbidden, "forbidden: insufficient permissions for this action")
	return false
}

func hashKey(k string) []byte {
	sum := sha256.Sum256([]byte(k))
	return sum[:]
}

type authFailureRecord struct {
	count     int
	lastSeen  time.Time
	blockedTo time.Time
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) checkAuthRate(ip string) (blocked bool, delay time.Duration) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.authFailures == nil {
		return false, 0
	}
	rec, exists := s.authFailures[ip]
	if !exists {
		return false, 0
	}
	now := time.Now()
	if rec.blockedTo.After(now) {
		return true, 0
	}
	if rec.count >= 4 {
		return false, 1 * time.Second
	}
	return false, 0
}

func (s *Server) recordAuthFailure(ip string) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.authFailures == nil {
		s.authFailures = make(map[string]*authFailureRecord)
	}
	now := time.Now()
	rec, exists := s.authFailures[ip]
	if !exists || now.Sub(rec.lastSeen) > 5*time.Minute {
		s.authFailures[ip] = &authFailureRecord{count: 1, lastSeen: now}
		return
	}
	rec.count++
	rec.lastSeen = now
	if rec.count >= 10 {
		rec.blockedTo = now.Add(5 * time.Minute)
	}
	if len(s.authFailures) > 100_000 {
		for k, v := range s.authFailures {
			if now.Sub(v.lastSeen) > 10*time.Minute {
				delete(s.authFailures, k)
			}
		}
	}
}

func (s *Server) recordAuthSuccess(ip string) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.authFailures == nil {
		return
	}
	delete(s.authFailures, ip)
}

func (s *Server) authed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if blocked, _ := s.checkAuthRate(ip); blocked {
			w.Header().Set("Retry-After", "300")
			writeError(w, http.StatusTooManyRequests, "too many failed authentication attempts; try again later")
			return
		}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok == "" {
			s.recordAuthFailure(ip)
			writeError(w, http.StatusUnauthorized, "missing API key")
			return
		}
		hKey := string(hashKey(tok))
		hexHash := hex.EncodeToString(hashKey(tok))
		var auth *keyAuth
		var uid string

		if strings.HasPrefix(tok, "re_usr_") {
			var ka keyAuth
			var role string
			err := s.db.QueryRow(r.Context(), `
SELECT s.account_id::text, s.user_id::text, coalesce(m.role, 'user')
FROM user_sessions s
JOIN organization_members m ON m.account_id = s.account_id AND m.user_id = s.user_id
WHERE s.token_hash = $1 AND s.expires_at > now()`, hashKey(tok)).Scan(&ka.AccountID, &uid, &role)
			if err == nil && ka.AccountID != "" {
				role = strings.ToLower(strings.TrimSpace(role))
				if role == "owner" || role == "admin" {
					role = "administrator"
				}
				ka.Role = role
				ka.UserID = uid
				ka.Permission = "full_access"
				auth = &ka
				go func(th []byte) {
					_, _ = s.db.Exec(context.Background(), `UPDATE user_sessions SET last_used_at = now() WHERE token_hash = $1`, th)
				}(hashKey(tok))
			}
		}

		if auth == nil && s.redis != nil {
			if data, ok, err := s.redis.Get(r.Context(), "apikey:"+hexHash); err == nil && ok {
				var ka keyAuth
				if json.Unmarshal(data, &ka) == nil && ka.AccountID != "" {
					auth = &ka
				}
			}
		}
		if auth == nil {
			var err error
			auth, err = s.keys.GetOrLoad(hKey, func() (*keyAuth, error) {
				if s.db == nil {
					return nil, nil
				}
				loadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var ka keyAuth
				err := s.db.QueryRow(loadCtx, `SELECT account_id, permission, domain_id::text FROM api_keys WHERE key_hash = $1`, hashKey(tok)).Scan(&ka.AccountID, &ka.Permission, &ka.DomainID)
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, nil
				}
				if ka.Permission == "" {
					ka.Permission = "full_access"
				}
				if ka.Permission == "full_access" {
					ka.Role = "administrator"
				} else {
					ka.Role = "sender"
				}
				return &ka, err
			})
			if err != nil {
				s.internal(w, err)
				return
			}
			if auth != nil && auth.AccountID != "" && s.redis != nil {
				if b, err := json.Marshal(auth); err == nil {
					_ = s.redis.Set(r.Context(), "apikey:"+hexHash, b, 5*time.Minute)
				}
			}
		}
		if auth == nil || auth.AccountID == "" {
			s.recordAuthFailure(ip)
			if _, delay := s.checkAuthRate(ip); delay > 0 {
				time.Sleep(delay)
			}
			writeError(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		s.recordAuthSuccess(ip)
		if auth.Permission == "sending_access" && !sendingAccessAllowed(r) {
			writeError(w, http.StatusForbidden, "insufficient permissions: this API key has sending_access only")
			return
		}
		if !s.allow(auth.AccountID) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, auth.AccountID)
		ctx = context.WithValue(ctx, permKey{}, auth.Permission)
		ctx = context.WithValue(ctx, roleKey{}, auth.Role)
		if uid != "" {
			ctx = context.WithValue(ctx, userIDKey{}, uid)
		}
		if auth.DomainID != nil && *auth.DomainID != "" {
			ctx = context.WithValue(ctx, domainKey{}, *auth.DomainID)
		}
		h(w, r.WithContext(ctx))
	})
}

func sendingAccessAllowed(r *http.Request) bool {
	path := strings.TrimRight(r.URL.Path, "/")
	cleanPath := path
	cleanPath = strings.TrimPrefix(cleanPath, "/v1")
	switch {
	case r.Method == http.MethodPost && (cleanPath == "/emails" || cleanPath == "/emails/batch" || cleanPath == "/emails/bulk" || cleanPath == "/batches"):
		return true
	case r.Method == http.MethodGet && (cleanPath == "/emails" || strings.HasPrefix(cleanPath, "/emails/")):
		return true
	case r.Method == http.MethodGet && (cleanPath == "/batches" || strings.HasPrefix(cleanPath, "/batches/")):
		return true
	case r.Method == http.MethodGet && (cleanPath == "/broadcasts" || strings.HasPrefix(cleanPath, "/broadcasts/")):
		return true
	case r.Method == http.MethodPost && strings.HasSuffix(cleanPath, "/send") && strings.HasPrefix(cleanPath, "/broadcasts/"):
		return true
	case r.Method == http.MethodPost && cleanPath == "/render":
		return true
	default:
		return false
	}
}

// allow applies a per-instance, per-account token bucket or Redis sliding-window; idle buckets are evicted by the cache.
func (s *Server) allow(acct string) bool {
	if s.cfg.RateLimitRPS <= 0 {
		return true
	}
	if s.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		allowed, err := s.redis.AllowRate(ctx, "ratelimit:"+acct, int64(s.cfg.RateLimitBurst), time.Second)
		if err == nil {
			return allowed
		}
	}
	lim, _ := s.limiters.GetOrLoad(acct, func() (*rate.Limiter, error) {
		return rate.NewLimiter(rate.Limit(s.cfg.RateLimitRPS), s.cfg.RateLimitBurst), nil
	})
	return lim.Allow()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		w.Header().Del("Server")
		w.Header().Del("X-Powered-By")

		ctx := context.WithValue(r.Context(), reqIDKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) metricsTracker(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		metrics.Default.RecordHTTP(r.Method, rec.status, time.Since(start))
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		// Full success logging becomes an I/O bottleneck at high request rates.
		// Keep all server errors and a configurable sample of the rest.
		if rec.status >= http.StatusInternalServerError || (s.cfg.AccessLogSample > 0 && mathrand.Float64() < s.cfg.AccessLogSample) {
			s.log.Info("http", "req_id", reqID(r), "method", r.Method, "path", r.URL.Path, "status", rec.status, "dur_ms", time.Since(start).Milliseconds())
		}
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if s.log != nil {
					s.log.Error("panic", "value", v, "path", r.URL.Path)
				}
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func decode(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	if limit <= 0 {
		limit = 10 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request body must contain exactly one JSON value")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeJSONBytes(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.log.Error("internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// decodeJSON decodes one bounded JSON value from r into v.
// Returns an error instead of writing to w, for callers that handle errors themselves.
func decodeJSON(r *http.Request, v any) error {
	const maxJSONBodyBytes = 10 << 20
	limited := &io.LimitedReader{R: r.Body, N: maxJSONBodyBytes + 1}
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain exactly one JSON value")
	}
	if limited.N == 0 {
		return errors.New("request body too large")
	}
	return nil
}

// audit is a convenience wrapper around auditLog that extracts IP and User-Agent from the request.
func (s *Server) audit(ctx context.Context, acctID, action, resourceType, resourceID string, r *http.Request) {
	s.auditLog(ctx, acctID, acctID, action, resourceType, resourceID, clientIP(r), r.UserAgent())
}

func newToken(prefix string, n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func validUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

func pathID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, "not found")
		return "", false
	}
	return id, true
}

func optionalUUID(w http.ResponseWriter, r *http.Request, name string) (*string, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, true
	}
	if _, err := uuid.Parse(v); err != nil {
		writeError(w, http.StatusUnprocessableEntity, name+" must be a UUID")
		return nil, false
	}
	return &v, true
}

// page parses ?limit=&before= (RFC 3339) keyset pagination on created_at.
func page(w http.ResponseWriter, r *http.Request) (int, time.Time, bool) {
	limit, before := 1000, time.Now().Add(time.Hour)
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusUnprocessableEntity, "limit must be between 1 and 1000")
			return 0, before, false
		}
		limit = n
	}
	if v := r.URL.Query().Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "before must be an RFC 3339 timestamp")
			return 0, before, false
		}
		before = t
	}
	return limit, before, true
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func domainOf(addr string) string {
	d := strings.ToLower(addr[strings.LastIndexByte(addr, '@')+1:])
	return strings.TrimRight(d, ">")
}
