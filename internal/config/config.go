// Package config loads and validates Mailhost configuration from environment variables.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contains validated runtime settings for all Mailhost roles.
type Config struct {
	HTTPAddr              string
	SMTPAddr              string
	AuthEmailSMTPAddr     string
	AuthEmailSMTPUsername string
	AuthEmailSMTPPassword string
	AuthEmailFrom         string
	SupportEmail          string
	OpenAIPluginToken     string
	Hostname              string // public FQDN used for EHLO, MX and SPF records
	DatabaseURL           string
	DatabaseReadURL       string // optional read replica for list/analytics endpoints
	DBMaxConns            int32
	MasterKey             []byte
	Roles                 map[string]bool
	Workers               int
	PollInterval          time.Duration
	MaxAttempts           int
	MaxMessageBytes       int64
	RateLimitRPS          float64
	RateLimitBurst        int
	AccessLogSample       float64 // fraction of successful requests written to the access log
	IdempotencyTTL        time.Duration
	RelayHost             string // optional smarthost host:port; bypasses direct MX delivery
	RelayUsername         string
	RelayPassword         string
	TLSCertFile           string
	TLSKeyFile            string
	MaxConnsPerHost       int     // concurrent outbound SMTP connections per MX host, per instance
	DestRateLimitRPS      float64 // rate limit per outbound MX destination host (0 to disable)
	DestRateLimitBurst    int
	RetentionMonths       int // event partitions older than this are dropped; 0 keeps forever
	DebugAddr             string
	RabbitMQURL           string       // optional amqp:// connection string for high-throughput RabbitMQ queuing
	RedisURL              string       // optional redis:// connection string for distributed caching & rate limiting
	MongoDBURI            string       // optional mongodb:// connection string for document store & payload offload
	MongoDBDatabase       string       // optional database name (defaults to "mailhost")
	AllowPrivateDelivery  bool         // optional flag to allow outbound delivery to private IP networks (for local/dev testing)
	SkipDNSVerification   bool         // dev only: mark domain DNS records verified without lookups
	DNSServer             string       // optional custom DNS resolver host:port (e.g. "127.0.0.1:1053" or "dns:53")
	OutboundSMTPPort      string       // optional outbound SMTP destination port (default: "25")
	IMAPAddr              string       // address and port for the IMAP server (default :143)
	POP3Addr              string       // address and port for the POP3 server (default :110)
	SubmissionAddr        string       // address and port for dedicated SMTP submission (default :587)
	TrustedProxies        []*net.IPNet // reverse proxies whose X-Forwarded-For header is trusted
}

func defaultHTTPAddr() string {
	if addr := os.Getenv("HTTP_ADDR"); addr != "" {
		return addr
	}
	bind := os.Getenv("MAIL_HTTP_BIND")
	port := os.Getenv("MAIL_HTTP_PORT")
	if bind != "" || port != "" {
		if port == "" {
			port = "8080"
		}
		if bind == "" {
			return ":" + port
		}
		return net.JoinHostPort(bind, port)
	}
	return ":8080"
}

func defaultSMTPAddr() string {
	if addr := os.Getenv("SMTP_ADDR"); addr != "" {
		return addr
	}
	if port := os.Getenv("SMTP_PORT"); port != "" {
		return ":" + port
	}
	return ":25"
}

func defaultIMAPAddr() string {
	if addr := os.Getenv("IMAP_ADDR"); addr != "" {
		return addr
	}
	if port := os.Getenv("IMAP_PORT"); port != "" {
		return ":" + port
	}
	return ":143"
}

func defaultPOP3Addr() string {
	if addr := os.Getenv("POP3_ADDR"); addr != "" {
		return addr
	}
	if port := os.Getenv("POP3_PORT"); port != "" {
		return ":" + port
	}
	return ":110"
}

func defaultSubmissionAddr() string {
	if addr := os.Getenv("SUBMISSION_ADDR"); addr != "" {
		return addr
	}
	if port := os.Getenv("SUBMISSION_PORT"); port != "" {
		return ":" + port
	}
	return ":587"
}

func validateDebugAddr(addr string) error {
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return errors.New("DEBUG_ADDR must be a localhost or loopback address with a port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("DEBUG_ADDR must include a valid port")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("DEBUG_ADDR must bind to localhost or a loopback IP")
	}
	return nil
}

// Load reads environment variables, applies defaults, and validates the result.
func Load() (*Config, error) {
	loadEnvFile(".env")
	if err := validateNumericEnv(); err != nil {
		return nil, err
	}
	c := &Config{
		HTTPAddr:              defaultHTTPAddr(),
		SMTPAddr:              defaultSMTPAddr(),
		AuthEmailSMTPAddr:     strings.TrimSpace(os.Getenv("AUTH_EMAIL_SMTP_ADDR")),
		AuthEmailSMTPUsername: strings.TrimSpace(os.Getenv("AUTH_EMAIL_SMTP_USERNAME")),
		AuthEmailSMTPPassword: os.Getenv("AUTH_EMAIL_SMTP_PASSWORD"),
		AuthEmailFrom:         strings.TrimSpace(os.Getenv("AUTH_EMAIL_FROM")),
		SupportEmail:          strings.TrimSpace(os.Getenv("SUPPORT_EMAIL")),
		OpenAIPluginToken:     strings.TrimSpace(os.Getenv("OPENAI_PLUGIN_TOKEN")),
		Hostname:              env("MAIL_HOSTNAME", os.Getenv("HOSTNAME")),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		DatabaseReadURL:       os.Getenv("DATABASE_READ_URL"),
		DBMaxConns:            int32(envInt("DB_MAX_CONNS", 50)),
		Workers:               envInt("WORKERS", 64),
		PollInterval:          envDuration("POLL_INTERVAL", 200*time.Millisecond),
		MaxAttempts:           envInt("MAX_ATTEMPTS", 12),
		MaxMessageBytes:       int64(envInt("MAX_MESSAGE_BYTES", 25<<20)),
		RateLimitRPS:          envFloat("RATE_LIMIT_RPS", 0),
		RateLimitBurst:        envInt("RATE_LIMIT_BURST", 0),
		AccessLogSample:       envFloat("ACCESS_LOG_SAMPLE", 0.01),
		IdempotencyTTL:        envDuration("IDEMPOTENCY_TTL", 24*time.Hour),
		RelayHost:             os.Getenv("RELAY_HOST"),
		RelayUsername:         os.Getenv("RELAY_USERNAME"),
		RelayPassword:         os.Getenv("RELAY_PASSWORD"),
		TLSCertFile:           env("TLS_CERT_FILE", os.Getenv("SMTP_TLS_CERT")),
		TLSKeyFile:            env("TLS_KEY_FILE", os.Getenv("SMTP_TLS_KEY")),
		MaxConnsPerHost:       envInt("MAX_CONNS_PER_HOST", 0),
		DestRateLimitRPS:      envFloat("DEST_RATE_LIMIT_RPS", 0),
		DestRateLimitBurst:    envInt("DEST_RATE_LIMIT_BURST", 0),
		RetentionMonths:       envInt("RETENTION_MONTHS", envInt("EVENT_RETENTION_MONTHS", 13)),
		DebugAddr:             os.Getenv("DEBUG_ADDR"),
		RabbitMQURL:           os.Getenv("RABBITMQ_URL"),
		RedisURL:              os.Getenv("REDIS_URL"),
		MongoDBURI:            os.Getenv("MONGODB_URI"),
		MongoDBDatabase:       env("MONGODB_DATABASE", "mailhost"),
		AllowPrivateDelivery:  envBool("ALLOW_PRIVATE_DELIVERY", false),
		SkipDNSVerification:   envBool("SKIP_DNS_VERIFICATION", false),
		DNSServer:             os.Getenv("DNS_SERVER"),
		OutboundSMTPPort:      env("OUTBOUND_SMTP_PORT", "25"),
		IMAPAddr:              defaultIMAPAddr(),
		POP3Addr:              defaultPOP3Addr(),
		SubmissionAddr:        defaultSubmissionAddr(),
		Roles:                 map[string]bool{},
	}
	if err := validateDebugAddr(c.DebugAddr); err != nil {
		return nil, err
	}
	for _, cidr := range strings.Split(os.Getenv("TRUSTED_PROXY_CIDRS"), ",") {
		if cidr = strings.TrimSpace(cidr); cidr == "" {
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS contains an invalid CIDR %q", cidr)
		}
		c.TrustedProxies = append(c.TrustedProxies, n)
	}
	for _, r := range strings.Split(env("ROLES", "api,smtp,worker"), ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		switch r {
		case "api", "smtp", "worker", "imap", "pop":
			c.Roles[r] = true
		case "all":
			c.Roles["api"] = true
			c.Roles["smtp"] = true
			c.Roles["worker"] = true
			c.Roles["imap"] = true
			c.Roles["pop"] = true
		default:
			return nil, errors.New("ROLES may contain only api, smtp, worker, imap, and pop (or all)")
		}
	}
	if len(c.Roles) == 0 {
		return nil, errors.New("ROLES must contain at least one role")
	}
	if c.DatabaseURL == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	if c.Hostname == "" {
		return nil, errors.New("MAIL_HOSTNAME is required")
	}
	if (c.AuthEmailSMTPAddr == "") != (c.AuthEmailFrom == "") {
		return nil, errors.New("AUTH_EMAIL_SMTP_ADDR and AUTH_EMAIL_FROM must be configured together")
	}
	if (c.AuthEmailSMTPUsername == "") != (c.AuthEmailSMTPPassword == "") {
		return nil, errors.New("AUTH_EMAIL_SMTP_USERNAME and AUTH_EMAIL_SMTP_PASSWORD must be set together")
	}
	if c.AuthEmailSMTPAddr != "" {
		if _, _, err := net.SplitHostPort(c.AuthEmailSMTPAddr); err != nil {
			return nil, errors.New("AUTH_EMAIL_SMTP_ADDR must be a host:port address")
		}
		if _, err := mail.ParseAddress(c.AuthEmailFrom); err != nil {
			return nil, errors.New("AUTH_EMAIL_FROM must be a valid email address")
		}
	}
	key, err := hex.DecodeString(os.Getenv("MASTER_KEY"))
	if err != nil || len(key) != 32 {
		return nil, errors.New("MASTER_KEY must be 64 hex characters (32 bytes)")
	}
	c.MasterKey = key
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return nil, errors.New("SMTP_TLS_CERT and SMTP_TLS_KEY must be set together")
	}
	if (c.RelayUsername == "") != (c.RelayPassword == "") {
		return nil, errors.New("RELAY_USERNAME and RELAY_PASSWORD must be set together")
	}
	if c.DBMaxConns < 1 || c.Workers < 1 || c.MaxAttempts < 1 || c.MaxMessageBytes < 1 || c.MaxConnsPerHost < 0 || c.PollInterval <= 0 || c.IdempotencyTTL <= 0 || c.RetentionMonths < 0 {
		return nil, errors.New("DB_MAX_CONNS, WORKERS, MAX_ATTEMPTS, MAX_MESSAGE_BYTES, POLL_INTERVAL and IDEMPOTENCY_TTL must be positive; MAX_CONNS_PER_HOST and EVENT_RETENTION_MONTHS must not be negative")
	}
	if c.RateLimitRPS < 0 || c.RateLimitBurst < 0 || c.AccessLogSample < 0 || c.AccessLogSample > 1 || (c.RateLimitRPS > 0 && c.RateLimitBurst < 1) {
		return nil, errors.New("RATE_LIMIT_RPS and RATE_LIMIT_BURST must not be negative, RATE_LIMIT_BURST must be positive when rate limiting is enabled, and ACCESS_LOG_SAMPLE must be between 0 and 1")
	}
	if c.DestRateLimitRPS < 0 || c.DestRateLimitBurst < 0 || (c.DestRateLimitRPS > 0 && c.DestRateLimitBurst < 1) {
		return nil, errors.New("DEST_RATE_LIMIT_RPS and DEST_RATE_LIMIT_BURST must not be negative, and DEST_RATE_LIMIT_BURST must be positive when rate limiting is enabled")
	}
	return c, nil
}

func validateNumericEnv() error {
	intKeys := []string{"DB_MAX_CONNS", "WORKERS", "MAX_ATTEMPTS", "MAX_MESSAGE_BYTES", "RATE_LIMIT_BURST", "MAX_CONNS_PER_HOST", "DEST_RATE_LIMIT_BURST", "EVENT_RETENTION_MONTHS"}
	for _, key := range intKeys {
		if value := os.Getenv(key); value != "" {
			if _, err := strconv.Atoi(value); err != nil {
				return fmt.Errorf("%s must be an integer", key)
			}
		}
	}
	floatKeys := []string{"RATE_LIMIT_RPS", "ACCESS_LOG_SAMPLE", "DEST_RATE_LIMIT_RPS"}
	for _, key := range floatKeys {
		if value := os.Getenv(key); value != "" {
			if _, err := strconv.ParseFloat(value, 64); err != nil {
				return fmt.Errorf("%s must be a number", key)
			}
		}
	}
	for _, key := range []string{"POLL_INTERVAL", "IDEMPOTENCY_TTL"} {
		if value := os.Getenv(key); value != "" {
			if _, err := time.ParseDuration(value); err != nil {
				return fmt.Errorf("%s must be a duration", key)
			}
		}
	}
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return n
	}
	return def
}

func envFloat(k string, def float64) float64 {
	if n, err := strconv.ParseFloat(os.Getenv(k), 64); err == nil {
		return n
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(k)); err == nil {
		return d
	}
	return def
}

func envBool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
}
