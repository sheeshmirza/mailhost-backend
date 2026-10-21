package config

import (
	"os"
	"testing"
)

func TestValidateDebugAddr(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
	}{
		{"", false},
		{"127.0.0.1:6060", false},
		{"localhost:6060", false},
		{"::1:6060", true}, // IPv6 loopback without brackets fails SplitHostPort
		{"[::1]:6060", false},
		{"0.0.0.0:6060", true},
		{"192.168.1.1:6060", true},
		{"127.0.0.1:0", true},
		{"127.0.0.1:70000", true},
		{"invalid-format", true},
	}

	for _, tt := range tests {
		err := validateDebugAddr(tt.addr)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateDebugAddr(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
		}
	}
}

func TestValidateNumericEnv(t *testing.T) {
	os.Setenv("DB_MAX_CONNS", "invalid")
	if err := validateNumericEnv(); err == nil {
		t.Error("expected error for non-integer DB_MAX_CONNS")
	}
	os.Unsetenv("DB_MAX_CONNS")

	os.Setenv("RATE_LIMIT_RPS", "not-a-number")
	if err := validateNumericEnv(); err == nil {
		t.Error("expected error for non-float RATE_LIMIT_RPS")
	}
	os.Unsetenv("RATE_LIMIT_RPS")

	os.Setenv("POLL_INTERVAL", "bad-duration")
	if err := validateNumericEnv(); err == nil {
		t.Error("expected error for invalid duration POLL_INTERVAL")
	}
	os.Unsetenv("POLL_INTERVAL")
}

func TestLoadConfigurationValidation(t *testing.T) {
	// Set baseline required valid environment
	os.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/mailhost")
	os.Setenv("MAIL_HOSTNAME", "mail.example.com")
	os.Setenv("MASTER_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	os.Setenv("ROLES", "api,worker")
	defer func() {
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("MAIL_HOSTNAME")
		os.Unsetenv("MASTER_KEY")
		os.Unsetenv("ROLES")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if !cfg.Roles["api"] || !cfg.Roles["worker"] || cfg.Roles["smtp"] {
		t.Errorf("unexpected roles loaded: %v", cfg.Roles)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("expected default HTTPAddr :8080, got %s", cfg.HTTPAddr)
	}

	// Test missing DATABASE_URL
	os.Unsetenv("DATABASE_URL")
	if _, err := Load(); err == nil {
		t.Error("expected error when DATABASE_URL is missing")
	}
	os.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/mailhost")

	// Test invalid MASTER_KEY length
	os.Setenv("MASTER_KEY", "shortkey")
	if _, err := Load(); err == nil {
		t.Error("expected error for invalid MASTER_KEY length")
	}
	os.Setenv("MASTER_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	// Test invalid Role
	os.Setenv("ROLES", "invalid_role")
	if _, err := Load(); err == nil {
		t.Error("expected error for invalid role")
	}
	os.Setenv("ROLES", "all")
	cfgAll, err := Load()
	if err != nil {
		t.Fatalf("expected valid config for ROLES=all, got: %v", err)
	}
	if !cfgAll.Roles["api"] || !cfgAll.Roles["smtp"] || !cfgAll.Roles["worker"] || !cfgAll.Roles["imap"] || !cfgAll.Roles["pop"] {
		t.Errorf("expected all roles enabled for ROLES=all, got: %v", cfgAll.Roles)
	}

	// Test empty roles
	os.Setenv("ROLES", " , ")
	if _, err := Load(); err == nil {
		t.Error("expected error for empty roles")
	}
	os.Setenv("ROLES", "api")

	// Test missing MAIL_HOSTNAME
	os.Unsetenv("MAIL_HOSTNAME")
	os.Unsetenv("HOSTNAME")
	if _, err := Load(); err == nil {
		t.Error("expected error for missing hostname")
	}
	os.Setenv("MAIL_HOSTNAME", "mail.example.com")

	// Test AuthEmailSMTPAddr without AuthEmailFrom
	os.Setenv("AUTH_EMAIL_SMTP_ADDR", "smtp.provider.com:587")
	if _, err := Load(); err == nil {
		t.Error("expected error for AuthEmailSMTPAddr without AuthEmailFrom")
	}
	os.Setenv("AUTH_EMAIL_FROM", "invalid-email")
	if _, err := Load(); err == nil {
		t.Error("expected error for invalid AUTH_EMAIL_FROM")
	}
	os.Setenv("AUTH_EMAIL_FROM", "admin@example.com")

	// Test AuthEmailSMTPUsername without AuthEmailSMTPPassword
	os.Setenv("AUTH_EMAIL_SMTP_USERNAME", "myuser")
	if _, err := Load(); err == nil {
		t.Error("expected error for username without password")
	}
	os.Setenv("AUTH_EMAIL_SMTP_PASSWORD", "mypass")

	// Test AuthEmailSMTPAddr without port (should auto-append 587)
	os.Setenv("AUTH_EMAIL_SMTP_ADDR", "smtp.provider.com")
	cfgAuth, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgAuth.AuthEmailSMTPAddr != "smtp.provider.com:587" {
		t.Errorf("expected smtp.provider.com:587, got %s", cfgAuth.AuthEmailSMTPAddr)
	}
	os.Unsetenv("AUTH_EMAIL_SMTP_ADDR")
	os.Unsetenv("AUTH_EMAIL_FROM")
	os.Unsetenv("AUTH_EMAIL_SMTP_USERNAME")
	os.Unsetenv("AUTH_EMAIL_SMTP_PASSWORD")

	// Test TLS mismatch
	os.Setenv("TLS_CERT_FILE", "/path/to/cert.pem")
	if _, err := Load(); err == nil {
		t.Error("expected error for TLS cert without key")
	}
	os.Unsetenv("TLS_CERT_FILE")

	// Test invalid CIDR
	os.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.1/32,not-a-cidr")
	if _, err := Load(); err == nil {
		t.Error("expected error for invalid CIDR in TRUSTED_PROXY_CIDRS")
	}
	os.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 172.16.0.0/12")
	cfgCIDR, err := Load()
	if err != nil {
		t.Fatalf("unexpected error with valid CIDRs: %v", err)
	}
	if len(cfgCIDR.TrustedProxies) != 2 {
		t.Errorf("expected 2 trusted proxies, got %d", len(cfgCIDR.TrustedProxies))
	}
	os.Unsetenv("TRUSTED_PROXY_CIDRS")

	// Test numeric validation bounds in Load()
	os.Setenv("WORKERS", "0")
	if _, err := Load(); err == nil {
		t.Error("expected error for WORKERS < 1")
	}
	os.Unsetenv("WORKERS")

	os.Setenv("RATE_LIMIT_RPS", "10")
	os.Setenv("RATE_LIMIT_BURST", "0")
	if _, err := Load(); err == nil {
		t.Error("expected error for RATE_LIMIT_RPS > 0 with RATE_LIMIT_BURST < 1")
	}
	os.Unsetenv("RATE_LIMIT_RPS")
	os.Unsetenv("RATE_LIMIT_BURST")

	os.Setenv("DEST_RATE_LIMIT_RPS", "5")
	os.Setenv("DEST_RATE_LIMIT_BURST", "0")
	if _, err := Load(); err == nil {
		t.Error("expected error for DEST_RATE_LIMIT_RPS > 0 with DEST_RATE_LIMIT_BURST < 1")
	}
	os.Unsetenv("DEST_RATE_LIMIT_RPS")
	os.Unsetenv("DEST_RATE_LIMIT_BURST")
}

func TestDefaultAddresses(t *testing.T) {
	// defaultHTTPAddr
	os.Setenv("HTTP_ADDR", "0.0.0.0:9090")
	if addr := defaultHTTPAddr(); addr != "0.0.0.0:9090" {
		t.Errorf("expected 0.0.0.0:9090, got %s", addr)
	}
	os.Unsetenv("HTTP_ADDR")

	os.Setenv("MAIL_HTTP_BIND", "127.0.0.1")
	os.Setenv("MAIL_HTTP_PORT", "8888")
	if addr := defaultHTTPAddr(); addr != "127.0.0.1:8888" {
		t.Errorf("expected 127.0.0.1:8888, got %s", addr)
	}
	os.Unsetenv("MAIL_HTTP_PORT")
	if addr := defaultHTTPAddr(); addr != "127.0.0.1:8080" {
		t.Errorf("expected 127.0.0.1:8080, got %s", addr)
	}
	os.Unsetenv("MAIL_HTTP_BIND")
	os.Setenv("MAIL_HTTP_PORT", "9999")
	if addr := defaultHTTPAddr(); addr != ":9999" {
		t.Errorf("expected :9999, got %s", addr)
	}
	os.Unsetenv("MAIL_HTTP_PORT")

	// defaultSMTPAddr
	os.Setenv("SMTP_ADDR", ":2525")
	if addr := defaultSMTPAddr(); addr != ":2525" {
		t.Errorf("expected :2525, got %s", addr)
	}
	os.Unsetenv("SMTP_ADDR")
	os.Setenv("SMTP_PORT", "1025")
	if addr := defaultSMTPAddr(); addr != ":1025" {
		t.Errorf("expected :1025, got %s", addr)
	}
	os.Unsetenv("SMTP_PORT")
	if addr := defaultSMTPAddr(); addr != ":25" {
		t.Errorf("expected :25, got %s", addr)
	}

	// defaultIMAPAddr
	os.Setenv("IMAP_ADDR", ":1143")
	if addr := defaultIMAPAddr(); addr != ":1143" {
		t.Errorf("expected :1143, got %s", addr)
	}
	os.Unsetenv("IMAP_ADDR")
	os.Setenv("IMAP_PORT", "993")
	if addr := defaultIMAPAddr(); addr != ":993" {
		t.Errorf("expected :993, got %s", addr)
	}
	os.Unsetenv("IMAP_PORT")
	if addr := defaultIMAPAddr(); addr != ":143" {
		t.Errorf("expected :143, got %s", addr)
	}

	// defaultPOP3Addr
	os.Setenv("POP3_ADDR", ":1110")
	if addr := defaultPOP3Addr(); addr != ":1110" {
		t.Errorf("expected :1110, got %s", addr)
	}
	os.Unsetenv("POP3_ADDR")
	os.Setenv("POP3_PORT", "995")
	if addr := defaultPOP3Addr(); addr != ":995" {
		t.Errorf("expected :995, got %s", addr)
	}
	os.Unsetenv("POP3_PORT")
	if addr := defaultPOP3Addr(); addr != ":110" {
		t.Errorf("expected :110, got %s", addr)
	}

	// defaultSubmissionAddr
	os.Setenv("SUBMISSION_ADDR", ":1587")
	if addr := defaultSubmissionAddr(); addr != ":1587" {
		t.Errorf("expected :1587, got %s", addr)
	}
	os.Unsetenv("SUBMISSION_ADDR")
	os.Setenv("SUBMISSION_PORT", "465")
	if addr := defaultSubmissionAddr(); addr != ":465" {
		t.Errorf("expected :465, got %s", addr)
	}
	os.Unsetenv("SUBMISSION_PORT")
	if addr := defaultSubmissionAddr(); addr != ":587" {
		t.Errorf("expected :587, got %s", addr)
	}
}

func TestEnvHelpers(t *testing.T) {
	os.Setenv("TEST_KEY", "value")
	if v := env("TEST_KEY", "fallback"); v != "value" {
		t.Errorf("expected value, got %s", v)
	}
	if v := env("NON_EXISTENT_KEY", "fallback"); v != "fallback" {
		t.Errorf("expected fallback, got %s", v)
	}

	os.Setenv("TEST_INT", "42")
	if v := envInt("TEST_INT", 10); v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
	os.Setenv("TEST_INT", "not-int")
	if v := envInt("TEST_INT", 10); v != 10 {
		t.Errorf("expected fallback 10, got %d", v)
	}

	os.Setenv("TEST_FLOAT", "3.14")
	if v := envFloat("TEST_FLOAT", 1.0); v != 3.14 {
		t.Errorf("expected 3.14, got %f", v)
	}
	os.Setenv("TEST_FLOAT", "invalid")
	if v := envFloat("TEST_FLOAT", 1.0); v != 1.0 {
		t.Errorf("expected fallback 1.0, got %f", v)
	}

	os.Setenv("TEST_BOOL", "true")
	if v := envBool("TEST_BOOL", false); !v {
		t.Error("expected true")
	}
	os.Setenv("TEST_BOOL", "invalid")
	if v := envBool("TEST_BOOL", false); v {
		t.Error("expected false")
	}
	os.Unsetenv("TEST_BOOL")
	if v := envBool("TEST_BOOL", true); !v {
		t.Error("expected default true")
	}

	// Clean up
	os.Unsetenv("TEST_KEY")
	os.Unsetenv("TEST_INT")
	os.Unsetenv("TEST_FLOAT")
}

func TestLoadEnvFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_env_*.env")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `
# Comment line
EMPTY_LINE=

KEY_SINGLE='single_quoted'
KEY_DOUBLE="double_quoted"
KEY_PLAIN=plain_value
INVALID_LINE_NO_EQUALS
`
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	loadEnvFile(tmpFile.Name())

	if os.Getenv("KEY_SINGLE") != "single_quoted" {
		t.Errorf("expected single_quoted, got %q", os.Getenv("KEY_SINGLE"))
	}
	if os.Getenv("KEY_DOUBLE") != "double_quoted" {
		t.Errorf("expected double_quoted, got %q", os.Getenv("KEY_DOUBLE"))
	}
	if os.Getenv("KEY_PLAIN") != "plain_value" {
		t.Errorf("expected plain_value, got %q", os.Getenv("KEY_PLAIN"))
	}

	// Test non-existent file shouldn't crash
	loadEnvFile("/path/to/nonexistent/file.env")

	os.Unsetenv("KEY_SINGLE")
	os.Unsetenv("KEY_DOUBLE")
	os.Unsetenv("KEY_PLAIN")
	os.Unsetenv("EMPTY_LINE")
}


