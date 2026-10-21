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
}

