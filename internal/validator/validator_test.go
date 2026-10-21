package validator

import (
	"testing"
)

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		email string
		valid bool
	}{
		{"test@example.com", true},
		{"user.name+tag@sub.domain.co.uk", true},
		{"simple@localhost.com", true},
		{"", false},
		{"plainaddress", false},
		{"@missingusername.com", false},
		{"username@.com", false},
		{"user@example..com", false},
		{"user\r\n@example.com", false},
		{"user@example.com\nBcc: evil@attacker.com", false},
		{"Name <>", false},
		{"Name <@domain.com>", false},
		{"user@@domain.com", false},
		{"user@domain@extra.com", false},
		{string(make([]byte, 300)), false},
	}

	for _, tt := range tests {
		if got := IsValidEmail(tt.email); got != tt.valid {
			t.Errorf("IsValidEmail(%q) = %v, want %v", tt.email, got, tt.valid)
		}
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		{"example.com", true},
		{"mail.example.org", true},
		{"sub.domain.co.uk", true},
		{"my-domain123.com", true},
		{"", false},
		{"-invalid.com", false},
		{"invalid-.com", false},
		{"example..com", false},
		{"example.c", false}, // TLD too short
		{"example\r.com", false},
		{"example\n.com", false},
	}

	for _, tt := range tests {
		if got := IsValidDomain(tt.domain); got != tt.valid {
			t.Errorf("IsValidDomain(%q) = %v, want %v", tt.domain, got, tt.valid)
		}
	}
}

func TestIsValidLocalPart(t *testing.T) {
	tests := []struct {
		localPart string
		valid     bool
	}{
		{"*", true},
		{"support", true},
		{"sales.team", true},
		{"user_name", true},
		{"hello-world", true},
		{"", false},
		{"+tag", false}, // Plus-addressing rejected for canonical alias definitions
		{"user+tag", false},
		{string(make([]byte, 100)), false},
	}

	for _, tt := range tests {
		if got := IsValidLocalPart(tt.localPart); got != tt.valid {
			t.Errorf("IsValidLocalPart(%q) = %v, want %v", tt.localPart, got, tt.valid)
		}
	}
}

func TestContainsCRLF(t *testing.T) {
	tests := []struct {
		input    string
		contains bool
	}{
		{"clean-string", false},
		{"line\rbreak", true},
		{"line\nbreak", true},
		{"line\r\nbreak", true},
		{"", false},
	}

	for _, tt := range tests {
		if got := ContainsCRLF(tt.input); got != tt.contains {
			t.Errorf("ContainsCRLF(%q) = %v, want %v", tt.input, got, tt.contains)
		}
	}
}

func TestIsValidRole(t *testing.T) {
	tests := []struct {
		role  string
		valid bool
	}{
		{"administrator", true},
		{"developer", true},
		{"user", true},
		{"billing_manager", true},
		{"custom-role-1", true},
		{"", false},
		{"123admin", false},
		{"Admin Role", false},
		{"admin@corp", false},
	}

	for _, tt := range tests {
		if got := IsValidRole(tt.role); got != tt.valid {
			t.Errorf("IsValidRole(%q) = %v, want %v", tt.role, got, tt.valid)
		}
	}
}

func TestIsValidVariableName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"first_name", true},
		{"orderID", true},
		{"total_123", true},
		{"", false},
		{"var with spaces", false},
		{"var-hyphen", false},
		{"var.dot", false},
	}

	for _, tt := range tests {
		if got := IsValidVariableName(tt.name); got != tt.valid {
			t.Errorf("IsValidVariableName(%q) = %v, want %v", tt.name, got, tt.valid)
		}
	}
}

func TestIsValidTriggerType(t *testing.T) {
	valid := []string{"event", "contact.created", "email.opened", "email.clicked", " EVENT ", "Contact.Created"}
	for _, tr := range valid {
		if !IsValidTriggerType(tr) {
			t.Errorf("expected %q to be valid trigger type", tr)
		}
	}

	invalid := []string{"", "unknown", "custom.trigger", "email.bounced"}
	for _, tr := range invalid {
		if IsValidTriggerType(tr) {
			t.Errorf("expected %q to be invalid trigger type", tr)
		}
	}
}

func TestIsDisposableDomain(t *testing.T) {
	disposable := []string{"mailinator.com", "guerrillamail.com", "tempmail.com", " YOPMAIL.COM "}
	for _, d := range disposable {
		if !IsDisposableDomain(d) {
			t.Errorf("expected %q to be identified as disposable", d)
		}
	}

	legit := []string{"gmail.com", "outlook.com", "corp.mailhost.io", ""}
	for _, d := range legit {
		if IsDisposableDomain(d) {
			t.Errorf("expected %q to NOT be disposable", d)
		}
	}
}

func TestIsRoleBasedEmail(t *testing.T) {
	roles := []string{
		"admin@domain.com", "support+urgent@corp.io", "billing@saas.com",
		"info@agency.org", "postmaster@relay.net", "abuse@network.com",
		"team@startup.io", "jobs@company.co",
	}
	for _, e := range roles {
		if !IsRoleBasedEmail(e) {
			t.Errorf("expected %q to be role-based email", e)
		}
	}

	nonRoles := []string{
		"alex@domain.com", "john.doe@company.com", "sarah+admin@corp.io",
		"invalid-email-without-at", "",
	}
	for _, e := range nonRoles {
		if IsRoleBasedEmail(e) {
			t.Errorf("expected %q to NOT be role-based email", e)
		}
	}
}
