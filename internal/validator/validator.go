// Package validator provides reusable, thread-safe validation utilities and schema guards across all platform services.
package validator

import (
	"net/mail"
	"regexp"
	"strings"
)

var (
	// LocalPartRegex matches valid RFC 5321/5322 local parts or wildcard catch-alls.
	// '+' is excluded to prevent ambiguous plus-addressing routing and VERP tags.
	LocalPartRegex = regexp.MustCompile(`^(\*|[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?)$`)

	// DomainRegex enforces RFC 1035 / RFC 1123 fully-qualified domain name constraints.
	DomainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

	// RoleNameRegex allows built-in and user-defined RBAC role names.
	RoleNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

	// VariableNameRegex ensures template variables adhere to safe identifier naming rules.
	VariableNameRegex = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

	// crlfRegex detects carriage return and line feed injection vectors.
	crlfRegex = regexp.MustCompile(`[\r\n]`)
)

// Standard Automation Trigger Types
var validTriggerTypes = map[string]bool{
	"event":           true,
	"contact.created": true,
	"email.opened":    true,
	"email.clicked":   true,
}

// IsValidEmail verifies standard RFC 5322 email syntax and ensures non-empty local and domain segments.
func IsValidEmail(email string) bool {
	if ContainsCRLF(email) {
		return false
	}
	clean := strings.TrimSpace(email)
	if clean == "" || len(clean) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(clean)
	if err != nil || addr.Address == "" {
		return false
	}
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	return true
}

// IsValidDomain validates a fully qualified domain name.
func IsValidDomain(domain string) bool {
	if ContainsCRLF(domain) {
		return false
	}
	clean := strings.ToLower(strings.TrimSpace(domain))
	if clean == "" || len(clean) > 253 {
		return false
	}
	return DomainRegex.MatchString(clean)
}

// IsValidLocalPart validates alias or mailbox local part syntax.
func IsValidLocalPart(localPart string) bool {
	clean := strings.ToLower(strings.TrimSpace(localPart))
	return LocalPartRegex.MatchString(clean)
}

// ContainsCRLF checks if a string contains \r or \n to prevent SMTP header injection attacks.
func ContainsCRLF(s string) bool {
	return crlfRegex.MatchString(s)
}

// IsValidRole validates organization RBAC membership roles.
func IsValidRole(role string) bool {
	return RoleNameRegex.MatchString(strings.ToLower(strings.TrimSpace(role)))
}

// IsValidVariableName checks whether a template variable name is a safe identifier.
func IsValidVariableName(name string) bool {
	return VariableNameRegex.MatchString(strings.TrimSpace(name))
}

// IsValidTriggerType validates automation workflow triggers.
func IsValidTriggerType(trigger string) bool {
	return validTriggerTypes[strings.ToLower(strings.TrimSpace(trigger))]
}
