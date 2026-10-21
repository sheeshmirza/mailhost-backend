// Package validator provides reusable, thread-safe validation utilities and schema guards across all platform services.
package validator

import (
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
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

var disposableDomains = map[string]bool{
	"mailinator.com": true, "guerrillamail.com": true, "tempmail.com": true,
	"10minutemail.com": true, "throwawaymail.com": true, "sharklasers.com": true,
	"yopmail.com": true, "trashmail.com": true, "temp-mail.org": true,
	"fakeinbox.com": true, "getairmail.com": true, "dispostable.com": true,
	"crazymailing.com": true, "mohmal.com": true, "burnermail.io": true,
	"inboxkitten.com": true, "nada.ltd": true, "getnada.com": true,
}

// IsDisposableDomain detects temporary, burner, and disposable inbox domains.
func IsDisposableDomain(domain string) bool {
	return disposableDomains[strings.ToLower(strings.TrimSpace(domain))]
}

var rolePrefixes = map[string]bool{
	"admin": true, "support": true, "sales": true, "billing": true,
	"info": true, "contact": true, "help": true, "postmaster": true,
	"hostmaster": true, "abuse": true, "webmaster": true, "marketing": true,
	"security": true, "compliance": true, "legal": true, "jobs": true,
	"careers": true, "press": true, "media": true, "team": true,
}

// IsRoleBasedEmail identifies team, department, or administrative aliases.
func IsRoleBasedEmail(email string) bool {
	clean := strings.ToLower(strings.TrimSpace(email))
	parts := strings.Split(clean, "@")
	if len(parts) != 2 {
		return false
	}
	local := parts[0]
	if idx := strings.IndexByte(local, '+'); idx != -1 {
		local = local[:idx]
	}
	return rolePrefixes[local]
}

var commonWeakPasswords = map[string]bool{
	"password": true, "password1": true, "password123": true, "12345678": true,
	"123456789": true, "1234567890": true, "qwertyui": true, "qwertyuiop": true,
	"admin123": true, "admin1234": true, "welcome1": true, "welcome123": true,
	"letmein123": true, "passphrase": true, "iloveyou": true, "monkey123": true,
	"dragon123": true, "mailhost": true, "mailhost123": true,
}

// ValidatePassword enforces enterprise password security policies:
// - Length between 8 and 72 characters (preventing bcrypt truncation and DoS)
// - Rejection of common dictionary passwords
// - Diverse character classes for passwords under 16 characters
// - Rejection of single-character repeated sequences
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	if len(password) > 72 {
		return errors.New("password must not exceed 72 characters")
	}

	lower := strings.ToLower(strings.TrimSpace(password))
	if commonWeakPasswords[lower] {
		return errors.New("password is too common and easily guessable")
	}

	allSame := true
	firstRune := rune(0)
	for i, r := range password {
		if i == 0 {
			firstRune = r
		} else if r != firstRune {
			allSame = false
			break
		}
	}
	if allSame {
		return errors.New("password cannot consist of a single repeated character")
	}

	if len(password) < 16 {
		var hasUpper, hasLower, hasDigit, hasSpecial bool
		for _, r := range password {
			switch {
			case unicode.IsUpper(r):
				hasUpper = true
			case unicode.IsLower(r):
				hasLower = true
			case unicode.IsDigit(r):
				hasDigit = true
			case unicode.IsPunct(r) || unicode.IsSymbol(r) || r == ' ':
				hasSpecial = true
			}
		}
		classes := 0
		if hasUpper {
			classes++
		}
		if hasLower {
			classes++
		}
		if hasDigit {
			classes++
		}
		if hasSpecial {
			classes++
		}
		if classes < 2 {
			return errors.New("password must contain at least two of: uppercase letters, lowercase letters, numbers, symbols")
		}
	}

	return nil
}

