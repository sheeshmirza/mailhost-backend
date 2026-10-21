package mailbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestVerifyCredentialPassword(t *testing.T) {
	password := "SecretP@ssw0rd!"

	// 1. Test 32-byte unsalted sha256
	h32 := sha256.Sum256([]byte(password))
	if !verifyCredentialPassword(h32[:], password) {
		t.Error("expected 32-byte sha256 hash to verify successfully")
	}
	if verifyCredentialPassword(h32[:], "wrongpassword") {
		t.Error("expected 32-byte sha256 hash to fail on wrong password")
	}

	// 2. Test 48-byte salted sha256 (16-byte salt + 32-byte sha256)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("failed to generate random salt: %v", err)
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	expected := h.Sum(nil)

	stored48 := append(salt, expected...)
	if !verifyCredentialPassword(stored48, password) {
		t.Error("expected 48-byte salted sha256 hash to verify successfully")
	}
	if verifyCredentialPassword(stored48, "wrongpassword") {
		t.Error("expected 48-byte salted sha256 hash to fail on wrong password")
	}

	// 3. Test invalid lengths
	if verifyCredentialPassword([]byte("too-short"), password) {
		t.Error("expected invalid length slice to fail")
	}
	if verifyCredentialPassword(make([]byte, 64), password) {
		t.Error("expected 64-byte slice to fail")
	}
}

func TestAuthenticateEmptyInputs(t *testing.T) {
	ctx := context.Background()

	if _, err := Authenticate(ctx, nil, "", "password"); err == nil {
		t.Error("expected error for empty username")
	}
	if _, err := Authenticate(ctx, nil, "user@example.com", ""); err == nil {
		t.Error("expected error for empty password")
	}
	if _, err := Authenticate(ctx, nil, "user@example.com", "password"); err == nil {
		t.Error("expected error for nil db")
	}
}

func TestMailboxInvalidUUIDs(t *testing.T) {
	ctx := context.Background()

	if _, err := GetOrCreateMailbox(ctx, nil, "invalid-uuid", "user@example.com", "INBOX"); err == nil {
		t.Error("expected error for invalid account UUID in GetOrCreateMailbox")
	}
	if _, err := ListMailboxes(ctx, nil, "invalid-uuid", "user@example.com"); err == nil {
		t.Error("expected error for invalid account UUID in ListMailboxes")
	}
}

