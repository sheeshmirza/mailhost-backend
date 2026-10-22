package mailbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"

	"mailhost/internal/db"
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
	if err := DeleteMailbox(ctx, nil, "invalid-uuid", "user@example.com", "Archive"); err == nil {
		t.Error("expected error for invalid account UUID in DeleteMailbox")
	}
	if err := DeleteMailbox(ctx, nil, uuid.New().String(), "user@example.com", "INBOX"); err == nil {
		t.Error("expected error when trying to delete INBOX")
	}
	if err := RenameMailbox(ctx, nil, uuid.New().String(), "user@example.com", "INBOX", "Archive"); err == nil {
		t.Error("expected error when trying to rename INBOX")
	}
	if err := CreateMailbox(ctx, nil, uuid.New().String(), "user@example.com", ""); err == nil {
		t.Error("expected error for empty folder name in CreateMailbox")
	}
	if _, err := DeliverMessage(ctx, nil, uuid.New().String(), "user@example.com", "INBOX", nil, nil, time.Time{}); err == nil {
		t.Error("expected error for nil db in DeliverMessage")
	}
	if err := UpdateFlags(ctx, nil, uuid.New(), nil, nil, FlagOpSet); err != nil {
		t.Errorf("expected nil for empty uids in UpdateFlags: %v", err)
	}
}

func TestMailboxLiveLifecycle(t *testing.T) {
	connURL := "postgres://mailhost:mailhost_secret@localhost:5433/mailhost?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, connURL, 5)
	if err != nil {
		t.Skipf("skipping live mailbox test (port 5433 unavailable): %v", err)
		return
	}
	defer pool.Close()

	accountID := uuid.New().String()
	_, err = pool.Exec(ctx, `INSERT INTO accounts (id, name) VALUES ($1, 'Test Account')`, accountID)
	if err != nil {
		t.Fatalf("failed to insert test account: %v", err)
	}

	defer pool.Exec(context.Background(), `DELETE FROM accounts WHERE id = $1`, accountID)

	email := "alice-" + accountID[:8] + "@example.com"

	// 1. GetOrCreateMailbox ("INBOX")
	inbox, err := GetOrCreateMailbox(ctx, pool, accountID, email, "INBOX")
	if err != nil {
		t.Fatalf("GetOrCreateMailbox failed: %v", err)
	}

	if inbox.Name != "INBOX" {
		t.Errorf("expected INBOX name, got: %s", inbox.Name)
	}

	// 2. DeliverMessage into INBOX
	rawMsg := []byte("Subject: Live Message\r\n\r\nHello IMAP & POP3!")
	msg, err := DeliverMessage(ctx, pool, accountID, email, "INBOX", rawMsg, []string{"\\Seen"}, time.Now())
	if err != nil {
		t.Fatalf("DeliverMessage failed: %v", err)
	}
	if msg.UID < 1 {
		t.Errorf("expected allocated UID >= 1, got %d", msg.UID)
	}

	// 3. Deliver a second message (unseen)
	msg2, err := DeliverMessage(ctx, pool, accountID, email, "INBOX", []byte("Subject: Msg 2\r\n\r\nHello 2"), nil, time.Now())
	if err != nil {
		t.Fatalf("DeliverMessage 2 failed: %v", err)
	}
	if msg2.UID <= msg.UID {
		t.Errorf("expected strictly increasing UID: %d <= %d", msg2.UID, msg.UID)
	}

	// 4. GetMessages
	msgs, err := GetMessages(ctx, pool, inbox.ID)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("GetMessages failed: len=%d, err=%v", len(msgs), err)
	}

	// 5. Status
	st, err := Status(ctx, pool, inbox)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if st.Messages != 2 || st.Unseen != 1 {
		t.Errorf("unexpected Status: messages=%d, unseen=%d", st.Messages, st.Unseen)
	}

	// 6. UpdateFlags (Add, Remove, Set)
	if err := UpdateFlags(ctx, pool, inbox.ID, []uint32{msg2.UID}, []string{"\\Flagged"}, FlagOpAdd); err != nil {
		t.Errorf("UpdateFlags FlagOpAdd failed: %v", err)
	}
	if err := UpdateFlags(ctx, pool, inbox.ID, []uint32{msg2.UID}, []string{"\\Flagged"}, FlagOpRemove); err != nil {
		t.Errorf("UpdateFlags FlagOpRemove failed: %v", err)
	}
	if err := UpdateFlags(ctx, pool, inbox.ID, []uint32{msg2.UID}, []string{"\\Deleted"}, FlagOpSet); err != nil {
		t.Errorf("UpdateFlags FlagOpSet failed: %v", err)
	}

	// 7. ExpungeDeleted
	expunged, err := ExpungeDeleted(ctx, pool, inbox.ID, []uint32{msg2.UID})
	if err != nil || len(expunged) != 1 || expunged[0] != msg2.UID {
		t.Errorf("ExpungeDeleted failed: expunged=%v, err=%v", expunged, err)
	}

	// 8. Create, List, Rename, and Delete user folder
	if err := CreateMailbox(ctx, pool, accountID, email, "Work"); err != nil {
		t.Fatalf("CreateMailbox failed: %v", err)
	}
	mbs, err := ListMailboxes(ctx, pool, accountID, email)
	if err != nil || len(mbs) < 2 {
		t.Errorf("ListMailboxes failed: len=%d, err=%v", len(mbs), err)
	}
	if err := RenameMailbox(ctx, pool, accountID, email, "Work", "Archive"); err != nil {
		t.Errorf("RenameMailbox failed: %v", err)
	}
	if err := DeleteMailbox(ctx, pool, accountID, email, "Archive"); err != nil {
		t.Errorf("DeleteMailbox failed: %v", err)
	}

	// 9. DeleteMessages
	deleted, err := DeleteMessages(ctx, pool, inbox.ID, []uint32{msg.UID})
	if err != nil || len(deleted) != 1 {
		t.Errorf("DeleteMessages failed: deleted=%v, err=%v", deleted, err)
	}

	// 10. Test API key authentication
	apiKeyRaw := "mh_live_secret12345"
	keyHash := sha256.Sum256([]byte(apiKeyRaw))
	_, err = pool.Exec(ctx, `INSERT INTO api_keys (account_id, key_hash, name, permission) VALUES ($1, $2, 'Test Key', 'full_access')`, accountID, keyHash[:])
	if err != nil {
		t.Fatalf("failed to insert test api_key: %v", err)
	}

	authUser, err := Authenticate(ctx, pool, "api", apiKeyRaw)
	if err != nil || authUser.AccountID != accountID {
		t.Errorf("Authenticate with API key failed: user=%+v, err=%v", authUser, err)
	}

	// 11. Test failed authentication
	if _, err := Authenticate(ctx, pool, "nonexistent@test.com", "badpass"); err == nil {
		t.Error("expected error for nonexistent user credentials")
	}
}



