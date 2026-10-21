package imap

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/google/uuid"

	"mailhost/internal/config"
	"mailhost/internal/db"
	"mailhost/internal/mailbox"
)

func TestNumSetContains(t *testing.T) {
	seqSet := imap.SeqSet{}
	seqSet.AddNum(5)

	if !numSetContains(seqSet, 5, 100) {
		t.Error("expected seqSet to contain seqNum 5")
	}
	if numSetContains(seqSet, 6, 100) {
		t.Error("expected seqSet to not contain seqNum 6")
	}

	uidSet := imap.UIDSet{}
	uidSet.AddNum(100)
	if !numSetContains(uidSet, 5, 100) {
		t.Error("expected uidSet to contain UID 100")
	}
	if numSetContains(uidSet, 5, 101) {
		t.Error("expected uidSet to not contain UID 101")
	}
}

func TestMatchesSearch(t *testing.T) {
	msg := &mailbox.Message{
		UID:   42,
		Size:  1024,
		Flags: []string{"\\Seen", "\\Flagged"},
		Date:  time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
	}

	// 1. Nil criteria matches all
	if !matchesSearch(msg, 1, nil) {
		t.Error("nil criteria should match message")
	}

	// 2. Flag matching
	flagCriteria := &imap.SearchCriteria{
		Flag: []imap.Flag{imap.FlagSeen},
	}
	if !matchesSearch(msg, 1, flagCriteria) {
		t.Error("expected \\Seen flag to match")
	}

	// 3. NotFlag matching
	notFlagCriteria := &imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagDeleted},
	}
	if !matchesSearch(msg, 1, notFlagCriteria) {
		t.Error("expected non-deleted message to match NotFlag Deleted")
	}

	notFlagFailing := &imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagSeen},
	}
	if matchesSearch(msg, 1, notFlagFailing) {
		t.Error("expected seen message to fail NotFlag Seen")
	}

	// 4. Size matching
	sizeCriteria := &imap.SearchCriteria{
		Larger:  500,
		Smaller: 2000,
	}
	if !matchesSearch(msg, 1, sizeCriteria) {
		t.Error("expected 1024 bytes to match [500, 2000]")
	}

	sizeCriteriaFail := &imap.SearchCriteria{
		Larger: 2000,
	}
	if matchesSearch(msg, 1, sizeCriteriaFail) {
		t.Error("expected 1024 bytes to fail Larger 2000")
	}

	// 5. Date matching
	dateCriteria := &imap.SearchCriteria{
		Since: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC),
	}
	if !matchesSearch(msg, 1, dateCriteria) {
		t.Error("expected Oct 20 to match Since Oct 19")
	}
}

func TestIMAPServerInit(t *testing.T) {
	cfg := &config.Config{
		IMAPAddr: ":1143",
	}
	s, err := NewServer(nil, cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if s.addr != ":1143" {
		t.Errorf("expected addr :1143, got %s", s.addr)
	}
}

func TestSessionRequireAuthAndSelected(t *testing.T) {
	sess := &session{}
	if err := sess.requireAuth(); err == nil {
		t.Error("expected requireAuth to return error when unauthenticated")
	}
	if err := sess.requireSelected(); err == nil {
		t.Error("expected requireSelected to return error when unselected")
	}

	// All session methods requiring auth should fail cleanly
	if _, err := sess.Select("INBOX", nil); err == nil {
		t.Error("expected error for unauthenticated Select")
	}
	if err := sess.Create("Test", nil); err == nil {
		t.Error("expected error for unauthenticated Create")
	}
	if err := sess.Delete("Test"); err == nil {
		t.Error("expected error for unauthenticated Delete")
	}
	if err := sess.Rename("Test", "Test2", nil); err == nil {
		t.Error("expected error for unauthenticated Rename")
	}
	if err := sess.Subscribe("Test"); err == nil {
		t.Error("expected error for unauthenticated Subscribe")
	}
	if err := sess.Unsubscribe("Test"); err == nil {
		t.Error("expected error for unauthenticated Unsubscribe")
	}
	if err := sess.List(nil, "", nil, nil); err == nil {
		t.Error("expected error for unauthenticated List")
	}
	if _, err := sess.Status("INBOX", nil); err == nil {
		t.Error("expected error for unauthenticated Status")
	}
	if _, err := sess.Append("INBOX", strings.NewReader(""), nil); err == nil {
		t.Error("expected error for unauthenticated Append")
	}
	if err := sess.Unselect(); err != nil {
		t.Errorf("unexpected error on Unselect: %v", err)
	}
	if err := sess.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
	if err := sess.Poll(nil, false); err != nil {
		t.Errorf("unexpected error on Poll when unselected: %v", err)
	}
}

func TestSessionLivePostgres(t *testing.T) {
	connURL := "postgres://mailhost:mailhost_secret@localhost:5433/mailhost?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, connURL, 5)
	if err != nil {
		t.Skipf("skipping live imap postgres test (port 5433 unavailable): %v", err)
		return
	}
	defer pool.Close()

	accountID := uuid.New().String()
	_, err = pool.Exec(ctx, `INSERT INTO accounts (id, name) VALUES ($1, 'IMAP Account')`, accountID)
	if err != nil {
		t.Fatalf("failed to insert test account: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM accounts WHERE id = $1`, accountID)

	email := "imap-" + accountID[:8] + "@example.com"
	sess := &session{
		db:   pool,
		user: &mailbox.AuthUser{AccountID: accountID, Email: email},
	}

	// 1. Select INBOX
	selData, err := sess.Select("INBOX", nil)
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	if selData == nil {
		t.Fatal("expected non-nil SelectData")
	}

	// 2. Status
	stData, err := sess.Status("INBOX", nil)
	if err != nil || stData == nil {
		t.Fatalf("Status failed: data=%+v, err=%v", stData, err)
	}

	// 3. Create, Rename, and Delete folder
	if err := sess.Create("CustomFolder", nil); err != nil {
		t.Fatalf("Create folder failed: %v", err)
	}
	if err := sess.Rename("CustomFolder", "RenamedFolder", nil); err != nil {
		t.Fatalf("Rename folder failed: %v", err)
	}
	if err := sess.Delete("RenamedFolder"); err != nil {
		t.Fatalf("Delete folder failed: %v", err)
	}

	// 4. Append message
	rawMsg := strings.NewReader("Subject: IMAP Append\r\n\r\nHello IMAP!")
	appData, err := sess.Append("INBOX", rawMsg, &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
		Time:  time.Now(),
	})
	if err != nil || appData == nil {
		t.Fatalf("Append failed: data=%+v, err=%v", appData, err)
	}

	// 5. Subscribe / Unsubscribe
	if err := sess.Subscribe("INBOX"); err != nil {
		t.Errorf("Subscribe failed: %v", err)
	}
	if err := sess.Unsubscribe("INBOX"); err != nil {
		t.Errorf("Unsubscribe failed: %v", err)
	}

	// 6. Poll with selected mailbox when message count is unchanged
	sess.lastNumMessages = 1
	if err := sess.Poll(nil, false); err != nil {
		t.Errorf("Poll failed: %v", err)
	}


	// 7. Unselect
	if err := sess.Unselect(); err != nil {
		t.Errorf("Unselect failed: %v", err)
	}
}


