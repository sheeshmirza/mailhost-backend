package imap

import (
	"log/slog"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"mailhost/internal/config"
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
}

