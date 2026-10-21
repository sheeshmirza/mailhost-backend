package imap

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
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

	// 7. Search
	sData, err := sess.Search(imapserver.NumKindSeq, &imap.SearchCriteria{Flag: []imap.Flag{imap.FlagSeen}}, nil)
	if err != nil || sData == nil {
		t.Errorf("Search failed: %v", err)
	}

	// 8. Copy to Custom
	if _, err := sess.Copy(imap.SeqSetNum(1), "INBOX"); err != nil {
		t.Errorf("Copy failed: %v", err)
	}

	// 9. AppendLimit
	_ = sess.AppendLimit()

	// 10. Unselect & Unauthenticate
	if err := sess.Unselect(); err != nil {
		t.Errorf("Unselect failed: %v", err)
	}
	if err := sess.Unauthenticate(); err != nil {
		t.Errorf("Unauthenticate failed: %v", err)
	}
}

func TestIMAPProtocolLive(t *testing.T) {
	connURL := "postgres://mailhost:mailhost_secret@localhost:5433/mailhost?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, connURL, 5)
	if err != nil {
		t.Skipf("skipping live imap postgres test: %v", err)
		return
	}
	defer pool.Close()

	accountID := uuid.New().String()
	_, err = pool.Exec(ctx, `INSERT INTO accounts (id, name) VALUES ($1, 'IMAP Live Account')`, accountID)
	if err != nil {
		t.Fatalf("failed to insert test account: %v", err)
		return
	}
	defer pool.Exec(context.Background(), `DELETE FROM accounts WHERE id = $1`, accountID)

	rawKey := "imap_live_key_" + accountID[:8]
	h := sha256.Sum256([]byte(rawKey))
	_, err = pool.Exec(ctx, `INSERT INTO api_keys (account_id, key_hash, name, permission) VALUES ($1, $2, 'IMAP Test Key', 'full_access')`, accountID, h[:])
	if err != nil {
		t.Fatalf("failed to insert api key: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	srv, err := NewServer(pool, &config.Config{IMAPAddr: ln.Addr().String()}, slog.Default())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	go srv.Server.Serve(ln)
	defer srv.Server.Close()

	// Connect client
	client, err := imapclient.DialInsecure(ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("DialInsecure failed: %v", err)
	}
	defer client.Close()

	// Login using api username and rawKey
	if err := client.Login("api", rawKey).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// List
	if _, err := client.List("", "*", nil).Collect(); err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Append a message to INBOX
	msgText := "Subject: Hello IMAP Live\r\n\r\nThis is an IMAP live body."
	appCmd := client.Append("INBOX", int64(len(msgText)), &imap.AppendOptions{Flags: []imap.Flag{imap.FlagSeen}})
	if _, err := appCmd.Write([]byte(msgText)); err != nil {
		t.Fatalf("Append write failed: %v", err)
	}
	if err := appCmd.Close(); err != nil {
		t.Fatalf("Append close failed: %v", err)
	}
	if _, err := appCmd.Wait(); err != nil {
		t.Fatalf("Append wait failed: %v", err)
	}

	// Select INBOX
	selData, err := client.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select failed: %v", err)
	}
	if selData.NumMessages == 0 {
		t.Errorf("expected at least 1 message in INBOX")
	}

	// Fetch message
	fetchCmd := client.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		Flags:        true,
		UID:          true,
		RFC822Size:   true,
		InternalDate: true,
		Envelope:     true,
	})
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if len(msgs) == 0 {
		t.Errorf("expected 1 fetch message, got 0")
	}

	// Store flags
	if err := client.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagFlagged},
	}, nil).Wait(); err != nil {
		t.Fatalf("Store flags failed: %v", err)
	}

	// Create and Copy to Archive
	if err := client.Create("Archive", nil).Wait(); err != nil {
		t.Fatalf("Create Archive failed: %v", err)
	}
	if _, err := client.Copy(imap.SeqSetNum(1), "Archive").Wait(); err != nil {
		t.Fatalf("Copy failed: %v", err)
	}

	// Move to Archive
	if _, err := client.Move(imap.SeqSetNum(1), "Archive").Wait(); err != nil {
		t.Logf("Move note: %v", err)
	}

	// Search
	searchRes, err := client.Search(&imap.SearchCriteria{Flag: []imap.Flag{imap.FlagSeen}}, nil).Wait()
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	_ = searchRes

	// Mark deleted and Expunge
	_ = client.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Wait()
	_ = client.Expunge().Collect()

	// Status on Archive
	if _, err := client.Status("Archive", &imap.StatusOptions{NumMessages: true}).Wait(); err != nil {
		t.Fatalf("Status failed: %v", err)
	}

	_ = client.Logout().Wait()
}


