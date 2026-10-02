// Package mailbox provides storage, authentication, and mailbox management
// for IMAP and POP3 client protocols.
package mailbox

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// AuthUser represents an authenticated email user.
type AuthUser struct {
	AccountID string
	DomainID  string
	Email     string
}

// Mailbox represents a named folder belonging to an email account.
type Mailbox struct {
	ID          uuid.UUID
	AccountID   uuid.UUID
	Email       string
	Name        string
	UIDValidity uint32
	NextUID     uint32
	CreatedAt   time.Time
}

// Message represents an email message stored in a mailbox.
type Message struct {
	ID        uuid.UUID
	MailboxID uuid.UUID
	UID       uint32
	Size      int
	Flags     []string
	Date      time.Time
	Raw       []byte
	CreatedAt time.Time
}

func verifyCredentialPassword(stored []byte, password string) bool {
	if len(stored) == 48 {
		salt := stored[:16]
		expected := stored[16:]
		h := sha256.New()
		h.Write(salt)
		h.Write([]byte(password))
		computed := h.Sum(nil)
		return subtle.ConstantTimeCompare(expected, computed) == 1
	}
	if len(stored) == 32 {
		computed := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(stored, computed[:]) == 1
	}
	return false
}

// Authenticate verifies user credentials against smtp_credentials and users.
func Authenticate(ctx context.Context, db *pgxpool.Pool, username, password string) (*AuthUser, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" || db == nil {
		return nil, errors.New("invalid credentials")
	}

	// 1. Try smtp_credentials
	rows, err := db.Query(ctx, `
SELECT sc.account_id, sc.domain_id, sc.email, sc.password_hash
FROM smtp_credentials sc
JOIN domains d ON d.id = sc.domain_id
WHERE lower(sc.email) = lower($1)
  AND d.status = 'verified'`, username)
	if err == nil {
		for rows.Next() {
			var acctID, domID, email string
			var storedHash []byte
			if scanErr := rows.Scan(&acctID, &domID, &email, &storedHash); scanErr == nil && verifyCredentialPassword(storedHash, password) {
				rows.Close()
				go db.Exec(context.Background(), `UPDATE smtp_credentials SET last_used_at = now() WHERE lower(email) = lower($1)`, username)
				return &AuthUser{AccountID: acctID, DomainID: domID, Email: email}, nil
			}
		}
		rows.Close()
	}

	// 2. Try users table
	var userID, acctID, userEmail, pwHash string
	err = db.QueryRow(ctx, `
SELECT u.id, om.account_id, u.email, u.password_hash
FROM users u
JOIN organization_members om ON om.user_id = u.id
WHERE lower(u.email) = lower($1)
LIMIT 1`, username).Scan(&userID, &acctID, &userEmail, &pwHash)
	if err == nil && bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(password)) == nil {
		return &AuthUser{AccountID: acctID, Email: userEmail}, nil
	}

	// 3. Fallback: API key authentication
	if strings.EqualFold(username, "api") || strings.EqualFold(username, "mailhost") || strings.EqualFold(username, "resend") {
		hash := sha256.Sum256([]byte(password))
		var aID, domainID string
		var storedKeyHash []byte
		err := db.QueryRow(ctx, `SELECT account_id, COALESCE(domain_id::text, ''), key_hash FROM api_keys WHERE key_hash = $1`, hash[:]).Scan(&aID, &domainID, &storedKeyHash)
		if err == nil && subtle.ConstantTimeCompare(storedKeyHash, hash[:]) == 1 {
			return &AuthUser{AccountID: aID, DomainID: domainID, Email: "api@" + aID}, nil
		}
	}

	return nil, errors.New("authentication failed")
}

// GetOrCreateMailbox retrieves or creates a mailbox folder.
func GetOrCreateMailbox(ctx context.Context, db *pgxpool.Pool, accountID, email, name string) (*Mailbox, error) {
	if name == "" {
		name = "INBOX"
	}
	email = strings.ToLower(strings.TrimSpace(email))
	acctUUID, err := uuid.Parse(accountID)
	if err != nil {
		return nil, err
	}

	mb := &Mailbox{
		AccountID: acctUUID,
		Email:     email,
		Name:      name,
	}

	err = db.QueryRow(ctx, `
SELECT id, uid_validity, next_uid, created_at
FROM mailboxes
WHERE account_id = $1 AND lower(email) = $2 AND lower(name) = lower($3)`,
		acctUUID, email, name).Scan(&mb.ID, &mb.UIDValidity, &mb.NextUID, &mb.CreatedAt)
	if err == nil {
		return mb, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	mb.UIDValidity = uint32(time.Now().Unix())
	mb.NextUID = 1
	err = db.QueryRow(ctx, `
INSERT INTO mailboxes (account_id, email, name, uid_validity, next_uid)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (account_id, email, name) DO UPDATE SET next_uid = mailboxes.next_uid
RETURNING id, uid_validity, next_uid, created_at`,
		acctUUID, email, name, mb.UIDValidity, mb.NextUID).Scan(&mb.ID, &mb.UIDValidity, &mb.NextUID, &mb.CreatedAt)
	if err != nil {
		return nil, err
	}
	return mb, nil
}

// ListMailboxes returns all mailboxes for an email account.
func ListMailboxes(ctx context.Context, db *pgxpool.Pool, accountID, email string) ([]Mailbox, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	acctUUID, err := uuid.Parse(accountID)
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(ctx, `
SELECT id, account_id, email, name, uid_validity, next_uid, created_at
FROM mailboxes
WHERE account_id = $1 AND lower(email) = $2
ORDER BY CASE WHEN lower(name) = 'inbox' THEN 0 ELSE 1 END, name ASC`,
		acctUUID, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mbs []Mailbox
	for rows.Next() {
		var mb Mailbox
		if err := rows.Scan(&mb.ID, &mb.AccountID, &mb.Email, &mb.Name, &mb.UIDValidity, &mb.NextUID, &mb.CreatedAt); err != nil {
			return nil, err
		}
		mbs = append(mbs, mb)
	}

	// Always ensure INBOX exists
	if len(mbs) == 0 {
		inbox, err := GetOrCreateMailbox(ctx, db, accountID, email, "INBOX")
		if err == nil && inbox != nil {
			mbs = append(mbs, *inbox)
		}
	}
	return mbs, nil
}

// CreateMailbox creates a new user folder.
func CreateMailbox(ctx context.Context, db *pgxpool.Pool, accountID, email, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("mailbox name cannot be empty")
	}
	_, err := GetOrCreateMailbox(ctx, db, accountID, email, name)
	return err
}

// DeleteMailbox deletes a user folder (INBOX cannot be deleted).
func DeleteMailbox(ctx context.Context, db *pgxpool.Pool, accountID, email, name string) error {
	if strings.EqualFold(name, "INBOX") {
		return errors.New("cannot delete INBOX")
	}
	acctUUID, err := uuid.Parse(accountID)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `
DELETE FROM mailboxes WHERE account_id = $1 AND lower(email) = lower($2) AND lower(name) = lower($3)`,
		acctUUID, strings.ToLower(email), name)
	return err
}

// RenameMailbox renames a user folder.
func RenameMailbox(ctx context.Context, db *pgxpool.Pool, accountID, email, oldName, newName string) error {
	if strings.EqualFold(oldName, "INBOX") {
		return errors.New("cannot rename INBOX")
	}
	acctUUID, err := uuid.Parse(accountID)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `
UPDATE mailboxes SET name = $4 WHERE account_id = $1 AND lower(email) = lower($2) AND lower(name) = lower($3)`,
		acctUUID, strings.ToLower(email), oldName, newName)
	return err
}

// DeliverMessage delivers an email into a mailbox, allocating a sequential UID.
func DeliverMessage(ctx context.Context, db *pgxpool.Pool, accountID, email, mailboxName string, raw []byte, flags []string, date time.Time) (*Message, error) {
	if db == nil {
		return nil, errors.New("database not available")
	}
	mb, err := GetOrCreateMailbox(ctx, db, accountID, email, mailboxName)
	if err != nil {
		return nil, err
	}

	if date.IsZero() {
		date = time.Now()
	}
	if flags == nil {
		flags = []string{}
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var nextUID uint32
	err = tx.QueryRow(ctx, `
UPDATE mailboxes SET next_uid = next_uid + 1 WHERE id = $1 RETURNING next_uid - 1`, mb.ID).Scan(&nextUID)
	if err != nil {
		return nil, err
	}

	msg := &Message{
		ID:        uuid.New(),
		MailboxID: mb.ID,
		UID:       nextUID,
		Size:      len(raw),
		Flags:     flags,
		Date:      date,
		Raw:       raw,
		CreatedAt: time.Now(),
	}

	_, err = tx.Exec(ctx, `
INSERT INTO mailbox_messages (id, mailbox_id, uid, size, flags, date, raw, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		msg.ID, msg.MailboxID, msg.UID, msg.Size, msg.Flags, msg.Date, msg.Raw, msg.CreatedAt)
	if err != nil {
		return nil, err
	}

	return msg, tx.Commit(ctx)
}

// GetMessages returns all messages in a mailbox ordered by UID.
func GetMessages(ctx context.Context, db *pgxpool.Pool, mailboxID uuid.UUID) ([]Message, error) {
	rows, err := db.Query(ctx, `
SELECT id, mailbox_id, uid, size, flags, date, raw, created_at
FROM mailbox_messages
WHERE mailbox_id = $1
ORDER BY uid ASC`, mailboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.MailboxID, &m.UID, &m.Size, &m.Flags, &m.Date, &m.Raw, &m.CreatedAt); err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	return msgs, nil
}

// GetMessageByUID retrieves a single message by its UID.
func GetMessageByUID(ctx context.Context, db *pgxpool.Pool, mailboxID uuid.UUID, uid uint32) (*Message, error) {
	var m Message
	err := db.QueryRow(ctx, `
SELECT id, mailbox_id, uid, size, flags, date, raw, created_at
FROM mailbox_messages
WHERE mailbox_id = $1 AND uid = $2`, mailboxID, uid).Scan(&m.ID, &m.MailboxID, &m.UID, &m.Size, &m.Flags, &m.Date, &m.Raw, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// FlagOp specifies flag modification operation.
type FlagOp int

const (
	FlagOpSet FlagOp = iota
	FlagOpAdd
	FlagOpRemove
)

// UpdateFlags modifies flags for a set of message UIDs.
func UpdateFlags(ctx context.Context, db *pgxpool.Pool, mailboxID uuid.UUID, uids []uint32, flags []string, op FlagOp) error {
	if len(uids) == 0 {
		return nil
	}
	switch op {
	case FlagOpSet:
		_, err := db.Exec(ctx, `
UPDATE mailbox_messages
SET flags = $3
WHERE mailbox_id = $1 AND uid = ANY($2)`, mailboxID, uids, flags)
		return err
	case FlagOpAdd:
		_, err := db.Exec(ctx, `
UPDATE mailbox_messages
SET flags = ARRAY(SELECT DISTINCT unnest(flags || $3))
WHERE mailbox_id = $1 AND uid = ANY($2)`, mailboxID, uids, flags)
		return err
	case FlagOpRemove:
		_, err := db.Exec(ctx, `
UPDATE mailbox_messages
SET flags = ARRAY(SELECT unnest(flags) EXCEPT SELECT unnest($3::text[]))
WHERE mailbox_id = $1 AND uid = ANY($2)`, mailboxID, uids, flags)
		return err
	}
	return nil
}

// ExpungeDeleted removes messages that have the `\Deleted` flag.
func ExpungeDeleted(ctx context.Context, db *pgxpool.Pool, mailboxID uuid.UUID, specificUIDs []uint32) ([]uint32, error) {
	var rows pgx.Rows
	var err error
	if len(specificUIDs) > 0 {
		rows, err = db.Query(ctx, `
DELETE FROM mailbox_messages
WHERE mailbox_id = $1 AND uid = ANY($2) AND $3 = ANY(flags)
RETURNING uid`, mailboxID, specificUIDs, "\\Deleted")
	} else {
		rows, err = db.Query(ctx, `
DELETE FROM mailbox_messages
WHERE mailbox_id = $1 AND $2 = ANY(flags)
RETURNING uid`, mailboxID, "\\Deleted")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var expunged []uint32
	for rows.Next() {
		var u uint32
		if err := rows.Scan(&u); err == nil {
			expunged = append(expunged, u)
		}
	}
	return expunged, nil
}

// DeleteMessages removes messages by UID directly (used by IMAP MOVE).
func DeleteMessages(ctx context.Context, db *pgxpool.Pool, mailboxID uuid.UUID, uids []uint32) ([]uint32, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	rows, err := db.Query(ctx, `
DELETE FROM mailbox_messages
WHERE mailbox_id = $1 AND uid = ANY($2)
RETURNING uid`, mailboxID, uids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deleted []uint32
	for rows.Next() {
		var u uint32
		if err := rows.Scan(&u); err == nil {
			deleted = append(deleted, u)
		}
	}
	return deleted, nil
}

// MailboxStatus holds status metadata for IMAP/POP3.
type MailboxStatus struct {
	Messages    uint32
	Recent      uint32
	Unseen      uint32
	UIDNext     uint32
	UIDValidity uint32
	TotalSize   int64
}

// Status returns statistics for a mailbox.
func Status(ctx context.Context, db *pgxpool.Pool, mb *Mailbox) (*MailboxStatus, error) {
	st := &MailboxStatus{
		UIDNext:     mb.NextUID,
		UIDValidity: mb.UIDValidity,
	}

	var count int64
	var totalSize *int64
	var unseenCount int64

	err := db.QueryRow(ctx, `
SELECT count(*), coalesce(sum(size), 0), count(*) FILTER (WHERE NOT ($2 = ANY(flags)))
FROM mailbox_messages
WHERE mailbox_id = $1`, mb.ID, "\\Seen").Scan(&count, &totalSize, &unseenCount)
	if err != nil {
		return nil, err
	}

	st.Messages = uint32(count)
	if totalSize != nil {
		st.TotalSize = *totalSize
	}
	st.Unseen = uint32(unseenCount)
	return st, nil
}
