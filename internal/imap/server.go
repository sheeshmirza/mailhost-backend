// Package imap implements an RFC 9051 / RFC 3501 compliant IMAP4rev1/rev2 server.
package imap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	msgtextproto "github.com/emersion/go-message/textproto"
	"github.com/jackc/pgx/v5/pgxpool"

	"mailhost/internal/config"
	"mailhost/internal/mailbox"
)

// Server is an IMAP server backed by PostgreSQL.
type Server struct {
	*imapserver.Server
	db   *pgxpool.Pool
	cfg  *config.Config
	log  *slog.Logger
	addr string
}

// NewServer initializes an IMAP server with authentication and session handling.
func NewServer(db *pgxpool.Pool, cfg *config.Config, log *slog.Logger) (*Server, error) {
	s := &Server{
		db:   db,
		cfg:  cfg,
		log:  log,
		addr: cfg.IMAPAddr,
	}

	opts := &imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return &session{
				s:   s,
				db:  db,
				log: log,
			}, &imapserver.GreetingData{}, nil
		},
		InsecureAuth: false,
	}

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		opts.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	s.Server = imapserver.New(opts)
	return s, nil
}

// ListenAndServe starts the IMAP server listener.
func (s *Server) ListenAndServe() error {
	s.log.Info("imap server listening", "addr", s.addr)
	return s.Server.ListenAndServe(s.addr)
}

type session struct {
	s               *Server
	db              *pgxpool.Pool
	log             *slog.Logger
	user            *mailbox.AuthUser
	selected        *mailbox.Mailbox
	lastNumMessages uint32
}

func (sess *session) Close() error {
	return nil
}

func (sess *session) Login(username, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := mailbox.Authenticate(ctx, sess.db, username, password)
	if err != nil {
		return imapserver.ErrAuthFailed
	}
	sess.user = user
	return nil
}

func (sess *session) requireAuth() error {
	if sess.user == nil {
		return errors.New("not authenticated")
	}
	return nil
}

func (sess *session) requireSelected() error {
	if err := sess.requireAuth(); err != nil {
		return err
	}
	if sess.selected == nil {
		return errors.New("no mailbox selected")
	}
	return nil
}

var standardFlags = []imap.Flag{
	imap.FlagSeen,
	imap.FlagAnswered,
	imap.FlagFlagged,
	imap.FlagDeleted,
	imap.FlagDraft,
}

func (sess *session) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	if err := sess.requireAuth(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mb, err := mailbox.GetOrCreateMailbox(ctx, sess.db, sess.user.AccountID, sess.user.Email, name)
	if err != nil {
		return nil, err
	}
	sess.selected = mb

	st, err := mailbox.Status(ctx, sess.db, mb)
	if err != nil {
		return nil, err
	}
	sess.lastNumMessages = st.Messages

	return &imap.SelectData{
		Flags:          standardFlags,
		PermanentFlags: standardFlags,
		NumMessages:    st.Messages,
		UIDNext:        imap.UID(st.UIDNext),
		UIDValidity:    st.UIDValidity,
	}, nil
}

func (sess *session) Unselect() error {
	sess.selected = nil
	sess.lastNumMessages = 0
	return nil
}

func (sess *session) Create(name string, options *imap.CreateOptions) error {
	if err := sess.requireAuth(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return mailbox.CreateMailbox(ctx, sess.db, sess.user.AccountID, sess.user.Email, name)
}

func (sess *session) Delete(name string) error {
	if err := sess.requireAuth(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return mailbox.DeleteMailbox(ctx, sess.db, sess.user.AccountID, sess.user.Email, name)
}

func (sess *session) Rename(oldName, newName string, options *imap.RenameOptions) error {
	if err := sess.requireAuth(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return mailbox.RenameMailbox(ctx, sess.db, sess.user.AccountID, sess.user.Email, oldName, newName)
}

func (sess *session) Subscribe(name string) error   { return sess.requireAuth() }
func (sess *session) Unsubscribe(name string) error { return sess.requireAuth() }

func (sess *session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if err := sess.requireAuth(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mbs, err := mailbox.ListMailboxes(ctx, sess.db, sess.user.AccountID, sess.user.Email)
	if err != nil {
		return err
	}

	for _, mb := range mbs {
		matched := len(patterns) == 0
		for _, pat := range patterns {
			if pat == "" || pat == "*" || pat == "%" || imapserver.MatchList(mb.Name, '/', ref, pat) {
				matched = true
				break
			}
		}
		if matched {
			if err := w.WriteList(&imap.ListData{
				Mailbox: mb.Name,
				Delim:   '/',
				Attrs:   []imap.MailboxAttr{},
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (sess *session) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if err := sess.requireAuth(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mb, err := mailbox.GetOrCreateMailbox(ctx, sess.db, sess.user.AccountID, sess.user.Email, name)
	if err != nil {
		return nil, err
	}
	st, err := mailbox.Status(ctx, sess.db, mb)
	if err != nil {
		return nil, err
	}

	data := &imap.StatusData{
		Mailbox:     name,
		UIDNext:     imap.UID(st.UIDNext),
		UIDValidity: st.UIDValidity,
	}
	if options == nil || options.NumMessages {
		data.NumMessages = &st.Messages
	}
	if options == nil || options.NumUnseen {
		data.NumUnseen = &st.Unseen
	}
	if options == nil || options.Size {
		data.Size = &st.TotalSize
	}
	return data, nil
}

func (sess *session) Append(name string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	if err := sess.requireAuth(); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var flags []string
	var date time.Time
	if options != nil {
		for _, f := range options.Flags {
			flags = append(flags, string(f))
		}
		date = options.Time
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msg, err := mailbox.DeliverMessage(ctx, sess.db, sess.user.AccountID, sess.user.Email, name, raw, flags, date)
	if err != nil {
		return nil, err
	}

	mb, _ := mailbox.GetOrCreateMailbox(ctx, sess.db, sess.user.AccountID, sess.user.Email, name)
	uidVal := uint32(1)
	if mb != nil {
		uidVal = mb.UIDValidity
	}

	return &imap.AppendData{
		UID:         imap.UID(msg.UID),
		UIDValidity: uidVal,
	}, nil
}

func (sess *session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if sess.selected == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	st, err := mailbox.Status(ctx, sess.db, sess.selected)
	if err == nil && st.Messages != sess.lastNumMessages {
		sess.lastNumMessages = st.Messages
		_ = w.WriteNumMessages(st.Messages)
	}
	return nil
}

func (sess *session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return nil
		case <-ticker.C:
			_ = sess.Poll(w, false)
		}
	}
}

func (sess *session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if err := sess.requireSelected(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var specificUIDs []uint32
	if uids != nil {
		for _, r := range *uids {
			for u := r.Start; u <= r.Stop; u++ {
				specificUIDs = append(specificUIDs, uint32(u))
			}
		}
	}

	msgs, err := mailbox.GetMessages(ctx, sess.db, sess.selected.ID)
	if err != nil {
		return err
	}

	expunged, err := mailbox.ExpungeDeleted(ctx, sess.db, sess.selected.ID, specificUIDs)
	if err != nil {
		return err
	}

	expSet := make(map[uint32]bool)
	for _, u := range expunged {
		expSet[u] = true
	}

	offset := uint32(0)
	for i, m := range msgs {
		seq := uint32(i+1) - offset
		if expSet[m.UID] {
			_ = w.WriteExpunge(seq)
			offset++
		}
	}
	return nil
}

func numSetContains(numSet imap.NumSet, seqNum uint32, uid uint32) bool {
	switch s := numSet.(type) {
	case imap.SeqSet:
		return s.Contains(seqNum)
	case *imap.SeqSet:
		return s != nil && s.Contains(seqNum)
	case imap.UIDSet:
		return s.Contains(imap.UID(uid))
	case *imap.UIDSet:
		return s != nil && s.Contains(imap.UID(uid))
	}
	return false
}

func matchesSearch(m *mailbox.Message, seqNum uint32, c *imap.SearchCriteria) bool {
	if c == nil {
		return true
	}
	for _, s := range c.SeqNum {
		if !s.Contains(seqNum) {
			return false
		}
	}
	for _, u := range c.UID {
		if !u.Contains(imap.UID(m.UID)) {
			return false
		}
	}
	msgFlags := make(map[string]bool)
	for _, f := range m.Flags {
		msgFlags[strings.ToLower(f)] = true
	}
	for _, f := range c.Flag {
		if !msgFlags[strings.ToLower(string(f))] {
			return false
		}
	}
	for _, f := range c.NotFlag {
		if msgFlags[strings.ToLower(string(f))] {
			return false
		}
	}
	if !c.Since.IsZero() && m.Date.Before(c.Since) {
		return false
	}
	if !c.Before.IsZero() && m.Date.After(c.Before) {
		return false
	}
	if c.Larger > 0 && int64(m.Size) <= c.Larger {
		return false
	}
	if c.Smaller > 0 && int64(m.Size) >= c.Smaller {
		return false
	}
	return true
}

func (sess *session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	if err := sess.requireSelected(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msgs, err := mailbox.GetMessages(ctx, sess.db, sess.selected.ID)
	if err != nil {
		return nil, err
	}

	var seqs []uint32
	var uids []imap.UID

	for i, m := range msgs {
		seq := uint32(i + 1)
		if matchesSearch(&m, seq, criteria) {
			seqs = append(seqs, seq)
			uids = append(uids, imap.UID(m.UID))
		}
	}

	var all imap.NumSet
	if kind == imapserver.NumKindSeq {
		all = imap.SeqSetNum(seqs...)
	} else {
		all = imap.UIDSetNum(uids...)
	}

	return &imap.SearchData{All: all}, nil
}

func (sess *session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	if err := sess.requireSelected(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msgs, err := mailbox.GetMessages(ctx, sess.db, sess.selected.ID)
	if err != nil {
		return err
	}

	for i, m := range msgs {
		seq := uint32(i + 1)
		if !numSetContains(numSet, seq, m.UID) {
			continue
		}

		resp := w.CreateMessage(seq)
		if options.Flags {
			var flags []imap.Flag
			for _, f := range m.Flags {
				flags = append(flags, imap.Flag(f))
			}
			resp.WriteFlags(flags)
		}
		if options.UID {
			resp.WriteUID(imap.UID(m.UID))
		}
		if options.InternalDate {
			resp.WriteInternalDate(m.Date)
		}
		if options.RFC822Size {
			resp.WriteRFC822Size(int64(m.Size))
		}
		if options.Envelope {
			msg, err := mail.ReadMessage(bytes.NewReader(m.Raw))
			if err == nil {
				h := msgtextproto.HeaderFromMap(map[string][]string(msg.Header))
				env := imapserver.ExtractEnvelope(h)
				resp.WriteEnvelope(env)
			}
		}
		if options.BodyStructure != nil {
			bs := imapserver.ExtractBodyStructure(bytes.NewReader(m.Raw))
			resp.WriteBodyStructure(bs)
		}
		for _, bs := range options.BodySection {
			body := imapserver.ExtractBodySection(bytes.NewReader(m.Raw), bs)
			wc := resp.WriteBodySection(bs, int64(len(body)))
			if wc != nil {
				_, _ = wc.Write(body)
				_ = wc.Close()
			}
		}
		_ = resp.Close()
	}
	return nil
}

func (sess *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, storeFlags *imap.StoreFlags, options *imap.StoreOptions) error {
	if err := sess.requireSelected(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msgs, err := mailbox.GetMessages(ctx, sess.db, sess.selected.ID)
	if err != nil {
		return err
	}

	var targetUIDs []uint32
	for i, m := range msgs {
		seq := uint32(i + 1)
		if numSetContains(numSet, seq, m.UID) {
			targetUIDs = append(targetUIDs, m.UID)
		}
	}

	if len(targetUIDs) > 0 {
		var flagStrings []string
		for _, f := range storeFlags.Flags {
			flagStrings = append(flagStrings, string(f))
		}
		var op mailbox.FlagOp
		switch storeFlags.Op {
		case imap.StoreFlagsSet:
			op = mailbox.FlagOpSet
		case imap.StoreFlagsAdd:
			op = mailbox.FlagOpAdd
		case imap.StoreFlagsDel:
			op = mailbox.FlagOpRemove
		}
		if err := mailbox.UpdateFlags(ctx, sess.db, sess.selected.ID, targetUIDs, flagStrings, op); err != nil {
			return err
		}
	}

	if storeFlags != nil && storeFlags.Silent {
		return nil
	}

	// Re-fetch updated messages to return modified flags
	updated, err := mailbox.GetMessages(ctx, sess.db, sess.selected.ID)
	if err != nil {
		return nil
	}
	for i, m := range updated {
		seq := uint32(i + 1)
		if numSetContains(numSet, seq, m.UID) {
			resp := w.CreateMessage(seq)
			var flags []imap.Flag
			for _, f := range m.Flags {
				flags = append(flags, imap.Flag(f))
			}
			resp.WriteFlags(flags)
			_ = resp.Close()
		}
	}
	return nil
}

func (sess *session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	if err := sess.requireSelected(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	destMB, err := mailbox.GetOrCreateMailbox(ctx, sess.db, sess.user.AccountID, sess.user.Email, dest)
	if err != nil {
		return nil, err
	}

	msgs, err := mailbox.GetMessages(ctx, sess.db, sess.selected.ID)
	if err != nil {
		return nil, err
	}

	var srcUIDs []imap.UID
	var dstUIDs []imap.UID

	for i, m := range msgs {
		seq := uint32(i + 1)
		if numSetContains(numSet, seq, m.UID) {
			newMsg, err := mailbox.DeliverMessage(ctx, sess.db, sess.user.AccountID, sess.user.Email, destMB.Name, m.Raw, m.Flags, m.Date)
			if err == nil {
				srcUIDs = append(srcUIDs, imap.UID(m.UID))
				dstUIDs = append(dstUIDs, imap.UID(newMsg.UID))
			}
		}
	}

	return &imap.CopyData{
		UIDValidity: destMB.UIDValidity,
		SourceUIDs:  imap.UIDSetNum(srcUIDs...),
		DestUIDs:    imap.UIDSetNum(dstUIDs...),
	}, nil
}

func (sess *session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	if err := sess.requireSelected(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	destMB, err := mailbox.GetOrCreateMailbox(ctx, sess.db, sess.user.AccountID, sess.user.Email, dest)
	if err != nil {
		return err
	}

	msgs, err := mailbox.GetMessages(ctx, sess.db, sess.selected.ID)
	if err != nil {
		return err
	}

	var srcUIDs []imap.UID
	var dstUIDs []imap.UID
	var movedUIDs []uint32

	for i, m := range msgs {
		seq := uint32(i + 1)
		if numSetContains(numSet, seq, m.UID) {
			newMsg, err := mailbox.DeliverMessage(ctx, sess.db, sess.user.AccountID, sess.user.Email, destMB.Name, m.Raw, m.Flags, m.Date)
			if err == nil {
				srcUIDs = append(srcUIDs, imap.UID(m.UID))
				dstUIDs = append(dstUIDs, imap.UID(newMsg.UID))
				movedUIDs = append(movedUIDs, m.UID)
			}
		}
	}

	copyData := &imap.CopyData{
		UIDValidity: destMB.UIDValidity,
		SourceUIDs:  imap.UIDSetNum(srcUIDs...),
		DestUIDs:    imap.UIDSetNum(dstUIDs...),
	}
	if err := w.WriteCopyData(copyData); err != nil {
		return err
	}

	if len(movedUIDs) == 0 {
		return nil
	}

	deleted, err := mailbox.DeleteMessages(ctx, sess.db, sess.selected.ID, movedUIDs)
	if err != nil {
		return err
	}

	delSet := make(map[uint32]bool)
	for _, u := range deleted {
		delSet[u] = true
	}

	offset := uint32(0)
	for i, m := range msgs {
		seq := uint32(i+1) - offset
		if delSet[m.UID] {
			if err := w.WriteExpunge(seq); err != nil {
				return err
			}
			offset++
		}
	}
	return nil
}

func (sess *session) AppendLimit() uint32 {
	if sess.s != nil && sess.s.cfg != nil && sess.s.cfg.MaxMessageBytes > 0 {
		return uint32(sess.s.cfg.MaxMessageBytes)
	}
	return 50 * 1024 * 1024
}

func (sess *session) Unauthenticate() error {
	sess.user = nil
	sess.selected = nil
	sess.lastNumMessages = 0
	return nil
}

var (
	_ imapserver.Session               = (*session)(nil)
	_ imapserver.SessionMove           = (*session)(nil)
	_ imapserver.SessionAppendLimit    = (*session)(nil)
	_ imapserver.SessionUnauthenticate = (*session)(nil)
)

