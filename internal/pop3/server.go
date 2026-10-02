// Package pop3 implements an RFC 1939 compliant POP3 server with STLS support.
package pop3

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"mailhost/internal/config"
	"mailhost/internal/mailbox"
)

// Server is an RFC 1939 POP3 server.
type Server struct {
	db        *pgxpool.Pool
	cfg       *config.Config
	log       *slog.Logger
	addr      string
	tlsConfig *tls.Config
	listener  net.Listener
	mu        sync.Mutex
	closed    bool
}

// NewServer constructs a new POP3 server.
func NewServer(db *pgxpool.Pool, cfg *config.Config, log *slog.Logger) (*Server, error) {
	s := &Server{
		db:   db,
		cfg:  cfg,
		log:  log,
		addr: cfg.POP3Addr,
	}

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		s.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}
	return s, nil
}

// ListenAndServe starts the POP3 network listener.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	s.log.Info("pop3 server listening", "addr", s.addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go s.handleConn(conn)
	}
}

// Close gracefully closes the POP3 listener.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

type pop3State int

const (
	stateAuth pop3State = iota
	stateTransaction
	stateUpdate
)

type pop3Msg struct {
	msg     mailbox.Message
	deleted bool
}

type session struct {
	s        *Server
	conn     net.Conn
	tp       *textproto.Conn
	state    pop3State
	username string
	user     *mailbox.AuthUser
	mb       *mailbox.Mailbox
	msgs     []pop3Msg
	isTLS    bool
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	sess := &session{
		s:     s,
		conn:  conn,
		tp:    textproto.NewConn(conn),
		state: stateAuth,
	}

	_ = sess.tp.PrintfLine("+OK Mailhost POP3 server ready")
	for {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
		line, err := sess.tp.ReadLine()
		if err != nil {
			return
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToUpper(parts[0])
		args := parts[1:]

		if sess.handleCommand(cmd, args) {
			return
		}
	}
}

func (sess *session) handleCommand(cmd string, args []string) (quit bool) {
	switch cmd {
	case "CAPA":
		_ = sess.tp.PrintfLine("+OK Capability list follows")
		_ = sess.tp.PrintfLine("USER")
		_ = sess.tp.PrintfLine("UIDL")
		_ = sess.tp.PrintfLine("TOP")
		_ = sess.tp.PrintfLine("RESP-CODES")
		if sess.s.tlsConfig != nil && !sess.isTLS {
			_ = sess.tp.PrintfLine("STLS")
		}
		_ = sess.tp.PrintfLine("IMPLEMENTATION Mailhost-POP3")
		_ = sess.tp.PrintfLine(".")

	case "STLS":
		if sess.state != stateAuth {
			_ = sess.tp.PrintfLine("-ERR command only valid in AUTHORIZATION state")
			return false
		}
		if sess.isTLS {
			_ = sess.tp.PrintfLine("-ERR already in TLS mode")
			return false
		}
		if sess.s.tlsConfig == nil {
			_ = sess.tp.PrintfLine("-ERR TLS not configured on server")
			return false
		}
		_ = sess.tp.PrintfLine("+OK Begin TLS negotiation")
		tlsConn := tls.Server(sess.conn, sess.s.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return true
		}
		sess.conn = tlsConn
		sess.tp = textproto.NewConn(tlsConn)
		sess.isTLS = true

	case "QUIT":
		if sess.state == stateTransaction {
			sess.state = stateUpdate
			sess.expunge()
		}
		_ = sess.tp.PrintfLine("+OK Mailhost POP3 server signing off")
		return true

	case "USER":
		if sess.state != stateAuth {
			_ = sess.tp.PrintfLine("-ERR command only valid in AUTHORIZATION state")
			return false
		}
		if len(args) == 0 {
			_ = sess.tp.PrintfLine("-ERR missing username")
			return false
		}
		sess.username = args[0]
		_ = sess.tp.PrintfLine("+OK User accepted, send PASS")

	case "PASS":
		if sess.state != stateAuth {
			_ = sess.tp.PrintfLine("-ERR command only valid in AUTHORIZATION state")
			return false
		}
		if !sess.isTLS {
			_ = sess.tp.PrintfLine("-ERR TLS is required before authentication")
			return false
		}
		if sess.username == "" {
			_ = sess.tp.PrintfLine("-ERR send USER first")
			return false
		}
		password := ""
		if len(args) > 0 {
			password = strings.Join(args, " ")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		user, err := mailbox.Authenticate(ctx, sess.s.db, sess.username, password)
		if err != nil {
			_ = sess.tp.PrintfLine("-ERR invalid credentials")
			return false
		}

		mb, err := mailbox.GetOrCreateMailbox(ctx, sess.s.db, user.AccountID, user.Email, "INBOX")
		if err != nil {
			_ = sess.tp.PrintfLine("-ERR failed to access mailbox")
			return false
		}

		dbMsgs, err := mailbox.GetMessages(ctx, sess.s.db, mb.ID)
		if err != nil {
			_ = sess.tp.PrintfLine("-ERR failed to load messages")
			return false
		}

		sess.user = user
		sess.mb = mb
		sess.msgs = make([]pop3Msg, len(dbMsgs))
		for i, m := range dbMsgs {
			sess.msgs[i] = pop3Msg{msg: m}
		}

		sess.state = stateTransaction
		totalSize := 0
		for _, m := range sess.msgs {
			totalSize += m.msg.Size
		}
		_ = sess.tp.PrintfLine("+OK Mailbox open, %d messages (%d octets)", len(sess.msgs), totalSize)

	case "STAT":
		if sess.state != stateTransaction {
			_ = sess.tp.PrintfLine("-ERR command only valid in TRANSACTION state")
			return false
		}
		count, size := 0, 0
		for _, m := range sess.msgs {
			if !m.deleted {
				count++
				size += m.msg.Size
			}
		}
		_ = sess.tp.PrintfLine("+OK %d %d", count, size)

	case "LIST":
		if sess.state != stateTransaction {
			_ = sess.tp.PrintfLine("-ERR command only valid in TRANSACTION state")
			return false
		}
		if len(args) > 0 {
			num, err := strconv.Atoi(args[0])
			if err != nil || num < 1 || num > len(sess.msgs) || sess.msgs[num-1].deleted {
				_ = sess.tp.PrintfLine("-ERR no such message")
				return false
			}
			_ = sess.tp.PrintfLine("+OK %d %d", num, sess.msgs[num-1].msg.Size)
		} else {
			count, size := 0, 0
			for _, m := range sess.msgs {
				if !m.deleted {
					count++
					size += m.msg.Size
				}
			}
			_ = sess.tp.PrintfLine("+OK %d messages (%d octets)", count, size)
			for i, m := range sess.msgs {
				if !m.deleted {
					_ = sess.tp.PrintfLine("%d %d", i+1, m.msg.Size)
				}
			}
			_ = sess.tp.PrintfLine(".")
		}

	case "UIDL":
		if sess.state != stateTransaction {
			_ = sess.tp.PrintfLine("-ERR command only valid in TRANSACTION state")
			return false
		}
		if len(args) > 0 {
			num, err := strconv.Atoi(args[0])
			if err != nil || num < 1 || num > len(sess.msgs) || sess.msgs[num-1].deleted {
				_ = sess.tp.PrintfLine("-ERR no such message")
				return false
			}
			_ = sess.tp.PrintfLine("+OK %d %d", num, sess.msgs[num-1].msg.UID)
		} else {
			_ = sess.tp.PrintfLine("+OK unique-id listing follows")
			for i, m := range sess.msgs {
				if !m.deleted {
					_ = sess.tp.PrintfLine("%d %d", i+1, m.msg.UID)
				}
			}
			_ = sess.tp.PrintfLine(".")
		}

	case "RETR":
		if sess.state != stateTransaction {
			_ = sess.tp.PrintfLine("-ERR command only valid in TRANSACTION state")
			return false
		}
		if len(args) == 0 {
			_ = sess.tp.PrintfLine("-ERR message number required")
			return false
		}
		num, err := strconv.Atoi(args[0])
		if err != nil || num < 1 || num > len(sess.msgs) || sess.msgs[num-1].deleted {
			_ = sess.tp.PrintfLine("-ERR no such message")
			return false
		}

		m := sess.msgs[num-1].msg
		_ = sess.tp.PrintfLine("+OK %d octets", m.Size)
		sess.sendDotStuffed(m.Raw)

	case "TOP":
		if sess.state != stateTransaction {
			_ = sess.tp.PrintfLine("-ERR command only valid in TRANSACTION state")
			return false
		}
		if len(args) < 2 {
			_ = sess.tp.PrintfLine("-ERR message number and line count required")
			return false
		}
		num, err := strconv.Atoi(args[0])
		lines, err2 := strconv.Atoi(args[1])
		if err != nil || err2 != nil || num < 1 || num > len(sess.msgs) || sess.msgs[num-1].deleted {
			_ = sess.tp.PrintfLine("-ERR no such message")
			return false
		}

		m := sess.msgs[num-1].msg
		topBytes := extractTop(m.Raw, lines)
		_ = sess.tp.PrintfLine("+OK top of message follows")
		sess.sendDotStuffed(topBytes)

	case "DELE":
		if sess.state != stateTransaction {
			_ = sess.tp.PrintfLine("-ERR command only valid in TRANSACTION state")
			return false
		}
		if len(args) == 0 {
			_ = sess.tp.PrintfLine("-ERR message number required")
			return false
		}
		num, err := strconv.Atoi(args[0])
		if err != nil || num < 1 || num > len(sess.msgs) || sess.msgs[num-1].deleted {
			_ = sess.tp.PrintfLine("-ERR no such message")
			return false
		}
		sess.msgs[num-1].deleted = true
		_ = sess.tp.PrintfLine("+OK message %d marked for deletion", num)

	case "RSET":
		if sess.state != stateTransaction {
			_ = sess.tp.PrintfLine("-ERR command only valid in TRANSACTION state")
			return false
		}
		for i := range sess.msgs {
			sess.msgs[i].deleted = false
		}
		_ = sess.tp.PrintfLine("+OK maildrop reset")

	case "NOOP":
		if sess.state != stateTransaction {
			_ = sess.tp.PrintfLine("-ERR command only valid in TRANSACTION state")
			return false
		}
		_ = sess.tp.PrintfLine("+OK")

	default:
		_ = sess.tp.PrintfLine("-ERR command unrecognized")
	}
	return false
}

func (sess *session) sendDotStuffed(data []byte) {
	r := bufio.NewReader(bytes.NewReader(data))
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimRight(line, "\r\n")
			if len(line) > 0 && line[0] == '.' {
				_ = sess.tp.PrintfLine(".%s", line)
			} else {
				_ = sess.tp.PrintfLine("%s", line)
			}
		}
		if err != nil {
			break
		}
	}
	_ = sess.tp.PrintfLine(".")
}

func extractTop(raw []byte, maxLines int) []byte {
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	sepLen := 4
	if headerEnd < 0 {
		headerEnd = bytes.Index(raw, []byte("\n\n"))
		sepLen = 2
	}
	if headerEnd < 0 {
		return raw
	}

	var out bytes.Buffer
	out.Write(raw[:headerEnd])
	out.WriteString("\r\n\r\n")

	body := raw[headerEnd+sepLen:]
	r := bufio.NewReader(bytes.NewReader(body))
	lines := 0
	for lines < maxLines {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			out.Write(bytes.TrimRight(line, "\r\n"))
			out.WriteString("\r\n")
			lines++
		}
		if err != nil {
			break
		}
	}
	return out.Bytes()
}

func (sess *session) expunge() {
	if sess.mb == nil || sess.s.db == nil {
		return
	}
	var toDelete []uint32
	for _, m := range sess.msgs {
		if m.deleted {
			toDelete = append(toDelete, m.msg.UID)
		}
	}
	if len(toDelete) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = mailbox.UpdateFlags(ctx, sess.s.db, sess.mb.ID, toDelete, []string{"\\Deleted"}, mailbox.FlagOpAdd)
	_, _ = mailbox.ExpungeDeleted(ctx, sess.s.db, sess.mb.ID, toDelete)
}
