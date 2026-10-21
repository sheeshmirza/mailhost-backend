package pop3

import (
	"bufio"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"mailhost/internal/config"
	"mailhost/internal/mailbox"
)

func TestPOP3ProtocolHandshake(t *testing.T) {
	cfg := &config.Config{
		POP3Addr: "127.0.0.1:0",
	}

	server, err := NewServer(nil, cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on ephemeral port: %v", err)
	}
	server.listener = ln
	server.addr = ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go server.handleConn(conn)
		}
	}()
	defer server.Close()

	// Connect client
	conn, err := net.DialTimeout("tcp", server.addr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial pop3 server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// 1. Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Errorf("expected +OK greeting, got: %s", greeting)
	}

	// 2. Send CAPA
	if _, err := conn.Write([]byte("CAPA\r\n")); err != nil {
		t.Fatalf("failed to write CAPA: %v", err)
	}
	capaResp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(capaResp, "+OK") {
		t.Fatalf("expected +OK for CAPA, got: %s", capaResp)
	}
	// Consume until "."
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("error reading CAPA body: %v", err)
		}
		if strings.TrimSpace(line) == "." {
			break
		}
	}

	// 3. Send NOOP before auth (should return -ERR in AUTHORIZATION state)
	if _, err := conn.Write([]byte("NOOP\r\n")); err != nil {
		t.Fatalf("failed to write NOOP: %v", err)
	}
	noopResp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(noopResp, "-ERR command only valid in TRANSACTION state") {
		t.Errorf("expected -ERR for NOOP before auth, got: %s", noopResp)
	}

	// 4. Send USER without argument
	if _, err := conn.Write([]byte("USER\r\n")); err != nil {
		t.Fatalf("failed to write USER: %v", err)
	}
	userResp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(userResp, "-ERR") {
		t.Errorf("expected -ERR for empty USER, got: %s", userResp)
	}

	// 5. Send QUIT
	if _, err := conn.Write([]byte("QUIT\r\n")); err != nil {
		t.Fatalf("failed to write QUIT: %v", err)
	}
	quitResp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(quitResp, "+OK") {
		t.Errorf("expected +OK for QUIT, got: %s", quitResp)
	}
}

func TestPOP3TransactionCommands(t *testing.T) {
	cfg := &config.Config{POP3Addr: "127.0.0.1:0"}
	srv, err := NewServer(nil, cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	sess := &session{
		s:     srv,
		conn:  serverConn,
		tp:    textproto.NewConn(serverConn),
		state: stateTransaction,
		msgs: []pop3Msg{
			{msg: mailbox.Message{UID: 101, Size: 45, Raw: []byte("Subject: Hi\r\n\r\nHello POP3\r\n.dotline\r\n")}},
			{msg: mailbox.Message{UID: 102, Size: 55, Raw: []byte("Subject: Bye\r\n\r\nGoodbye POP3\r\n")}},
		},
	}

	go func() {
		for {
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
	}()

	clientTp := textproto.NewConn(clientConn)

	// STAT
	_ = clientTp.PrintfLine("STAT")
	line, _ := clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK 2 100") {
		t.Errorf("unexpected STAT: %s", line)
	}

	// LIST all
	_ = clientTp.PrintfLine("LIST")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK 2 messages (100 octets)") {
		t.Errorf("unexpected LIST header: %s", line)
	}
	_, _ = readDotResponse(clientTp)

	// LIST 1 (valid) and LIST 99 (invalid)
	_ = clientTp.PrintfLine("LIST 1")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK 1 45") {
		t.Errorf("unexpected LIST 1: %s", line)
	}
	_ = clientTp.PrintfLine("LIST 99")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "-ERR") {
		t.Errorf("expected -ERR for LIST 99: %s", line)
	}

	// UIDL all
	_ = clientTp.PrintfLine("UIDL")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Errorf("unexpected UIDL header: %s", line)
	}
	_, _ = readDotResponse(clientTp)

	// UIDL 1 (valid) and UIDL 99 (invalid)
	_ = clientTp.PrintfLine("UIDL 1")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK 1 101") {
		t.Errorf("unexpected UIDL 1: %s", line)
	}
	_ = clientTp.PrintfLine("UIDL 99")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "-ERR") {
		t.Errorf("expected -ERR for UIDL 99: %s", line)
	}

	// RETR 1 (valid with dot-stuffing)
	_ = clientTp.PrintfLine("RETR 1")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Errorf("unexpected RETR 1 header: %s", line)
	}
	_, _ = readDotResponse(clientTp)

	// RETR missing and invalid
	_ = clientTp.PrintfLine("RETR")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "-ERR") {
		t.Errorf("expected -ERR for RETR without args: %s", line)
	}
	_ = clientTp.PrintfLine("RETR 99")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "-ERR") {
		t.Errorf("expected -ERR for RETR 99: %s", line)
	}

	// TOP 1 2
	_ = clientTp.PrintfLine("TOP 1 2")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Errorf("unexpected TOP header: %s", line)
	}
	_, _ = readDotResponse(clientTp)

	// TOP invalid arguments
	_ = clientTp.PrintfLine("TOP 1")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "-ERR") {
		t.Errorf("expected -ERR for TOP missing line count: %s", line)
	}

	// NOOP
	_ = clientTp.PrintfLine("NOOP")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Errorf("unexpected NOOP: %s", line)
	}

	// DELE 1
	_ = clientTp.PrintfLine("DELE 1")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Errorf("unexpected DELE: %s", line)
	}
	// Verify STAT reflects deletion
	_ = clientTp.PrintfLine("STAT")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK 1 55") {
		t.Errorf("unexpected STAT after DELE: %s", line)
	}

	// RSET (undo deletions)
	_ = clientTp.PrintfLine("RSET")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Errorf("unexpected RSET: %s", line)
	}
	// Verify STAT reflects reset
	_ = clientTp.PrintfLine("STAT")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK 2 100") {
		t.Errorf("unexpected STAT after RSET: %s", line)
	}

	// Unrecognized command
	_ = clientTp.PrintfLine("UNKNOWN")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "-ERR") {
		t.Errorf("expected -ERR for UNKNOWN: %s", line)
	}

	// QUIT in transaction state
	_ = clientTp.PrintfLine("QUIT")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Errorf("unexpected QUIT: %s", line)
	}
}


func TestExtractTop(t *testing.T) {
	rawCRLF := []byte("Header1: Value\r\nHeader2: Value\r\n\r\nLine1\r\nLine2\r\nLine3\r\n")
	top := extractTop(rawCRLF, 1)
	if !strings.Contains(string(top), "Header1: Value") || !strings.Contains(string(top), "Line1") || strings.Contains(string(top), "Line2") {
		t.Errorf("unexpected top output: %s", string(top))
	}

	// LF only separator
	rawLF := []byte("Header1: Value\nHeader2: Value\n\nLine1\nLine2\n")
	topLF := extractTop(rawLF, 2)
	if !strings.Contains(string(topLF), "Header1: Value") || !strings.Contains(string(topLF), "Line1") {
		t.Errorf("unexpected top LF output: %s", string(topLF))
	}

	// No separator
	rawNoSep := []byte("Just a raw blob without headers")
	if string(extractTop(rawNoSep, 5)) != string(rawNoSep) {
		t.Error("expected unchanged blob when no header separator exists")
	}
}

func TestPOP3AuthStateAndErrors(t *testing.T) {
	cfg := &config.Config{POP3Addr: "127.0.0.1:0"}
	srv, err := NewServer(nil, cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	sess := &session{
		s:     srv,
		conn:  serverConn,
		tp:    textproto.NewConn(serverConn),
		state: stateAuth,
	}

	go func() {
		for {
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
	}()

	clientTp := textproto.NewConn(clientConn)

	// STLS when TLS not configured
	_ = clientTp.PrintfLine("STLS")
	line, _ := clientTp.ReadLine()
	if !strings.HasPrefix(line, "-ERR TLS not configured on server") {
		t.Errorf("expected -ERR for STLS without config, got: %s", line)
	}

	// PASS before USER and without TLS
	_ = clientTp.PrintfLine("PASS secret")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "-ERR TLS is required") {
		t.Errorf("expected -ERR for PASS without TLS, got: %s", line)
	}

	// USER command valid
	_ = clientTp.PrintfLine("USER alice@example.com")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK User accepted") {
		t.Errorf("expected +OK for valid USER, got: %s", line)
	}

	// Fake TLS session to test USER already set + PASS without DB
	sess.isTLS = true
	_ = clientTp.PrintfLine("PASS secret")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "-ERR") {
		t.Errorf("expected -ERR for DB nil authenticate, got: %s", line)
	}

	// STLS when already in TLS mode
	_ = clientTp.PrintfLine("STLS")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "-ERR already in TLS mode") {
		t.Errorf("expected -ERR already in TLS mode, got: %s", line)
	}

	// Commands requiring TRANSACTION state must fail in AUTH state
	invalidInAuth := []string{"STAT", "LIST", "UIDL", "RETR 1", "TOP 1 1", "DELE 1", "RSET"}
	for _, cmd := range invalidInAuth {
		_ = clientTp.PrintfLine("%s", cmd)
		line, _ = clientTp.ReadLine()
		if !strings.HasPrefix(line, "-ERR") {
			t.Errorf("expected -ERR for %s in auth state: %s", cmd, line)
		}
	}

	// QUIT in auth state
	_ = clientTp.PrintfLine("QUIT")
	line, _ = clientTp.ReadLine()
	if !strings.HasPrefix(line, "+OK") {
		t.Errorf("expected +OK for QUIT, got: %s", line)
	}

	// expunge on nil mailbox / DB
	sess.expunge()

	// NewServer with non-existent TLS cert/key
	tlsCfg := &config.Config{
		POP3Addr:    "127.0.0.1:0",
		TLSCertFile: "/path/to/missing/cert.pem",
		TLSKeyFile:  "/path/to/missing/key.pem",
	}
	if _, err := NewServer(nil, tlsCfg, slog.Default()); err == nil {
		t.Error("expected error for missing TLS keypair in NewServer")
	}
}


func TestPOP3ListenAndServe(t *testing.T) {
	cfg := &config.Config{POP3Addr: "127.0.0.1:0"}
	srv, err := NewServer(nil, cfg, slog.Default())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	srv.addr = ln.Addr().String()
	ln.Close() // close immediately so ListenAndServe can bind

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	// Wait for listener to bind
	var conn net.Conn
	for range 20 {
		conn, err = net.DialTimeout("tcp", srv.addr, 200*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if conn != nil {
		conn.Close()
	}

	_ = srv.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ListenAndServe returned unexpected error on Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("timed out waiting for ListenAndServe to exit on Close()")
	}
}

func readDotResponse(tp *textproto.Conn) ([]string, error) {
	var lines []string
	for {
		l, err := tp.ReadLine()
		if err != nil {
			return lines, err
		}
		if strings.TrimSpace(l) == "." {
			break
		}
		lines = append(lines, l)
	}
	return lines, nil
}



