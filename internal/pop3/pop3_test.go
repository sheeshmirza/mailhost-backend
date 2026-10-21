package pop3

import (
	"bufio"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"mailhost/internal/config"
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
