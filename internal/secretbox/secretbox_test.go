package secretbox

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSecretbox(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	box, err := New(key)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	plaintext := []byte("highly-sensitive-dkim-private-key-data-1234567890")
	ciphertext, err := box.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	decrypted, err := box.Open(ciphertext)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted %q != plaintext %q", decrypted, plaintext)
	}

	// Tampering detection
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xff

	if _, err := box.Open(tampered); err == nil {
		t.Fatal("Open succeeded on tampered ciphertext, expected authentication error")
	}

	// Invalid key length checks
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("New succeeded with 16-byte key, expected error")
	}
	if _, err := New(nil); err == nil {
		t.Fatal("New succeeded with nil key, expected error")
	}
}

