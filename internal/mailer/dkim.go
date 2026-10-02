package mailer

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/emersion/go-msgauth/dkim"
)

// GenerateDKIMKey returns a PEM-encoded RSA private key and the matching DNS TXT value.
func GenerateDKIMKey() (privatePEM []byte, dnsValue string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}
	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return privatePEM, "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub), nil
}

func ParsePrivateKey(p []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("dkim: invalid PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if rsaKey, err1 := x509.ParsePKCS1PrivateKey(block.Bytes); err1 == nil {
			return rsaKey, nil
		}
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("dkim: key is not a signer")
	}
	return s, nil
}

func Sign(raw []byte, domain, selector string, signer crypto.Signer) ([]byte, error) {
	var out bytes.Buffer
	out.Grow(len(raw) + 512)
	err := dkim.Sign(&out, bytes.NewReader(raw), &dkim.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Signer:                 signer,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             []string{"From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "List-Unsubscribe", "List-Unsubscribe-Post", "Feedback-ID"},
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
