// Package mailer validates addresses and builds or parses RFC 5322 messages.
package mailer

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Attachment is a MIME attachment included in an outgoing message.
type Attachment struct {
	Filename    string
	ContentType string
	Content     []byte
}

// Message contains the headers, bodies, and attachments for an outgoing email.
type Message struct {
	From        string
	To, Cc      []string
	ReplyTo     []string
	Subject     string
	Text, HTML  string
	Headers     map[string]string
	Attachments []Attachment
	MessageID   string // without angle brackets
	Date        time.Time
}

var (
	headerNameRe    = regexp.MustCompile(`^[A-Za-z0-9-]{1,76}$`)
	reservedHeaders = map[string]bool{
		"From": true, "To": true, "Cc": true, "Bcc": true, "Reply-To": true, "Subject": true,
		"Date": true, "Message-Id": true, "Mime-Version": true, "Content-Type": true,
		"Content-Transfer-Encoding": true, "Dkim-Signature": true, "Return-Path": true, "Sender": true,
	}
)

func isDangerousHeaderString(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == '\r' || b == '\n' || b == 0 {
			return true
		}
		if b >= 0x80 {
			// Multi-byte UTF-8 detected: scan runes for Bidirectional Override characters and forbidden chars
			for _, r := range s[i:] {
				if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == '\r' || r == '\n' || r == 0 {
					return true
				}
			}
			return false
		}
	}
	return false
}

// ParseAddress parses an RFC 5322 address, rejecting line breaks, null bytes, and directional overrides.
func ParseAddress(s string) (*mail.Address, error) {
	if isDangerousHeaderString(s) {
		return nil, errors.New("address contains forbidden characters")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q", s)
	}
	return a, nil
}

func formatList(list []string) (string, error) {
	out := make([]string, 0, len(list))
	for _, s := range list {
		a, err := ParseAddress(s)
		if err != nil {
			return "", err
		}
		out = append(out, a.String())
	}
	return strings.Join(out, ",\r\n "), nil
}

var bufPool = sync.Pool{
	New: func() any {
		b := new(bytes.Buffer)
		b.Grow(4096)
		return b
	},
}

func getBuf() *bytes.Buffer {
	b := bufPool.Get().(*bytes.Buffer)
	b.Reset()
	return b
}

func putBuf(b *bytes.Buffer) {
	if b.Cap() <= 1<<20 { // keep buffers <= 1MB to prevent memory bloat
		bufPool.Put(b)
	}
}

// Build renders an RFC 5322 message with CRLF line endings.
func Build(m *Message) ([]byte, error) {
	buf := getBuf()
	defer putBuf(buf)
	put := func(k, v string) {
		buf.WriteString(k)
		buf.WriteString(": ")
		buf.WriteString(v)
		buf.WriteString("\r\n")
	}

	from, err := ParseAddress(m.From)
	if err != nil {
		return nil, err
	}
	put("From", from.String())
	for _, h := range []struct {
		name string
		list []string
	}{{"To", m.To}, {"Cc", m.Cc}, {"Reply-To", m.ReplyTo}} {
		if len(h.list) == 0 {
			continue
		}
		v, err := formatList(h.list)
		if err != nil {
			return nil, err
		}
		put(h.name, v)
	}
	if isDangerousHeaderString(m.Subject) || len(m.Subject) > 900 {
		return nil, errors.New("subject must be a single line without forbidden characters of at most 900 bytes")
	}
	put("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	date := m.Date
	if date.IsZero() {
		date = time.Now()
	}
	put("Date", date.Format(time.RFC1123Z))
	put("Message-ID", "<"+m.MessageID+">")
	put("MIME-Version", "1.0")

	names := make([]string, 0, len(m.Headers))
	for k := range m.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := m.Headers[k]
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if !headerNameRe.MatchString(k) || reservedHeaders[ck] {
			return nil, fmt.Errorf("header %q is not allowed", k)
		}
		if isDangerousHeaderString(v) || len(v) > 900 {
			return nil, fmt.Errorf("header %q has an invalid value", k)
		}
		put(ck, mime.QEncoding.Encode("utf-8", v))
	}

	body, err := buildBody(m)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(body.header))
	for k := range body.header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		put(k, body.header.Get(k))
	}
	buf.WriteString("\r\n")
	buf.Write(body.data)
	res := make([]byte, buf.Len())
	copy(res, buf.Bytes())
	return res, nil
}

type part struct {
	header textproto.MIMEHeader
	data   []byte
}

func buildBody(m *Message) (part, error) {
	var content part
	var err error
	switch {
	case m.Text != "" && m.HTML != "":
		content, err = multipartOf("alternative", []part{qpPart("text/plain", m.Text), qpPart("text/html", m.HTML)})
		if err != nil {
			return part{}, err
		}
	case m.HTML != "":
		content = qpPart("text/html", m.HTML)
	default:
		content = qpPart("text/plain", m.Text)
	}
	if len(m.Attachments) == 0 {
		return content, nil
	}
	parts := []part{content}
	for _, a := range m.Attachments {
		p, err := attachmentPart(a)
		if err != nil {
			return part{}, err
		}
		parts = append(parts, p)
	}
	return multipartOf("mixed", parts)
}

func qpPart(ctype, s string) part {
	b := getBuf()
	w := quotedprintable.NewWriter(b)
	w.Write([]byte(s))
	w.Close()
	data := make([]byte, b.Len())
	copy(data, b.Bytes())
	putBuf(b)
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", ctype+"; charset=utf-8")
	h.Set("Content-Transfer-Encoding", "quoted-printable")
	return part{h, data}
}

func attachmentPart(a Attachment) (part, error) {
	if a.Filename == "" || isDangerousHeaderString(a.Filename) {
		return part{}, errors.New("attachment filename is invalid")
	}
	ct := a.ContentType
	if ct == "" {
		if ct = mime.TypeByExtension(filepath.Ext(a.Filename)); ct == "" {
			ct = "application/octet-stream"
		}
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || isDangerousHeaderString(ct) {
		return part{}, fmt.Errorf("invalid attachment content type %q", ct)
	}
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", mime.FormatMediaType(mt, params))
	disp := mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename})
	if disp == "" {
		return part{}, errors.New("attachment filename is invalid")
	}
	h.Set("Content-Disposition", disp)
	h.Set("Content-Transfer-Encoding", "base64")

	enc := base64.StdEncoding.EncodeToString(a.Content)
	b := getBuf()
	b.Grow(len(enc) + len(enc)/76*2 + 2)
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteString("\r\n")
	data := make([]byte, b.Len())
	copy(data, b.Bytes())
	putBuf(b)
	return part{h, data}, nil
}

func multipartOf(sub string, parts []part) (part, error) {
	b := getBuf()
	mw := multipart.NewWriter(b)
	for _, p := range parts {
		w, err := mw.CreatePart(p.header)
		if err != nil {
			putBuf(b)
			return part{}, err
		}
		w.Write(p.data)
	}
	mw.Close()
	data := make([]byte, b.Len())
	copy(data, b.Bytes())
	boundary := mw.Boundary()
	putBuf(b)
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", mime.FormatMediaType("multipart/"+sub, map[string]string{"boundary": boundary}))
	return part{h, data}, nil
}
